"""End-to-end contract -> request -> decide -> claim -> revoke flow for Azure and GCP
contracts, run through AccessService/Analyzer exactly like the AWS flow in test_access.py,
but against FakeAzureGateway/FakeGCPGateway so it needs no real cloud account."""
from datetime import datetime, timedelta, timezone

import pytest

from plumbline.access import AccessError
from plumbline.app_factory import build
from plumbline.gateway import FakeGateway
from plumbline.gateway_azure import FakeAzureGateway
from plumbline.gateway_gcp import FakeGCPGateway

T0 = datetime(2026, 1, 5, 9, 0, 0, tzinfo=timezone.utc)

AZURE_REF = ("11111111-1111-1111-1111-111111111111@/subscriptions/"
            "22222222-2222-2222-2222-222222222222/resourceGroups/acme-rg"
            "#33333333-3333-3333-3333-333333333333")
GCP_REF = "contractor-acme@my-project.iam.gserviceaccount.com"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def multicloud_pl(clock):
    return build(FakeGateway(clock=clock), clock=clock,
                gateways={"azure": FakeAzureGateway(clock=clock), "gcp": FakeGCPGateway(clock=clock)})


AZURE_CEILING = {"Statement": [{"Effect": "Allow",
                                "Action": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                                "Resource": "*"}]}
GCP_CEILING = {"Statement": [{"Effect": "Allow", "Action": ["storage.objects.get", "storage.objects.list"],
                             "Resource": "*"}]}


def test_build_defaults_unconfigured_contracts_to_aws(multicloud_pl):
    assert set(multicloud_pl.access.gateways) == {"aws", "azure", "gcp"}
    assert multicloud_pl.gateway is multicloud_pl.access.gateways["aws"]  # back-compat property


def test_azure_contract_full_flow(multicloud_pl, clock):
    pl = multicloud_pl
    c = pl.access.create_contract("admin", "alice@acme.example", "Acme Consulting", "bob@corp.example",
                                  AZURE_REF, T0.isoformat(), (T0 + timedelta(days=30)).isoformat(),
                                  AZURE_CEILING, provider="azure")
    assert c["provider"] == "azure"
    req = pl.access.request_access("alice@acme.example", c["id"], "Investigate a storage access issue",
                                   "OPS-1", {"Statement": [{"Effect": "Allow",
                                                            "Action": "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                                                            "Resource": "*"}]}, 30)
    pl.access.decide("bob@corp.example", req["id"], approve=True)
    out = pl.access.claim("alice@acme.example", req["id"])
    assert out["credentials"]["provider"] == "azure" and out["credentials"]["narrowing_enforced"] is False
    assert "access_key_id" not in out["credentials"]  # Azure hands back no bearer credential
    grant = out["grant"]
    assert grant["provider"] == "azure"

    revoked = pl.access.revoke("bob@corp.example", grant["id"], "done early")
    assert revoked["status"] == "revoked"
    # revoke_sessions was called with the FULL encoded reference, not a short name - Azure
    # needs the scope and role definition too, which a short name can't carry.
    assert pl.access.gateways["azure"].revocations == [AZURE_REF]


def test_gcp_contract_full_flow_and_token_shape(multicloud_pl, clock):
    pl = multicloud_pl
    c = pl.access.create_contract("admin", "carol@vendor.example", "Vendor Co", "bob@corp.example",
                                  GCP_REF, T0.isoformat(), (T0 + timedelta(days=30)).isoformat(),
                                  GCP_CEILING, provider="gcp")
    req = pl.access.request_access("carol@vendor.example", c["id"], "Pull storage objects for a migration",
                                   "OPS-2", {"Statement": [{"Effect": "Allow", "Action": "storage.objects.get",
                                                            "Resource": "*"}]}, 30)
    pl.access.decide("bob@corp.example", req["id"], approve=True)
    out = pl.access.claim("carol@vendor.example", req["id"])
    assert out["credentials"]["access_token"].startswith("ya29.")
    revoked = pl.access.revoke("bob@corp.example", out["grant"]["id"], "done")
    assert pl.access.gateways["gcp"].revocations == [GCP_REF]
    assert revoked["status"] == "revoked"


def test_gcp_duration_is_capped_at_one_hour_even_if_requested_longer(multicloud_pl, clock):
    pl = multicloud_pl
    c = pl.access.create_contract("admin", "carol@vendor.example", "Vendor Co", "bob@corp.example",
                                  GCP_REF, T0.isoformat(), (T0 + timedelta(days=30)).isoformat(),
                                  GCP_CEILING, provider="gcp")
    with pytest.raises(AccessError, match="duration must be between"):
        pl.access.request_access("carol@vendor.example", c["id"], "Needs a longer window than GCP allows",
                                 "OPS-3", {"Statement": [{"Effect": "Allow", "Action": "storage.objects.get",
                                                          "Resource": "*"}]}, 120)  # 2h > GCP's 1h ceiling


def test_azure_policy_in_aws_action_syntax_is_rejected(multicloud_pl):
    pl = multicloud_pl
    c = pl.access.create_contract("admin", "alice@acme.example", "Acme Consulting", "bob@corp.example",
                                  AZURE_REF, T0.isoformat(), (T0 + timedelta(days=30)).isoformat(),
                                  AZURE_CEILING, provider="azure")
    with pytest.raises(Exception):
        pl.access.request_access("alice@acme.example", c["id"], "Wrong action syntax for this provider",
                                 "OPS-4", {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}, 30)


def test_bad_principal_ref_for_provider_is_rejected(multicloud_pl):
    pl = multicloud_pl
    with pytest.raises(AccessError):
        pl.access.create_contract("admin", "alice@acme.example", "Acme", "bob@corp.example",
                                  "not-a-gcp-email", T0.isoformat(), (T0 + timedelta(days=30)).isoformat(),
                                  GCP_CEILING, provider="gcp")


def test_unconfigured_provider_gateway_raises_a_clear_error(clock):
    # Only AWS configured - an azure contract has nowhere to get credentials from.
    pl = build(FakeGateway(clock=clock), clock=clock)
    c = pl.access.create_contract("admin", "alice@acme.example", "Acme", "bob@corp.example",
                                  AZURE_REF, T0.isoformat(), (T0 + timedelta(days=30)).isoformat(),
                                  AZURE_CEILING, provider="azure")
    req = pl.access.request_access("alice@acme.example", c["id"], "Needs a gateway that isn't configured",
                                   "OPS-5", {"Statement": [{"Effect": "Allow",
                                                            "Action": "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                                                            "Resource": "*"}]}, 30)
    pl.access.decide("bob@corp.example", req["id"], approve=True)
    with pytest.raises(AccessError, match="no gateway configured"):
        pl.access.claim("alice@acme.example", req["id"])


def test_orphan_scan_merges_principals_across_all_configured_clouds(multicloud_pl, clock):
    pl = multicloud_pl
    pl.access.gateways["aws"].principals = [
        {"name": "vendor-legacy", "arn": "arn:aws:iam::1:user/vendor-legacy", "kind": "user",
         "contract_id": None, "created": "2025-01-01T00:00:00Z", "last_used": "2025-02-01T00:00:00Z"},
    ]
    pl.access.gateways["azure"].principals = [
        {"name": "vendor-azure-legacy", "arn": "app-999", "kind": "service-principal",
         "contract_id": None, "created": None, "last_used": None},
    ]
    pl.access.gateways["gcp"].principals = [
        {"name": "legacy@my-project.iam.gserviceaccount.com", "arn": "legacy@my-project.iam.gserviceaccount.com",
         "kind": "service-account", "contract_id": None, "created": None, "last_used": None},
    ]
    findings = pl.analyzer.scan_orphans()
    kinds_by_provider = {(f["detail"]["principal"]["provider"]) for f in findings}
    assert kinds_by_provider == {"aws", "azure", "gcp"}
    assert all(f["kind"] == "NO_CONTRACT_TAG" for f in findings)


def test_orphan_scan_skips_a_provider_whose_gateway_errors_instead_of_failing_entirely(multicloud_pl):
    pl = multicloud_pl
    pl.access.gateways["aws"].principals = [
        {"name": "vendor-legacy", "arn": "arn:aws:iam::1:user/vendor-legacy", "kind": "user",
         "contract_id": None, "created": "2025-01-01T00:00:00Z", "last_used": "2025-02-01T00:00:00Z"},
    ]

    def boom():
        raise RuntimeError("no graph_client configured")

    pl.access.gateways["azure"].list_contractor_principals = boom
    findings = pl.analyzer.scan_orphans()
    assert len(findings) == 1 and findings[0]["detail"]["principal"]["provider"] == "aws"
    audit_entry = [e for e in pl.audit.entries() if e["action"] == "scan.orphans"][-1]
    assert "azure" in audit_entry["detail"]["skipped_providers"]
