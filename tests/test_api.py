import pytest
from fastapi.testclient import TestClient

from conftest import CEILING, READ_POLICY, ROLE
from plumbline.api import create_app, parse_keys

KEYS = parse_keys("ka=alice@acme.example:contractor;kb=bob@corp.example:approver;kz=admin@corp.example:admin;km=mallory@evil.example:contractor")
H = lambda k: {"X-API-Key": k}  # noqa: E731


@pytest.fixture
def client(pl):
    return TestClient(create_app(pl, KEYS))


def make_contract(client):
    return client.post("/contracts", headers=H("kz"), json={
        "contractor": "alice@acme.example", "vendor": "Acme", "owner": "bob@corp.example", "role_arn": ROLE,
        "starts_at": "2026-01-01T00:00:00Z", "ends_at": "2026-03-31T00:00:00Z", "ceiling": CEILING})


def test_parse_keys_rejects_bad_specs():
    with pytest.raises(ValueError):
        parse_keys("k=alice:superuser")
    with pytest.raises(ValueError):
        parse_keys("nonsense")


def test_requires_valid_key(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers=H("wrong")).status_code == 401
    assert client.get("/me", headers=H("ka")).json() == {"name": "alice@acme.example", "role": "contractor"}


def test_role_enforcement(client):
    assert make_contract(client).status_code == 201
    assert client.post("/contracts", headers=H("ka"), json={}).status_code == 403
    assert client.get("/findings", headers=H("ka")).status_code == 403
    assert client.get("/audit", headers=H("ka")).status_code == 403
    assert client.post("/scan/run", headers=H("ka")).status_code == 403
    assert client.get("/contracts", headers=H("kb")).status_code == 200


def test_full_flow_over_http(client, gw):
    cid = make_contract(client).json()["id"]
    r = client.post("/requests", headers=H("ka"), json={"contract_id": cid, "purpose": "Debug the nightly export job",
                                                       "ticket": "OPS-9", "policy": READ_POLICY, "duration_minutes": 60})
    assert r.status_code == 201 and r.json()["blast_radius"]["risk"] == "low"
    rid = r.json()["id"]
    assert client.post(f"/requests/{rid}/claim", headers=H("ka")).status_code == 400          # not approved yet
    assert client.post(f"/requests/{rid}/decision", headers=H("ka"), json={"approve": True}).status_code == 403
    assert client.post(f"/requests/{rid}/decision", headers=H("kb"), json={"approve": True}).status_code == 200
    out = client.post(f"/requests/{rid}/claim", headers=H("ka"))
    assert out.status_code == 200 and out.headers["cache-control"] == "no-store"
    assert out.json()["credentials"]["session_token"]
    assert client.get("/audit/verify", headers=H("kb")).json()["ok"] is True


def test_contractors_only_see_their_own_requests_and_cannot_claim_others(client):
    cid = make_contract(client).json()["id"]
    rid = client.post("/requests", headers=H("ka"), json={"contract_id": cid, "purpose": "Debug the nightly export job",
                      "ticket": "OPS-9", "policy": READ_POLICY, "duration_minutes": 60}).json()["id"]
    client.post(f"/requests/{rid}/decision", headers=H("kb"), json={"approve": True})
    assert client.get("/requests", headers=H("km")).json() == []
    assert client.post(f"/requests/{rid}/claim", headers=H("km")).status_code == 400
    assert len(client.get("/requests", headers=H("ka")).json()) == 1


def test_scope_violation_returns_400_with_reason(client):
    cid = make_contract(client).json()["id"]
    r = client.post("/requests", headers=H("ka"), json={"contract_id": cid, "purpose": "Debug the nightly export job",
                    "ticket": "OPS-9", "duration_minutes": 60,
                    "policy": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}})
    assert r.status_code == 400 and "exceeds the contract scope" in r.json()["error"]


def test_malformed_policy_is_422_and_unknown_ids_404(client):
    cid = make_contract(client).json()["id"]
    r = client.post("/requests", headers=H("ka"), json={"contract_id": cid, "purpose": "Debug the nightly export job",
                    "ticket": "OPS-9", "duration_minutes": 60, "policy": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}})
    assert r.status_code == 422
    assert client.get("/findings/fnd_nope", headers=H("kb")).status_code == 404
    assert client.post("/requests/req_nope/decision", headers=H("kb"), json={"approve": True}).status_code == 404


def test_findings_evidence_and_explanation_endpoints(client, pl, gw):
    gw.principals = [{"name": "vendor-x", "arn": "arn:aws:iam::1:user/vendor-x", "kind": "user", "contract_id": None,
                      "created": "2025-01-01T00:00:00Z", "last_used": None}]
    assert client.post("/scan/run", headers=H("kb")).json()["orphan_findings"] == 1
    fid = client.get("/findings", headers=H("kb")).json()[0]["id"]
    full = client.get(f"/findings/{fid}", headers=H("kb")).json()
    assert full["kind"] == "NO_CONTRACT_TAG" and full["evidence"][0]["event"]["name"] == "vendor-x"
    ex = client.get(f"/findings/{fid}/explanation", headers=H("kb")).json()
    assert ex["source"] == "template" and full["evidence_ids"][0] in ex["summary"]
    assert client.post(f"/findings/{fid}/close", headers=H("kb")).json()["status"] == "closed"


def test_dashboard_is_served_and_does_not_use_innerhtml(client):
    r = client.get("/")
    assert r.status_code == 200 and "Plumbline" in r.text
    assert "innerHTML" not in r.text and "eval(" not in r.text   # untrusted event data is rendered as text only


def test_demo_seed_works(pl):
    from plumbline.demo import seed
    out = seed(pl)
    assert len(pl.access.list_requests()) == 2 and out["contract"].startswith("ctr_")


def test_create_contract_accepts_a_non_aws_provider(client):
    azure_ref = ("11111111-1111-1111-1111-111111111111@/subscriptions/"
                "22222222-2222-2222-2222-222222222222/resourceGroups/acme-rg"
                "#33333333-3333-3333-3333-333333333333")
    r = client.post("/contracts", headers=H("kz"), json={
        "contractor": "alice@acme.example", "vendor": "Acme", "owner": "bob@corp.example",
        "role_arn": azure_ref, "provider": "azure",
        "starts_at": "2026-01-01T00:00:00Z", "ends_at": "2026-03-31T00:00:00Z",
        "ceiling": {"Statement": [{"Effect": "Allow",
                                   "Action": "Microsoft.Storage/storageAccounts/blobServices/containers/read",
                                   "Resource": "*"}]}})
    assert r.status_code == 201 and r.json()["provider"] == "azure"


def test_create_contract_rejects_a_ref_that_does_not_match_its_provider(client):
    r = client.post("/contracts", headers=H("kz"), json={
        "contractor": "alice@acme.example", "vendor": "Acme", "owner": "bob@corp.example",
        "role_arn": ROLE, "provider": "gcp",  # an AWS-shaped ARN is not a GCP service account email
        "starts_at": "2026-01-01T00:00:00Z", "ends_at": "2026-03-31T00:00:00Z", "ceiling": CEILING})
    assert r.status_code == 400
