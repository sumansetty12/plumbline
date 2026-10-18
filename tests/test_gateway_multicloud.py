"""Unit tests for the Azure and GCP gateways.

There is no moto-equivalent emulator for Azure or GCP readily available here, so the real
gateways (AzureGateway, GCPGateway) are tested by injecting lightweight stand-in SDK
clients and checking what they get called with - this proves the wiring (parameter names,
where things come from the encoded role_arn, what shape comes back) is correct, which is
the part Plumbline's own code is responsible for. It does not prove the real Azure/GCP
APIs behave the way their docs say; that only a live account can confirm, and unlike AWS
(which this project has tested against a real account - see the README), neither has been
exercised here. FakeAzureGateway/FakeGCPGateway (the in-memory stand-ins used elsewhere in
the test suite) are tested directly, the same way FakeGateway already is in test_gateway.py.
"""
from datetime import datetime, timedelta, timezone

import pytest

from plumbline.gateway_azure import AzureGateway, FakeAzureGateway
from plumbline.gateway_gcp import GCPGateway, FakeGCPGateway

AZURE_PRINCIPAL = "11111111-1111-1111-1111-111111111111"
AZURE_SCOPE = "/subscriptions/2222/resourceGroups/acme-rg"
AZURE_ROLE_DEF = "3333333333333333333333333333333333"
AZURE_REF = f"{AZURE_PRINCIPAL}@{AZURE_SCOPE}#{AZURE_ROLE_DEF}"
GCP_REF = "contractor-acme@my-project.iam.gserviceaccount.com"


# ---------- FakeAzureGateway / FakeGCPGateway ----------

def test_fake_azure_gateway_enforces_duration_bounds():
    gw = FakeAzureGateway()
    with pytest.raises(ValueError):
        gw.assume_role(AZURE_REF, "s", "{}", 60)  # below the 300s floor
    with pytest.raises(ValueError):
        gw.assume_role(AZURE_REF, "s", "{}", 100_000)  # above the 86400s ceiling


def test_fake_azure_gateway_assume_role_has_no_bearer_credential():
    gw = FakeAzureGateway()
    out = gw.assume_role(AZURE_REF, "plb-abc", "{}", 1800)
    assert out["narrowing_enforced"] is False
    assert "access_key_id" not in out and "access_token" not in out
    assert out["provider"] == "azure"


def test_fake_azure_gateway_records_revocations():
    gw = FakeAzureGateway()
    gw.revoke_sessions(AZURE_REF, datetime.now(timezone.utc))
    assert gw.revocations == [AZURE_REF]


def test_fake_gcp_gateway_enforces_duration_bounds():
    gw = FakeGCPGateway()
    with pytest.raises(ValueError):
        gw.assume_role(GCP_REF, "s", "{}", 60)  # below the 600s floor
    with pytest.raises(ValueError):
        gw.assume_role(GCP_REF, "s", "{}", 7200)  # above the 3600s ceiling (1 hour)


def test_fake_gcp_gateway_assume_role_returns_a_bearer_token():
    gw = FakeGCPGateway()
    out = gw.assume_role(GCP_REF, "plb-abc", "{}", 1800)
    assert out["access_token"].startswith("ya29.") and out["narrowing_enforced"] is False


def test_fake_gcp_gateway_records_revocations():
    gw = FakeGCPGateway()
    gw.revoke_sessions(GCP_REF, datetime.now(timezone.utc))
    assert gw.revocations == [GCP_REF]


def test_fake_gateways_filter_events_by_window_and_principal():
    for gw in (FakeAzureGateway(), FakeGCPGateway()):
        gw.events = [
            {"id": "e1", "time": "2026-01-05T09:00:00Z", "principal": "alice", "error": None},
            {"id": "e2", "time": "2026-01-05T11:00:00Z", "principal": "bob", "error": None},
        ]
        start, end = datetime(2026, 1, 5, 8, tzinfo=timezone.utc), datetime(2026, 1, 5, 10, tzinfo=timezone.utc)
        assert [e["id"] for e in gw.lookup_events(start, end)] == ["e1"]
        assert [e["id"] for e in gw.lookup_events(start, end, "alice")] == ["e1"]
        assert gw.lookup_events(start, end, "nobody") == []


# ---------- real gateways, with injected stand-in SDK clients ----------

class _FakeAzureScheduleRequests:
    def __init__(self):
        self.calls = []

    def create(self, scope, role_assignment_schedule_request_name, parameters):
        self.calls.append({"scope": scope, "name": role_assignment_schedule_request_name,
                           "parameters": parameters})


class _FakeAzureAuth:
    def __init__(self):
        self.role_assignment_schedule_requests = _FakeAzureScheduleRequests()


def test_azure_gateway_assume_role_activates_the_right_scope_and_role():
    auth = _FakeAzureAuth()
    gw = AzureGateway(authorization_client=auth, monitor_client=object())
    out = gw.assume_role(AZURE_REF, "plb-abc", "{}", 1800)
    call = auth.role_assignment_schedule_requests.calls[0]
    assert call["scope"] == AZURE_SCOPE
    props = call["parameters"]["properties"]
    assert props["principalId"] == AZURE_PRINCIPAL and props["roleDefinitionId"] == AZURE_ROLE_DEF
    assert props["requestType"] == "AdminAssign"
    assert out["narrowing_enforced"] is False and "access_token" not in out


def test_azure_gateway_assume_role_rejects_out_of_bounds_duration():
    gw = AzureGateway(authorization_client=_FakeAzureAuth(), monitor_client=object())
    with pytest.raises(ValueError):
        gw.assume_role(AZURE_REF, "plb-abc", "{}", 60)


def test_azure_gateway_revoke_sessions_requests_admin_remove():
    auth = _FakeAzureAuth()
    gw = AzureGateway(authorization_client=auth, monitor_client=object())
    gw.revoke_sessions(AZURE_REF, datetime.now(timezone.utc))
    call = auth.role_assignment_schedule_requests.calls[0]
    assert call["parameters"]["properties"]["requestType"] == "AdminRemove"
    assert call["parameters"]["properties"]["principalId"] == AZURE_PRINCIPAL


class _AzureStatus:
    def __init__(self, value):
        self.value = value


class _AzureOpName:
    def __init__(self, value):
        self.value = value


class _AzureActivityEvent:
    def __init__(self, event_data_id, caller, operation, succeeded, resource_id=None):
        self.event_data_id = event_data_id
        self.caller = caller
        self.event_timestamp = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
        self.operation_name = _AzureOpName(operation)
        self.status = _AzureStatus("Succeeded" if succeeded else "Failed")
        self.resource_id = resource_id


class _FakeAzureMonitor:
    def __init__(self, events):
        self._events = events
        self.activity_logs = self

    def list(self, filter):
        self.last_filter = filter
        return iter(self._events)


def test_azure_gateway_lookup_events_normalizes_and_filters_by_caller():
    events = [_AzureActivityEvent("e1", "alice", "Microsoft.Storage/storageAccounts/read", True, "rg/acct"),
             _AzureActivityEvent("e2", "bob", "Microsoft.Storage/storageAccounts/write", False)]
    gw = AzureGateway(authorization_client=_FakeAzureAuth(), monitor_client=_FakeAzureMonitor(events))
    out = gw.lookup_events(datetime(2026, 1, 5, tzinfo=timezone.utc), datetime(2026, 1, 6, tzinfo=timezone.utc),
                           session_name="alice")
    assert len(out) == 1 and out[0]["id"] == "e1" and out[0]["error"] is None
    all_out = gw.lookup_events(datetime(2026, 1, 5, tzinfo=timezone.utc), datetime(2026, 1, 6, tzinfo=timezone.utc))
    assert [e["error"] for e in all_out] == [None, "Failed"]


def test_azure_gateway_list_contractor_principals_decodes_the_contract_id_tag():
    class SP:
        def __init__(self, display_name, app_id, tags):
            self.display_name, self.app_id, self.tags = display_name, app_id, tags

    class SPList:
        def __init__(self, value):
            self.value = value

    class Graph:
        def __init__(self, sps):
            self._sps = sps
            self.service_principals = self

        def get(self):
            return SPList(self._sps)

    graph = Graph([
        SP("vendor-acme", "app-1", ["plumbline-contractor", "plumbline-contract-id:ctr_1"]),
        SP("internal-app", "app-2", []),
    ])
    gw = AzureGateway(authorization_client=_FakeAzureAuth(), monitor_client=object(), graph_client=graph)
    out = gw.list_contractor_principals()
    assert len(out) == 1
    assert out[0]["name"] == "vendor-acme" and out[0]["contract_id"] == "ctr_1"
    assert out[0]["created"] is None  # honestly unknown, not guessed


class _FakeIamCredentials:
    def __init__(self):
        self.calls = []

    def generate_access_token(self, request):
        self.calls.append(request)

        class Resp:
            access_token = "ya29.stand-in"
            expire_time = datetime(2026, 1, 5, 10, 0, tzinfo=timezone.utc)

        return Resp()


def test_gcp_gateway_assume_role_calls_generate_access_token_with_bounded_lifetime():
    iamc = _FakeIamCredentials()
    gw = GCPGateway("my-project", iam_credentials_client=iamc, logging_client=object())
    out = gw.assume_role(GCP_REF, "plb-abc", "{}", 1800)
    req = iamc.calls[0]
    assert req["name"] == f"projects/-/serviceAccounts/{GCP_REF}"
    assert req["lifetime"]["seconds"] == 1800
    assert out["access_token"] == "ya29.stand-in" and out["narrowing_enforced"] is False


def test_gcp_gateway_assume_role_rejects_out_of_bounds_duration():
    gw = GCPGateway("my-project", iam_credentials_client=_FakeIamCredentials(), logging_client=object())
    with pytest.raises(ValueError):
        gw.assume_role(GCP_REF, "plb-abc", "{}", 7200)


class _FakeIamAdminServiceAccounts:
    def __init__(self, policy=None, accounts=None):
        self.policy = policy or {"bindings": [{"role": "roles/viewer", "members": [f"serviceAccount:{GCP_REF}"]}]}
        self.accounts = accounts or []
        self.set_calls = []

    def getIamPolicy(self, resource):
        self._get_resource = resource
        return self

    def setIamPolicy(self, resource, body):
        self.set_calls.append((resource, body))
        return self

    def list(self, name):
        self._list_name = name
        return self

    def execute(self):
        if hasattr(self, "_list_name"):
            return {"accounts": self.accounts}
        return self.policy


class _FakeIamAdmin:
    def __init__(self, service_accounts):
        self._sa = service_accounts

    def projects(self):
        return self

    def serviceAccounts(self):
        return self._sa


def test_gcp_gateway_revoke_sessions_removes_the_matching_binding():
    sa = _FakeIamAdminServiceAccounts()
    gw = GCPGateway("my-project", iam_credentials_client=_FakeIamCredentials(), logging_client=object(),
                   iam_admin_client=_FakeIamAdmin(sa))
    gw.revoke_sessions(GCP_REF, datetime.now(timezone.utc))
    resource, body = sa.set_calls[0]
    assert resource == f"projects/-/serviceAccounts/{GCP_REF}"
    assert body["policy"]["bindings"] == []  # the only binding named this service account


def test_gcp_gateway_list_contractor_principals_filters_by_label():
    sa = _FakeIamAdminServiceAccounts(accounts=[
        {"email": GCP_REF, "labels": {"plumbline-contractor": "true", "plumbline-contract-id": "ctr_1"}},
        {"email": "internal@my-project.iam.gserviceaccount.com", "labels": {}},
    ])
    gw = GCPGateway("my-project", iam_credentials_client=_FakeIamCredentials(), logging_client=object(),
                   iam_admin_client=_FakeIamAdmin(sa))
    out = gw.list_contractor_principals()
    assert len(out) == 1 and out[0]["name"] == GCP_REF and out[0]["contract_id"] == "ctr_1"


class _GCPLogEntry:
    def __init__(self, insert_id, principal_email, method, resource_name, failed=False, caller_ip=None):
        self.insert_id = insert_id
        self.timestamp = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
        self.payload = {
            "authenticationInfo": {"principalEmail": principal_email},
            "methodName": method, "resourceName": resource_name,
            "status": {"code": 7, "message": "PERMISSION_DENIED"} if failed else {},
            "requestMetadata": {"callerIp": caller_ip},
        }


class _FakeLoggingClient:
    def __init__(self, entries):
        self._entries = entries

    def list_entries(self, filter_):
        self.last_filter = filter_
        return iter(self._entries)


def test_gcp_gateway_lookup_events_normalizes_entries():
    entries = [_GCPLogEntry("e1", GCP_REF, "storage.objects.get", "acme-data", caller_ip="203.0.113.5"),
              _GCPLogEntry("e2", GCP_REF, "storage.objects.delete", "acme-data", failed=True)]
    gw = GCPGateway("my-project", iam_credentials_client=_FakeIamCredentials(), logging_client=_FakeLoggingClient(entries))
    out = gw.lookup_events(datetime(2026, 1, 5, tzinfo=timezone.utc), datetime(2026, 1, 6, tzinfo=timezone.utc))
    assert [e["action"] for e in out] == ["storage.objects.get", "storage.objects.delete"]
    assert out[0]["source_ip"] == "203.0.113.5" and out[1]["error"] == "PERMISSION_DENIED"
