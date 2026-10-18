"""Azure access behind the same small interface as gateway.py's AWS implementation.

Azure's access-control primitives don't line up one-to-one with AWS's, so each method
below says exactly what it maps to and what is different. The short version lives in the
README's "Azure and GCP: what's the same, what's not" section.

`AzureGateway` makes real calls and needs azure-identity, azure-mgmt-authorization and
azure-mgmt-monitor (the project's optional 'azure' extra) - imported lazily so nothing
here is required unless you actually point Plumbline at Azure. `FakeAzureGateway` is the
in-memory stand-in used by tests and mirrors `FakeGateway`'s shape.

A contract's `role_arn` field holds, for an Azure contract, the string
"<service principal object id>@<role-assignment scope>#<role definition id>" - see
plumbline.identifiers for why it's packed into one field instead of three columns.
"""
from __future__ import annotations

from datetime import timedelta

from .clock import iso, parse, utcnow
from .identifiers import DURATION_BOUNDS

CONTRACTOR_TAG = "plumbline-contractor"
CONTRACT_ID_PREFIX = "plumbline-contract-id:"


def _parse_ref(ref: str) -> tuple[str, str, str]:
    principal, _, rest = ref.partition("@")
    scope, _, role_def = rest.partition("#")
    return principal, scope, role_def


class AzureGateway:
    """Real Azure.

    What 'assume_role' means here: Plumbline activates a time-bound Azure RBAC role
    assignment over the contract's (principal, scope, role) triple - a PIM "eligible role"
    activation where PIM is licensed on the tenant, otherwise a plain role assignment that
    Plumbline itself removes at expiry. There is no secret to hand back: once the
    assignment is active, the contractor's OWN Azure AD sign-in picks up the access, the
    same way any Azure RBAC grant works. The dict `claim()` returns therefore has no
    access_key_id/secret pair - just a confirmation, the activation window, and an explicit
    `narrowing_enforced: False` (see below) - unlike AWS, which mints real credentials.

    What 'revoke_sessions' means here: Plumbline removes the role assignment (or ends the
    PIM activation). Azure re-checks role assignments on every request, so this is not the
    AWS deny-older-sessions workaround - there is no older session to out-live. The
    documented caveat is Azure's own: role-assignment changes are not instant. Microsoft's
    guidance is "usually under 5 minutes, occasionally longer," so a call made in that
    window can still succeed on the old assignment.

    What 'lookup_events' means here: the subscription's Activity Log (azure-mgmt-monitor),
    which covers control-plane (ARM) operations only. Azure does not log data-plane calls -
    a blob read, a Key Vault secret GET - in the Activity Log; that needs Diagnostic
    Settings routing resource logs to Log Analytics, configured per resource, which is out
    of scope here. This is the same shape of gap as CloudTrail's management-events-only
    default, just drawn along a different line.

    What 'list_contractor_principals' means here: Azure AD service principals, found by
    their `tags`. Service principals support a flat list of tag strings, not key/value
    pairs, so the contract id is encoded as a second tag ("plumbline-contract-id:<id>")
    rather than a proper key. Listing needs a Microsoft Graph client, which has no single
    official synchronous Python SDK to default-construct the way boto3 does, so it is
    passed in rather than built here.
    """

    def __init__(self, credential=None, subscription_id: str | None = None,
                 authorization_client=None, monitor_client=None, graph_client=None):
        self.subscription_id = subscription_id
        if authorization_client is not None and monitor_client is not None:
            self.auth, self.monitor = authorization_client, monitor_client
        else:
            import azure.identity as azid
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.monitor import MonitorManagementClient
            cred = credential or azid.DefaultAzureCredential()
            self.auth = authorization_client or AuthorizationManagementClient(cred, subscription_id)
            self.monitor = monitor_client or MonitorManagementClient(cred, subscription_id)
        self.graph = graph_client  # a Microsoft Graph client; required only for list_contractor_principals

    def assume_role(self, role_arn, session_name, policy_json, duration_seconds):
        lo, hi = DURATION_BOUNDS["azure"]
        if not (lo <= duration_seconds <= hi):
            raise ValueError(f"an Azure role activation must be between {lo} and {hi} seconds")
        principal, scope, role_def = _parse_ref(role_arn)
        now = utcnow()
        exp = now + timedelta(seconds=duration_seconds)
        self.auth.role_assignment_schedule_requests.create(
            scope=scope,
            role_assignment_schedule_request_name=session_name,
            parameters={
                "properties": {
                    "principalId": principal,
                    "roleDefinitionId": role_def,
                    "requestType": "AdminAssign",
                    "scheduleInfo": {
                        "startDateTime": iso(now),
                        "expiration": {"type": "AfterDateTime", "endDateTime": iso(exp)},
                    },
                }
            },
        )
        return {
            "provider": "azure", "activation": session_name, "scope": scope,
            "role_definition_id": role_def, "expiration": iso(exp),
            "narrowing_enforced": False,
            "note": ("No bearer credential is issued. Access is through the contractor's own Azure AD "
                     "sign-in once this role assignment is active, scoped to the contract's role - not "
                     "to the narrower policy requested for this session. Azure RBAC does not support "
                     "narrowing an active role assignment below the role it grants."),
        }

    def revoke_sessions(self, role_arn, issued_before):
        principal, scope, role_def = _parse_ref(role_arn)
        self.auth.role_assignment_schedule_requests.create(
            scope=scope,
            role_assignment_schedule_request_name=f"revoke-{principal}",
            parameters={"properties": {"principalId": principal, "roleDefinitionId": role_def,
                                       "requestType": "AdminRemove"}},
        )

    def lookup_events(self, start, end, session_name=None):
        filt = f"eventTimestamp ge '{iso(start)}' and eventTimestamp le '{iso(end)}'"
        out = []
        for e in self.monitor.activity_logs.list(filter=filt):
            caller = getattr(e, "caller", None)
            if session_name and caller != session_name:
                continue
            status = getattr(e, "status", None)
            out.append({
                "id": e.event_data_id, "time": iso(e.event_timestamp), "principal": caller,
                "principal_type": "ServicePrincipal", "role": None,
                "action": e.operation_name.value if e.operation_name else None,
                "resources": [e.resource_id] if getattr(e, "resource_id", None) else [],
                "error": None if (status and status.value == "Succeeded") else (status.value if status else None),
                "source_ip": None,  # the Activity Log carries no source IP; CloudTrail does
            })
        return out

    def list_contractor_principals(self):
        if self.graph is None:
            raise RuntimeError(
                "AzureGateway has no graph_client configured; list_contractor_principals (the orphan "
                "scan) needs a Microsoft Graph client to list service principals, and this gateway was "
                "built without one. assume_role, revoke_sessions and lookup_events do not need it.")
        out = []
        for sp in self.graph.service_principals.get().value:
            tags = sp.tags or []
            if CONTRACTOR_TAG not in tags:
                continue
            cid = next((t[len(CONTRACT_ID_PREFIX):] for t in tags if t.startswith(CONTRACT_ID_PREFIX)), None)
            # Azure AD does not expose a last-sign-in time on the service principal object
            # itself without a separate, more heavily-scoped sign-in-logs call Plumbline does
            # not make here - "created"/"last_used" are honestly None rather than guessed, so
            # the DORMANT check in analysis.py simply never fires for Azure principals yet.
            out.append({"name": sp.display_name, "arn": sp.app_id, "kind": "service-principal",
                       "contract_id": cid, "created": None, "last_used": None})
        return out


class FakeAzureGateway:
    """In-memory Azure stand-in for tests, mirroring FakeGateway's shape and the same
    duration bound, so a test written against the real floor/ceiling fails here first."""

    def __init__(self, clock=utcnow):
        self.clock = clock
        self.events: list[dict] = []
        self.principals: list[dict] = []
        self.activations: list[dict] = []
        self.revocations: list[str] = []
        self.fail_assume = False

    def assume_role(self, role_arn, session_name, policy_json, duration_seconds):
        if self.fail_assume:
            raise RuntimeError("simulated Azure failure")
        lo, hi = DURATION_BOUNDS["azure"]
        if not (lo <= duration_seconds <= hi):
            raise ValueError(f"an Azure role activation must be between {lo} and {hi} seconds")
        exp = self.clock() + timedelta(seconds=duration_seconds)
        self.activations.append({"role_arn": role_arn, "session_name": session_name, "duration": duration_seconds})
        return {"provider": "azure", "activation": session_name, "expiration": iso(exp),
                "narrowing_enforced": False,
                "note": "No bearer credential is issued; access follows the contractor's own Azure AD sign-in."}

    def revoke_sessions(self, role_arn, issued_before):
        self.revocations.append(role_arn)

    def lookup_events(self, start, end, session_name=None):
        out = []
        for e in self.events:
            t = parse(e["time"])
            if start <= t <= end and (session_name is None or e["principal"] == session_name):
                out.append(dict(e))
        return out

    def list_contractor_principals(self):
        return [dict(p) for p in self.principals]
