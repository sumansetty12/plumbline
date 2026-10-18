"""GCP access behind the same interface as the AWS and Azure gateways.

`GCPGateway` makes real calls and needs google-auth plus google-cloud-iam-credentials and
google-cloud-logging (the project's optional 'gcp' extra) - imported lazily, same pattern as
the AWS and Azure gateways. `FakeGCPGateway` is the in-memory stand-in used by tests.

A contract's `role_arn` field holds, for a GCP contract, the service account's email, e.g.
"contractor-acme@my-project.iam.gserviceaccount.com".

What 'assume_role' means here: the IAM Credentials API's generateAccessToken, called against
the contract's service account. This does mint a real bearer token - closer to AWS STS than
to Azure's grant-based model - but GCP caps a directly generated token's lifetime at 1 hour,
which is why this provider's duration bounds top out there; a sub-request that needs longer
has to be re-claimed, the same idea as AWS's own max-session-duration ceiling.

What 'revoke_sessions' means here: GCP has no API to invalidate a token that has already
been minted. Unlike AWS's deny-policy trick or Azure's role-assignment removal, a GCP access
token keeps working until it simply expires, however the service account's IAM bindings
change in the meantime. `revoke_sessions` removes the IAM policy binding so no FUTURE call to
generateAccessToken can mint a new token, and because GCP also checks IAM policy on every API
call, resources covered by that check do stop honouring the token too - but only once the
binding change has propagated, which Google documents as eventually consistent within a few
minutes, not immediately. The honest summary: expect an already-issued token to keep working
for up to the shorter of "a few minutes" and whatever is left of its (at most one hour)
lifetime.

What 'lookup_events' means here: Cloud Logging's Admin Activity audit logs, which are always
on but cover control-plane calls only. Data Access audit logs - the equivalent of an
individual object read - are off by default per service, billed separately, and not
available for every GCP service at all. That is the same "management events only" gap
CloudTrail and Azure's Activity Log both have, for the same reason: full data-plane logging
is opt-in and billed separately on every major cloud, not a Plumbline limitation specifically.

What 'list_contractor_principals' means here: service accounts in the project, filtered by
label. GCP service accounts support real key/value labels, so this is the cleanest of the
three gateways - no tag-string encoding needed the way Azure's service principals require.
"""
from __future__ import annotations

from datetime import timedelta

from .clock import iso, parse, utcnow
from .identifiers import DURATION_BOUNDS

CONTRACTOR_LABEL = "plumbline-contractor"
CONTRACT_ID_LABEL = "plumbline-contract-id"


class GCPGateway:
    """Real GCP. `iam_admin` is a googleapiclient 'iam' v1 Resource (there is no single
    canonical google-cloud-python client for reading/writing a service account's IAM
    policy or labels as of writing), so it is passed in rather than built here."""

    def __init__(self, project_id: str, credentials=None,
                 iam_credentials_client=None, logging_client=None, iam_admin_client=None):
        self.project_id = project_id
        if iam_credentials_client is not None and logging_client is not None:
            self.iam_credentials, self.logging = iam_credentials_client, logging_client
        else:
            import google.auth
            from google.cloud import iam_credentials_v1, logging_v2
            creds = credentials or google.auth.default()[0]
            self.iam_credentials = iam_credentials_client or iam_credentials_v1.IAMCredentialsClient(credentials=creds)
            self.logging = logging_client or logging_v2.Client(project=project_id, credentials=creds)
        self.iam_admin = iam_admin_client  # googleapiclient 'iam' v1 Resource; needed for
                                           # revoke_sessions and list_contractor_principals

    def assume_role(self, role_arn, session_name, policy_json, duration_seconds):
        lo, hi = DURATION_BOUNDS["gcp"]
        if not (lo <= duration_seconds <= hi):
            raise ValueError(f"a GCP access token's lifetime must be between {lo} and {hi} seconds")
        name = f"projects/-/serviceAccounts/{role_arn}"
        resp = self.iam_credentials.generate_access_token(
            request={"name": name, "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                     "lifetime": {"seconds": duration_seconds}},
        )
        return {
            "provider": "gcp", "access_token": resp.access_token, "expiration": iso(resp.expire_time),
            "narrowing_enforced": False,
            "note": ("The token carries the service account's full IAM bindings, not the narrower "
                     "policy requested for this session; GCP has no equivalent of an inline, "
                     "per-call AWS STS session policy."),
        }

    def revoke_sessions(self, role_arn, issued_before):
        resource = f"projects/-/serviceAccounts/{role_arn}"
        policy = self.iam_admin.projects().serviceAccounts().getIamPolicy(resource=resource).execute()
        policy["bindings"] = [b for b in policy.get("bindings", [])
                              if not any(role_arn in m for m in b.get("members", []))]
        self.iam_admin.projects().serviceAccounts().setIamPolicy(
            resource=resource, body={"policy": policy}).execute()

    def lookup_events(self, start, end, session_name=None):
        filt = (f'timestamp>="{iso(start)}" AND timestamp<="{iso(end)}" '
               f'AND logName="projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity"')
        if session_name:
            filt += f' AND protoPayload.authenticationInfo.principalEmail="{session_name}"'
        out = []
        for entry in self.logging.list_entries(filter_=filt):
            p = entry.payload or {}
            auth = p.get("authenticationInfo", {})
            status = p.get("status", {})
            req = p.get("requestMetadata", {})
            out.append({
                "id": entry.insert_id, "time": iso(entry.timestamp), "principal": auth.get("principalEmail"),
                "principal_type": "ServiceAccount", "role": None,
                "action": p.get("methodName"),
                "resources": [p["resourceName"]] if p.get("resourceName") else [],
                "error": status.get("message") if status.get("code") else None,
                "source_ip": req.get("callerIp"),
            })
        return out

    def list_contractor_principals(self):
        out = []
        resp = self.iam_admin.projects().serviceAccounts().list(name=f"projects/{self.project_id}").execute()
        for sa in resp.get("accounts", []):
            labels = sa.get("labels", {})
            if labels.get(CONTRACTOR_LABEL) != "true":
                continue
            out.append({"name": sa["email"], "arn": sa["email"], "kind": "service-account",
                       "contract_id": labels.get(CONTRACT_ID_LABEL), "created": None, "last_used": None})
        return out


class FakeGCPGateway:
    """In-memory GCP stand-in for tests, mirroring FakeGateway's shape and the same
    duration bound, so a test written against the real floor/ceiling fails here first."""

    def __init__(self, clock=utcnow):
        self.clock = clock
        self.events: list[dict] = []
        self.principals: list[dict] = []
        self.tokens_issued: list[dict] = []
        self.revocations: list[str] = []
        self.fail_assume = False

    def assume_role(self, role_arn, session_name, policy_json, duration_seconds):
        if self.fail_assume:
            raise RuntimeError("simulated GCP failure")
        lo, hi = DURATION_BOUNDS["gcp"]
        if not (lo <= duration_seconds <= hi):
            raise ValueError(f"a GCP access token's lifetime must be between {lo} and {hi} seconds")
        exp = self.clock() + timedelta(seconds=duration_seconds)
        self.tokens_issued.append({"role_arn": role_arn, "session_name": session_name, "duration": duration_seconds})
        return {"provider": "gcp", "access_token": "ya29.fake-" + session_name[-6:], "expiration": iso(exp),
                "narrowing_enforced": False,
                "note": "The token carries the service account's full IAM bindings, not a narrower session policy."}

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
