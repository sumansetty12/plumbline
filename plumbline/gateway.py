"""AWS access behind a small interface.

`Boto3Gateway` talks to real AWS (STS, IAM, CloudTrail). `FakeGateway` is an in-memory
stand-in used by the tests and the evaluation harness, so nothing needs an AWS account.
Both return the same normalised shapes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Protocol

from .clock import iso, parse, utcnow

CONTRACTOR_TAG = "plumbline-contractor"      # value "true" marks a contractor principal
CONTRACT_ID_TAG = "plumbline-contract-id"    # which contract the principal belongs to

_SERVICE_ALIASES = {"monitoring": "cloudwatch", "email": "ses"}


class Gateway(Protocol):
    def assume_role(self, role_arn: str, session_name: str, policy_json: str, duration_seconds: int) -> dict: ...
    def revoke_sessions(self, role_name: str, issued_before: datetime) -> None: ...
    def lookup_events(self, start: datetime, end: datetime, session_name: str | None = None) -> list[dict]: ...
    def list_contractor_principals(self) -> list[dict]: ...


def normalize_cloudtrail_event(raw: dict) -> dict:
    """Turn one CloudTrail LookupEvents record into Plumbline's flat event shape."""
    ct = json.loads(raw["CloudTrailEvent"])
    ui = ct.get("userIdentity", {})
    ptype = ui.get("type", "")
    arn = ui.get("arn", "")
    role = None
    if ptype == "AssumedRole" and ":assumed-role/" in arn:
        tail = arn.split(":assumed-role/", 1)[1]
        role, _, session = tail.partition("/")
    else:
        session = ui.get("userName") or arn.rsplit("/", 1)[-1]
    service = ct.get("eventSource", "").split(".")[0]
    service = _SERVICE_ALIASES.get(service, service)
    when = raw["EventTime"]
    return {
        "id": raw["EventId"],
        "time": iso(when) if isinstance(when, datetime) else iso(parse(str(when))),
        "principal": session,
        "principal_type": ptype,
        "role": role,
        "action": f"{service}:{ct.get('eventName', '')}",
        "resources": [r["ResourceName"] for r in raw.get("Resources", []) if r.get("ResourceName")],
        "error": ct.get("errorCode"),
        "source_ip": ct.get("sourceIPAddress"),
    }


class Boto3Gateway:
    """Real AWS. Clients can be injected (tests do) or are created from boto3 defaults.

    Notes on AWS limits that shape the design:
    * STS session durations are at least 900 seconds (15 minutes).
    * CloudTrail LookupEvents covers management events from the last 90 days only and is
      rate limited (about 2 requests per second per account).
    * Temporary credentials cannot be revoked one by one. `revoke_sessions` uses the
      standard AWS pattern: a Deny policy keyed on aws:TokenIssueTime, which ends EVERY
      session issued earlier on that role, not just one contractor's.
    """

    def __init__(self, region: str = "us-east-1", sts=None, iam=None, cloudtrail=None):
        import boto3
        self.sts = sts or boto3.client("sts", region_name=region)
        self.iam = iam or boto3.client("iam", region_name=region)
        self.cloudtrail = cloudtrail or boto3.client("cloudtrail", region_name=region)

    def assume_role(self, role_arn, session_name, policy_json, duration_seconds):
        resp = self.sts.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name,
            Policy=policy_json, DurationSeconds=duration_seconds,
        )
        c = resp["Credentials"]
        exp = c["Expiration"]
        return {
            "access_key_id": c["AccessKeyId"],
            "secret_access_key": c["SecretAccessKey"],
            "session_token": c["SessionToken"],
            "expiration": iso(exp) if isinstance(exp, datetime) else str(exp),
        }

    def revoke_sessions(self, role_name, issued_before):
        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny", "Action": "*", "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": iso(issued_before)}},
            }],
        }
        self.iam.put_role_policy(
            RoleName=role_name, PolicyName="PlumblineRevokeOlderSessions",
            PolicyDocument=json.dumps(doc),
        )

    def lookup_events(self, start, end, session_name=None):
        kwargs = {"StartTime": start, "EndTime": end}
        if session_name:
            kwargs["LookupAttributes"] = [{"AttributeKey": "Username", "AttributeValue": session_name}]
        events, token = [], None
        while True:
            if token:
                kwargs["NextToken"] = token
            resp = self.cloudtrail.lookup_events(**kwargs)
            events.extend(normalize_cloudtrail_event(e) for e in resp.get("Events", []))
            token = resp.get("NextToken")
            if not token:
                return events

    def list_contractor_principals(self):
        out = []
        for page in self.iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                tags = {t["Key"]: t["Value"] for t in self.iam.list_role_tags(RoleName=name).get("Tags", [])}
                if tags.get(CONTRACTOR_TAG) != "true":
                    continue
                detail = self.iam.get_role(RoleName=name)["Role"]
                used = detail.get("RoleLastUsed", {}).get("LastUsedDate")
                out.append({
                    "name": name, "arn": role["Arn"], "kind": "role",
                    "contract_id": tags.get(CONTRACT_ID_TAG),
                    "created": iso(role["CreateDate"]),
                    "last_used": iso(used) if used else None,
                })
        for page in self.iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                tags = {t["Key"]: t["Value"] for t in self.iam.list_user_tags(UserName=name).get("Tags", [])}
                if tags.get(CONTRACTOR_TAG) != "true":
                    continue
                used = user.get("PasswordLastUsed")
                out.append({
                    "name": name, "arn": user["Arn"], "kind": "user",
                    "contract_id": tags.get(CONTRACT_ID_TAG),
                    "created": iso(user["CreateDate"]),
                    "last_used": iso(used) if used else None,
                })
        return out


class FakeGateway:
    """In-memory gateway for tests and simulation. Mirrors the real gateway's behaviour,
    including the 15 minute STS minimum, so mistakes show up here first."""

    def __init__(self, clock=utcnow):
        self.clock = clock
        self.events: list[dict] = []
        self.principals: list[dict] = []
        self.assumed: list[dict] = []
        self.revocations: list[tuple[str, str]] = []
        self.fail_assume = False

    def assume_role(self, role_arn, session_name, policy_json, duration_seconds):
        if self.fail_assume:
            raise RuntimeError("simulated STS failure")
        if duration_seconds < 900:
            raise ValueError("DurationSeconds must be at least 900")
        exp = self.clock() + timedelta(seconds=duration_seconds)
        self.assumed.append({"role_arn": role_arn, "session_name": session_name,
                             "policy_json": policy_json, "duration": duration_seconds})
        return {"access_key_id": "ASIAFAKE" + session_name[-6:].upper(),
                "secret_access_key": "fake-secret", "session_token": "fake-token",
                "expiration": iso(exp)}

    def revoke_sessions(self, role_name, issued_before):
        self.revocations.append((role_name, iso(issued_before)))

    def lookup_events(self, start, end, session_name=None):
        out = []
        for e in self.events:
            t = parse(e["time"])
            if start <= t <= end and (session_name is None or e["principal"] == session_name):
                out.append(dict(e))
        return out

    def list_contractor_principals(self):
        return [dict(p) for p in self.principals]
