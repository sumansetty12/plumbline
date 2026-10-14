"""Simulated contractor scenarios with known ground truth.

IMPORTANT: this data is simulated. Scenarios are written by the people who wrote the
rules, so the 'designed-for' categories test that the implementation does what it was
built to do, not how well it would do against real attackers. The 'known-hard'
categories are cases the rules deliberately do not cover; they exist so the results
cannot look better than the tool really is.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from plumbline.access import AccessError
from plumbline.app_factory import build
from plumbline.gateway import FakeGateway

T0 = datetime(2026, 2, 2, 9, 0, 0, tzinfo=timezone.utc)
CEILING = {"Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
    "s3:Get*", "s3:List*", "logs:Get*", "ec2:Describe*", "cloudwatch:Get*"]}]}
CEILING_WITH_DELETE = {"Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
    "s3:Get*", "s3:List*", "s3:DeleteObject"]}]}
READ_ACTIONS = ["s3:GetObject", "s3:ListBucket", "logs:GetLogEvents", "ec2:DescribeInstances", "cloudwatch:GetMetricData"]
DENIED_POOL = ["iam:CreateAccessKey", "iam:AttachRolePolicy", "iam:PassRole", "sts:AssumeRole", "s3:PutObject",
               "ec2:TerminateInstances", "secretsmanager:GetSecretValue", "rds:DeleteDBInstance"]
BAD_REQUESTS = [
    ["iam:PassRole"], ["s3:*"], ["ec2:TerminateInstances"], ["secretsmanager:GetSecretValue"],
    ["s3:PutObject", "s3:GetObject"], ["*"], ["iam:CreateAccessKey"], ["rds:DeleteDBInstance"],
]


class SimClock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


@dataclass
class Result:
    alerts: set[str] = field(default_factory=set)


@dataclass
class Scenario:
    name: str
    category: str          # 'benign' | 'designed' | 'known-hard'
    harmful: bool
    required: set[str]     # alert kinds that must appear
    allowed_extra: set[str]
    run: callable


def _ev(n, t, session, role, action, resources=None, error=None, ip="203.0.113.10"):
    return {"id": f"ev-{n}", "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "principal": session,
            "principal_type": "AssumedRole", "role": role, "action": action,
            "resources": resources or [], "error": error, "source_ip": ip}


class Env:
    def __init__(self, rng: random.Random, ceiling=CEILING):
        self.rng = rng
        self.clock = SimClock()
        self.gw = FakeGateway(clock=self.clock)
        self.pl = build(self.gw, clock=self.clock)
        self.n = 0
        tag = rng.randrange(10 ** 6)
        self.role = f"contractor-{tag}"
        self.contractor = f"c{tag}@vendor.example"
        self.contract = self.pl.access.create_contract(
            "admin", self.contractor, "Vendor", "owner@corp.example",
            f"arn:aws:iam::111111111111:role/{self.role}", "2026-01-01T00:00:00Z", "2026-06-30T00:00:00Z", ceiling)

    def eid(self):
        self.n += 1
        return self.n

    def issue(self, actions, minutes=120):
        pol = {"Statement": [{"Effect": "Allow", "Action": actions,
                              "Resource": ["arn:aws:s3:::data-bucket", "arn:aws:s3:::data-bucket/*"]}]}
        r = self.pl.access.request_access(self.contractor, self.contract["id"], "Investigate export failures", "OPS-1", pol, minutes)
        self.pl.access.decide("owner@corp.example", r["id"], True)
        return self.pl.access.claim(self.contractor, r["id"])["grant"]

    def event(self, grant_or_session, minute, action, error=None, ip="203.0.113.10", role=None):
        session = grant_or_session["session_name"] if isinstance(grant_or_session, dict) else grant_or_session
        e = _ev(self.eid(), self.clock() + timedelta(minutes=minute), session, role or self.role, action,
                ["arn:aws:s3:::data-bucket/obj"], error, ip)
        self.gw.events.append(e)

    def principal(self, name, contract_id, created="2025-01-01T00:00:00Z", last_used="2026-02-01T00:00:00Z"):
        self.gw.principals.append({"name": name, "arn": f"arn:aws:iam::1:role/{name}", "kind": "role",
                                   "contract_id": contract_id, "created": created, "last_used": last_used})

    def finish(self, hours=3):
        self.clock.advance(hours=hours)
        self.pl.analyzer.run_all()
        return Result({f["kind"] for f in self.pl.findings.list() if f["severity"] != "info"})


# ---------- designed-for ----------
def benign_session(rng):
    env = Env(rng)
    acts = rng.sample(READ_ACTIONS, rng.randint(1, 4))
    g = env.issue(acts)
    for i in range(rng.randint(3, 40)):
        env.event(g, 1 + i, rng.choice(acts), error=rng.choice([None, None, None, "NoSuchKey", "ThrottlingException"]))
    return env.finish()


def benign_healthy_principal(rng):
    env = Env(rng)
    env.principal(env.role, env.contract["id"])
    return env.finish()


def benign_new_unused_principal(rng):
    env = Env(rng)
    env.principal(env.role, env.contract["id"], created="2026-02-01T00:00:00Z", last_used=None)
    return env.finish()


def scope_creep(rng):
    env = Env(rng)
    acts = rng.sample(READ_ACTIONS, rng.randint(1, 3))
    g = env.issue(acts)
    for i in range(rng.randint(2, 15)):
        env.event(g, 1 + i, rng.choice(acts))
    for j in range(rng.randint(1, 5)):
        env.event(g, 20 + j, rng.choice(DENIED_POOL), error="AccessDenied")
    return env.finish()


def destructive_in_scope(rng):
    env = Env(rng, ceiling=CEILING_WITH_DELETE)
    g = env.issue(["s3:GetObject", "s3:DeleteObject"])
    for i in range(rng.randint(1, 8)):
        env.event(g, 1 + i, "s3:GetObject")
    for j in range(rng.randint(1, 10)):
        env.event(g, 30 + j, "s3:DeleteObject")
    return env.finish()


def stolen_credentials(rng):
    env = Env(rng)
    if rng.random() < 0.5:
        g = env.issue(["s3:GetObject"])
        env.event(g, 1, "s3:GetObject")
    stolen = f"plb-stolen{rng.randrange(10 ** 5)}"
    for i in range(rng.randint(1, 10)):
        env.event(stolen, 5 + i, rng.choice(READ_ACTIONS), ip="198.51.100.77",
                  error=rng.choice([None, None, "AccessDenied"]))
    return env.finish()


def use_after_revocation(rng):
    env = Env(rng)
    g = env.issue(["s3:GetObject"], minutes=240)
    env.event(g, 2, "s3:GetObject")
    env.clock.advance(minutes=10)
    env.pl.access.revoke("owner@corp.example", g["id"], "suspicious")
    for i in range(rng.randint(1, 6)):
        env.event(g, 30 + i, "s3:GetObject", error="AccessDenied")
    return env.finish(hours=5)


def use_after_expiry(rng):
    env = Env(rng)
    g = env.issue(["s3:GetObject"], minutes=30)
    env.event(g, 5, "s3:GetObject")
    for i in range(rng.randint(1, 6)):
        env.event(g, 45 + i * 3, "s3:GetObject", error="ExpiredToken")
    return env.finish()


def forgotten_account(rng):
    env = Env(rng)
    env.principal(env.role, env.contract["id"])
    if rng.random() < 0.5:
        env.pl.access.end_contract("admin", env.contract["id"])
    else:
        env.clock.advance(days=200)
    return env.finish()


def untagged_principal(rng):
    env = Env(rng)
    env.principal(f"vendor-{rng.randrange(10 ** 5)}", None)
    return env.finish()


def unknown_contract(rng):
    env = Env(rng)
    env.principal(f"vendor-{rng.randrange(10 ** 5)}", f"ctr_{rng.randrange(10 ** 6):06x}")
    return env.finish()


def dormant_principal(rng):
    env = Env(rng)
    env.principal(env.role, env.contract["id"], created="2025-01-01T00:00:00Z",
                  last_used=rng.choice([None, "2025-06-15T00:00:00Z"]))
    return env.finish()


def over_broad_request(rng):
    env = Env(rng)
    try:
        env.issue(rng.choice(BAD_REQUESTS))
    except AccessError:
        return Result({"REQUEST_REFUSED"})
    return Result(set())


# ---------- known-hard: the rules do not claim to catch these ----------
def slow_exfiltration_within_scope(rng):
    env = Env(rng)
    g = env.issue(["s3:GetObject", "s3:ListBucket"], minutes=240)
    for i in range(rng.randint(150, 300)):
        env.event(g, 1 + i // 2, "s3:GetObject")
    return env.finish(hours=5)


def reads_unrelated_to_purpose(rng):
    env = Env(rng)
    g = env.issue(["s3:GetObject"])
    for i in range(rng.randint(5, 30)):
        env.event(g, 1 + i, "s3:GetObject")   # purpose said "export failures"; reads HR data in scope
    return env.finish()


def credentials_used_from_two_places(rng):
    env = Env(rng)
    g = env.issue(["s3:GetObject"])
    for i in range(rng.randint(3, 10)):
        env.event(g, 1 + i, "s3:GetObject", ip="203.0.113.10")
    for i in range(rng.randint(3, 10)):
        env.event(g, 20 + i, "s3:GetObject", ip="198.51.100.200")
    return env.finish()


def S(name, cat, harmful, required, extra, fn):
    return Scenario(name, cat, harmful, set(required), set(extra), fn)


SCENARIOS = [
    S("benign_session", "benign", False, [], [], benign_session),
    S("benign_healthy_principal", "benign", False, [], [], benign_healthy_principal),
    S("benign_new_unused_principal", "benign", False, [], [], benign_new_unused_principal),
    S("scope_creep", "designed", True, ["OUT_OF_SCOPE_ATTEMPT"], [], scope_creep),
    S("destructive_in_scope", "designed", True, ["SENSITIVE_ACTION"], [], destructive_in_scope),
    S("stolen_credentials", "designed", True, ["UNGRANTED_ACTIVITY"], [], stolen_credentials),
    S("use_after_revocation", "designed", True, ["UNGRANTED_ACTIVITY"], ["OUT_OF_SCOPE_ATTEMPT"], use_after_revocation),
    S("use_after_expiry", "designed", True, ["UNGRANTED_ACTIVITY"], [], use_after_expiry),
    S("forgotten_account", "designed", True, ["CONTRACT_ENDED"], [], forgotten_account),
    S("untagged_principal", "designed", True, ["NO_CONTRACT_TAG"], [], untagged_principal),
    S("unknown_contract", "designed", True, ["UNKNOWN_CONTRACT"], [], unknown_contract),
    S("dormant_principal", "designed", True, ["DORMANT"], [], dormant_principal),
    S("over_broad_request", "designed", True, ["REQUEST_REFUSED"], [], over_broad_request),
    S("slow_exfiltration_within_scope", "known-hard", True, [], [], slow_exfiltration_within_scope),
    S("reads_unrelated_to_purpose", "known-hard", True, [], [], reads_unrelated_to_purpose),
    S("credentials_used_from_two_places", "known-hard", True, [], [], credentials_used_from_two_places),
]
