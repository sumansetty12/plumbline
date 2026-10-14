import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plumbline.app_factory import build  # noqa: E402
from plumbline.gateway import FakeGateway  # noqa: E402

T0 = datetime(2026, 1, 5, 9, 0, 0, tzinfo=timezone.utc)
ROLE = "arn:aws:iam::111111111111:role/contractor-acme"


class Clock:
    def __init__(self, start=T0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


CEILING = {"Statement": [{"Effect": "Allow",
                          "Action": ["s3:Get*", "s3:List*", "logs:GetLogEvents", "ec2:Describe*"],
                          "Resource": "*"}]}
READ_POLICY = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                              "Resource": ["arn:aws:s3:::acme-data", "arn:aws:s3:::acme-data/*"]}]}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def gw(clock):
    return FakeGateway(clock=clock)


@pytest.fixture
def pl(gw, clock):
    return build(gw, clock=clock)


@pytest.fixture
def contract(pl):
    return pl.access.create_contract(
        "admin", "alice@acme.example", "Acme Consulting", "bob@corp.example", ROLE,
        "2026-01-01T00:00:00Z", "2026-03-31T00:00:00Z", CEILING)


def make_event(eid, t, session, action, resources=None, error=None, role="contractor-acme", ip="203.0.113.7"):
    return {"id": eid, "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "principal": session,
            "principal_type": "AssumedRole", "role": role, "action": action,
            "resources": resources or [], "error": error, "source_ip": ip}
