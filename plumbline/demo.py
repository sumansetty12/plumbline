"""Demo data so the dashboard can be tried with no AWS account. Everything is simulated."""
from __future__ import annotations

from datetime import timedelta

from .app_factory import Plumbline
from .clock import iso

ROLE = "arn:aws:iam::111111111111:role/contractor-acme"
CEILING = {"Statement": [{"Effect": "Allow", "Resource": "*",
                          "Action": ["s3:Get*", "s3:List*", "logs:Get*", "ec2:Describe*"]}]}


def seed(pl: Plumbline) -> dict:
    now = pl.analyzer.clock()
    c = pl.access.create_contract("demo-admin", "alice@acme.example", "Acme Consulting", "bob@corp.example", ROLE,
                                  iso(now - timedelta(days=30)), iso(now + timedelta(days=60)), CEILING)
    pol = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                          "Resource": ["arn:aws:s3:::acme-data", "arn:aws:s3:::acme-data/*"]}]}
    r1 = pl.access.request_access("alice@acme.example", c["id"], "Investigate failed nightly export job",
                                  "OPS-1042", pol, 60)
    r2 = pl.access.request_access("alice@acme.example", c["id"], "Check log output for the billing sync",
                                  "OPS-1043", {"Statement": [{"Effect": "Allow", "Action": "logs:GetLogEvents",
                                                              "Resource": "*"}]}, 30)
    pl.gateway.principals = [
        {"name": "vendor-legacy", "arn": "arn:aws:iam::111111111111:user/vendor-legacy", "kind": "user",
         "contract_id": None, "created": iso(now - timedelta(days=400)), "last_used": iso(now - timedelta(days=5))},
    ]
    return {"contract": c["id"], "requests": [r1["id"], r2["id"]]}
