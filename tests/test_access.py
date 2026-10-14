import json

import pytest

from plumbline.access import AccessError, NotFound
from plumbline.policy import PolicyError

from conftest import READ_POLICY, ROLE


def request(pl, contract, policy=READ_POLICY, minutes=60, actor="alice@acme.example",
            purpose="Debug the nightly export job", ticket="OPS-123"):
    return pl.access.request_access(actor, contract["id"], purpose, ticket, policy, minutes)


def test_contract_validation(pl):
    with pytest.raises(AccessError):
        pl.access.create_contract("admin", "a", "v", "o", ROLE, "2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z",
                                  {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]})
    with pytest.raises(AccessError):
        pl.access.create_contract("admin", "a", "v", "o", "not-an-arn", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z",
                                  {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]})
    with pytest.raises(PolicyError):
        pl.access.create_contract("admin", "a", "v", "o", ROLE, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z",
                                  {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})


@pytest.mark.parametrize("bad_arn", [
    "arn:aws:iam:::role/contractor-acme",            # empty account id (a real mistake seen in testing)
    "arn:aws:iam::12345:role/contractor-acme",       # account id too short
    "arn:aws:iam::111111111111:user/someone",        # not a role
    "arn:aws:iam::111111111111:role/",               # no name
])
def test_malformed_role_arn_is_refused(pl, bad_arn):
    with pytest.raises(AccessError, match="role_arn must look like"):
        pl.access.create_contract("admin", "a", "v", "o", bad_arn, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z",
                                  {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]})


def test_one_role_per_active_contract(pl, contract):
    with pytest.raises(AccessError, match="one role per contract"):
        pl.access.create_contract("admin", "bob@other.example", "Other", "o", ROLE, "2026-01-01T00:00:00Z",
                                  "2026-02-01T00:00:00Z", {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]})


def test_request_records_blast_radius_for_the_approver(pl, contract):
    r = request(pl, contract)
    assert r["status"] == "pending" and r["blast_radius"]["risk"] == "low"


def test_only_the_named_contractor_can_request(pl, contract):
    with pytest.raises(AccessError, match="only the contractor"):
        request(pl, contract, actor="mallory@evil.example")


@pytest.mark.parametrize("kwargs,msg", [
    ({"purpose": "debug"}, "purpose"),
    ({"ticket": "  "}, "ticket"),
    ({"minutes": 5}, "duration"),
    ({"minutes": 9999}, "duration"),
])
def test_request_rules(pl, contract, kwargs, msg):
    with pytest.raises(AccessError, match=msg):
        request(pl, contract, **kwargs)


def test_request_outside_contract_scope_is_refused_and_audited(pl, contract):
    bad = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    with pytest.raises(AccessError, match="exceeds the contract scope"):
        request(pl, contract, policy=bad)
    actions = [e["action"] for e in pl.audit.entries()]
    assert "request.rejected_scope" in actions


def test_request_after_contract_end_is_refused(pl, contract, clock):
    clock.advance(days=200)
    with pytest.raises(AccessError, match="not active"):
        request(pl, contract)


def test_cannot_approve_own_request(pl, contract):
    r = request(pl, contract)
    with pytest.raises(AccessError, match="your own"):
        pl.access.decide("alice@acme.example", r["id"], True)


def test_claim_before_approval_fails(pl, contract):
    r = request(pl, contract)
    with pytest.raises(AccessError, match="not approved"):
        pl.access.claim("alice@acme.example", r["id"])


def test_happy_path_issues_session_scoped_to_request(pl, contract, gw, clock):
    r = request(pl, contract, minutes=60)
    pl.access.decide("bob@corp.example", r["id"], True, "ok")
    out = pl.access.claim("alice@acme.example", r["id"])
    assert out["grant"]["status"] == "active"
    assert out["credentials"]["session_token"]
    call = gw.assumed[0]
    assert call["role_arn"] == ROLE and call["duration"] == 3600
    sent = json.loads(call["policy_json"])
    assert sent["Statement"][0]["Action"] == ["s3:GetObject", "s3:ListBucket"]
    # secrets are not stored anywhere
    dump = json.dumps([dict(r) for r in pl.db.query("SELECT * FROM grants")])
    assert "fake-secret" not in dump and "fake-token" not in dump


def test_claim_can_only_happen_once_and_only_by_requester(pl, contract):
    r = request(pl, contract)
    pl.access.decide("bob@corp.example", r["id"], True)
    with pytest.raises(AccessError, match="only the requester"):
        pl.access.claim("mallory@evil.example", r["id"])
    pl.access.claim("alice@acme.example", r["id"])
    with pytest.raises(AccessError, match="claimed"):
        pl.access.claim("alice@acme.example", r["id"])


def test_grant_never_outlives_contract(pl, clock):
    c = pl.access.create_contract("admin", "alice@acme.example", "Acme", "bob@corp.example", ROLE,
                                  "2026-01-01T00:00:00Z", "2026-01-05T11:00:00Z",
                                  {"Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}]})
    r = request(pl, c, minutes=480)   # would run to 17:00, contract ends 11:00
    pl.access.decide("bob@corp.example", r["id"], True)
    g = pl.access.claim("alice@acme.example", r["id"])["grant"]
    assert g["expires_at"] == "2026-01-05T11:00:00Z"


def test_contract_ending_within_15_minutes_cannot_be_approved(pl):
    c = pl.access.create_contract("admin", "alice@acme.example", "Acme", "bob@corp.example", ROLE,
                                  "2026-01-01T00:00:00Z", "2026-01-05T09:10:00Z",
                                  {"Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}]})
    r = request(pl, c, minutes=30)
    with pytest.raises(AccessError, match="under 15 minutes"):
        pl.access.decide("bob@corp.example", r["id"], True)


def test_approval_lapses_if_claimed_too_late(pl, contract, clock):
    r = request(pl, contract, minutes=30)
    pl.access.decide("bob@corp.example", r["id"], True)
    clock.advance(minutes=20)   # only 10 minutes of approved time remain
    with pytest.raises(AccessError, match="run out"):
        pl.access.claim("alice@acme.example", r["id"])
    assert pl.access.get_request(r["id"])["status"] == "lapsed"


def test_denied_request_cannot_be_claimed(pl, contract):
    r = request(pl, contract)
    pl.access.decide("bob@corp.example", r["id"], False, "not needed")
    with pytest.raises(AccessError, match="denied"):
        pl.access.claim("alice@acme.example", r["id"])


def test_sts_failure_leaves_request_claimable(pl, contract, gw):
    r = request(pl, contract)
    pl.access.decide("bob@corp.example", r["id"], True)
    gw.fail_assume = True
    with pytest.raises(AccessError, match="could not issue"):
        pl.access.claim("alice@acme.example", r["id"])
    assert pl.access.get_request(r["id"])["status"] == "approved"
    gw.fail_assume = False
    assert pl.access.claim("alice@acme.example", r["id"])["grant"]["status"] == "active"


def test_expire_due_marks_grants(pl, contract, clock):
    r = request(pl, contract, minutes=30)
    pl.access.decide("bob@corp.example", r["id"], True)
    g = pl.access.claim("alice@acme.example", r["id"])["grant"]
    assert pl.access.expire_due() == []
    clock.advance(minutes=31)
    assert pl.access.expire_due() == [g["id"]]
    assert pl.access.get_grant(g["id"])["status"] == "expired"


def test_revoke_calls_gateway_for_the_contracts_own_role(pl, contract, gw):
    r = request(pl, contract)
    pl.access.decide("bob@corp.example", r["id"], True)
    g = pl.access.claim("alice@acme.example", r["id"])["grant"]
    out = pl.access.revoke("bob@corp.example", g["id"], "suspicious")
    assert out["status"] == "revoked" and gw.revocations[0][0] == "contractor-acme"
    with pytest.raises(AccessError, match="already"):
        pl.access.revoke("bob@corp.example", g["id"], "again")


def test_ending_a_contract_revokes_grants_and_cancels_open_requests(pl, contract):
    r1 = request(pl, contract)
    pl.access.decide("bob@corp.example", r1["id"], True)
    g = pl.access.claim("alice@acme.example", r1["id"])["grant"]
    r2 = request(pl, contract)
    pl.access.end_contract("admin", contract["id"])
    assert pl.access.get_grant(g["id"])["status"] == "revoked"
    assert pl.access.get_request(r2["id"])["status"] == "cancelled"
    with pytest.raises(AccessError):
        request(pl, contract)


def test_not_found(pl):
    with pytest.raises(NotFound):
        pl.access.get_request("req_nope")


def test_every_step_is_in_the_audit_trail(pl, contract):
    r = request(pl, contract)
    pl.access.decide("bob@corp.example", r["id"], True)
    pl.access.claim("alice@acme.example", r["id"])
    actions = [e["action"] for e in reversed(pl.audit.entries())]
    assert actions == ["contract.create", "request.create", "request.approve", "grant.issue"]
    assert pl.audit.verify()["ok"]
