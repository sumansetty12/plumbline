from datetime import timedelta

import pytest

from conftest import READ_POLICY, ROLE, make_event
from plumbline.clock import iso

ALICE = "alice@acme.example"
BOB = "bob@corp.example"


def issue(pl, contract, minutes=60, policy=READ_POLICY):
    r = pl.access.request_access(ALICE, contract["id"], "Debug the nightly export job", "OPS-1", policy, minutes)
    pl.access.decide(BOB, r["id"], True)
    return pl.access.claim(ALICE, r["id"])["grant"]


def kinds(findings):
    return sorted(f["kind"] for f in findings)


def test_clean_session_produces_no_alerts(pl, gw, contract, clock):
    g = issue(pl, contract)
    t = clock()
    gw.events += [make_event("e1", t + timedelta(minutes=1), g["session_name"], "s3:GetObject", ["arn:aws:s3:::acme-data/a"]),
                  make_event("e2", t + timedelta(minutes=2), g["session_name"], "s3:ListBucket", ["arn:aws:s3:::acme-data"])]
    clock.advance(minutes=61)
    pl.access.expire_due()
    res = pl.analyzer.review_grant(g["id"])
    assert res["events_seen"] == 2
    assert kinds(res["findings"]) == []


def test_denied_calls_become_out_of_scope_attempt_with_evidence(pl, gw, contract, clock):
    g = issue(pl, contract)
    t = clock()
    gw.events += [make_event("e1", t + timedelta(minutes=1), g["session_name"], "iam:CreateAccessKey", error="AccessDenied"),
                  make_event("e2", t + timedelta(minutes=2), g["session_name"], "s3:GetObject", ["arn:aws:s3:::acme-data/a"])]
    clock.advance(minutes=10)
    res = pl.analyzer.review_grant(g["id"])
    f = [x for x in res["findings"] if x["kind"] == "OUT_OF_SCOPE_ATTEMPT"][0]
    assert f["severity"] == "high"                      # privilege action attempted
    ev = pl.evidence.get_many(f["evidence_ids"])
    assert any(e["event"].get("id") == "e1" for e in ev)
    assert all(e["event"].get("id") != "e2" for e in ev)  # the harmless call is not cited


def test_successful_destructive_call_is_flagged_even_though_allowed(pl, gw, contract, clock):
    pol = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}
    g = issue(pl, contract, policy=pol)
    gw.events.append(make_event("e1", clock() + timedelta(minutes=1), g["session_name"], "s3:DeleteObject", ["arn:aws:s3:::acme-data/a"]))
    clock.advance(minutes=5)
    res = pl.analyzer.review_grant(g["id"])
    assert "SENSITIVE_ACTION" in kinds(res["findings"])


def test_unused_permissions_only_reported_when_grant_has_finished(pl, gw, contract, clock):
    g = issue(pl, contract)
    gw.events.append(make_event("e1", clock() + timedelta(minutes=1), g["session_name"], "s3:GetObject", ["arn:aws:s3:::acme-data/a"]))
    clock.advance(minutes=5)
    assert "UNUSED_PERMISSIONS" not in kinds(pl.analyzer.review_grant(g["id"])["findings"])  # still active
    clock.advance(minutes=60)
    pl.access.expire_due()
    res = pl.analyzer.review_grant(g["id"])
    f = [x for x in res["findings"] if x["kind"] == "UNUSED_PERMISSIONS"][0]
    assert f["detail"]["unused_action_patterns"] == ["s3:ListBucket"]
    assert f["detail"]["suggested_policy"]["Statement"][0]["Action"] == ["s3:GetObject"]
    assert f["severity"] == "info"


def test_review_is_idempotent(pl, gw, contract, clock):
    g = issue(pl, contract)
    gw.events.append(make_event("e1", clock() + timedelta(minutes=1), g["session_name"], "iam:PassRole", error="AccessDenied"))
    clock.advance(minutes=5)
    first = pl.analyzer.review_grant(g["id"])["findings"]
    second = pl.analyzer.review_grant(g["id"])["findings"]
    assert len(first) == 1 and second == []
    assert len(pl.findings.list()) == 1


def test_other_sessions_events_are_not_attributed_to_the_grant(pl, gw, contract, clock):
    g = issue(pl, contract)
    gw.events.append(make_event("e1", clock() + timedelta(minutes=1), "someone-else", "iam:PassRole", error="AccessDenied"))
    clock.advance(minutes=5)
    assert pl.analyzer.review_grant(g["id"])["events_seen"] == 0


# ---- orphans ----
def principal(name, **kw):
    base = {"name": name, "arn": f"arn:aws:iam::1:role/{name}", "kind": "role", "contract_id": None,
            "created": "2025-01-01T00:00:00Z", "last_used": "2026-01-04T00:00:00Z"}
    base.update(kw)
    return base


def test_orphan_scan_covers_each_case(pl, gw, contract, clock):
    gw.principals = [
        principal("untagged"),
        principal("ghost", contract_id="ctr_missing"),
        principal("contractor-acme", contract_id=contract["id"]),                     # healthy
        principal("old-acme", contract_id=contract["id"], last_used="2025-06-01T00:00:00Z"),  # dormant
    ]
    found = pl.analyzer.scan_orphans()
    assert kinds(found) == ["DORMANT", "NO_CONTRACT_TAG", "UNKNOWN_CONTRACT"]


def test_principal_of_ended_contract_is_critical(pl, gw, contract):
    gw.principals = [principal("contractor-acme", contract_id=contract["id"])]
    assert pl.analyzer.scan_orphans() == []
    pl.access.end_contract("admin", contract["id"])
    f = pl.analyzer.scan_orphans()
    assert kinds(f) == ["CONTRACT_ENDED"] and f[0]["severity"] == "critical"


def test_principal_after_contract_date_passes_is_critical(pl, gw, contract, clock):
    gw.principals = [principal("contractor-acme", contract_id=contract["id"])]
    clock.advance(days=200)
    assert kinds(pl.analyzer.scan_orphans()) == ["CONTRACT_ENDED"]


def test_orphan_scan_does_not_duplicate_open_findings(pl, gw):
    gw.principals = [principal("untagged")]
    assert len(pl.analyzer.scan_orphans()) == 1
    assert pl.analyzer.scan_orphans() == []


def test_new_unused_principal_is_not_dormant(pl, gw, contract, clock):
    gw.principals = [principal("contractor-acme", contract_id=contract["id"], created="2026-01-01T00:00:00Z", last_used=None)]
    assert pl.analyzer.scan_orphans() == []


# ---- ungranted activity ----
def test_activity_with_no_grant_is_critical(pl, gw, contract, clock):
    t = clock()
    gw.events.append(make_event("e1", t, "stolen-session", "s3:GetObject", ["arn:aws:s3:::acme-data/a"], ip="198.51.100.9"))
    f = pl.analyzer.scan_ungranted_activity(t - timedelta(hours=1), t + timedelta(hours=1))
    assert kinds(f) == ["UNGRANTED_ACTIVITY"] and f[0]["severity"] == "critical"
    assert f[0]["detail"]["source_ips"] == ["198.51.100.9"]


def test_all_refused_ungranted_activity_is_high(pl, gw, contract, clock):
    t = clock()
    gw.events.append(make_event("e1", t, "stolen-session", "s3:GetObject", error="AccessDenied"))
    f = pl.analyzer.scan_ungranted_activity(t - timedelta(hours=1), t + timedelta(hours=1))
    assert f[0]["severity"] == "high"


def test_activity_inside_a_grant_window_is_not_flagged(pl, gw, contract, clock):
    g = issue(pl, contract)
    gw.events.append(make_event("e1", clock() + timedelta(minutes=5), g["session_name"], "s3:GetObject"))
    assert pl.analyzer.scan_ungranted_activity(clock() - timedelta(hours=1), clock() + timedelta(hours=2)) == []


def test_activity_after_revocation_is_flagged(pl, gw, contract, clock):
    g = issue(pl, contract)
    clock.advance(minutes=10)
    pl.access.revoke(BOB, g["id"], "suspicious")
    gw.events.append(make_event("e1", clock() + timedelta(minutes=30), g["session_name"], "s3:GetObject"))
    f = pl.analyzer.scan_ungranted_activity(clock() - timedelta(hours=1), clock() + timedelta(hours=2))
    assert kinds(f) == ["UNGRANTED_ACTIVITY"]


def test_events_from_unrelated_roles_are_ignored(pl, gw, contract, clock):
    gw.events.append(make_event("e1", clock(), "ci-job", "s3:GetObject", role="some-other-role"))
    assert pl.analyzer.scan_ungranted_activity(clock() - timedelta(hours=1), clock() + timedelta(hours=1)) == []


def test_run_all_reviews_finished_grants_and_audits(pl, gw, contract, clock):
    g = issue(pl, contract, minutes=30)
    gw.events.append(make_event("e1", clock() + timedelta(minutes=1), g["session_name"], "iam:PassRole", error="AccessDenied"))
    clock.advance(minutes=40)
    out = pl.analyzer.run_all()
    assert out["expired"] == [g["id"]]
    assert any(f["kind"] == "OUT_OF_SCOPE_ATTEMPT" for r in out["reviews"] for f in r["findings"])
    assert pl.audit.verify()["ok"]
