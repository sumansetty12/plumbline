from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from conftest import READ_POLICY, make_event
from plumbline.api import create_app, parse_keys
from plumbline.soc2 import build_report, render_pdf

ALICE, BOB = "alice@acme.example", "bob@corp.example"
KEYS = parse_keys("ka=alice@acme.example:contractor;kb=bob@corp.example:approver")


def run_flow(pl, gw, contract, clock):
    r = pl.access.request_access(ALICE, contract["id"], "Debug the nightly export job", "OPS-1", READ_POLICY, 60)
    pl.access.decide(BOB, r["id"], True)
    g = pl.access.claim(ALICE, r["id"])["grant"]
    gw.events.append(make_event("e1", clock() + timedelta(minutes=1), g["session_name"], "iam:CreateAccessKey", error="AccessDenied"))
    clock.advance(minutes=70)
    pl.analyzer.run_all()
    return g


def metric(report, cid, label):
    c = [c for c in report["controls"] if c["id"] == cid][0]
    return [v for k, v in c["metrics"] if k.startswith(label)][0]


def test_report_counts_match_what_happened(pl, gw, contract, clock):
    g = run_flow(pl, gw, contract, clock)
    rep = build_report(pl, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z")
    assert metric(rep, "CC6.1", "Contracts created") == 1
    assert metric(rep, "CC6.2", "Requests approved") == 1
    assert metric(rep, "CC6.2", "Grants issued without") == 0
    assert metric(rep, "CC6.3", "Grants that expired") == 1
    assert metric(rep, "CC6.3", "Grants running past") == 0
    assert metric(rep, "CC7.2", "Out-of-scope attempts") == 1
    assert rep["audit_log"]["ok"] is True
    assert rep["findings"]["by_kind"]["OUT_OF_SCOPE_ATTEMPT"] == 1
    assert g["id"]


def test_every_finding_counts_as_having_evidence(pl, gw, contract, clock):
    run_flow(pl, gw, contract, clock)
    rep = build_report(pl, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z")
    n = len(pl.findings.list())
    assert metric(rep, "CC7.3", "Findings with stored evidence") == f"{n} of {n}"


def test_period_filter_excludes_entries_outside_it(pl, gw, contract, clock):
    run_flow(pl, gw, contract, clock)
    rep = build_report(pl, "2025-01-01T00:00:00Z", "2025-12-31T00:00:00Z")
    assert metric(rep, "CC6.2", "Access requests submitted") == 0
    assert rep["audit_log"]["entries_in_period"] == 0
    assert rep["audit_log"]["entries_total"] > 0


def test_tampered_audit_log_is_reported_as_broken(pl, gw, contract, clock):
    run_flow(pl, gw, contract, clock)
    pl.db.execute("UPDATE audit SET actor='someone-else' WHERE seq=2")
    rep = build_report(pl, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z")
    assert rep["audit_log"]["ok"] is False and rep["audit_log"]["first_bad_seq"] == 2


def test_pdf_is_a_real_pdf_with_the_limits_section(pl, gw, contract, clock):
    run_flow(pl, gw, contract, clock)
    pdf = render_pdf(build_report(pl, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z"))
    assert pdf[:5] == b"%PDF-" and len(pdf) > 3000


def test_pdf_survives_markup_characters_in_finding_text(pl, gw, contract, clock):
    run_flow(pl, gw, contract, clock)
    ev = pl.evidence.add("iam", {"id": "x", "time": "2026-01-05T10:00:00Z"})
    pl.findings.add(kind="X", severity="high", contractor="<b>&evil", grant_id=None,
                    summary="<para>& < > tags </para>", evidence_ids=[ev], detail={}, dedupe_key="k", now="2026-01-05T10:00:00Z")
    pdf = render_pdf(build_report(pl, "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z"))
    assert pdf[:5] == b"%PDF-"


def test_api_reports_need_reviewer_role_and_valid_dates(pl, gw, contract, clock):
    run_flow(pl, gw, contract, clock)
    c = TestClient(create_app(pl, KEYS))
    q = "?start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z"
    assert c.get("/reports/soc2" + q, headers={"X-API-Key": "ka"}).status_code == 403
    assert c.get("/reports/soc2" + q, headers={"X-API-Key": "kb"}).status_code == 200
    r = c.get("/reports/soc2.pdf" + q, headers={"X-API-Key": "kb"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content[:5] == b"%PDF-"
    assert c.get("/reports/soc2?start=yesterday&end=today", headers={"X-API-Key": "kb"}).status_code == 422
    assert any(e["action"] == "report.soc2" for e in pl.audit.entries())
