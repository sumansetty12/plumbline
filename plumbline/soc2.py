"""SOC 2 control mapping and audit report.

Maps what Plumbline recorded during a period to the SOC 2 Trust Services Criteria it supports
(Security category, Common Criteria CC6 and CC7), and renders a PDF an auditor can read.

Important limits, repeated in the report itself: Plumbline produces evidence about contractor
access to AWS. It does not make an organisation SOC 2 compliant, it covers only part of each
criterion, and the auditor decides what is sufficient. Criterion wording below is a short
paraphrase, not the AICPA text.
"""
from __future__ import annotations

import io
import json
from collections import Counter
from xml.sax.saxutils import escape

from .clock import iso, parse

CONTROLS = [
    ("CC6.1", "Logical access security",
     "Access to systems is restricted through logical access controls.",
     "Every contractor has a contract with a scope ceiling. Requests beyond the ceiling are refused. "
     "Credentials are short-lived STS sessions limited by a session policy."),
    ("CC6.2", "Registering and authorising users before credentials are issued",
     "New access is authorised before credentials are issued.",
     "Each request states a purpose and ticket, is approved by someone other than the requester, "
     "and only then can the contractor collect credentials, once."),
    ("CC6.3", "Modifying and removing access; least privilege; segregation of duties",
     "Access is granted by role and least privilege, duties are separated, and access is removed when no longer needed.",
     "Grants expire automatically and never outlive the contract. Ending a contract or revoking a grant removes access. "
     "Unused permissions are reported with a tighter suggested policy, and leftover contractor accounts are found by the orphan scan."),
    ("CC7.2", "Monitoring for anomalies",
     "System activity is monitored for anomalies that could indicate malicious acts or failures.",
     "CloudTrail activity is compared with what each contractor declared, with their own earlier sessions, and with the set of "
     "approved grants."),
    ("CC7.3", "Evaluating security events",
     "Security events are evaluated to decide whether they are incidents.",
     "Every finding is stored with the evidence behind it, and is tracked until a reviewer closes it."),
]

ORPHAN_KINDS = ("NO_CONTRACT_TAG", "UNKNOWN_CONTRACT", "CONTRACT_ENDED", "DORMANT")


def _count(entries, *actions):
    return sum(1 for e in entries if e["action"] in actions)


def build_report(pl, start: str, end: str, now: str | None = None) -> dict:
    """Collect everything the report needs for entries timestamped in [start, end]."""
    s, e = parse(start), parse(end)
    rows = pl.db.query("SELECT * FROM audit ORDER BY seq ASC")
    entries = [{"seq": r["seq"], "ts": r["ts"], "actor": r["actor"], "action": r["action"],
                "detail": json.loads(r["detail_json"])} for r in rows if s <= parse(r["ts"]) <= e]
    findings = [f for f in pl.findings.list() if s <= parse(f["created_at"]) <= e]
    by_kind = Counter(f["kind"] for f in findings)
    open_f = [f for f in findings if f["status"] == "open"]
    sev = Counter(f["severity"] for f in findings)

    # approvals: made by someone other than the requester, for grants issued in the period
    grants = [g for g in pl.access.list_grants() if s <= parse(g["issued_at"]) <= e]
    unapproved = 0
    for g in grants:
        r = pl.access.get_request(g["request_id"])
        if not r.get("decided_by") or r["decided_by"] == r["contractor"]:
            unapproved += 1
    over_end = sum(1 for g in grants
                   if parse(g["expires_at"]) > parse(pl.access.get_contract(g["contract_id"])["ends_at"]))
    with_evidence = sum(1 for f in findings if f["evidence_ids"])

    verification = pl.audit.verify()
    metrics = {
        "CC6.1": [
            ("Contracts created", _count(entries, "contract.create")),
            ("Requests refused for exceeding the contract's scope ceiling", _count(entries, "request.rejected_scope")),
            ("Credential sessions issued with a session policy", _count(entries, "grant.issue")),
        ],
        "CC6.2": [
            ("Access requests submitted", _count(entries, "request.create")),
            ("Requests approved", _count(entries, "request.approve")),
            ("Requests denied", _count(entries, "request.deny")),
            ("Grants issued in the period", len(grants)),
            ("Grants issued without a separate approver (should be 0)", unapproved),
        ],
        "CC6.3": [
            ("Grants that expired automatically", _count(entries, "grant.expire")),
            ("Grants revoked by a person", _count(entries, "grant.revoke")),
            ("Contracts ended", _count(entries, "contract.end")),
            ("Grants running past their contract's end date (should be 0)", over_end),
            ("Leftover or unlinked contractor accounts found", sum(by_kind[k] for k in ORPHAN_KINDS)),
            ("Grants with unused permissions reported", by_kind["UNUSED_PERMISSIONS"]),
        ],
        "CC7.2": [
            ("Grant reviews run", _count(entries, "review.grant")),
            ("Orphan-account scans run", _count(entries, "scan.orphans")),
            ("Ungranted-activity scans run", _count(entries, "scan.ungranted")),
            ("Out-of-scope attempts found", by_kind["OUT_OF_SCOPE_ATTEMPT"]),
            ("Allowed but sensitive actions found", by_kind["SENSITIVE_ACTION"]),
            ("Activity outside any grant found", by_kind["UNGRANTED_ACTIVITY"]),
            ("Sessions unusual for the contractor found", by_kind["ANOMALOUS_SESSION"]),
        ],
        "CC7.3": [
            ("Findings raised", len(findings)),
            ("Findings with stored evidence", f"{with_evidence} of {len(findings)}"),
            ("Findings closed by a reviewer", _count(entries, "finding.close")),
            ("Findings still open at report time", len(open_f)),
        ],
    }
    limits = [
        "Covers contractor access to AWS granted through Plumbline. It says nothing about other systems, employee access, or contractors who were never registered.",
        "CloudTrail lookups cover management events for the last 90 days and can arrive several minutes late. Data events (such as S3 object reads) appear only if enabled in CloudTrail.",
        "Temporary credentials cannot be revoked one by one; revocation ends all earlier sessions on the contract's role.",
        "The audit log is tamper-evident, not tamper-proof. Removing the newest entries is detected only if an earlier head hash was saved elsewhere.",
        "Anomaly checks compare a contractor with their own history and cannot judge whether activity fits the stated purpose.",
        "This report is evidence for an auditor. It is not a SOC 2 report or a statement of compliance.",
    ]
    return {
        "period": {"start": start, "end": end}, "generated_at": now or iso(pl.analyzer.clock()),
        "controls": [{"id": cid, "title": t, "asks": asks, "how": how, "metrics": metrics[cid]}
                     for cid, t, asks, how in CONTROLS],
        "audit_log": {"ok": verification["ok"], "entries_total": verification["entries"],
                      "entries_in_period": len(entries), "head": pl.audit.head(),
                      "first_bad_seq": verification["first_bad_seq"]},
        "findings": {"by_severity": dict(sev), "by_kind": dict(by_kind),
                     "open_high_or_critical": [{"id": f["id"], "kind": f["kind"], "severity": f["severity"],
                                                "contractor": f["contractor"], "summary": f["summary"]}
                                               for f in open_f if f["severity"] in ("high", "critical")]},
        "limits": limits,
    }


def render_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8.5, leading=11, textColor=colors.HexColor("#444444"))
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=18, alignment=0, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=3,
                        textColor=colors.HexColor("#1F3A5F"))
    P = lambda t, st=body: Paragraph(escape(str(t)), st)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=0.8 * inch, rightMargin=0.8 * inch,
                            topMargin=0.7 * inch, bottomMargin=0.7 * inch, title="Plumbline SOC 2 evidence report")
    story = [P("Plumbline contractor-access evidence report", h1),
             P(f"Period: {report['period']['start']} to {report['period']['end']}.  Generated: {report['generated_at']}.", small),
             Spacer(1, 6),
             P("This report summarises what Plumbline recorded about contractor access to AWS and maps it to the SOC 2 "
               "Security criteria it supports. It is evidence for your auditor, not a statement of compliance. Criterion "
               "wording is a short paraphrase, not the AICPA text.", body)]
    al = report["audit_log"]
    status = "intact" if al["ok"] else f"BROKEN at entry {al['first_bad_seq']}"
    story += [P("Audit log integrity", h2),
              P(f"Hash chain: {status}. Entries in total: {al['entries_total']}; in this period: {al['entries_in_period']}.", body),
              P(f"Head hash: {al['head']}", small),
              P("Save this head hash somewhere outside Plumbline. It is the only way to detect removal of the newest entries.", small)]
    for c in report["controls"]:
        story += [P(f"{c['id']}  {c['title']}", h2), P(f"What it asks: {c['asks']}", body),
                  P(f"What Plumbline does: {c['how']}", body), Spacer(1, 3)]
        t = Table([[P(k), P(v)] for k, v in c["metrics"]], colWidths=[5.0 * inch, 1.9 * inch])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
                               ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F9FC")),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(t)
    fi = report["findings"]
    story.append(P("Open high and critical findings", h2))
    if fi["open_high_or_critical"]:
        t = Table([[P("Finding"), P("Severity"), P("Summary")]] +
                  [[P(f["id"]), P(f["severity"]), P(f["summary"])] for f in fi["open_high_or_critical"]],
                  colWidths=[1.0 * inch, 0.8 * inch, 5.1 * inch], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6ECF5")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
    else:
        story.append(P("None.", body))
    story.append(P("What this report does not cover", h2))
    for line in report["limits"]:
        story.append(P("• " + line, body))
    doc.build(story)
    return buf.getvalue()
