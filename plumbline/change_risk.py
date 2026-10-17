"""Module 2: change-risk scorer.

Scores a proposed production change from facts about the change itself: who is making it,
who reviewed it, whether there is a tested rollback, how big it is, how many services it
touches, and when it is scheduled. Every score is a sum of named, weighted signals, each with
its own plain-language reason, so an approver sees exactly why a change scored the way it did.

This is not a static-analysis or test-coverage tool. It knows nothing about the change's
actual code or logic, only the facts it is given, and those facts are supplied by whoever
submits the change, not independently verified. A requester who misreports review_count or
has_rollback_plan gets a lower score than the change deserves; nothing here catches that.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .clock import iso, parse

_id_n = 0


def _id() -> str:
    global _id_n
    _id_n += 1
    import secrets
    return "chg_" + secrets.token_hex(5)


RISK_THRESHOLDS = (("critical", 11), ("high", 8), ("medium", 4), ("low", 0))

# UTC business hours used for the off-hours signal. A real deployment would read this from
# the team's own calendar; this is a fixed, documented stand-in.
BUSINESS_START_HOUR, BUSINESS_END_HOUR = 13, 23  # 8am-6pm US Eastern, roughly, in UTC


@dataclass
class Signal:
    name: str
    weight: int
    text: str


def _risk_for(score: int) -> str:
    for name, floor in RISK_THRESHOLDS:
        if score >= floor:
            return name
    return "low"  # pragma: no cover - RISK_THRESHOLDS always has a 0 floor


def score_change(*, environment: str, services: list[str], requester: str, approver: str | None,
                  scheduled_at, freeze_windows: list[tuple] | None, lines_changed: int,
                  review_count: int, has_rollback_plan: bool, rollback_tested: bool) -> dict:
    """Pure function: same inputs always give the same score. No side effects, no storage."""
    signals: list[Signal] = []
    if environment == "production":
        signals.append(Signal("PRODUCTION", 2, "Change targets production."))
    if not approver or approver == requester:
        signals.append(Signal("NO_SEPARATE_APPROVER", 3,
                               "No approver distinct from the requester; the author would be approving their own change."))
    if review_count < 1:
        signals.append(Signal("UNREVIEWED", 2, "No one has reviewed this change."))
    if not has_rollback_plan:
        signals.append(Signal("NO_ROLLBACK_PLAN", 3, "There is no rollback plan."))
    elif not rollback_tested:
        signals.append(Signal("ROLLBACK_UNTESTED", 1, "A rollback plan exists but has not been tested."))
    if lines_changed > 500:
        signals.append(Signal("LARGE_CHANGE", 2, f"{lines_changed} lines changed, a large single change."))
    elif lines_changed > 150:
        signals.append(Signal("MEDIUM_CHANGE", 1, f"{lines_changed} lines changed."))
    if len(services) >= 3:
        signals.append(Signal("MANY_SERVICES", 2, f"Touches {len(services)} services at once: {', '.join(services)}."))
    t = parse(scheduled_at) if isinstance(scheduled_at, str) else scheduled_at
    if t.weekday() >= 5 or not (BUSINESS_START_HOUR <= t.hour < BUSINESS_END_HOUR):
        signals.append(Signal("OFF_HOURS", 1, f"Scheduled for {iso(t)}, outside normal business hours, when fewer people are available if something goes wrong."))
    for start, end in (freeze_windows or []):
        s, e = (parse(x) if isinstance(x, str) else x for x in (start, end))
        if s <= t <= e:
            signals.append(Signal("CHANGE_FREEZE", 3, f"Scheduled inside a declared change freeze ({iso(s)} to {iso(e)})."))
            break
    score = sum(s.weight for s in signals)
    return {"score": score, "risk": _risk_for(score),
            "signals": [{"name": s.name, "weight": s.weight, "text": s.text} for s in signals]}


class ChangeRiskService:
    """Stores scored changes and keeps an audit trail. Freeze windows are configured once,
    for the whole service; a per-change override is out of scope for this starter version."""

    def __init__(self, db, audit, clock, freeze_windows: list[tuple] | None = None):
        self.db, self.audit, self.clock = db, audit, clock
        self.freeze_windows = freeze_windows or []

    def submit(self, actor: str, title: str, environment: str, services: list[str],
               requester: str, approver: str | None, scheduled_at: str, lines_changed: int,
               review_count: int, has_rollback_plan: bool, rollback_tested: bool) -> dict:
        if environment not in ("production", "staging", "development"):
            raise ValueError("environment must be production, staging or development")
        if lines_changed < 0 or review_count < 0:
            raise ValueError("lines_changed and review_count cannot be negative")
        result = score_change(environment=environment, services=services, requester=requester,
                              approver=approver, scheduled_at=scheduled_at, freeze_windows=self.freeze_windows,
                              lines_changed=lines_changed, review_count=review_count,
                              has_rollback_plan=has_rollback_plan, rollback_tested=rollback_tested)
        cid = _id()
        now = iso(self.clock())
        with self.db.lock:
            self.db.execute(
                "INSERT INTO changes (id, title, environment, services_json, requester, approver, scheduled_at,"
                " lines_changed, review_count, has_rollback_plan, rollback_tested, score, risk, signals_json,"
                " status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'proposed',?)",
                (cid, title, environment, json.dumps(services), requester, approver, scheduled_at,
                 lines_changed, review_count, int(has_rollback_plan), int(rollback_tested),
                 result["score"], result["risk"], json.dumps(result["signals"]), now),
            )
        self.audit.append(actor, "change.submit", {"change_id": cid, "title": title, "risk": result["risk"],
                                                    "score": result["score"]}, now)
        return self.get(cid)

    def get(self, cid: str) -> dict:
        r = self.db.one("SELECT * FROM changes WHERE id=?", (cid,))
        if not r:
            raise KeyError(f"change {cid} not found")
        return self._row(r)

    def list(self, risk: str | None = None) -> list[dict]:
        rows = (self.db.query("SELECT * FROM changes WHERE risk=? ORDER BY created_at DESC", (risk,))
                if risk else self.db.query("SELECT * FROM changes ORDER BY created_at DESC"))
        return [self._row(r) for r in rows]

    def mark_status(self, actor: str, cid: str, status: str) -> dict:
        if status not in ("proposed", "approved", "deployed", "rolled_back", "rejected"):
            raise ValueError(f"unknown status {status!r}")
        self.get(cid)  # raises if missing
        self.db.execute("UPDATE changes SET status=? WHERE id=?", (status, cid))
        self.audit.append(actor, "change.status", {"change_id": cid, "status": status}, iso(self.clock()))
        return self.get(cid)

    @staticmethod
    def _row(r) -> dict:
        return {"id": r["id"], "title": r["title"], "environment": r["environment"],
                "services": json.loads(r["services_json"]), "requester": r["requester"],
                "approver": r["approver"], "scheduled_at": r["scheduled_at"],
                "lines_changed": r["lines_changed"], "review_count": r["review_count"],
                "has_rollback_plan": bool(r["has_rollback_plan"]), "rollback_tested": bool(r["rollback_tested"]),
                "score": r["score"], "risk": r["risk"], "signals": json.loads(r["signals_json"]),
                "status": r["status"], "created_at": r["created_at"]}
