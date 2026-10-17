"""Module 3: SLO starter kit.

Define a Service Level Objective (a target like "99.9% of requests succeed over 30 days"),
record good/bad events against it, and get back the error budget remaining and whether it is
burning faster than the window allows.

The burn-rate alert follows the two-window method from Google's SRE Workbook ("Alerting on
SLOs"): a short lookback and a long lookback must both show the budget burning faster than a
fixed multiple of the sustainable rate before an alert fires, which avoids both a single bad
minute and a slow background drift each triggering alerts on their own.

What this does not do: collect metrics for you (you call `record`, or something upstream of
this does), model multiple dependent services, or know anything about *why* an event was bad.
It is a starter kit: the budget math and the alerting rule, nothing about your observability
stack."""
from __future__ import annotations

import secrets
from datetime import timedelta

from .clock import iso, parse

# (name, short_lookback_hours, long_lookback_hours, burn_rate_multiple) - Google SRE Workbook's
# published two fast/slow pairs for a 30-day SLO window, scaled by window_days / 30.
BURN_RATE_WINDOWS = (("fast", 1, 1, 14.4), ("slow", 6, 3, 6.0))


class SLOService:
    def __init__(self, db, audit, clock):
        self.db, self.audit, self.clock = db, audit, clock

    def define(self, actor: str, service: str, name: str, target_percent: float, window_days: int) -> dict:
        if not (0 < target_percent < 100):
            raise ValueError("target_percent must be between 0 and 100")
        if window_days < 1:
            raise ValueError("window_days must be at least 1")
        sid = "slo_" + secrets.token_hex(5)
        now = iso(self.clock())
        self.db.execute(
            "INSERT INTO slos (id, service, name, target_percent, window_days, created_at) VALUES (?,?,?,?,?,?)",
            (sid, service, name, target_percent, window_days, now))
        self.audit.append(actor, "slo.define", {"slo_id": sid, "service": service, "name": name,
                                                "target_percent": target_percent, "window_days": window_days}, now)
        return self.get(sid)

    def get(self, sid: str) -> dict:
        r = self.db.one("SELECT * FROM slos WHERE id=?", (sid,))
        if not r:
            raise KeyError(f"SLO {sid} not found")
        return {"id": r["id"], "service": r["service"], "name": r["name"],
                "target_percent": r["target_percent"], "window_days": r["window_days"], "created_at": r["created_at"]}

    def list(self) -> list[dict]:
        return [self.get(r["id"]) for r in self.db.query("SELECT id FROM slos ORDER BY created_at")]

    def record(self, sid: str, good: bool, ts: str | None = None) -> None:
        self.get(sid)  # raises if the SLO doesn't exist
        self.db.execute("INSERT INTO slo_events (slo_id, ts, good) VALUES (?,?,?)",
                        (sid, ts or iso(self.clock()), int(good)))

    def _counts(self, sid: str, since, until) -> tuple[int, int]:
        rows = self.db.query("SELECT good, COUNT(*) as n FROM slo_events WHERE slo_id=? AND ts>=? AND ts<=?"
                             " GROUP BY good", (sid, iso(since), iso(until)))
        good = sum(r["n"] for r in rows if r["good"])
        total = sum(r["n"] for r in rows)
        return good, total

    def status(self, sid: str, as_of=None) -> dict:
        """Budget remaining over the SLO's full window, plus the two-window burn-rate check."""
        slo = self.get(sid)
        now = parse(as_of) if isinstance(as_of, str) else (as_of or self.clock())
        window_start = now - timedelta(days=slo["window_days"])
        good, total = self._counts(sid, window_start, now)
        allowed_bad_rate = 1 - slo["target_percent"] / 100
        observed_percent = round(100 * good / total, 4) if total else None
        budget_total = allowed_bad_rate * total if total else 0.0
        budget_consumed = total - good
        budget_remaining_percent = (round(100 * (1 - budget_consumed / budget_total), 2)
                                    if budget_total > 0 else (100.0 if total == 0 else -0.0))

        burn: dict[str, dict] = {}
        for label, short_h, long_h, multiple in BURN_RATE_WINDOWS:
            scale = slo["window_days"] / 30  # the Workbook's thresholds are defined for a 30-day window
            thr = multiple / scale
            s_good, s_total = self._counts(sid, now - timedelta(hours=short_h), now)
            l_good, l_total = self._counts(sid, now - timedelta(hours=long_h), now)
            s_rate = (s_total - s_good) / s_total / allowed_bad_rate if s_total and allowed_bad_rate else 0.0
            l_rate = (l_total - l_good) / l_total / allowed_bad_rate if l_total and allowed_bad_rate else 0.0
            burn[label] = {"short_lookback_hours": short_h, "long_lookback_hours": long_h,
                           "threshold_multiple": round(thr, 2),
                           "short_burn_rate": round(s_rate, 2), "long_burn_rate": round(l_rate, 2),
                           "alert": bool(s_total and l_total and s_rate >= thr and l_rate >= thr)}

        return {"slo": slo, "window": {"start": iso(window_start), "end": iso(now)},
                "total_events": total, "good_events": good, "bad_events": budget_consumed,
                "observed_percent": observed_percent, "error_budget_total_events": round(budget_total, 2),
                "error_budget_remaining_percent": budget_remaining_percent,
                "burn_rate": burn, "alert": any(b["alert"] for b in burn.values())}
