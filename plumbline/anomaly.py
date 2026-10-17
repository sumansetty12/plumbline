"""Per-contractor anomaly detection (feature M1.8).

Compares one contractor session with that contractor's own earlier sessions on the same
contract role. Everything is explainable: each signal says what it saw and which events
drove it. An optional Isolation Forest adds a second opinion when there is enough history.

What this is not: it cannot judge whether the activity makes sense for the stated purpose,
and a contractor who stays close to their own normal pattern will not be flagged.
Earlier sessions are assumed to be legitimate; a contractor already misbehaving during the
baseline window teaches the baseline to accept that behaviour.
"""
from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field

from .clock import parse

MIN_HISTORY = 5          # earlier sessions needed before baseline signals can fire
MIN_FOREST_HISTORY = 20  # earlier sessions needed before the Isolation Forest is used
FLAG_SCORE = 3           # total signal weight needed to raise a finding
HIGH_SCORE = 5

WEIGHTS = {
    "MULTI_SOURCE_IP": 3,
    "VOLUME_SPIKE": 3,
    "BREADTH_SPIKE": 2,
    "NEW_SOURCE_IP": 2,
    "FOREST_OUTLIER": 2,
    "UNUSUAL_HOUR": 1,
    "NEW_ACTIONS": 1,
}


@dataclass
class Signal:
    name: str
    text: str
    event_ids: list[str] = field(default_factory=list)

    @property
    def weight(self) -> int:
        return WEIGHTS[self.name]


def features(events: list[dict]) -> dict:
    ok = [e for e in events if not e.get("error")]
    hours = [parse(e["time"]).hour for e in events]
    return {
        "events": len(events),
        "distinct_actions": len({e["action"] for e in events}),
        "distinct_resources": len({r for e in events for r in e.get("resources", [])}),
        "error_rate": round(1 - len(ok) / len(events), 3) if events else 0.0,
        "ips": len({e["source_ip"] for e in events if e.get("source_ip")}),
        "median_hour": statistics.median(hours) if hours else 0,
    }


def group_sessions(events: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in events:
        out.setdefault(e["principal"], []).append(e)
    return out


def _robust_spike(value: float, past: list[float], min_ratio: float = 4.0, min_abs: float = 20.0) -> tuple[bool, dict]:
    med = statistics.median(past)
    mad = statistics.median([abs(x - med) for x in past])
    scale = max(1.4826 * mad, 0.25 * med, 1.0)   # floor so a very steady baseline does not flag tiny changes
    z = (value - med) / scale
    stats = {"value": value, "baseline_median": med, "robust_z": round(z, 2)}
    return (z >= 3.5 and value >= min_ratio * max(med, 1) and value >= min_abs), stats


def _forest_outlier(session_feats: dict, history_feats: list[dict]) -> bool:
    """True only if the session is both outside the range this contractor has shown before on at
    least one measure AND scores no better than the most unusual earlier session.

    The score cut-off comes from the contractor's own history, so a normal day is rarely flagged.
    The range check is needed because an Isolation Forest gives every far-out point the same
    score as the most extreme point it was trained on."""
    try:  # optional dependency
        from sklearn.ensemble import IsolationForest
    except Exception:
        return False
    keys = ["events", "distinct_actions", "distinct_resources", "error_rate", "ips", "median_hour"]
    X = [[h[k] for k in keys] for h in history_feats]
    row = [session_feats[k] for k in keys]
    if not any(v < min(col) or v > max(col) for v, col in zip(row, zip(*X))):
        return False
    model = IsolationForest(n_estimators=200, random_state=0).fit(X)
    return bool(model.score_samples([row])[0] <= min(model.score_samples(X)))


def detect(session_events: list[dict], history: dict[str, list[dict]]) -> dict | None:
    """Return None, or {'score', 'severity', 'signals', 'baseline'} for one session."""
    if not session_events:
        return None
    sig: list[Signal] = []
    f = features(session_events)

    # 1. One session used from several places (needs no history).
    ip_counts = Counter(e["source_ip"] for e in session_events if e.get("source_ip"))
    if len(ip_counts) > 1:
        main = ip_counts.most_common(1)[0][0]
        other = [e for e in session_events if e.get("source_ip") and e["source_ip"] != main]
        sig.append(Signal("MULTI_SOURCE_IP",
                          f"One session was used from {len(ip_counts)} source addresses: {', '.join(sorted(ip_counts))}.",
                          [e["id"] for e in other]))

    past_sessions = [evs for evs in history.values() if evs]
    baseline = {"sessions": len(past_sessions)}
    if len(past_sessions) >= MIN_HISTORY:
        pf = [features(evs) for evs in past_sessions]
        past_ips = {e["source_ip"] for evs in past_sessions for e in evs if e.get("source_ip")}
        past_actions = {e["action"] for evs in past_sessions for e in evs}
        past_hours = [parse(e["time"]).hour for evs in past_sessions for e in evs]
        baseline.update({"median_events": statistics.median(p["events"] for p in pf),
                         "median_resources": statistics.median(p["distinct_resources"] for p in pf),
                         "known_ips": len(past_ips), "known_actions": len(past_actions)})

        spike, st = _robust_spike(f["events"], [p["events"] for p in pf])
        if spike:
            sig.append(Signal("VOLUME_SPIKE",
                              f"{f['events']} calls in one session against a usual {st['baseline_median']:.0f} "
                              f"(robust z-score {st['robust_z']}).", [e["id"] for e in session_events[:25]]))
        spike, st = _robust_spike(f["distinct_resources"], [p["distinct_resources"] for p in pf], min_abs=10.0)
        if spike:
            sig.append(Signal("BREADTH_SPIKE",
                              f"Touched {f['distinct_resources']} different resources against a usual "
                              f"{st['baseline_median']:.0f}.", [e["id"] for e in session_events[:25]]))
        new_ips = sorted({e["source_ip"] for e in session_events if e.get("source_ip")} - past_ips)
        if new_ips:
            sig.append(Signal("NEW_SOURCE_IP", f"Source address(es) never seen for this contractor before: {', '.join(new_ips)}.",
                              [e["id"] for e in session_events if e.get("source_ip") in new_ips]))
        new_actions = sorted({e["action"] for e in session_events} - past_actions)
        if new_actions:
            sig.append(Signal("NEW_ACTIONS", f"Actions this contractor has not used before: {', '.join(new_actions)}.",
                              [e["id"] for e in session_events if e["action"] in new_actions]))
        hrs = {parse(e["time"]).hour for e in session_events}
        near = lambda h: any(min((h - p) % 24, (p - h) % 24) <= 2 for p in past_hours)
        off = sorted(h for h in hrs if not near(h))
        if off:
            sig.append(Signal("UNUSUAL_HOUR", f"Activity at hour(s) {off} UTC, outside this contractor's usual working hours.",
                              [e["id"] for e in session_events if parse(e["time"]).hour in off]))
        if len(past_sessions) >= MIN_FOREST_HISTORY and _forest_outlier(f, pf):
            sig.append(Signal("FOREST_OUTLIER", "An Isolation Forest trained on this contractor's earlier sessions "
                                                "scores this session as an outlier.", []))

    score = sum(s.weight for s in sig)
    if score < FLAG_SCORE:
        return None
    return {"score": score, "severity": "high" if score >= HIGH_SCORE else "medium",
            "signals": sig, "features": f, "baseline": baseline}
