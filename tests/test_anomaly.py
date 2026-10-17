"""Tests for per-contractor anomaly detection (M1.8)."""
from plumbline import anomaly as an


def ev(i, t, sess="s-now", ip="10.0.0.1", action="s3:GetObject", res="r1", err=None):
    return {"id": f"e{i}", "time": t, "principal": sess, "role": "contractor-x", "action": action,
            "resources": [res], "error": err, "source_ip": ip}


def history(n=8, per=20, ip="10.0.0.1", hour=9):
    out = {}
    for k in range(n):
        out[f"h{k}"] = [ev(f"h{k}-{i}", f"2026-01-{1 + k:02d}T{hour:02d}:{i % 50:02d}:00Z", f"h{k}", ip) for i in range(per)]
    return out


def today(n, ip="10.0.0.1", hour=9, action="s3:GetObject"):
    return [ev(i, f"2026-02-01T{hour:02d}:{i % 50:02d}:00Z", ip=ip, action=action) for i in range(n)]


def names(r):
    return {s.name for s in r["signals"]} if r else set()


def test_normal_day_is_not_flagged():
    assert an.detect(today(22), history()) is None


def test_two_source_addresses_flag_even_without_history():
    evs = today(5) + [ev(100 + i, "2026-02-01T09:30:00Z", ip="203.0.113.9") for i in range(3)]
    r = an.detect(evs, {})
    assert names(r) == {"MULTI_SOURCE_IP"}
    assert r["severity"] == "medium"
    assert set(r["signals"][0].event_ids) == {"e100", "e101", "e102"}


def test_volume_spike_needs_history_and_real_size():
    assert "VOLUME_SPIKE" in names(an.detect(today(200), history()))
    assert an.detect(today(200), {}) is None                       # cold start: nothing to compare
    assert an.detect(today(200), history(n=3)) is None             # too little history
    assert an.detect(today(70), history()) is None                 # 3.5x but under the 4x floor


def test_new_ip_alone_is_not_enough_but_with_odd_hour_it_is():
    assert an.detect(today(20, ip="192.0.2.5"), history()) is None
    r = an.detect(today(20, ip="192.0.2.5", hour=2), history())
    assert names(r) == {"NEW_SOURCE_IP", "UNUSUAL_HOUR"}


def test_unusual_hour_wraps_around_midnight():
    hist = history(hour=23)
    assert an.detect(today(20, ip="192.0.2.5", hour=0), hist) is None  # 1 hour away: normal
    assert "UNUSUAL_HOUR" in names(an.detect(today(20, ip="192.0.2.5", hour=12), hist))


def test_high_severity_when_many_signals_agree():
    evs = today(300, ip="192.0.2.5", hour=3, action="iam:ListUsers")
    r = an.detect(evs, history())
    assert r["severity"] == "high" and r["score"] >= an.HIGH_SCORE


def test_empty_session_returns_none():
    assert an.detect([], history()) is None


def test_forest_only_flags_sessions_worse_than_all_history(monkeypatch):
    hist = {f"h{k}": history(n=1, per=15 + k % 10)["h0"] for k in range(25)}   # sessions of 15-24 calls
    normal = an.features(today(20))
    assert an._forest_outlier(normal, [an.features(v) for v in hist.values()]) is False
    weird = {**normal, "events": 5000, "distinct_resources": 400, "ips": 6, "error_rate": 0.9}
    assert an._forest_outlier(weird, [an.features(v) for v in hist.values()]) is True


def test_forest_missing_dependency_is_ignored(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("sklearn"):
            raise ImportError
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    assert an._forest_outlier(an.features(today(5000)), [an.features(v) for v in history(25).values()]) is False
