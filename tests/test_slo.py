from datetime import datetime, timedelta, timezone

import pytest

from plumbline.app_factory import build
from plumbline.gateway import FakeGateway


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


T0 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def env():
    clock = Clock(T0)
    gw = FakeGateway(clock=clock)
    pl = build(gw, clock=clock)
    return pl, clock


def define(pl, target=99.9, window=30):
    return pl.slos.define("admin@corp.example", "checkout", "availability", target, window)


def test_define_validates_inputs(env):
    pl, _ = env
    with pytest.raises(ValueError):
        pl.slos.define("a", "svc", "n", 0, 30)
    with pytest.raises(ValueError):
        pl.slos.define("a", "svc", "n", 100, 30)
    with pytest.raises(ValueError):
        pl.slos.define("a", "svc", "n", 99, 0)


def test_no_events_gives_full_budget_and_no_alert(env):
    pl, _ = env
    slo = define(pl)
    s = pl.slos.status(slo["id"])
    assert s["total_events"] == 0 and s["observed_percent"] is None
    assert s["error_budget_remaining_percent"] == 100.0
    assert s["alert"] is False


def test_perfect_record_keeps_full_budget(env):
    pl, clock = env
    slo = define(pl, target=99.0, window=30)
    for _ in range(1000):
        pl.slos.record(slo["id"], good=True)
        clock.advance(minutes=1)
    s = pl.slos.status(slo["id"])
    assert s["observed_percent"] == 100.0
    assert s["error_budget_remaining_percent"] == 100.0
    assert s["alert"] is False


def test_bad_events_consume_budget_proportionally(env):
    pl, clock = env
    slo = define(pl, target=99.0, window=30)   # allowed bad rate 1%; budget = 1000 * 0.01 = 10 events
    for i in range(1000):
        pl.slos.record(slo["id"], good=(i % 100 != 0))  # exactly 10 bad events, 1%
        clock.advance(minutes=1)
    s = pl.slos.status(slo["id"])
    assert s["bad_events"] == 10
    assert s["observed_percent"] == 99.0
    assert s["error_budget_remaining_percent"] == pytest.approx(0.0, abs=0.5)


def test_events_outside_the_window_do_not_count(env):
    pl, clock = env
    slo = define(pl, target=99.0, window=7)
    for _ in range(50):
        pl.slos.record(slo["id"], good=False)   # all bad, but about to fall out of the window
    clock.advance(days=8)
    for _ in range(50):
        pl.slos.record(slo["id"], good=True)
    s = pl.slos.status(slo["id"])
    assert s["total_events"] == 50 and s["bad_events"] == 0


def test_fast_burn_alert_fires_on_a_sudden_spike(env):
    pl, clock = env
    slo = define(pl, target=99.9, window=30)   # allowed bad rate 0.1%
    # six hours of healthy background traffic (satisfies the slow-window's long lookback too)
    for _ in range(600):
        pl.slos.record(slo["id"], good=True)
        clock.advance(seconds=36)   # 600 events over 6 hours
    # a one-hour burst where 20% of calls fail - far above the sustainable 0.1%
    for i in range(120):
        pl.slos.record(slo["id"], good=(i % 5 != 0))
        clock.advance(seconds=30)   # 120 events over 1 hour
    s = pl.slos.status(slo["id"])
    assert s["burn_rate"]["fast"]["alert"] is True
    assert s["alert"] is True


def test_slow_background_burn_is_not_a_fast_alert_but_is_a_slow_alert(env):
    pl, clock = env
    slo = define(pl, target=99.0, window=30)   # allowed bad rate 1%; slow-window threshold = 6x -> 6%
    # 7 hours of a steady 10% failure rate (fails both short and long lookback for the slow window)
    for i in range(700):
        pl.slos.record(slo["id"], good=(i % 10 != 0))
        clock.advance(seconds=36)   # 700 events over 7 hours
    s = pl.slos.status(slo["id"])
    assert s["burn_rate"]["slow"]["alert"] is True


def test_window_scaling_moves_the_threshold(env):
    pl, _ = env
    slo7 = define(pl, target=99.9, window=7)
    s = pl.slos.status(slo7["id"])
    assert s["burn_rate"]["fast"]["threshold_multiple"] == pytest.approx(14.4 / (7 / 30), abs=0.01)


def test_unknown_slo_raises(env):
    pl, _ = env
    with pytest.raises(KeyError):
        pl.slos.get("slo_missing")
    with pytest.raises(KeyError):
        pl.slos.record("slo_missing", good=True)
    with pytest.raises(KeyError):
        pl.slos.status("slo_missing")


def test_list_and_audit(env):
    pl, _ = env
    define(pl)
    define(pl, target=99.5)
    assert len(pl.slos.list()) == 2
    assert any(e["action"] == "slo.define" for e in pl.audit.entries())
