from datetime import datetime, timezone

import pytest

from plumbline.change_risk import ChangeRiskService, score_change

MON_NOON = "2026-03-02T15:00:00Z"   # Monday, 15:00 UTC -> inside business hours
SAT_NOON = "2026-03-07T15:00:00Z"   # Saturday
NIGHT = "2026-03-02T03:00:00Z"      # Monday, 3am UTC


def base(**over):
    d = dict(environment="production", services=["payments"], requester="alice", approver="bob",
             scheduled_at=MON_NOON, freeze_windows=None, lines_changed=10, review_count=1,
             has_rollback_plan=True, rollback_tested=True)
    d.update(over)
    return d


def test_clean_small_reviewed_change_is_low_risk():
    r = score_change(**base())
    assert r["risk"] == "low" and {s["name"] for s in r["signals"]} == {"PRODUCTION"}


def test_self_approved_change_is_flagged():
    r = score_change(**base(approver="alice"))
    assert any(s["name"] == "NO_SEPARATE_APPROVER" for s in r["signals"])
    r2 = score_change(**base(approver=None))
    assert any(s["name"] == "NO_SEPARATE_APPROVER" for s in r2["signals"])


def test_no_rollback_outweighs_untested_rollback():
    no_plan = score_change(**base(has_rollback_plan=False, rollback_tested=False))
    untested = score_change(**base(has_rollback_plan=True, rollback_tested=False))
    tested = score_change(**base(has_rollback_plan=True, rollback_tested=True))
    assert no_plan["score"] > untested["score"] > tested["score"]
    assert {s["name"] for s in no_plan["signals"]} >= {"NO_ROLLBACK_PLAN"}
    assert {s["name"] for s in untested["signals"]} >= {"ROLLBACK_UNTESTED"}


def test_large_change_and_many_services_add_up():
    r = score_change(**base(lines_changed=800, services=["a", "b", "c"]))
    names = {s["name"] for s in r["signals"]}
    assert "LARGE_CHANGE" in names and "MANY_SERVICES" in names
    r_med = score_change(**base(lines_changed=200))
    assert any(s["name"] == "MEDIUM_CHANGE" for s in r_med["signals"])


def test_weekend_and_night_are_off_hours():
    assert any(s["name"] == "OFF_HOURS" for s in score_change(**base(scheduled_at=SAT_NOON))["signals"])
    assert any(s["name"] == "OFF_HOURS" for s in score_change(**base(scheduled_at=NIGHT))["signals"])
    assert not any(s["name"] == "OFF_HOURS" for s in score_change(**base())["signals"])


def test_freeze_window_is_detected():
    fw = [(datetime(2026, 3, 1, tzinfo=timezone.utc), datetime(2026, 3, 10, tzinfo=timezone.utc))]
    r = score_change(**base(freeze_windows=fw))
    assert any(s["name"] == "CHANGE_FREEZE" for s in r["signals"])
    r_out = score_change(**base(scheduled_at="2026-04-01T15:00:00Z", freeze_windows=fw))
    assert not any(s["name"] == "CHANGE_FREEZE" for s in r_out["signals"])


def test_risk_bands_are_ordered():
    worst = score_change(**base(approver=None, has_rollback_plan=False, review_count=0,
                                lines_changed=900, services=["a", "b", "c"], scheduled_at=SAT_NOON))
    assert worst["risk"] == "critical" and worst["score"] >= 11
    assert score_change(**base())["risk"] == "low"


def test_environment_only_matters_for_production():
    prod = score_change(**base(environment="production"))
    staging = score_change(**base(environment="staging"))
    assert any(s["name"] == "PRODUCTION" for s in prod["signals"])
    assert not any(s["name"] == "PRODUCTION" for s in staging["signals"])


def test_same_inputs_always_score_the_same():
    assert score_change(**base()) == score_change(**base())


# ---------- service layer ----------
def test_submit_stores_score_and_audits(pl):
    c = pl.changes.submit("admin@corp.example", "Deploy v2", "production", ["payments"],
                          "alice", "bob", MON_NOON, 10, 1, True, True)
    assert c["risk"] == "low" and c["status"] == "proposed"
    assert pl.changes.get(c["id"]) == c
    assert any(e["action"] == "change.submit" for e in pl.audit.entries())


def test_list_can_filter_by_risk(pl):
    pl.changes.submit("a", "Low", "staging", ["x"], "alice", "bob", MON_NOON, 5, 2, True, True)
    pl.changes.submit("a", "High", "production", ["x", "y", "z"], "alice", None, SAT_NOON, 900, 0, False, False)
    assert {c["risk"] for c in pl.changes.list()} == {"low", "critical"}
    assert len(pl.changes.list(risk="critical")) == 1


def test_status_transitions_are_validated(pl):
    c = pl.changes.submit("a", "Deploy", "production", ["x"], "alice", "bob", MON_NOON, 5, 1, True, True)
    updated = pl.changes.mark_status("bob", c["id"], "approved")
    assert updated["status"] == "approved"
    with pytest.raises(ValueError):
        pl.changes.mark_status("bob", c["id"], "nonsense")
    with pytest.raises(KeyError):
        pl.changes.mark_status("bob", "chg_missing", "approved")


def test_rejects_bad_environment_and_negative_counts(pl):
    with pytest.raises(ValueError):
        pl.changes.submit("a", "x", "prod", ["x"], "alice", "bob", MON_NOON, 5, 1, True, True)
    with pytest.raises(ValueError):
        pl.changes.submit("a", "x", "production", ["x"], "alice", "bob", MON_NOON, -1, 1, True, True)
