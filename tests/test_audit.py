from plumbline.audit import AuditLog
from plumbline.db import Database


def make():
    db = Database()
    return db, AuditLog(db)


def test_empty_log_verifies():
    _, a = make()
    assert a.verify() == {"ok": True, "entries": 0, "first_bad_seq": None}


def test_chain_verifies_and_head_changes():
    _, a = make()
    h0 = a.head()
    a.append("u", "x", {"n": 1}, "2026-01-01T00:00:00Z")
    a.append("u", "y", {"n": 2}, "2026-01-01T00:00:01Z")
    assert a.verify()["ok"] and a.verify()["entries"] == 2
    assert a.head() != h0


def test_editing_an_entry_is_detected():
    db, a = make()
    for i in range(4):
        a.append("u", "x", {"n": i}, f"2026-01-01T00:00:0{i}Z")
    db.execute("UPDATE audit SET detail_json='{\"n\":99}' WHERE seq=2")
    r = a.verify()
    assert not r["ok"] and r["first_bad_seq"] == 2


def test_deleting_a_middle_entry_is_detected():
    db, a = make()
    for i in range(4):
        a.append("u", "x", {"n": i}, f"2026-01-01T00:00:0{i}Z")
    db.execute("DELETE FROM audit WHERE seq=2")
    r = a.verify()
    assert not r["ok"] and r["first_bad_seq"] == 3


def test_truncating_the_tail_is_only_caught_with_a_saved_head():
    db, a = make()
    for i in range(3):
        a.append("u", "x", {"n": i}, f"2026-01-01T00:00:0{i}Z")
    saved = a.head()
    db.execute("DELETE FROM audit WHERE seq=3")
    assert a.verify()["ok"]            # documented limitation
    assert a.head() != saved           # but an externally saved head exposes it
