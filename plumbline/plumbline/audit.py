"""Tamper-evident audit trail: each entry's hash covers the previous entry's hash.

Editing or deleting a middle entry breaks the chain and `verify()` reports where.
This is tamper-*evident*, not tamper-proof: someone who can rewrite the whole table can
rebuild a valid chain, and truncating the newest entries is only caught if you saved an
earlier `head()` somewhere else. Anchor the head hash externally (commit it, email it).
"""
from __future__ import annotations

import hashlib
import json

from .db import Database

GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _digest(prev: str, ts: str, actor: str, action: str, detail: dict) -> str:
    body = _canonical({"ts": ts, "actor": actor, "action": action, "detail": detail})
    return hashlib.sha256((prev + body).encode()).hexdigest()


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def append(self, actor: str, action: str, detail: dict, ts: str) -> dict:
        with self.db.lock:
            last = self.db.one("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
            prev = last["hash"] if last else GENESIS
            h = _digest(prev, ts, actor, action, detail)
            cur = self.db.execute(
                "INSERT INTO audit (ts, actor, action, detail_json, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (ts, actor, action, _canonical(detail), prev, h),
            )
            return {"seq": cur.lastrowid, "hash": h}

    def entries(self, limit: int = 200) -> list[dict]:
        rows = self.db.query("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))
        return [
            {"seq": r["seq"], "ts": r["ts"], "actor": r["actor"], "action": r["action"],
             "detail": json.loads(r["detail_json"]), "hash": r["hash"]}
            for r in rows
        ]

    def head(self) -> str:
        last = self.db.one("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
        return last["hash"] if last else GENESIS

    def verify(self) -> dict:
        prev = GENESIS
        n = 0
        for r in self.db.query("SELECT * FROM audit ORDER BY seq ASC"):
            n += 1
            detail = json.loads(r["detail_json"])
            expected = _digest(prev, r["ts"], r["actor"], r["action"], detail)
            if r["prev_hash"] != prev or r["hash"] != expected:
                return {"ok": False, "entries": n, "first_bad_seq": r["seq"]}
            prev = r["hash"]
        return {"ok": True, "entries": n, "first_bad_seq": None}
