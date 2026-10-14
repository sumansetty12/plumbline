"""Evidence store and findings. The rule: a finding cannot exist without evidence that exists."""
from __future__ import annotations

import hashlib
import json
import re
import secrets

from .db import Database

EVIDENCE_ID_RE = re.compile(r"\bev_[0-9a-f]{12}\b")
SEVERITIES = ("info", "medium", "high", "critical")


class EvidenceStore:
    def __init__(self, db: Database):
        self.db = db

    def add(self, source: str, event: dict) -> str:
        """Store one event (CloudTrail, IAM, grant record). Same event -> same id."""
        eid = "ev_" + hashlib.sha1(f"{source}|{event['id']}".encode()).hexdigest()[:12]
        self.db.execute(
            "INSERT OR IGNORE INTO evidence (id, source, event_time, event_json) VALUES (?,?,?,?)",
            (eid, source, event.get("time"), json.dumps(event, sort_keys=True)),
        )
        return eid

    def get_many(self, ids: list[str]) -> list[dict]:
        out = []
        for i in ids:
            r = self.db.one("SELECT * FROM evidence WHERE id=?", (i,))
            if r:
                out.append({"id": r["id"], "source": r["source"], "time": r["event_time"],
                            "event": json.loads(r["event_json"])})
        return out

    def exists(self, eid: str) -> bool:
        return self.db.one("SELECT 1 FROM evidence WHERE id=?", (eid,)) is not None


class FindingStore:
    def __init__(self, db: Database, evidence: EvidenceStore):
        self.db, self.evidence = db, evidence

    def add(self, *, kind: str, severity: str, contractor: str | None, grant_id: str | None,
            summary: str, evidence_ids: list[str], detail: dict | None = None,
            dedupe_key: str | None = None, now: str) -> dict | None:
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity {severity}")
        evidence_ids = list(dict.fromkeys(evidence_ids))
        if not evidence_ids:
            raise ValueError("a finding must cite at least one piece of evidence")
        missing = [e for e in evidence_ids if not self.evidence.exists(e)]
        if missing:
            raise ValueError(f"finding cites evidence that does not exist: {missing}")
        if dedupe_key and self.db.one(
                "SELECT 1 FROM findings WHERE dedupe_key=? AND status='open'", (dedupe_key,)):
            return None
        fid = "fnd_" + secrets.token_hex(5)
        self.db.execute(
            "INSERT INTO findings (id, kind, severity, contractor, grant_id, summary, evidence_ids,"
            " detail_json, dedupe_key, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,'open',?)",
            (fid, kind, severity, contractor, grant_id, summary, json.dumps(evidence_ids),
             json.dumps(detail or {}), dedupe_key, now),
        )
        return self.get(fid)

    @staticmethod
    def _row(r) -> dict:
        return {"id": r["id"], "kind": r["kind"], "severity": r["severity"],
                "contractor": r["contractor"], "grant_id": r["grant_id"], "summary": r["summary"],
                "evidence_ids": json.loads(r["evidence_ids"]), "detail": json.loads(r["detail_json"]),
                "status": r["status"], "created_at": r["created_at"]}

    def get(self, fid: str) -> dict | None:
        r = self.db.one("SELECT * FROM findings WHERE id=?", (fid,))
        return self._row(r) if r else None

    def list(self, status: str | None = None) -> list[dict]:
        rows = (self.db.query("SELECT * FROM findings WHERE status=? ORDER BY created_at, id", (status,))
                if status else self.db.query("SELECT * FROM findings ORDER BY created_at, id"))
        return [self._row(r) for r in rows]

    def close(self, fid: str) -> dict | None:
        self.db.execute("UPDATE findings SET status='closed' WHERE id=?", (fid,))
        return self.get(fid)
