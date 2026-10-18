"""SQLite storage. One small class so the rest of the code never touches raw connections."""
from __future__ import annotations

import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS contracts (
    id TEXT PRIMARY KEY, contractor TEXT NOT NULL, vendor TEXT NOT NULL, owner TEXT NOT NULL,
    role_arn TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'aws',
    starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, ceiling_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, contract_id TEXT NOT NULL, contractor TEXT NOT NULL,
    purpose TEXT NOT NULL, ticket TEXT NOT NULL, policy_json TEXT NOT NULL,
    duration_minutes INTEGER NOT NULL, blast_json TEXT NOT NULL,
    status TEXT NOT NULL, requested_at TEXT NOT NULL,
    decided_by TEXT, decided_at TEXT, decision_note TEXT, access_expires_at TEXT
);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL, contract_id TEXT NOT NULL,
    contractor TEXT NOT NULL, role_arn TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'aws',
    session_name TEXT NOT NULL, policy_json TEXT NOT NULL, issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, status TEXT NOT NULL, revoked_at TEXT, revoked_reason TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, event_time TEXT, event_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL, contractor TEXT,
    grant_id TEXT, summary TEXT NOT NULL, evidence_ids TEXT NOT NULL, detail_json TEXT NOT NULL,
    dedupe_key TEXT, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, environment TEXT NOT NULL, services_json TEXT NOT NULL,
    requester TEXT NOT NULL, approver TEXT, scheduled_at TEXT NOT NULL,
    lines_changed INTEGER NOT NULL, review_count INTEGER NOT NULL,
    has_rollback_plan INTEGER NOT NULL, rollback_tested INTEGER NOT NULL,
    score INTEGER NOT NULL, risk TEXT NOT NULL, signals_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS slos (
    id TEXT PRIMARY KEY, service TEXT NOT NULL, name TEXT NOT NULL,
    target_percent REAL NOT NULL, window_days INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS slo_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, slo_id TEXT NOT NULL, ts TEXT NOT NULL, good INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, detail_json TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def execute(self, sql: str, params: tuple = ()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()):
        rows = self.query(sql, params)
        return rows[0] if rows else None
