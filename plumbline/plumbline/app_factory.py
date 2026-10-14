"""Wires the services together. Used by the API, the tests and the evaluation harness."""
from __future__ import annotations

from dataclasses import dataclass

from .access import AccessService
from .analysis import Analyzer
from .audit import AuditLog
from .clock import utcnow
from .db import Database
from .evidence import EvidenceStore, FindingStore
from .explain import Explainer, TemplateExplainer


@dataclass
class Plumbline:
    db: Database
    gateway: object
    audit: AuditLog
    access: AccessService
    evidence: EvidenceStore
    findings: FindingStore
    analyzer: Analyzer
    explainer: Explainer


def build(gateway, db_path: str = ":memory:", clock=utcnow, explainer: Explainer | None = None,
          max_duration_minutes: int = 480) -> Plumbline:
    db = Database(db_path)
    audit = AuditLog(db)
    access = AccessService(db, gateway, audit, clock=clock, max_duration_minutes=max_duration_minutes)
    evidence = EvidenceStore(db)
    findings = FindingStore(db, evidence)
    analyzer = Analyzer(db, gateway, access, evidence, findings, audit, clock=clock)
    return Plumbline(db, gateway, audit, access, evidence, findings, analyzer, explainer or TemplateExplainer())
