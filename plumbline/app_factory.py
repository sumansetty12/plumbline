"""Wires the services together. Used by the API, the tests and the evaluation harness."""
from __future__ import annotations

from dataclasses import dataclass

from .access import AccessService
from .change_risk import ChangeRiskService
from .analysis import Analyzer
from .audit import AuditLog
from .clock import utcnow
from .db import Database
from .evidence import EvidenceStore, FindingStore
from .explain import Explainer, TemplateExplainer
from .slo import SLOService


@dataclass
class Plumbline:
    db: Database
    gateways: dict
    audit: AuditLog
    access: AccessService
    evidence: EvidenceStore
    findings: FindingStore
    analyzer: Analyzer
    explainer: Explainer
    changes: ChangeRiskService
    slos: SLOService

    @property
    def gateway(self):
        """Back-compat for single-cloud (AWS) callers, e.g. demo.py: `pl.gateway`."""
        return self.gateways["aws"]


def build(gateway, db_path: str = ":memory:", clock=utcnow, explainer: Explainer | None = None,
          max_duration_minutes: int = 480, freeze_windows: list[tuple] | None = None,
          gateways: dict | None = None) -> Plumbline:
    """`gateway` is the AWS gateway, kept as the first positional argument so existing
    single-cloud callers don't change. For Azure and/or GCP too, pass `gateways` with the
    extra providers, e.g. build(aws_gw, gateways={"azure": azure_gw, "gcp": gcp_gw})."""
    gw_map = {"aws": gateway, **(gateways or {})}
    db = Database(db_path)
    audit = AuditLog(db)
    access = AccessService(db, gw_map, audit, clock=clock, max_duration_minutes=max_duration_minutes)
    evidence = EvidenceStore(db)
    findings = FindingStore(db, evidence)
    analyzer = Analyzer(db, gw_map, access, evidence, findings, audit, clock=clock)
    changes = ChangeRiskService(db, audit, clock, freeze_windows=freeze_windows)
    slos = SLOService(db, audit, clock)
    return Plumbline(db, gw_map, audit, access, evidence, findings, analyzer,
                     explainer or TemplateExplainer(), changes, slos)
