"""Checks that turn raw cloud activity into findings (features M1.4, M1.6, M1.7, M1.8).

All rules here are deterministic, except the optional Isolation Forest second opinion inside the anomaly check (fixed seed). Every finding stores the ids of the events behind it.
"""
from __future__ import annotations

import threading
from datetime import timedelta

from . import anomaly as anom
from . import policy as pol
from .access import AccessService
from .audit import AuditLog
from .clock import iso, parse, utcnow
from .db import Database
from .evidence import EvidenceStore, FindingStore

RISKY = {"destructive", "privilege", "secret-read", "admin"}
DORMANT_DAYS = 90
GRACE = timedelta(seconds=60)  # clock skew allowance when matching events to grant windows


def is_denied(error: str | None) -> bool:
    return bool(error) and ("AccessDenied" in error or "Unauthorized" in error)


class Analyzer:
    def __init__(self, db: Database, gateway, access: AccessService, evidence: EvidenceStore,
                 findings: FindingStore, audit: AuditLog, clock=utcnow,
                 anomaly_enabled: bool = True, anomaly_lookback_days: int = 30):
        """`gateway` is either one gateway (treated as 'aws', same convention as
        AccessService) or a {'aws': ..., 'azure': ..., 'gcp': ...} dict."""
        self.anomaly_enabled, self.anomaly_lookback = anomaly_enabled, timedelta(days=anomaly_lookback_days)
        self.db, self.access = db, access
        self.gateways = gateway if isinstance(gateway, dict) else {"aws": gateway}
        self.evidence, self.findings, self.audit, self.clock = evidence, findings, audit, clock
        self._lock = threading.RLock()  # one scan or review at a time (a double-click must not race)

    def _add(self, **kw):
        return self.findings.add(now=iso(self.clock()), **kw)

    def gw_for(self, provider: str):
        try:
            return self.gateways[provider]
        except KeyError:
            raise KeyError(f"no gateway configured for provider {provider!r}; "
                           f"configured providers: {sorted(self.gateways)}") from None

    # ---------- M1.4: orphan access ----------
    def scan_orphans(self, actor: str = "system") -> list[dict]:
        with self._lock:
            return self._scan_orphans(actor)

    def _scan_orphans(self, actor: str) -> list[dict]:
        now = self.clock()
        contracts = {c["id"]: c for c in self.access.list_contracts()}
        created, skipped = [], {}
        for provider, gw in self.gateways.items():
            try:
                principals = gw.list_contractor_principals()
            except Exception as e:  # one misconfigured provider must not blind the scan to the others
                skipped[provider] = f"{type(e).__name__}: {e}"[:200]
                continue
            for p in principals:
                p = {**p, "provider": provider}
                created.extend(self._orphan_findings_for(p, contracts, now))
        self.audit.append(actor, "scan.orphans", {"findings": len(created), "skipped_providers": skipped},
                          iso(self.clock()))
        return created

    def _orphan_findings_for(self, p: dict, contracts: dict, now) -> list[dict]:
        key = f"{p['provider']}:{p['arn']}"
        eid = self.evidence.add("iam", {"id": f"principal:{key}", "time": iso(now), **p})
        cid, name = p.get("contract_id"), p["name"]
        who = f"{p['provider']} {p['kind']} {name}"
        f = None
        if not cid:
            f = self._add(kind="NO_CONTRACT_TAG", severity="high", contractor=None, grant_id=None,
                          summary=f"{who} is marked as a contractor but is not linked to any contract.",
                          evidence_ids=[eid], detail={"principal": p}, dedupe_key=f"nocontract:{key}")
        elif cid not in contracts:
            f = self._add(kind="UNKNOWN_CONTRACT", severity="high", contractor=None, grant_id=None,
                          summary=f"{who} points at contract {cid}, which Plumbline has no record of.",
                          evidence_ids=[eid], detail={"principal": p}, dedupe_key=f"unknown:{key}")
        else:
            c = contracts[cid]
            ended = c["status"] == "ended" or parse(c["ends_at"]) <= now
            if ended:
                f = self._add(kind="CONTRACT_ENDED", severity="critical", contractor=c["contractor"],
                              grant_id=None,
                              summary=f"{who} still exists although contract {cid} with {c['vendor']} ended on {c['ends_at']}.",
                              evidence_ids=[eid], detail={"principal": p, "contract": cid},
                              dedupe_key=f"ended:{key}")
            elif p.get("created"):
                # Only AWS currently reports created/last_used; Azure and GCP gateways
                # report both as None rather than guess, so dormancy just can't be checked
                # for those principals yet (documented in each gateway's docstring).
                last = parse(p["last_used"]) if p.get("last_used") else None
                age_ok = parse(p["created"]) <= now - timedelta(days=DORMANT_DAYS)
                if age_ok and (last is None or last <= now - timedelta(days=DORMANT_DAYS)):
                    f = self._add(kind="DORMANT", severity="medium", contractor=c["contractor"], grant_id=None,
                                  summary=f"{who} has not been used in over {DORMANT_DAYS} days but its contract is still active.",
                                  evidence_ids=[eid], detail={"principal": p}, dedupe_key=f"dormant:{key}")
        return [f] if f else []

    # ---------- M1.6 / M1.7: declared vs actual, right-sizing ----------
    def review_grant(self, grant_id: str, actor: str = "system") -> dict:
        with self._lock:
            return self._review_grant(grant_id, actor)

    def _review_grant(self, grant_id: str, actor: str) -> dict:
        g = self.access.get_grant(grant_id)
        req = self.access.get_request(g["request_id"])
        now = self.clock()
        end = min(parse(g["expires_at"]), now)
        events = self.gw_for(g["provider"]).lookup_events(parse(g["issued_at"]), end, g["session_name"])
        grant_ev = self.evidence.add("grant", {"id": grant_id, "time": g["issued_at"], "purpose": req["purpose"],
                                               "ticket": req["ticket"], "policy": g["policy"],
                                               "expires_at": g["expires_at"]})
        ev_ids = {e["id"]: self.evidence.add("cloudtrail", e) for e in events}
        base = {"purpose": req["purpose"], "ticket": req["ticket"], "session": g["session_name"]}
        created = []

        denied = [e for e in events if is_denied(e["error"])]
        if denied:
            acts = sorted({e["action"] for e in denied})
            sev = "high" if any(pol.classify_action(a, g["provider"]) in RISKY for a in acts) else "medium"
            f = self._add(kind="OUT_OF_SCOPE_ATTEMPT", severity=sev, contractor=g["contractor"], grant_id=grant_id,
                          summary=f"{g['contractor']} tried {len(denied)} call(s) outside the approved scope: {', '.join(acts)}.",
                          evidence_ids=[ev_ids[e["id"]] for e in denied] + [grant_ev],
                          detail={**base, "actions": acts}, dedupe_key=f"oos:{grant_id}")
            if f:
                created.append(f)

        ok_events = [e for e in events if not e["error"]]
        sensitive = [e for e in ok_events if pol.classify_action(e["action"], g["provider"]) in RISKY]
        if sensitive:
            acts = sorted({e["action"] for e in sensitive})
            sev = "high" if any(pol.classify_action(a, g["provider"]) in ("privilege", "admin") for a in acts) else "medium"
            f = self._add(kind="SENSITIVE_ACTION", severity=sev, contractor=g["contractor"], grant_id=grant_id,
                          summary=f"{g['contractor']} performed {len(sensitive)} sensitive call(s) that were allowed by the grant: {', '.join(acts)}.",
                          evidence_ids=[ev_ids[e["id"]] for e in sensitive] + [grant_ev],
                          detail={**base, "actions": acts}, dedupe_key=f"sens:{grant_id}")
            if f:
                created.append(f)

        anomaly_note = None
        if self.anomaly_enabled and events:
            try:
                f = self._anomaly_finding(g, events, ev_ids, grant_ev, base)
                if f:
                    created.append(f)
            except Exception as e:  # a failed baseline lookup must not hide the rest of the review
                anomaly_note = f"skipped: {type(e).__name__}"

        used = [{"action": e["action"], "resources": e["resources"]} for e in ok_events]
        rs = pol.right_size(g["policy"], used)
        finished = g["status"] != "active" or parse(g["expires_at"]) <= now
        if finished and rs["unused_action_patterns"]:
            f = self._add(kind="UNUSED_PERMISSIONS", severity="info", contractor=g["contractor"], grant_id=grant_id,
                          summary=(f"{len(rs['unused_action_patterns'])} of {rs['requested_action_patterns']} granted action "
                                   f"pattern(s) were never used: {', '.join(rs['unused_action_patterns'])}. A tighter policy is suggested."),
                          evidence_ids=[grant_ev] + [ev_ids[e["id"]] for e in ok_events[:20]],
                          detail={**base, **rs}, dedupe_key=f"unused:{grant_id}")
            if f:
                created.append(f)
        self.audit.append(actor, "review.grant", {"grant_id": grant_id, "events": len(events),
                                                  "findings": len(created),
                                                  "anomaly_check": anomaly_note or "ran"}, iso(self.clock()))
        return {"grant_id": grant_id, "events_seen": len(events), "findings": created, "right_sizing": rs}

    # ---------- M1.8: unusual for this contractor ----------
    def _anomaly_finding(self, g, events, ev_ids, grant_ev, base):
        role = self.access.role_name(g["provider"], g["role_arn"])
        issued = parse(g["issued_at"])
        past = [e for e in self.gw_for(g["provider"]).lookup_events(issued - self.anomaly_lookback, issued - timedelta(seconds=1))
                if e.get("role") == role and e["principal"] != g["session_name"]]
        result = anom.detect(events, anom.group_sessions(past))
        if not result:
            return None
        base_ev = self.evidence.add("baseline", {"id": f"baseline:{g['id']}", "time": g["issued_at"],
                                                 "contract_role": role, "window_days": self.anomaly_lookback.days,
                                                 "session_features": result["features"], **result["baseline"]})
        ids = [grant_ev, base_ev]
        for sgn in result["signals"]:
            ids += [ev_ids[i] for i in sgn.event_ids if i in ev_ids]
        ids = list(dict.fromkeys(ids))
        names = ", ".join(sgn.name for sgn in result["signals"])
        return self._add(kind="ANOMALOUS_SESSION", severity=result["severity"], contractor=g["contractor"],
                         grant_id=g["id"],
                         summary=(f"{g['contractor']}'s session looks unusual compared with their own earlier sessions "
                                  f"(score {result['score']}): " + " ".join(sgn.text for sgn in result["signals"])),
                         evidence_ids=ids,
                         detail={**base, "score": result["score"], "signals": names,
                                 "baseline": result["baseline"]},
                         dedupe_key=f"anomaly:{g['id']}")

    # ---------- activity with no matching grant ----------
    def scan_ungranted_activity(self, since, until, actor: str = "system") -> list[dict]:
        with self._lock:
            return self._scan_ungranted(since, until, actor)

    def _scan_ungranted(self, since, until, actor: str) -> list[dict]:
        roles = {(c["provider"], self.access.role_name(c["provider"], c["role_arn"])): c
                 for c in self.access.list_contracts()}
        grants: dict[str, list[dict]] = {}
        for g in self.access.list_grants():
            grants.setdefault(g["session_name"], []).append(g)
        groups: dict[tuple, list[dict]] = {}
        for provider, gw in self.gateways.items():
            for e in gw.lookup_events(since, until):
                if (provider, e["role"]) not in roles:
                    continue
                t = parse(e["time"])
                covered = False
                for g in grants.get(e["principal"], []):
                    stop = parse(g["expires_at"])
                    if g["revoked_at"]:
                        stop = min(stop, parse(g["revoked_at"]))
                    if parse(g["issued_at"]) - GRACE <= t <= stop + GRACE:
                        covered = True
                        break
                if not covered:
                    groups.setdefault((provider, e["role"], e["principal"]), []).append(e)
        created = []
        for (provider, role, session), evs in groups.items():
            c = roles[(provider, role)]
            ev_ids = [self.evidence.add("cloudtrail", e) for e in evs]
            any_ok = any(not e["error"] for e in evs)
            f = self._add(kind="UNGRANTED_ACTIVITY", severity="critical" if any_ok else "high",
                          contractor=c["contractor"], grant_id=None,
                          summary=(f"Session '{session}' on {provider} role {role} made {len(evs)} call(s) with no approved "
                                   f"grant covering them ({'some succeeded' if any_ok else 'all were refused'}). Credentials "
                                   "may have been used outside Plumbline or after expiry or revocation."),
                          evidence_ids=ev_ids, detail={"provider": provider, "role": role, "session": session,
                                                       "source_ips": sorted({e["source_ip"] for e in evs if e["source_ip"]})},
                          dedupe_key=f"ungranted:{provider}:{role}:{session}")
            if f:
                created.append(f)
        self.audit.append(actor, "scan.ungranted", {"findings": len(created)}, iso(self.clock()))
        return created

    def run_all(self, lookback_hours: int = 24, actor: str = "system") -> dict:
        with self._lock:
            return self._run_all(lookback_hours, actor)

    def _run_all(self, lookback_hours: int, actor: str) -> dict:
        now = self.clock()
        expired = self.access.expire_due(actor)
        out = {"expired": expired, "orphans": self.scan_orphans(actor), "reviews": []}
        for g in self.access.list_grants():
            if g["status"] != "active":
                out["reviews"].append(self.review_grant(g["id"], actor))
        out["ungranted"] = self.scan_ungranted_activity(now - timedelta(hours=lookback_hours), now, actor)
        return out
