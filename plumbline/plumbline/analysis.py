"""Checks that turn raw cloud activity into findings (features M1.4, M1.6, M1.7).

All rules here are deterministic. Every finding stores the ids of the events behind it.
"""
from __future__ import annotations

from datetime import timedelta

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
                 findings: FindingStore, audit: AuditLog, clock=utcnow):
        self.db, self.gw, self.access = db, gateway, access
        self.evidence, self.findings, self.audit, self.clock = evidence, findings, audit, clock

    def _add(self, **kw):
        return self.findings.add(now=iso(self.clock()), **kw)

    # ---------- M1.4: orphan access ----------
    def scan_orphans(self, actor: str = "system") -> list[dict]:
        now = self.clock()
        contracts = {c["id"]: c for c in self.access.list_contracts()}
        created = []
        for p in self.gw.list_contractor_principals():
            eid = self.evidence.add("iam", {"id": f"principal:{p['arn']}", "time": iso(now), **p})
            cid, name = p.get("contract_id"), p["name"]
            who = f"{p['kind']} {name}"
            if not cid:
                f = self._add(kind="NO_CONTRACT_TAG", severity="high", contractor=None, grant_id=None,
                              summary=f"{who} is marked as a contractor but is not linked to any contract.",
                              evidence_ids=[eid], detail={"principal": p}, dedupe_key=f"nocontract:{p['arn']}")
            elif cid not in contracts:
                f = self._add(kind="UNKNOWN_CONTRACT", severity="high", contractor=None, grant_id=None,
                              summary=f"{who} points at contract {cid}, which Plumbline has no record of.",
                              evidence_ids=[eid], detail={"principal": p}, dedupe_key=f"unknown:{p['arn']}")
            else:
                c = contracts[cid]
                ended = c["status"] == "ended" or parse(c["ends_at"]) <= now
                if ended:
                    f = self._add(kind="CONTRACT_ENDED", severity="critical", contractor=c["contractor"],
                                  grant_id=None,
                                  summary=f"{who} still exists although contract {cid} with {c['vendor']} ended on {c['ends_at']}.",
                                  evidence_ids=[eid], detail={"principal": p, "contract": cid},
                                  dedupe_key=f"ended:{p['arn']}")
                else:
                    last = parse(p["last_used"]) if p.get("last_used") else None
                    age_ok = parse(p["created"]) <= now - timedelta(days=DORMANT_DAYS)
                    if age_ok and (last is None or last <= now - timedelta(days=DORMANT_DAYS)):
                        f = self._add(kind="DORMANT", severity="medium", contractor=c["contractor"], grant_id=None,
                                      summary=f"{who} has not been used in over {DORMANT_DAYS} days but its contract is still active.",
                                      evidence_ids=[eid], detail={"principal": p}, dedupe_key=f"dormant:{p['arn']}")
                    else:
                        f = None
            if f:
                created.append(f)
        self.audit.append(actor, "scan.orphans", {"findings": len(created)}, iso(now))
        return created

    # ---------- M1.6 / M1.7: declared vs actual, right-sizing ----------
    def review_grant(self, grant_id: str, actor: str = "system") -> dict:
        g = self.access.get_grant(grant_id)
        req = self.access.get_request(g["request_id"])
        now = self.clock()
        end = min(parse(g["expires_at"]), now)
        events = self.gw.lookup_events(parse(g["issued_at"]), end, g["session_name"])
        grant_ev = self.evidence.add("grant", {"id": grant_id, "time": g["issued_at"], "purpose": req["purpose"],
                                               "ticket": req["ticket"], "policy": g["policy"],
                                               "expires_at": g["expires_at"]})
        ev_ids = {e["id"]: self.evidence.add("cloudtrail", e) for e in events}
        base = {"purpose": req["purpose"], "ticket": req["ticket"], "session": g["session_name"]}
        created = []

        denied = [e for e in events if is_denied(e["error"])]
        if denied:
            acts = sorted({e["action"] for e in denied})
            sev = "high" if any(pol.classify_action(a) in RISKY for a in acts) else "medium"
            f = self._add(kind="OUT_OF_SCOPE_ATTEMPT", severity=sev, contractor=g["contractor"], grant_id=grant_id,
                          summary=f"{g['contractor']} tried {len(denied)} call(s) outside the approved scope: {', '.join(acts)}.",
                          evidence_ids=[ev_ids[e["id"]] for e in denied] + [grant_ev],
                          detail={**base, "actions": acts}, dedupe_key=f"oos:{grant_id}")
            if f:
                created.append(f)

        ok_events = [e for e in events if not e["error"]]
        sensitive = [e for e in ok_events if pol.classify_action(e["action"]) in RISKY]
        if sensitive:
            acts = sorted({e["action"] for e in sensitive})
            sev = "high" if any(pol.classify_action(a) in ("privilege", "admin") for a in acts) else "medium"
            f = self._add(kind="SENSITIVE_ACTION", severity=sev, contractor=g["contractor"], grant_id=grant_id,
                          summary=f"{g['contractor']} performed {len(sensitive)} sensitive call(s) that were allowed by the grant: {', '.join(acts)}.",
                          evidence_ids=[ev_ids[e["id"]] for e in sensitive] + [grant_ev],
                          detail={**base, "actions": acts}, dedupe_key=f"sens:{grant_id}")
            if f:
                created.append(f)

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
                                                  "findings": len(created)}, iso(now))
        return {"grant_id": grant_id, "events_seen": len(events), "findings": created, "right_sizing": rs}

    # ---------- activity with no matching grant ----------
    def scan_ungranted_activity(self, since, until, actor: str = "system") -> list[dict]:
        roles = {self.access.role_name(c["role_arn"]): c for c in self.access.list_contracts()}
        grants: dict[str, list[dict]] = {}
        for g in self.access.list_grants():
            grants.setdefault(g["session_name"], []).append(g)
        groups: dict[tuple, list[dict]] = {}
        for e in self.gw.lookup_events(since, until):
            if e["role"] not in roles:
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
                groups.setdefault((e["role"], e["principal"]), []).append(e)
        created = []
        for (role, session), evs in groups.items():
            c = roles[role]
            ids = [self.evidence.add("cloudtrail", e) for e in evs]
            any_ok = any(not e["error"] for e in evs)
            f = self._add(kind="UNGRANTED_ACTIVITY", severity="critical" if any_ok else "high",
                          contractor=c["contractor"], grant_id=None,
                          summary=(f"Session '{session}' on role {role} made {len(evs)} call(s) with no approved grant covering them "
                                   f"({'some succeeded' if any_ok else 'all were refused'}). Credentials may have been used outside Plumbline "
                                   "or after expiry or revocation."),
                          evidence_ids=ids, detail={"role": role, "session": session,
                                                    "source_ips": sorted({e["source_ip"] for e in evs if e["source_ip"]})},
                          dedupe_key=f"ungranted:{role}:{session}")
            if f:
                created.append(f)
        self.audit.append(actor, "scan.ungranted", {"findings": len(created)}, iso(self.clock()))
        return created

    def run_all(self, lookback_hours: int = 24, actor: str = "system") -> dict:
        now = self.clock()
        expired = self.access.expire_due(actor)
        out = {"expired": expired, "orphans": self.scan_orphans(actor), "reviews": []}
        for g in self.access.list_grants():
            if g["status"] != "active":
                out["reviews"].append(self.review_grant(g["id"], actor))
        out["ungranted"] = self.scan_ungranted_activity(now - timedelta(hours=lookback_hours), now, actor)
        return out
