"""Contract-bound, time-limited contractor access (features M1.1 to M1.3, plus revocation).

Flow: admin records a contract with a scope ceiling -> contractor requests access for a
named purpose and ticket -> approver sees the blast radius and decides -> contractor claims
credentials once. Secrets are returned to the contractor and never stored.
"""
from __future__ import annotations

import json
import secrets
from datetime import timedelta

from . import identifiers as ids
from . import policy as pol
from .audit import AuditLog
from .clock import iso, parse, utcnow
from .db import Database


class AccessError(Exception):
    """A request breaks a rule (bad state, scope, timing, separation of duties)."""


class NotFound(AccessError):
    pass


def _id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(5)}"


class AccessService:
    def __init__(self, db: Database, gateway, audit: AuditLog,
                 clock=utcnow, max_duration_minutes: int = 480):
        """`gateway` is either one gateway (treated as the 'aws' provider, for backward
        compatibility with single-cloud setups) or a {'aws': ..., 'azure': ..., 'gcp': ...}
        dict naming a gateway per provider a contract might use."""
        self.db, self.audit = db, audit
        self.gateways = gateway if isinstance(gateway, dict) else {"aws": gateway}
        self.clock = clock
        self.max_duration_minutes = max_duration_minutes

    # ----- helpers -----
    def gw_for(self, provider: str):
        try:
            return self.gateways[provider]
        except KeyError:
            raise AccessError(
                f"no gateway configured for provider {provider!r}; configured providers: "
                f"{sorted(self.gateways)}") from None

    def _log(self, actor: str, action: str, detail: dict) -> None:
        self.audit.append(actor, action, detail, iso(self.clock()))

    def _contract(self, contract_id: str):
        row = self.db.one("SELECT * FROM contracts WHERE id=?", (contract_id,))
        if not row:
            raise NotFound(f"contract {contract_id} not found")
        return row

    def _request(self, request_id: str):
        row = self.db.one("SELECT * FROM requests WHERE id=?", (request_id,))
        if not row:
            raise NotFound(f"request {request_id} not found")
        return row

    @staticmethod
    def role_name(provider: str, arn: str) -> str:
        """What a gateway needs to act on an already-valid principal reference. For AWS
        this is IAM's own short role name; Azure and GCP need the reference unchanged
        (see identifiers.principal_handle)."""
        return ids.principal_handle(provider, arn)

    # ----- contracts -----
    def create_contract(self, actor: str, contractor: str, vendor: str, owner: str,
                        role_arn: str, starts_at: str, ends_at: str, ceiling: dict,
                        provider: str = "aws") -> dict:
        """Each contract gets its OWN principal (role_arn) on its OWN cloud (provider).
        Revoking access works per principal, so a shared one would cut off every
        contractor using it - true on all three clouds, not just AWS."""
        if provider not in ids.PROVIDERS:
            raise AccessError(f"provider must be one of {ids.PROVIDERS}, not {provider!r}")
        if self.db.one("SELECT 1 FROM contracts WHERE role_arn=? AND provider=? AND status='active'",
                       (role_arn, provider)):
            raise AccessError("that principal is already used by another active contract; use one role per contract")
        try:
            ids.validate(provider, role_arn)
        except ids.BadPrincipalRef as e:
            raise AccessError(str(e)) from e
        start, end = parse(starts_at), parse(ends_at)
        if end <= start:
            raise AccessError("contract must end after it starts")
        ceiling_stmts = pol.normalize(ceiling, provider)  # also validates
        cid = _id("ctr")
        self.db.execute(
            "INSERT INTO contracts (id, contractor, vendor, owner, role_arn, provider, starts_at, ends_at,"
            " ceiling_json, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,'active',?)",
            (cid, contractor, vendor, owner, role_arn, provider, iso(start), iso(end),
             json.dumps(ceiling_stmts), iso(self.clock())),
        )
        self._log(actor, "contract.create", {"contract_id": cid, "contractor": contractor,
                                             "vendor": vendor, "provider": provider, "ends_at": iso(end)})
        return self.get_contract(cid)

    def get_contract(self, contract_id: str) -> dict:
        r = self._contract(contract_id)
        return {"id": r["id"], "contractor": r["contractor"], "vendor": r["vendor"],
                "owner": r["owner"], "role_arn": r["role_arn"], "provider": r["provider"],
                "starts_at": r["starts_at"], "ends_at": r["ends_at"],
                "ceiling": json.loads(r["ceiling_json"]), "status": r["status"]}

    def list_contracts(self) -> list[dict]:
        return [self.get_contract(r["id"]) for r in self.db.query("SELECT id FROM contracts ORDER BY created_at")]

    def end_contract(self, actor: str, contract_id: str) -> dict:
        """End a contract now and cut off everything issued under it."""
        c = self._contract(contract_id)
        if c["status"] == "ended":
            raise AccessError("contract already ended")
        self.db.execute("UPDATE contracts SET status='ended' WHERE id=?", (contract_id,))
        self._log(actor, "contract.end", {"contract_id": contract_id})
        for g in self.db.query("SELECT id FROM grants WHERE contract_id=? AND status='active'", (contract_id,)):
            self.revoke(actor, g["id"], "contract ended")
        self.db.execute(
            "UPDATE requests SET status='cancelled' WHERE contract_id=? AND status IN ('pending','approved')",
            (contract_id,),
        )
        return self.get_contract(contract_id)

    # ----- requests (M1.1) -----
    def request_access(self, actor: str, contract_id: str, purpose: str, ticket: str,
                       policy_doc: dict, duration_minutes: int) -> dict:
        c = self._contract(contract_id)
        if actor != c["contractor"]:
            raise AccessError("only the contractor named on the contract can request access under it")
        now = self.clock()
        if c["status"] != "active" or not (parse(c["starts_at"]) <= now < parse(c["ends_at"])):
            raise AccessError("contract is not active right now")
        if len(purpose.strip()) < 15:
            raise AccessError("purpose must say what the access is for (at least 15 characters)")
        if not ticket.strip():
            raise AccessError("a ticket or change reference is required")
        lo_s, hi_s = ids.duration_bounds(c["provider"])
        lo_m, hi_m = -(-lo_s // 60), min(self.max_duration_minutes, hi_s // 60)
        if not (lo_m <= duration_minutes <= hi_m):
            raise AccessError(f"duration must be between {lo_m} and {hi_m} minutes for provider {c['provider']}")
        stmts = pol.normalize(policy_doc, c["provider"])
        ok, violations = pol.is_within_ceiling(stmts, json.loads(c["ceiling_json"]))
        if not ok:
            self._log(actor, "request.rejected_scope", {"contract_id": contract_id, "violations": violations})
            raise AccessError("request exceeds the contract scope: " + "; ".join(violations))
        pol.session_policy_json(stmts, c["provider"])  # fail early if it will not fit in a session policy
        blast = pol.blast_radius(stmts, c["provider"])
        rid = _id("req")
        self.db.execute(
            "INSERT INTO requests (id, contract_id, contractor, purpose, ticket, policy_json, duration_minutes,"
            " blast_json, status, requested_at) VALUES (?,?,?,?,?,?,?,?,'pending',?)",
            (rid, contract_id, actor, purpose.strip(), ticket.strip(), json.dumps(stmts),
             duration_minutes, json.dumps(blast), iso(now)),
        )
        self._log(actor, "request.create", {"request_id": rid, "contract_id": contract_id,
                                            "ticket": ticket.strip(), "risk": blast["risk"]})
        return self.get_request(rid)

    def get_request(self, request_id: str) -> dict:
        r = self._request(request_id)
        return {
            "id": r["id"], "contract_id": r["contract_id"], "contractor": r["contractor"],
            "purpose": r["purpose"], "ticket": r["ticket"], "policy": json.loads(r["policy_json"]),
            "duration_minutes": r["duration_minutes"], "blast_radius": json.loads(r["blast_json"]),
            "status": r["status"], "requested_at": r["requested_at"], "decided_by": r["decided_by"],
            "decided_at": r["decided_at"], "decision_note": r["decision_note"],
            "access_expires_at": r["access_expires_at"],
        }

    def list_requests(self, contractor: str | None = None) -> list[dict]:
        rows = (self.db.query("SELECT id FROM requests WHERE contractor=? ORDER BY requested_at", (contractor,))
                if contractor else self.db.query("SELECT id FROM requests ORDER BY requested_at"))
        return [self.get_request(r["id"]) for r in rows]

    # ----- decision -----
    def decide(self, actor: str, request_id: str, approve: bool, note: str = "") -> dict:
        r = self._request(request_id)
        if r["status"] != "pending":
            raise AccessError(f"request is already {r['status']}")
        if actor == r["contractor"]:
            raise AccessError("you cannot decide your own request")
        now = self.clock()
        c = self._contract(r["contract_id"])
        if approve:
            if c["status"] != "active" or now >= parse(c["ends_at"]):
                raise AccessError("contract is no longer active")
            expires = min(now + timedelta(minutes=r["duration_minutes"]), parse(c["ends_at"]))
            min_seconds = ids.duration_bounds(c["provider"])[0]
            if (expires - now).total_seconds() < min_seconds:
                raise AccessError(f"the contract ends in under {min_seconds // 60} minutes, too soon to issue access")
            self.db.execute(
                "UPDATE requests SET status='approved', decided_by=?, decided_at=?, decision_note=?, access_expires_at=? WHERE id=?",
                (actor, iso(now), note, iso(expires), request_id),
            )
        else:
            self.db.execute(
                "UPDATE requests SET status='denied', decided_by=?, decided_at=?, decision_note=? WHERE id=?",
                (actor, iso(now), note, request_id),
            )
        self._log(actor, "request.approve" if approve else "request.deny",
                  {"request_id": request_id, "note": note})
        return self.get_request(request_id)

    # ----- claim (M1.2 / M1.3) -----
    def claim(self, actor: str, request_id: str) -> dict:
        """Contractor collects credentials once. The window ends at the approved expiry,
        which is never later than the contract end."""
        r = self._request(request_id)
        if actor != r["contractor"]:
            raise AccessError("only the requester can claim this access")
        if r["status"] != "approved":
            raise AccessError(f"request is {r['status']}, not approved")
        now = self.clock()
        c = self._contract(r["contract_id"])
        if c["status"] != "active":
            raise AccessError("contract is no longer active")
        expires = min(parse(r["access_expires_at"]), parse(c["ends_at"]))
        remaining = int((expires - now).total_seconds())
        if remaining < ids.duration_bounds(c["provider"])[0]:
            self.db.execute("UPDATE requests SET status='lapsed' WHERE id=?", (request_id,))
            self._log(actor, "request.lapsed", {"request_id": request_id})
            raise AccessError("approval has run out; submit a new request")
        stmts = json.loads(r["policy_json"])
        gid = _id("grt")
        session_name = f"plb-{gid[4:]}"
        remaining = min(remaining, ids.duration_bounds(c["provider"])[1])  # provider's own ceiling
        expires = now + timedelta(seconds=remaining)  # keep the stored expiry truthful if that capped it
        try:
            creds = self.gw_for(c["provider"]).assume_role(
                c["role_arn"], session_name, pol.session_policy_json(stmts, c["provider"]), remaining)
        except Exception as e:  # leave the request approved so the contractor can retry
            self._log(actor, "grant.issue_failed", {"request_id": request_id, "error": str(e)[:200]})
            raise AccessError(f"could not issue credentials: {e}") from e
        self.db.execute("UPDATE requests SET status='claimed' WHERE id=?", (request_id,))
        self.db.execute(
            "INSERT INTO grants (id, request_id, contract_id, contractor, role_arn, provider, session_name,"
            " policy_json, issued_at, expires_at, status) VALUES (?,?,?,?,?,?,?,?,?,?,'active')",
            (gid, request_id, r["contract_id"], actor, c["role_arn"], c["provider"], session_name,
             json.dumps(stmts), iso(now), iso(expires)),
        )
        self._log(actor, "grant.issue", {"grant_id": gid, "request_id": request_id,
                                         "session_name": session_name, "expires_at": iso(expires)})
        return {"grant": self.get_grant(gid), "credentials": creds}

    # ----- grants -----
    def get_grant(self, grant_id: str) -> dict:
        g = self.db.one("SELECT * FROM grants WHERE id=?", (grant_id,))
        if not g:
            raise NotFound(f"grant {grant_id} not found")
        return {"id": g["id"], "request_id": g["request_id"], "contract_id": g["contract_id"],
                "contractor": g["contractor"], "session_name": g["session_name"],
                "role_arn": g["role_arn"], "provider": g["provider"], "policy": json.loads(g["policy_json"]),
                "issued_at": g["issued_at"], "expires_at": g["expires_at"], "status": g["status"],
                "revoked_at": g["revoked_at"], "revoked_reason": g["revoked_reason"]}

    def list_grants(self, contractor: str | None = None) -> list[dict]:
        rows = (self.db.query("SELECT id FROM grants WHERE contractor=? ORDER BY issued_at", (contractor,))
                if contractor else self.db.query("SELECT id FROM grants ORDER BY issued_at"))
        return [self.get_grant(r["id"]) for r in rows]

    def revoke(self, actor: str, grant_id: str, reason: str) -> dict:
        g = self.get_grant(grant_id)
        if g["status"] != "active":
            raise AccessError(f"grant is already {g['status']}")
        now = self.clock()
        self.gw_for(g["provider"]).revoke_sessions(self.role_name(g["provider"], g["role_arn"]), now)
        self.db.execute("UPDATE grants SET status='revoked', revoked_at=?, revoked_reason=? WHERE id=?",
                        (iso(now), reason, grant_id))
        self._log(actor, "grant.revoke", {"grant_id": grant_id, "reason": reason})
        return self.get_grant(grant_id)

    def expire_due(self, actor: str = "system") -> list[str]:
        """Mark grants whose time is up. The credentials already die on their own at
        expiry; this keeps our records and audit trail in step."""
        now = self.clock()
        expired = []
        for g in self.db.query("SELECT id, expires_at FROM grants WHERE status='active'"):
            if parse(g["expires_at"]) <= now:
                self.db.execute("UPDATE grants SET status='expired' WHERE id=?", (g["id"],))
                self._log(actor, "grant.expire", {"grant_id": g["id"]})
                expired.append(g["id"])
        return expired
