"""HTTP API. Roles: contractor, approver, admin. Authentication here is a simple API key
per user (PLUMBLINE_KEYS) so the project runs anywhere. In real use put it behind your
single sign-on / reverse proxy; do not expose it to the internet as is."""
from __future__ import annotations

import hmac
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .access import AccessError, NotFound
from .app_factory import Plumbline
from .explain import verified_explanation
from .policy import PolicyError

STATIC = Path(__file__).parent / "static"


class User(BaseModel):
    name: str
    role: str


def parse_keys(spec: str) -> dict[str, User]:
    """'key1=alice@x.com:contractor;key2=bob@y.com:approver' -> {key: User}."""
    out = {}
    for item in filter(None, (s.strip() for s in spec.split(";"))):
        key, _, rest = item.partition("=")
        name, _, role = rest.rpartition(":")
        if not key or not name or role not in ("contractor", "approver", "admin"):
            raise ValueError(f"bad key spec: {item!r}")
        out[key] = User(name=name, role=role)
    return out


class ContractIn(BaseModel):
    contractor: str
    vendor: str
    owner: str
    role_arn: str
    starts_at: str
    ends_at: str
    ceiling: dict


class RequestIn(BaseModel):
    contract_id: str
    purpose: str
    ticket: str
    policy: dict
    duration_minutes: int = Field(ge=1)


class DecisionIn(BaseModel):
    approve: bool
    note: str = ""


class RevokeIn(BaseModel):
    reason: str = Field(min_length=3)


def create_app(pl: Plumbline, keys: dict[str, User]) -> FastAPI:
    app = FastAPI(title="Plumbline", version="0.1.0")

    @app.exception_handler(NotFound)
    async def _nf(_, e):
        return JSONResponse({"error": str(e)}, status_code=404)

    @app.exception_handler(AccessError)
    async def _ae(_, e):
        return JSONResponse({"error": str(e)}, status_code=400)

    @app.exception_handler(PolicyError)
    async def _pe(_, e):
        return JSONResponse({"error": str(e)}, status_code=422)

    def current(x_api_key: str = Header(default="")) -> User:
        for k, u in keys.items():
            if hmac.compare_digest(k.encode(), x_api_key.encode()):
                return u
        raise HTTPException(401, "missing or invalid API key")

    def need(*roles: str):
        def dep(u: User = Depends(current)) -> User:
            if u.role not in roles:
                raise HTTPException(403, f"requires role: {' or '.join(roles)}")
            return u
        return dep

    reviewer = need("approver", "admin")

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC / "dashboard.html")

    @app.get("/me")
    def me(u: User = Depends(current)):
        return u

    # ---- contracts ----
    @app.post("/contracts", status_code=201)
    def create_contract(body: ContractIn, u: User = Depends(need("admin"))):
        return pl.access.create_contract(u.name, **body.model_dump())

    @app.get("/contracts")
    def list_contracts(u: User = Depends(reviewer)):
        return pl.access.list_contracts()

    @app.post("/contracts/{cid}/end")
    def end_contract(cid: str, u: User = Depends(need("admin"))):
        return pl.access.end_contract(u.name, cid)

    # ---- requests ----
    @app.post("/requests", status_code=201)
    def create_request(body: RequestIn, u: User = Depends(need("contractor"))):
        return pl.access.request_access(u.name, body.contract_id, body.purpose, body.ticket,
                                        body.policy, body.duration_minutes)

    @app.get("/requests")
    def list_requests(u: User = Depends(current)):
        return pl.access.list_requests(u.name if u.role == "contractor" else None)

    @app.post("/requests/{rid}/decision")
    def decide(rid: str, body: DecisionIn, u: User = Depends(reviewer)):
        return pl.access.decide(u.name, rid, body.approve, body.note)

    @app.post("/requests/{rid}/claim")
    def claim(rid: str, u: User = Depends(need("contractor"))):
        out = pl.access.claim(u.name, rid)
        return JSONResponse(out, headers={"Cache-Control": "no-store"})  # credentials: never cache

    # ---- grants ----
    @app.get("/grants")
    def list_grants(u: User = Depends(current)):
        return pl.access.list_grants(u.name if u.role == "contractor" else None)

    @app.post("/grants/{gid}/revoke")
    def revoke(gid: str, body: RevokeIn, u: User = Depends(reviewer)):
        return pl.access.revoke(u.name, gid, body.reason)

    @app.post("/grants/{gid}/review")
    def review(gid: str, u: User = Depends(reviewer)):
        return pl.analyzer.review_grant(gid, u.name)

    # ---- scans and findings ----
    @app.post("/scan/run")
    def scan(lookback_hours: int = 24, u: User = Depends(reviewer)):
        r = pl.analyzer.run_all(lookback_hours, u.name)
        return {"expired": r["expired"], "orphan_findings": len(r["orphans"]),
                "grants_reviewed": len(r["reviews"]), "ungranted_findings": len(r["ungranted"])}

    @app.get("/findings")
    def findings(status: str | None = None, u: User = Depends(reviewer)):
        return pl.findings.list(status)

    @app.get("/findings/{fid}")
    def finding(fid: str, u: User = Depends(reviewer)):
        f = pl.findings.get(fid)
        if not f:
            raise NotFound(f"finding {fid} not found")
        return {**f, "evidence": pl.evidence.get_many(f["evidence_ids"])}

    @app.get("/findings/{fid}/explanation")
    def explanation(fid: str, u: User = Depends(reviewer)):
        f = pl.findings.get(fid)
        if not f:
            raise NotFound(f"finding {fid} not found")
        return verified_explanation(pl.explainer, f, pl.evidence.get_many(f["evidence_ids"]))

    @app.post("/findings/{fid}/close")
    def close(fid: str, u: User = Depends(reviewer)):
        if not pl.findings.get(fid):
            raise NotFound(f"finding {fid} not found")
        pl.audit.append(u.name, "finding.close", {"finding_id": fid}, _now(pl))
        return pl.findings.close(fid)

    # ---- audit ----
    @app.get("/audit")
    def audit(limit: int = 100, u: User = Depends(reviewer)):
        return pl.audit.entries(min(limit, 500))

    @app.get("/audit/verify")
    def verify(u: User = Depends(reviewer)):
        return {**pl.audit.verify(), "head": pl.audit.head()}

    return app


def _now(pl: Plumbline) -> str:
    from .clock import iso
    return iso(pl.analyzer.clock())
