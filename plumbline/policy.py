"""Pure functions over IAM-style policy documents: validation, scope checks, blast radius,
and right-sizing. No AWS calls and no AI here: this is the deterministic rules tier."""
from __future__ import annotations

import json
from fnmatch import fnmatchcase

MAX_SESSION_POLICY_CHARS = 2048  # AWS limit for an inline session policy


class PolicyError(ValueError):
    """The policy is malformed or uses constructs Plumbline refuses to reason about."""


# ---------- normalisation ----------

def normalize(doc: dict | str) -> list[dict]:
    """Return [{'actions': [...], 'resources': [...]}] from an Allow-only policy document.

    Refuses Deny, NotAction, NotResource and Principal so a request can never hide
    broad access behind an inverted statement. Conditions are rejected too: Plumbline
    does not evaluate them, so pretending to would be dishonest.
    """
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError as e:
            raise PolicyError(f"policy is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or "Statement" not in doc:
        raise PolicyError("policy must be an object with a 'Statement' key")
    stmts = doc["Statement"]
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list) or not stmts:
        raise PolicyError("'Statement' must be a non-empty list")
    out = []
    for s in stmts:
        if not isinstance(s, dict):
            raise PolicyError("each statement must be an object")
        if s.get("Effect") != "Allow":
            raise PolicyError("only Effect=Allow statements are supported")
        for banned in ("NotAction", "NotResource", "Principal", "Condition"):
            if banned in s:
                raise PolicyError(f"'{banned}' is not supported")
        actions, resources = s.get("Action"), s.get("Resource")
        if actions is None or resources is None:
            raise PolicyError("each statement needs Action and Resource")
        actions = [actions] if isinstance(actions, str) else list(actions)
        resources = [resources] if isinstance(resources, str) else list(resources)
        if not actions or not resources:
            raise PolicyError("Action and Resource must not be empty")
        for a in actions:
            if not isinstance(a, str) or (a != "*" and ":" not in a):
                raise PolicyError(f"bad action: {a!r}")
        for r in resources:
            if not isinstance(r, str) or not r:
                raise PolicyError(f"bad resource: {r!r}")
        out.append({"actions": actions, "resources": resources})
    return out


def to_document(statements: list[dict]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": s["actions"], "Resource": s["resources"]}
            for s in statements
        ],
    }


def session_policy_json(statements: list[dict]) -> str:
    text = json.dumps(to_document(statements), separators=(",", ":"))
    if len(text) > MAX_SESSION_POLICY_CHARS:
        raise PolicyError(
            f"policy is {len(text)} characters; AWS allows at most {MAX_SESSION_POLICY_CHARS} "
            "for a session policy. Request fewer or broader-by-resource actions."
        )
    return text


# ---------- scope check (is a request inside the contract's ceiling?) ----------

def _covered(item: str, ceiling_patterns: list[str], case_insensitive: bool) -> bool:
    a = item.lower() if case_insensitive else item
    for c in ceiling_patterns:
        c2 = c.lower() if case_insensitive else c
        if c2 == "*" or fnmatchcase(a, c2):
            return True
    return False


def is_within_ceiling(requested: list[dict], ceiling: list[dict]) -> tuple[bool, list[str]]:
    """Every requested (action, resource) pair must be matched by one ceiling statement.

    A requested wildcard is compared as literal text, so 's3:*' is NOT inside 's3:Get*'.
    Known limitation: if a request's resource pattern is broader than a ceiling pattern in
    a way fnmatch can't see, it is rejected (fails closed).
    """
    violations = []
    for rs in requested:
        for act in rs["actions"]:
            for res in rs["resources"]:
                ok = any(
                    _covered(act, cs["actions"], True) and _covered(res, cs["resources"], False)
                    for cs in ceiling
                )
                if not ok:
                    violations.append(f"{act} on {res} is outside the contract's allowed scope")
    return (not violations, violations)


# ---------- action classification and blast radius ----------

READ_PREFIXES = ("get", "list", "describe", "lookup", "search", "view", "head", "batchget", "select", "scan", "query")
DESTRUCTIVE_PREFIXES = ("delete", "terminate", "remove", "destroy", "purge", "disable", "deregister", "revoke", "detach", "stop")
SECRET_READS = {
    "secretsmanager:getsecretvalue", "ssm:getparameter", "ssm:getparameters",
    "ssm:getparametersbypath", "kms:decrypt",
}
PRIVILEGE_ACTIONS = {
    "iam:passrole", "iam:attachrolepolicy", "iam:putrolepolicy", "iam:createpolicyversion",
    "iam:createaccesskey", "iam:updateassumerolepolicy", "iam:attachuserpolicy",
    "iam:putuserpolicy", "iam:createrole", "iam:createuser", "iam:attachgrouppolicy",
    "iam:setdefaultpolicyversion", "sts:assumerole", "organizations:*",
}


def _split(action: str) -> tuple[str, str]:
    service, _, name = action.partition(":")
    return service.lower(), name.lower()


def classify_action(action: str) -> str:
    """One of: admin, secret-read, privilege, destructive, read, write."""
    if action == "*":
        return "admin"
    service, name = _split(action)
    if name == "*":
        return "admin"
    lower = f"{service}:{name}"
    if any(fnmatchcase(s, lower) for s in SECRET_READS):
        return "secret-read"
    if any(fnmatchcase(p, lower) for p in PRIVILEGE_ACTIONS) or (
        service in ("iam", "organizations") and not name.startswith(READ_PREFIXES)
    ):
        return "privilege"
    if name.startswith(DESTRUCTIVE_PREFIXES):
        return "destructive"
    if name.startswith(READ_PREFIXES):
        return "read"
    return "write"


_RISK_ORDER = ["low", "medium", "high", "critical"]


def blast_radius(statements: list[dict]) -> dict:
    """Plain-language summary of what a policy can reach, plus a risk level."""
    by_cat: dict[str, set[str]] = {}
    services: set[str] = set()
    resources: set[str] = set()
    wildcard_resource = False
    for s in statements:
        for r in s["resources"]:
            resources.add(r)
            if r == "*":
                wildcard_resource = True
        for a in s["actions"]:
            services.add("all services" if a == "*" else _split(a)[0])
            by_cat.setdefault(classify_action(a), set()).add(a)

    reasons: list[str] = []
    risk = "low"

    def bump(level: str) -> None:
        nonlocal risk
        if _RISK_ORDER.index(level) > _RISK_ORDER.index(risk):
            risk = level

    if "admin" in by_cat:
        bump("critical")
        reasons.append("Allows every action on at least one service (a '*' action). That is effectively administrator access there.")
    if "privilege" in by_cat:
        bump("critical")
        reasons.append("Can change who has access (IAM or role actions). A holder could grant themselves more access than approved.")
    if "secret-read" in by_cat:
        bump("high")
        reasons.append("Can read secrets or decrypt data (" + ", ".join(sorted(by_cat["secret-read"])) + ").")
    if "destructive" in by_cat:
        bump("high")
        reasons.append("Can delete or shut down resources (" + ", ".join(sorted(by_cat["destructive"])) + ").")
    if "write" in by_cat:
        bump("medium")
        reasons.append("Can create or change resources (" + ", ".join(sorted(by_cat["write"])) + ").")
    if wildcard_resource and risk != "low":
        bump("high")
        reasons.append("Applies to all resources ('*'), not a named set, so it reaches everything of that type in the account.")
    if wildcard_resource and risk == "low":
        reasons.append("Read-only, but across all resources ('*').")
    if not reasons:
        reasons.append("Read-only access to specific, named resources.")

    return {
        "risk": risk,
        "services": sorted(services),
        "categories": {k: sorted(v) for k, v in sorted(by_cat.items())},
        "resources": sorted(resources),
        "reasons": reasons,
    }


# ---------- right-sizing ----------

def right_size(statements: list[dict], used: list[dict]) -> dict:
    """Propose a tighter policy from what was actually used.

    `used` items look like {'action': 's3:GetObject', 'resources': [arn, ...]}; only
    successful calls should be passed in. The suggestion is never broader than the
    request: an action keeps the observed resources, or falls back to the resources of
    the requested statements that covered it.
    """
    allowed_patterns = sorted({a for s in statements for a in s["actions"]})
    seen: dict[str, set[str]] = {}
    for u in used:
        seen.setdefault(u["action"], set()).update(u.get("resources") or [])

    new_statements = []
    for action in sorted(seen):
        res = set(seen[action])
        if not res:
            for s in statements:
                if any(_covered(action, [p], True) for p in s["actions"]):
                    res.update(s["resources"])
        if not res:
            continue
        new_statements.append({"actions": [action], "resources": sorted(res)})

    return {
        "suggested_policy": to_document(new_statements) if new_statements else None,
        "requested_action_patterns": len(allowed_patterns),
        "actions_actually_used": len(seen),
        "unused_action_patterns": [
            p for p in allowed_patterns
            if not any(_covered(a, [p], True) for a in seen)
        ],
    }
