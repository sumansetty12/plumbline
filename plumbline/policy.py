"""Pure functions over IAM-style policy documents: validation, scope checks, blast radius,
and right-sizing. No cloud calls and no AI here: this is the deterministic rules tier.

The document shape (Statement / Effect / Action / Resource) is AWS IAM's, kept as-is for
all three providers because it is a fine, general way to write "these actions, on these
resources" and there is no reason to invent a second syntax just to look provider-neutral.
What differs per provider is the *action string* format, so `normalize` and
`classify_action` both take a `provider` argument that changes how an action string is
validated and split into (service, verb):

* aws   - "service:Action", e.g. "s3:GetObject" (colon-separated)
* azure - "Provider.Namespace/resourceType/action", e.g. "Microsoft.Storage/storageAccounts/read"
* gcp   - "service.resource.verb", e.g. "storage.objects.get" (dot-separated)
"""
from __future__ import annotations

import json
import re
from fnmatch import fnmatchcase

MAX_SESSION_POLICY_CHARS = 2048  # AWS limit for an inline session policy

_AZURE_ACTION_RE = re.compile(r"^[A-Za-z0-9]+(\.[A-Za-z0-9]+)*/[A-Za-z0-9*]+(/[A-Za-z0-9*]+)*$")
_GCP_ACTION_RE = re.compile(r"^[a-z][a-zA-Z0-9]*(\.[a-zA-Z0-9*]+){1,}$")


class PolicyError(ValueError):
    """The policy is malformed or uses constructs Plumbline refuses to reason about."""


def _valid_action(a: str, provider: str) -> bool:
    if not isinstance(a, str) or not a:
        return False
    if a == "*":
        return True
    if provider == "aws":
        return ":" in a
    if provider == "azure":
        return bool(_AZURE_ACTION_RE.match(a))
    if provider == "gcp":
        return bool(_GCP_ACTION_RE.match(a))
    raise PolicyError(f"unknown provider {provider!r}")


# ---------- normalisation ----------

def normalize(doc: dict | str, provider: str = "aws") -> list[dict]:
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
            if not _valid_action(a, provider):
                raise PolicyError(f"bad action for provider={provider!r}: {a!r}")
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


def session_policy_json(statements: list[dict], provider: str = "aws") -> str:
    """Serialize the requested scope. For AWS this is a real inline STS session policy and
    is also checked against AWS's 2048-character limit. Azure and GCP have no equivalent of
    an inline, per-call session policy that narrows an already-granted role below its own
    permissions (see access.AccessService.claim), so for those providers this JSON is kept
    only as the auditable record of what was asked for, not as something enforced at the
    cloud layer - the size limit is an AWS-specific constraint and is not applied."""
    text = json.dumps(to_document(statements), separators=(",", ":"))
    if provider == "aws" and len(text) > MAX_SESSION_POLICY_CHARS:
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

READ_PREFIXES = ("get", "list", "describe", "lookup", "search", "view", "head", "batchget", "select", "scan",
                 "query", "read")
DESTRUCTIVE_PREFIXES = ("delete", "terminate", "remove", "destroy", "purge", "disable", "deregister", "revoke", "detach", "stop")

# Per-provider privileged-namespace markers: a service/namespace starting with one of these
# is treated as identity/access-management territory unless the verb is a plain read.
_IAM_NAMESPACES = {"aws": ("iam", "organizations"), "azure": ("microsoft.authorization",), "gcp": ("iam", "resourcemanager")}

SECRET_READS = {
    "aws": {"secretsmanager:getsecretvalue", "ssm:getparameter", "ssm:getparameters",
            "ssm:getparametersbypath", "kms:decrypt"},
    "azure": {"microsoft.keyvault/vaults/secrets/getsecret/action", "microsoft.keyvault/vaults/secrets/read"},
    "gcp": {"secretmanager.versions.access", "cloudkms.cryptokeyversions.usetodecrypt"},
}
# Specific actions (not whole namespaces, except AWS's pre-existing 'organizations:*') that
# grant or escalate access on their own. A plain read of IAM/authorization/IAM-namespace
# metadata is deliberately NOT swept in here for any provider - it falls through to the
# namespace check in classify_action below instead, so "who can see this" and "who can
# change this" stay distinguishable the same way for every cloud.
PRIVILEGE_ACTIONS = {
    "aws": {"iam:passrole", "iam:attachrolepolicy", "iam:putrolepolicy", "iam:createpolicyversion",
            "iam:createaccesskey", "iam:updateassumerolepolicy", "iam:attachuserpolicy",
            "iam:putuserpolicy", "iam:createrole", "iam:createuser", "iam:attachgrouppolicy",
            "iam:setdefaultpolicyversion", "sts:assumerole", "organizations:*"},
    "azure": {"microsoft.keyvault/vaults/accesspolicies/write"},
    "gcp": {"*.setiampolicy", "iam.serviceaccounts.actas", "iam.serviceaccountkeys.create"},
}


def _split(action: str, provider: str = "aws") -> tuple[str, str]:
    """(service-or-namespace, verb), both lower-cased, using each provider's own separator."""
    if provider == "aws":
        service, _, name = action.partition(":")
    elif provider == "azure":
        service, _, rest = action.partition("/")
        name = rest.rsplit("/", 1)[-1] if rest else ""
    elif provider == "gcp":
        head, _, name = action.rpartition(".")
        service = head.partition(".")[0]
    else:
        raise PolicyError(f"unknown provider {provider!r}")
    return service.lower(), name.lower()


def _matches_any(lower: str, patterns: set[str]) -> bool:
    """True if `lower` matches one of `patterns`, checking both directions: either side
    may be the one carrying the wildcard - a caller's own action can be wildcarded (e.g.
    requesting "secretsmanager:Get*"), and so can an entry in SECRET_READS/PRIVILEGE_ACTIONS
    (e.g. "*.setiampolicy", AWS's "organizations:*")."""
    return any(fnmatchcase(p, lower) or fnmatchcase(lower, p) for p in patterns)


def classify_action(action: str, provider: str = "aws") -> str:
    """One of: admin, secret-read, privilege, destructive, read, write."""
    if action == "*":
        return "admin"
    service, name = _split(action, provider)
    if name == "*":
        return "admin"
    lower = action.lower()
    if _matches_any(lower, SECRET_READS[provider]):
        return "secret-read"
    if _matches_any(lower, PRIVILEGE_ACTIONS[provider]) or (
        service in _IAM_NAMESPACES[provider] and not name.startswith(READ_PREFIXES)
    ):
        return "privilege"
    if name.startswith(DESTRUCTIVE_PREFIXES):
        return "destructive"
    if name.startswith(READ_PREFIXES):
        return "read"
    return "write"


_RISK_ORDER = ["low", "medium", "high", "critical"]


def blast_radius(statements: list[dict], provider: str = "aws") -> dict:
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
            services.add("all services" if a == "*" else _split(a, provider)[0])
            by_cat.setdefault(classify_action(a, provider), set()).add(a)

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
