"""Per-provider principal references and duration limits.

Plumbline keeps one field (called `role_arn`, for historical reasons - it started AWS-only)
to name "the principal this contract grants access through." What that string has to look
like, and what a gateway needs out of it, is provider-specific:

* aws   - an IAM role ARN: arn:aws:iam::<12-digit account id>:role/<name>
* azure - "<service principal object id>@<role-assignment scope>#<role definition id>"
          Azure RBAC needs all three (who, where, which role) to activate a role
          assignment, and there is no single ARN-like identifier that carries them, so
          Plumbline encodes them into one string rather than adding three new columns for
          one provider.
* gcp   - a service account email: <name>@<project>.iam.gserviceaccount.com

Each provider also has its own real floor and ceiling on how long an "issue me access"
call can be asked to last for - these are not Plumbline's choice, they come from the
underlying API:

* aws   - STS AssumeRole: minimum 900 seconds (15 minutes); maximum is the role's own
          MaxSessionDuration, commonly configured up to 43200 seconds (12 hours).
* azure - PIM-eligible role activation: Microsoft's guidance allows 5 minutes up to 24
          hours.
* gcp   - IAM Credentials API generateAccessToken: GCP will not mint a service-account
          access token with a lifetime outside 600-3600 seconds (10 minutes to 1 hour).
"""
from __future__ import annotations

import re

PROVIDERS = ("aws", "azure", "gcp")

_AWS_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$")
_AZURE_RE = re.compile(
    r"^(?P<principal>[0-9a-fA-F-]{36})@(?P<scope>/subscriptions/[0-9a-fA-F-]{36}"
    r"(?:/resourceGroups/[^/#]+)?(?:/providers/[^#]+)?)#(?P<role>[0-9a-fA-F-]{36})$"
)
_GCP_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$")

_EXAMPLE = {
    "aws": "arn:aws:iam::123456789012:role/contractor-acme",
    "azure": "11111111-1111-1111-1111-111111111111@/subscriptions/<sub-guid>/resourceGroups/<rg>"
             "#22222222-2222-2222-2222-222222222222",
    "gcp": "contractor-acme@my-project.iam.gserviceaccount.com",
}

# (min_seconds, max_seconds) for each provider's real access-issuing primitive.
DURATION_BOUNDS = {"aws": (900, 43200), "azure": (300, 86400), "gcp": (600, 3600)}


class BadPrincipalRef(ValueError):
    pass


def _pattern(provider: str):
    try:
        return {"aws": _AWS_RE, "azure": _AZURE_RE, "gcp": _GCP_RE}[provider]
    except KeyError:
        raise BadPrincipalRef(f"unknown provider {provider!r}; must be one of {PROVIDERS}") from None


def validate(provider: str, ref: str) -> None:
    """Raise BadPrincipalRef if `ref` is not a well-formed principal reference for `provider`."""
    pattern = _pattern(provider)
    if not isinstance(ref, str) or not pattern.match(ref):
        raise BadPrincipalRef(f"for provider={provider!r}, role_arn must look like {_EXAMPLE[provider]!r}")


def principal_handle(provider: str, ref: str) -> str:
    """What a gateway needs to act on a principal that is already known-valid.

    AWS gateways work with IAM's own short role name (no account id, no 'role/' prefix) -
    that is what `iam.put_role_policy(RoleName=...)` wants, and it is what Plumbline has
    always logged, so this keeps that behaviour unchanged. Azure and GCP gateways need
    more than a short name can carry (Azure needs the scope and role definition too; GCP's
    APIs are happy to take the full email), so they get the reference unchanged.
    """
    if provider == "aws":
        _pattern("aws")  # validates `provider` itself
        return ref.rsplit("/", 1)[-1]
    _pattern(provider)
    return ref


def duration_bounds(provider: str) -> tuple[int, int]:
    if provider not in DURATION_BOUNDS:
        raise BadPrincipalRef(f"unknown provider {provider!r}; must be one of {PROVIDERS}")
    return DURATION_BOUNDS[provider]
