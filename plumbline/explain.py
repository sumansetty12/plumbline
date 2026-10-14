"""Two-tier explanations. Tier 1 is a deterministic template. Tier 2 is an optional LLM
(bring your own key). Every LLM answer is checked before it is shown: it must cite
evidence ids that belong to this finding, and may not mention any other id. Anything
that fails the check is thrown away and the template is shown instead, with the reason.
"""
from __future__ import annotations

import json
import os
from typing import Protocol

import httpx

from .evidence import EVIDENCE_ID_RE

CONFIDENCE = {"low", "medium", "high"}


class Explainer(Protocol):
    def explain(self, finding: dict, evidence: list[dict]) -> dict: ...


class TemplateExplainer:
    """No AI. Restates the finding and points at its evidence."""

    kind = "template"

    def explain(self, finding: dict, evidence: list[dict]) -> dict:
        ids = [e["id"] for e in evidence]
        return {
            "summary": f"{finding['summary']} See evidence: {', '.join(ids)}.",
            "cited_evidence_ids": ids,
            "confidence": "high",
        }


def validate(result: object, allowed_ids: set[str]) -> str | None:
    """Return None if the explanation is acceptable, otherwise the reason it is not."""
    if not isinstance(result, dict):
        return "explanation was not an object"
    summary, cited, conf = result.get("summary"), result.get("cited_evidence_ids"), result.get("confidence")
    if not isinstance(summary, str) or not summary.strip():
        return "missing summary"
    if conf not in CONFIDENCE:
        return "confidence must be low, medium or high"
    if not isinstance(cited, list) or not cited:
        return "no evidence cited"
    if not all(isinstance(c, str) for c in cited):
        return "evidence ids must be strings"
    unknown = [c for c in cited if c not in allowed_ids]
    if unknown:
        return f"cited evidence that is not part of this finding: {unknown}"
    mentioned = set(EVIDENCE_ID_RE.findall(summary))
    if not mentioned <= allowed_ids:
        return f"summary mentions evidence ids that do not exist: {sorted(mentioned - allowed_ids)}"
    return None


def verified_explanation(explainer: Explainer, finding: dict, evidence: list[dict]) -> dict:
    allowed = {e["id"] for e in evidence}
    fallback = TemplateExplainer().explain(finding, evidence)
    try:
        result = explainer.explain(finding, evidence)
    except Exception as e:  # network, bad key, malformed reply: never block the finding
        return {**fallback, "source": "template", "ai_rejected_reason": f"AI call failed: {str(e)[:120]}"}
    reason = validate(result, allowed)
    if reason:
        return {**fallback, "source": "template", "ai_rejected_reason": reason}
    return {**result, "source": getattr(explainer, "kind", "ai"), "ai_rejected_reason": None}


PROMPT = """You are helping a small team review contractor access to their cloud account.
Explain the finding below in 2-3 plain sentences for a non-expert approver. Use ONLY the
evidence provided. If the evidence is thin, say so and set confidence to "low". Where the
finding includes a stated purpose, say whether the activity matches it.
Reply with JSON only: {"summary": str, "cited_evidence_ids": [str], "confidence": "low"|"medium"|"high"}.
Every sentence of fact must be backed by an evidence id listed in cited_evidence_ids.

FINDING:
%s

EVIDENCE (id -> event):
%s
"""


class AnthropicExplainer:
    """Calls the Anthropic Messages API with the user's own key (ANTHROPIC_API_KEY).

    Not exercised against the live API in this repository's tests: the tests use a mock
    transport. Try it yourself with your key before relying on it.
    """

    kind = "ai"

    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 transport: httpx.BaseTransport | None = None, timeout: float = 30.0):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("PLUMBLINE_MODEL", "claude-sonnet-5-5")
        self.client = httpx.Client(transport=transport, timeout=timeout)

    def explain(self, finding: dict, evidence: list[dict]) -> dict:
        if not self.api_key:
            raise RuntimeError("no ANTHROPIC_API_KEY set")
        ev = "\n".join(f"{e['id']}: {json.dumps(e['event'], sort_keys=True)}" for e in evidence[:40])
        body = {
            "model": self.model, "max_tokens": 500,
            "messages": [{"role": "user", "content": PROMPT % (json.dumps(
                {k: finding[k] for k in ("kind", "severity", "contractor", "summary", "detail")}, indent=1), ev)}],
        }
        resp = self.client.post(self.URL, json=body, headers={
            "x-api-key": self.api_key, "anthropic-version": "2023-06-01",
            "content-type": "application/json"})
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"].strip()
        if text.startswith("```"):
            text = text.strip("`").removeprefix("json").strip()
        return json.loads(text)
