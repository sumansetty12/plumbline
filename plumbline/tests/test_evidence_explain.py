import json

import httpx
import pytest

from plumbline.evidence import EvidenceStore, FindingStore
from plumbline.explain import AnthropicExplainer, TemplateExplainer, validate, verified_explanation
from plumbline.db import Database


def stores():
    db = Database()
    ev = EvidenceStore(db)
    return ev, FindingStore(db, ev)


def test_finding_requires_real_evidence():
    ev, fs = stores()
    with pytest.raises(ValueError, match="at least one"):
        fs.add(kind="K", severity="high", contractor="c", grant_id=None, summary="s", evidence_ids=[], now="t")
    with pytest.raises(ValueError, match="does not exist"):
        fs.add(kind="K", severity="high", contractor="c", grant_id=None, summary="s", evidence_ids=["ev_000000000000"], now="t")


def test_evidence_ids_are_stable_and_deduplicated():
    ev, _ = stores()
    a = ev.add("cloudtrail", {"id": "e1", "time": "t"})
    b = ev.add("cloudtrail", {"id": "e1", "time": "t"})
    assert a == b and a.startswith("ev_") and len(a) == 15
    assert ev.add("iam", {"id": "e1"}) != a


def test_unknown_severity_rejected():
    ev, fs = stores()
    eid = ev.add("x", {"id": "1"})
    with pytest.raises(ValueError):
        fs.add(kind="K", severity="meh", contractor=None, grant_id=None, summary="s", evidence_ids=[eid], now="t")


def finding_and_evidence():
    ev, fs = stores()
    e1 = ev.add("cloudtrail", {"id": "e1", "action": "iam:CreateAccessKey"})
    f = fs.add(kind="OUT_OF_SCOPE_ATTEMPT", severity="high", contractor="c", grant_id="g", summary="tried a thing",
               evidence_ids=[e1], now="t", detail={"purpose": "debug"})
    return f, ev.get_many(f["evidence_ids"])


class Fake:
    def __init__(self, result=None, exc=None):
        self.result, self.exc = result, exc

    def explain(self, finding, evidence):
        if self.exc:
            raise self.exc
        return self.result


def test_template_explainer_cites_all_evidence():
    f, ev = finding_and_evidence()
    r = TemplateExplainer().explain(f, ev)
    assert r["cited_evidence_ids"] == [ev[0]["id"]] and ev[0]["id"] in r["summary"]


def test_good_ai_answer_is_accepted():
    f, ev = finding_and_evidence()
    eid = ev[0]["id"]
    out = verified_explanation(Fake({"summary": f"It tried to create an access key ({eid}).",
                                     "cited_evidence_ids": [eid], "confidence": "medium"}), f, ev)
    assert out["source"] == "ai" and out["ai_rejected_reason"] is None


@pytest.mark.parametrize("result,fragment", [
    ({"summary": "x", "cited_evidence_ids": ["ev_aaaaaaaaaaaa"], "confidence": "high"}, "not part of this finding"),
    ({"summary": "x", "cited_evidence_ids": [], "confidence": "high"}, "no evidence cited"),
    ({"summary": "", "cited_evidence_ids": ["EV"], "confidence": "high"}, "missing summary"),
    ({"summary": "x", "cited_evidence_ids": ["EV"], "confidence": "certain"}, "confidence"),
    ("just a string", "not an object"),
    ({"summary": "see ev_bbbbbbbbbbbb for details", "cited_evidence_ids": ["EV"], "confidence": "low"}, "do not exist"),
])
def test_bad_ai_answers_are_rejected_and_replaced(result, fragment):
    f, ev = finding_and_evidence()
    if isinstance(result, dict) and result.get("cited_evidence_ids") == ["EV"]:
        result = {**result, "cited_evidence_ids": [ev[0]["id"]]}
    out = verified_explanation(Fake(result), f, ev)
    assert out["source"] == "template" and fragment in out["ai_rejected_reason"]
    assert out["cited_evidence_ids"] == [ev[0]["id"]]


def test_ai_failure_falls_back_to_template():
    f, ev = finding_and_evidence()
    out = verified_explanation(Fake(exc=RuntimeError("boom")), f, ev)
    assert out["source"] == "template" and "boom" in out["ai_rejected_reason"]


def test_validate_accepts_only_allowed_ids():
    assert validate({"summary": "ok", "cited_evidence_ids": ["ev_aaaaaaaaaaaa"], "confidence": "low"}, {"ev_aaaaaaaaaaaa"}) is None


def anthropic_with(handler):
    return AnthropicExplainer(api_key="k", model="m", transport=httpx.MockTransport(handler))


def test_anthropic_explainer_sends_key_and_parses_json_reply():
    f, ev = finding_and_evidence()
    eid = ev[0]["id"]
    seen = {}

    def handler(request):
        seen["headers"], seen["body"] = request.headers, json.loads(request.content)
        reply = json.dumps({"summary": f"Tried to make a key ({eid}).", "cited_evidence_ids": [eid], "confidence": "high"})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "```json\n" + reply + "\n```"}]})

    out = verified_explanation(anthropic_with(handler), f, ev)
    assert out["source"] == "ai"
    assert seen["headers"]["x-api-key"] == "k" and seen["body"]["model"] == "m"
    assert eid in seen["body"]["messages"][0]["content"] and "debug" in seen["body"]["messages"][0]["content"]


def test_anthropic_http_error_falls_back():
    f, ev = finding_and_evidence()
    out = verified_explanation(anthropic_with(lambda r: httpx.Response(401, json={})), f, ev)
    assert out["source"] == "template"


def test_anthropic_without_key_falls_back(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    f, ev = finding_and_evidence()
    out = verified_explanation(AnthropicExplainer(api_key=""), f, ev)
    assert out["source"] == "template" and "no ANTHROPIC_API_KEY" in out["ai_rejected_reason"]


def test_template_result_is_never_labelled_as_ai():
    f, ev = finding_and_evidence()
    assert verified_explanation(TemplateExplainer(), f, ev)["source"] == "template"
