import pytest
from fastapi.testclient import TestClient

from plumbline.api import create_app, parse_keys

KEYS = parse_keys("ka=alice@acme.example:contractor;kb=bob@corp.example:approver;kz=admin@corp.example:admin")
H = lambda k: {"X-API-Key": k}  # noqa: E731


@pytest.fixture
def client(pl):
    return TestClient(create_app(pl, KEYS))


def change_body(**over):
    d = dict(title="Deploy v2", environment="production", services=["payments"],
             requester="alice@acme.example", approver="bob@corp.example",
             scheduled_at="2026-03-02T15:00:00Z", lines_changed=10, review_count=1,
             has_rollback_plan=True, rollback_tested=True)
    d.update(over)
    return d


def test_submit_change_requires_approver_role(client):
    assert client.post("/changes", headers=H("ka"), json=change_body()).status_code == 403
    r = client.post("/changes", headers=H("kb"), json=change_body())
    assert r.status_code == 201 and r.json()["risk"] in ("low", "medium", "high", "critical")


def test_submit_change_rejects_bad_environment(client):
    r = client.post("/changes", headers=H("kb"), json=change_body(environment="prod"))
    assert r.status_code == 422


def test_list_get_and_status_flow(client):
    cid = client.post("/changes", headers=H("kb"), json=change_body()).json()["id"]
    assert client.get("/changes", headers=H("kb")).status_code == 200
    assert client.get(f"/changes/{cid}", headers=H("kb")).json()["status"] == "proposed"
    assert client.get("/changes/chg_missing", headers=H("kb")).status_code == 404
    r = client.post(f"/changes/{cid}/status", headers=H("kb"), json={"status": "approved"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert client.post(f"/changes/{cid}/status", headers=H("kb"), json={"status": "bogus"}).status_code == 422
    assert client.post("/changes/chg_missing/status", headers=H("kb"), json={"status": "approved"}).status_code == 404


def test_slo_requires_admin_to_define_but_approver_to_read(client):
    assert client.post("/slos", headers=H("kb"),
                       json={"service": "checkout", "name": "availability", "target_percent": 99.9}).status_code == 403
    r = client.post("/slos", headers=H("kz"),
                    json={"service": "checkout", "name": "availability", "target_percent": 99.9})
    assert r.status_code == 201
    sid = r.json()["id"]
    assert client.get("/slos", headers=H("kb")).status_code == 200
    assert client.post(f"/slos/{sid}/events", headers=H("kb"), json={"good": True}).status_code == 201
    s = client.get(f"/slos/{sid}/status", headers=H("kb")).json()
    assert s["total_events"] == 1


def test_slo_bad_target_percent_is_422(client):
    r = client.post("/slos", headers=H("kz"), json={"service": "x", "name": "y", "target_percent": 0})
    assert r.status_code == 422


def test_slo_event_and_status_for_missing_slo_is_404(client):
    assert client.post("/slos/slo_missing/events", headers=H("kb"), json={"good": True}).status_code == 404
    assert client.get("/slos/slo_missing/status", headers=H("kb")).status_code == 404
