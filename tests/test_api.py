# tests/test_api.py
import json
import threading

import pytest
from fastapi.testclient import TestClient

import api.main as main
from src.models import Base, Evidence, Incident, PlaybookExecution


@pytest.fixture(scope="function")
def client(session_factory, monkeypatch):
    # Monkeypatch main.SessionLocal to use test session factory
    monkeypatch.setattr(main, "SessionLocal", session_factory)
    # Ensure tables exist: they are created by fixture db_engine, but we need to ensure
    # init_db is called on main's engine? We can just call Base.metadata.create_all on the engine
    # used by session_factory.
    engine = session_factory.kw["bind"]
    Base.metadata.create_all(engine)

    # Use FastAPI TestClient
    with TestClient(main.app) as c:
        yield c


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["ok", "degraded"]  # may be ok if db connected
    assert "playbooks_loaded" in data


def test_create_incident_and_get(client, session_factory):
    # First create incident
    payload = {
        "type": "malware",
        "severity": "critical",
        "affected_host": "WS-1234",
        "description": "Test API incident",
        "source_ip": "192.168.1.100",
    }
    response = client.post("/incidents", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["processing"] is True
    assert data["incident_id"].startswith("INC-")
    incident_id = data["incident_id"]

    # Give background task time to run (if synchronous, it may run immediately)
    # In TestClient, BackgroundTasks run after response is sent, but in a synchronous
    # environment they run before returning? Actually they run after response, but in test
    # we may need to wait. We can poll GET /incidents/{id} until status changes.
    # For simplicity, we can call GET immediately and expect status to be "triaging" or "closed"
    # depending on timing. To avoid flakiness, we can poll a few times.
    import time
    for _ in range(10):
        resp = client.get(f"/incidents/{incident_id}")
        assert resp.status_code == 200
        inc_data = resp.json()
        if inc_data["status"] in ["closed", "eradicating"]:
            break
        time.sleep(0.2)
    # Now assert some fields
    assert "executions" in inc_data
    assert len(inc_data["executions"]) > 0  # at least one step should have run


def test_get_incident_timeline(client, session_factory):
    # Create an incident and ensure timeline works
    payload = {
        "type": "malware",
        "severity": "high",
        "affected_host": "WS-1234",
        "description": "Timeline test",
    }
    resp = client.post("/incidents", json=payload)
    incident_id = resp.json()["incident_id"]

    # Wait for processing
    import time
    for _ in range(10):
        resp2 = client.get(f"/incidents/{incident_id}")
        if resp2.json()["status"] in ["closed", "eradicating"]:
            break
        time.sleep(0.2)

    # Timeline JSON
    tl_resp = client.get(f"/incidents/{incident_id}/timeline?format=json")
    assert tl_resp.status_code == 200
    events = tl_resp.json()
    assert isinstance(events, list)
    assert len(events) > 0
    # Check chronological order
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)