# tests/test_containment.py
import datetime
import json

from src.containment import ContainmentSimulator
from src.models import Incident, PlaybookExecution


def create_incident(session, incident_id="INC-2026-0001"):
    inc = Incident(
        incident_id=incident_id,
        type="malware",
        severity="high",
        timestamp=datetime.datetime.utcnow(),
        affected_host="WS-1234",
        affected_user="jdoe",
        source_ip="192.168.1.100",
    )
    session.add(inc)
    session.commit()
    return inc


def test_isolate_host_returns_dict(session_factory, session):
    inc = create_incident(session)
    sim = ContainmentSimulator(session_factory)
    result = sim.isolate_host(inc.incident_id, "WS-1234")
    assert result["action"] == "isolate_host"
    assert result["status"] == "success"
    assert result["target"] == "WS-1234"


def test_isolate_host_logs_playbook_execution(session_factory, session):
    inc = create_incident(session)
    sim = ContainmentSimulator(session_factory)
    sim.isolate_host(inc.incident_id, "WS-1234")
    # Check PlaybookExecution record
    execution = session.query(PlaybookExecution).filter_by(
        incident_id=inc.id, step_action="isolate_host"
    ).first()
    assert execution is not None
    assert execution.status == "completed"
    result_dict = json.loads(execution.result)
    assert result_dict["target"] == "WS-1234"


def test_disable_user_nonexistent_handles_gracefully(session_factory, session):
    # If incident doesn't exist, should log error but not crash
    sim = ContainmentSimulator(session_factory)
    # Pass a non-existent incident_id; should not raise
    result = sim.disable_user("INC-9999", "unknown_user")
    assert result["action"] == "disable_user"  # still returns dict