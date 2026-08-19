# tests/test_models.py
import datetime
import json

from src.models import Evidence, Incident, PlaybookExecution


def test_create_incident(session):
    inc = Incident(
        incident_id="INC-2026-0001",
        type="malware",
        severity="critical",
        timestamp=datetime.datetime.utcnow(),
        affected_host="WS-1234",
        affected_user="jdoe",
        source_ip="192.168.1.100",
        description="Test incident",
        raw_logs=json.dumps([{"timestamp": "2026-08-08T12:00:00", "message": "alert"}]),
        current_step=0,
    )
    session.add(inc)
    session.commit()
    assert inc.id is not None
    assert inc.incident_id == "INC-2026-0001"


def test_playbook_execution_relationship(session):
    inc = Incident(
        incident_id="INC-2026-0002",
        type="phishing",
        severity="high",
        timestamp=datetime.datetime.utcnow(),
        affected_host="WS-1234",
    )
    session.add(inc)
    session.flush()

    exec1 = PlaybookExecution(
        incident_id=inc.id,
        step_name="Initial Triage",
        step_action="classify_severity",
        status="completed",
        started_at=datetime.datetime.utcnow(),
        completed_at=datetime.datetime.utcnow(),
        result=json.dumps({"escalated": False}),
        mock=True,
    )
    session.add(exec1)
    session.commit()

    assert len(inc.executions) == 1  # relationship exists
    assert inc.executions[0].step_name == "Initial Triage"


def test_evidence_relationship(session):
    inc = Incident(
        incident_id="INC-2026-0003",
        type="malware",
        severity="high",
        timestamp=datetime.datetime.utcnow(),
        affected_host="WS-1234",
    )
    session.add(inc)
    session.flush()

    ev = Evidence(
        incident_id=inc.id,
        evidence_type="hash_lookup",
        source="virustotal",
        data=json.dumps({"hash": "abc123", "verdict": "malicious"}),
    )
    session.add(ev)
    session.commit()

    assert len(inc.evidence) == 1
    assert inc.evidence[0].evidence_type == "hash_lookup"