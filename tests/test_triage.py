# tests/test_triage.py
import datetime
import json
import os

import pytest
import yaml

from src.models import Evidence, Incident, PlaybookExecution
from src.schemas import IncidentCreate
from src.triage import IncidentTriage


@pytest.fixture
def sample_playbooks(tmp_path):
    playbook_yaml = """
id: test_playbook
name: Test Playbook
description: A test playbook
version: "1.0"
severity_trigger: [critical]

steps:
  - name: Initial Triage
    action: classify_severity
    params:
      escalate_if: critical

  - name: Hash Enrichment
    action: lookup_hash
    params:
      source: virustotal
      hash_field: file_hash

  - name: Containment
    action: isolate_host
    params:
      target: "{{affected_host}}"
      notify: true

  - name: Notify
    action: send_alert
    params:
      channel: slack
      message: "Test alert for {{incident_id}}"
"""
    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()
    p = playbooks_dir / "test_playbook.yml"
    p.write_text(playbook_yaml)
    return str(playbooks_dir)


def test_create_incident_generates_id(session_factory, sample_playbooks):
    from src.triage import PlaybookLoader
    triage = IncidentTriage(session_factory)
    triage.playbook_loader = PlaybookLoader(sample_playbooks)

    data = IncidentCreate(
        type="malware",
        severity="critical",
        affected_host="WS-1234",
        description="Test incident",
    )
    inc = triage.create_incident(data)
    assert inc.incident_id.startswith("INC-")
    parts = inc.incident_id.split("-")
    assert len(parts) == 3
    assert parts[0] == "INC"
    assert len(parts[1]) == 4
    assert int(parts[2]) > 0


def test_process_incident_runs_all_steps(session_factory, sample_playbooks):
    from src.triage import PlaybookLoader
    triage = IncidentTriage(session_factory)
    triage.playbook_loader = PlaybookLoader(sample_playbooks)

    data = IncidentCreate(
        type="test_playbook",
        severity="critical",
        affected_host="WS-1234",
        description="Test incident",
        source_ip="192.168.1.100",
    )
    inc = triage.create_incident(data)
    triage.process_incident(inc.incident_id)

    session = session_factory()
    try:
        incident = session.query(Incident).filter_by(incident_id=inc.incident_id).first()
        assert incident.status == "closed"
        executions = session.query(PlaybookExecution).filter_by(incident_id=incident.id).all()
        # Expected 5 because 'Containment' step also logs via ContainmentSimulator
        assert len(executions) == 5
        for ex in executions:
            assert ex.status == "completed"
    finally:
        session.close()


def test_process_incident_failure_handled(session_factory, sample_playbooks):
    playbook_yaml = """
id: fail_playbook
name: Failing Playbook
description: A playbook with a failing step
version: "1.0"
steps:
  - name: Good Step
    action: lookup_hash
    params:
      source: virustotal

  - name: Bad Step
    action: nonexistent_action
"""
    playbooks_dir = os.path.dirname(sample_playbooks)
    with open(os.path.join(playbooks_dir, "fail_playbook.yml"), "w") as f:
        f.write(playbook_yaml)

    from src.triage import PlaybookLoader
    triage = IncidentTriage(session_factory)
    triage.playbook_loader = PlaybookLoader(playbooks_dir)

    data = IncidentCreate(
        type="fail_playbook",
        severity="critical",
        affected_host="WS-1234",
        description="Test failure",
    )
    inc = triage.create_incident(data)
    triage.process_incident(inc.incident_id)

    session = session_factory()
    try:
        incident = session.query(Incident).filter_by(incident_id=inc.incident_id).first()
        assert incident.status != "closed"
        executions = session.query(PlaybookExecution).filter_by(incident_id=incident.id).all()
        assert executions[0].status == "completed"
        assert executions[1].status == "failed"
    finally:
        session.close()


def test_context_shared_between_steps(session_factory, sample_playbooks):
    playbook_yaml = """
id: context_playbook
name: Context Playbook
description: Test context sharing
version: "1.0"
steps:
  - name: Set Variable
    action: send_alert
    params:
      channel: test
      message: "Setting variable"
  - name: Use Variable
    action: send_alert
    params:
      channel: slack
      message: "Context value: {{custom_var}}"
"""
    playbooks_dir = os.path.dirname(sample_playbooks)
    with open(os.path.join(playbooks_dir, "context_playbook.yml"), "w") as f:
        f.write(playbook_yaml)

    from src.triage import PlaybookLoader
    triage = IncidentTriage(session_factory)
    triage.playbook_loader = PlaybookLoader(playbooks_dir)

    data = IncidentCreate(
        type="context_playbook",
        severity="high",
        affected_host="WS-1234",
        description="Test context",
    )
    inc = triage.create_incident(data)
    triage.process_incident(inc.incident_id)

    session = session_factory()
    try:
        incident = session.query(Incident).filter_by(incident_id=inc.incident_id).first()
        context = json.loads(incident.context)
        assert len(context["step_results"]) == 2
    finally:
        session.close()