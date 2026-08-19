# tests/test_playbook_engine.py
import os
import yaml

import pytest

from src.playbook_engine import Playbook, PlaybookEngine, PlaybookLoader, PlaybookStep


@pytest.fixture
def sample_playbook(tmp_path):
    playbook_yaml = """
id: test_playbook
name: Test Playbook
description: A test playbook
version: "1.0"
severity_trigger: [critical]

steps:
  - name: Step One
    action: classify_severity
    params:
      escalate_if: critical

  - name: Step Two
    action: lookup_hash
    params:
      source: virustotal
      hash_field: file_hash

  - name: Step Three
    action: isolate_host
    params:
      target: "{{affected_host}}"
      notify: true
"""
    p = tmp_path / "test_playbook.yml"
    p.write_text(playbook_yaml)
    return tmp_path


def test_load_playbooks(sample_playbook):
    loader = PlaybookLoader(playbooks_dir=str(sample_playbook))
    playbooks = loader.load_all()
    assert len(playbooks) == 1
    pb = playbooks[0]
    assert pb.id == "test_playbook"
    assert len(pb.steps) == 3
    assert pb.steps[2].action == "isolate_host"


def test_get_by_id(sample_playbook):
    loader = PlaybookLoader(playbooks_dir=str(sample_playbook))
    pb = loader.get_by_id("test_playbook")
    assert pb is not None
    assert pb.name == "Test Playbook"


def test_match_playbook_by_type(sample_playbook):
    loader = PlaybookLoader(playbooks_dir=str(sample_playbook))
    # Exact type match
    pb = loader.match_playbook("test_playbook", "critical")
    assert pb.id == "test_playbook"


def test_match_playbook_by_severity(sample_playbook):
    loader = PlaybookLoader(playbooks_dir=str(sample_playbook))
    # No type match, but severity matches trigger
    pb = loader.match_playbook("unknown_type", "critical")
    assert pb.id == "test_playbook"


def test_jinja_render_params():
    engine = PlaybookEngine(None, None)  # session_factory and loader not needed for this
    context = {"affected_host": "WS-1234", "incident_id": "INC-2026-0001"}
    params = {"target": "{{affected_host}}", "message": "Hello {{incident_id}}", "plain": "no_template"}
    rendered = engine._render_params(params, context)
    assert rendered["target"] == "WS-1234"
    assert rendered["message"] == "Hello INC-2026-0001"
    assert rendered["plain"] == "no_template"


def test_step_dispatch():
    # We can test dispatch by creating a dummy engine and adding a handler
    engine = PlaybookEngine(None, None)
    # Create a mock handler
    class DummyHandler:
        def __call__(self, params, context, session, incident):
            return {"result": "mocked", **params}

    # Monkeypatch the dispatch map
    engine._action_test = DummyHandler()
    # Actually, we need to use _dispatch if we override. Simpler: test handler invocation
    result = engine._dispatch("lookup_hash", {"source": "vt"}, {}, None, None)
    assert result["action"] == "lookup_hash"