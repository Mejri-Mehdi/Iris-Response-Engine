# src/playbook_engine.py
from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from jinja2 import Template
from sqlalchemy.orm import Session, sessionmaker

from src.models import Evidence, Incident, PlaybookExecution

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes for playbook definitions
# ---------------------------------------------------------------------------

@dataclass
class PlaybookStep:
    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    version: str
    severity_trigger: List[str] = field(default_factory=list)
    steps: List[PlaybookStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Playbook Loader – reads YAML files from disk
# ---------------------------------------------------------------------------

class PlaybookLoader:
    """Loads and caches playbooks from a directory of YAML files."""

    def __init__(self, playbooks_dir: str = "playbooks"):
        self.playbooks_dir = Path(playbooks_dir)
        self._playbooks: Dict[str, Playbook] = {}
        self.load_all()

    def _parse_yaml(self, file_path: Path) -> Optional[Playbook]:
        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
            steps = [
                PlaybookStep(
                    name=s["name"],
                    action=s["action"],
                    params=s.get("params", {}),
                )
                for s in data["steps"]
            ]
            return Playbook(
                id=data["id"],
                name=data["name"],
                description=data.get("description", ""),
                version=data.get("version", "1.0"),
                severity_trigger=data.get("severity_trigger", []),
                steps=steps,
            )
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return None

    def load_all(self) -> List[Playbook]:
        self._playbooks.clear()
        for yml_file in self.playbooks_dir.glob("*.yml"):
            pb = self._parse_yaml(yml_file)
            if pb:
                self._playbooks[pb.id] = pb
        return list(self._playbooks.values())

    def get_by_id(self, playbook_id: str) -> Optional[Playbook]:
        return self._playbooks.get(playbook_id)

    def match_playbook(self, incident_type: str, severity: str) -> Optional[Playbook]:
        """Return first playbook whose id matches the incident type,
        or whose severity_trigger contains the given severity."""
        # First, exact match by type as playbook id
        if incident_type in self._playbooks:
            return self._playbooks[incident_type]
        # Then, check severity triggers
        for pb in self._playbooks.values():
            if severity in pb.severity_trigger:
                return pb
        return None


# ---------------------------------------------------------------------------
# Playbook Engine – state machine that executes steps
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """Executes a playbook against an incident, step by step."""

    def __init__(self, session_factory: sessionmaker[Session], playbook_loader: PlaybookLoader):
        self.Session = session_factory
        self.loader = playbook_loader

    def run_playbook(self, incident_id: str, playbook_id: str) -> None:
        """Main entry point: run the given playbook on the incident."""
        with self.Session() as session:
            incident = session.query(Incident).filter_by(incident_id=incident_id).first()
            if not incident:
                raise ValueError(f"Incident {incident_id} not found")

            # Build initial context from the incident
            context = self._build_initial_context(incident)

            # Load playbook
            playbook = self.loader.get_by_id(playbook_id)
            if not playbook:
                raise ValueError(f"Playbook {playbook_id} not found")

            # Update incident fields
            incident.playbook_id = playbook_id
            incident.status = "triaging"
            session.commit()

            # Execute each step sequentially
            for idx, step in enumerate(playbook.steps):
                # Create audit record
                execution = PlaybookExecution(
                    incident_id=incident.id,
                    step_name=step.name,
                    step_action=step.action,
                    status="running",
                    started_at=datetime.datetime.utcnow(),
                    mock=True,
                )
                session.add(execution)
                incident.current_step = idx
                session.commit()

                try:
                    # Execute the step
                    result = self._execute_step(step, context, session, incident)

                    # Mark step completed
                    execution.status = "completed"
                    execution.result = json.dumps(result)
                    execution.completed_at = datetime.datetime.utcnow()
                    context["step_results"].append({
                        "step": step.name,
                        "action": step.action,
                        "result": result,
                        "status": "success",
                    })

                except Exception as e:
                    logger.exception(f"Step '{step.name}' failed: {e}")
                    execution.status = "failed"
                    execution.result = json.dumps({"error": str(e)})
                    execution.completed_at = datetime.datetime.utcnow()
                    context["step_results"].append({
                        "step": step.name,
                        "action": step.action,
                        "result": {"error": str(e)},
                        "status": "failed",
                    })
                    # Stop playbook execution on failure
                    incident.status = "eradicating"  # or could be "failed"
                    session.commit()
                    return

                # Persist updated context back to the incident
                incident.context = json.dumps(context)
                session.commit()

            # All steps completed successfully
            incident.status = "closed"
            incident.resolved_at = datetime.datetime.utcnow()
            session.commit()

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _build_initial_context(self, incident: Incident) -> Dict[str, Any]:
        return {
            "incident_id": incident.incident_id,
            "type": incident.type,
            "severity": incident.severity,
            "affected_host": incident.affected_host,
            "affected_user": incident.affected_user,
            "source_ip": incident.source_ip,
            "description": incident.description,
            "step_results": [],
        }

    def _execute_step(
        self,
        step: PlaybookStep,
        context: Dict[str, Any],
        session: Session,
        incident: Incident,
    ) -> Dict[str, Any]:
        """Dispatch the step action to the correct handler."""
        # Render parameters with Jinja2
        rendered_params = self._render_params(step.params, context)

        action_handlers = {
            "classify_severity": self._action_classify_severity,
            "lookup_hash": self._action_lookup_hash,
            "isolate_host": self._action_isolate_host,
            "collect_evidence": self._action_collect_evidence,
            "send_alert": self._action_send_alert,
        }
        handler = action_handlers.get(step.action)
        if not handler:
            raise NotImplementedError(f"No handler for action '{step.action}'")

        result = handler(rendered_params, context, session, incident)
        # Merge new keys from result into context (except 'step_results')
        for k, v in result.items():
            if k != "step_results":
                context[k] = v
        return result



    def _dispatch(self, action: str, params: Dict[str, Any], context: Dict[str, Any],
              session: Session, incident: Incident) -> Dict[str, Any]:
        """Dispatch an action to the appropriate handler."""
        action_handlers = {
            "classify_severity": self._action_classify_severity,
            "lookup_hash": self._action_lookup_hash,
            "lookup_ip": self._action_lookup_ip,
            "lookup_url": self._action_lookup_url,
            "geoip": self._action_geoip,
            "isolate_host": self._action_isolate_host,
            "disable_user": self._action_disable_user,
            "block_ip": self._action_block_ip,
            "kill_process": self._action_kill_process,
            "snapshot_vm": self._action_snapshot_vm,
            "quarantine_file": self._action_quarantine_file,
            "send_alert": self._action_send_alert,
            "collect_evidence": self._action_collect_evidence,
            "create_ticket": self._action_create_ticket,
        }
        handler = action_handlers.get(action)
        if not handler:
            raise NotImplementedError(f"No handler for action '{action}'")
        return handler(params, context, session, incident)



    def _render_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Render all string values in params as Jinja2 templates using the context."""
        rendered = {}
        for key, value in params.items():
            if isinstance(value, str) and "{{" in value:
                template = Template(value)
                rendered[key] = template.render(**context)
            else:
                rendered[key] = value
        return rendered

    # -----------------------------------------------------------------------
    # Mocked action handlers
    # -----------------------------------------------------------------------

    def _action_classify_severity(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        session: Session,
        incident: Incident,
    ) -> Dict[str, Any]:
        """Mock: if severity matches escalate_if, escalate (change status)."""
        escalate = params.get("escalate_if")
        result = {"action": "classify_severity", "escalated": False}
        if escalate and context["severity"] == escalate:
            # Simulate escalation
            incident.status = "containing"  # escalate to containment
            result["escalated"] = True
            result["message"] = f"Severity is {escalate}, escalating immediately."
        else:
            result["message"] = "Severity classification unchanged."
        return result

    def _action_lookup_hash(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        session: Session,
        incident: Incident,
    ) -> Dict[str, Any]:
        """Mock: simulate VirusTotal hash lookup."""
        hash_field = params.get("hash_field", "file_hash")
        # Try to get the hash from context, or generate a dummy one
        file_hash = context.get(hash_field, "dummy_md5_hash_12345")
        # Mock result
        result = {
            "action": "lookup_hash",
            "source": params.get("source", "virustotal"),
            "hash": file_hash,
            "verdict": "malicious",
            "detection_ratio": "5/60",
        }
        # Record evidence
        evidence = Evidence(
            incident_id=incident.id,
            evidence_type="hash_lookup",
            source=params.get("source", "virustotal"),
            data=json.dumps(result),
        )
        session.add(evidence)
        return result

    def _action_isolate_host(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        session: Session,
        incident: Incident,
    ) -> Dict[str, Any]:
        """Mock: isolate the target host."""
        target = params.get("target", context.get("affected_host", "unknown"))
        result = {
            "action": "isolate_host",
            "target": target,
            "status": "isolated",
            "notified": params.get("notify", False),
        }
        # Record evidence (containment action)
        evidence = Evidence(
            incident_id=incident.id,
            evidence_type="containment_action",
            source="playbook",
            data=json.dumps(result),
        )
        session.add(evidence)
        return result

    def _action_collect_evidence(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        session: Session,
        incident: Incident,
    ) -> Dict[str, Any]:
        """Mock: collect evidence (e.g., memory dump)."""
        evidence_type = params.get("type", "unknown")
        target = params.get("target", context.get("affected_host", "unknown"))
        # Simulate evidence data
        data = {
            "type": evidence_type,
            "target": target,
            "content": f"Mock {evidence_type} data from {target}",
        }
        result = {"action": "collect_evidence", "type": evidence_type, "collected": True}

        evidence = Evidence(
            incident_id=incident.id,
            evidence_type=evidence_type,
            source=target,
            data=json.dumps(data),
        )
        session.add(evidence)
        return result

    def _action_send_alert(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        session: Session,
        incident: Incident,
    ) -> Dict[str, Any]:
        """Mock: send an alert via Slack (or other channel)."""
        channel = params.get("channel", "general")
        message = params.get("message", "")
        # Render the message again (it's already rendered, but just in case)
        template = Template(message)
        rendered_msg = template.render(**context)

        result = {
            "action": "send_alert",
            "channel": channel,
            "message_sent": True,
            "content": rendered_msg,
        }

        evidence = Evidence(
            incident_id=incident.id,
            evidence_type="notification",
            source=channel,
            data=json.dumps({"message": rendered_msg}),
        )
        session.add(evidence)
        return result