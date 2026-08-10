# src/triage.py
from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, List, Optional

import jinja2
from sqlalchemy.orm import Session, sessionmaker

from src.containment import ContainmentSimulator
from src.enricher import Enricher
from src.models import Evidence, Incident, PlaybookExecution
from src.playbook_engine import Playbook, PlaybookLoader
from src.schemas import IncidentCreate
from src.timeline import TimelineBuilder, TimelineRenderer

logger = logging.getLogger(__name__)


class IncidentTriage:
    """
    Central orchestrator for incident creation, playbook execution,
    evidence collection, and timeline reporting.
    """

    def __init__(self, session_factory: sessionmaker[Session]):
        self.Session = session_factory
        self.playbook_loader = PlaybookLoader()
        self.render_env = jinja2.Environment()   # for step param rendering

        # These will be created with a session inside methods that need them
        # We'll initialise them lazily to avoid keeping a session alive.
        # Alternatively, we can pass a session when needed.

    def _get_session(self) -> Session:
        """Return a new session from the factory."""
        return self.Session()

    # ------------------------------------------------------------------
    # Incident creation
    # ------------------------------------------------------------------
    def create_incident(self, data: IncidentCreate) -> Incident:
        """
        Creates a new incident in the database.
        Returns the Incident ORM object.
        """
        session = self._get_session()
        try:
            incident_id = self._generate_incident_id(session)

            incident = Incident(
                incident_id=incident_id,
                type=data.type,
                severity=data.severity if data.severity else "medium",
                status="open",
                timestamp=datetime.datetime.utcnow(),
                affected_host=data.affected_host,
                affected_user=data.affected_user,
                source_ip=data.source_ip,
                description=data.description,
                raw_logs=json.dumps(data.raw_logs) if data.raw_logs else None,
                current_step=0,
            )

            # Match playbook
            playbook = self.playbook_loader.match_playbook(data.type, incident.severity)
            if playbook:
                incident.playbook_id = playbook.id
            else:
                incident.playbook_id = None   # no matching playbook; may be handled later

            session.add(incident)
            session.commit()
            session.refresh(incident)
            return incident
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _generate_incident_id(self, session: Session) -> str:
        """Generate a new incident ID: INC-YYYY-NNNN (auto-increment)."""
        current_year = datetime.datetime.utcnow().year
        # Get the highest number for this year
        max_num = 0
        latest = (
            session.query(Incident.incident_id)
            .filter(Incident.incident_id.like(f"INC-{current_year}-%"))
            .order_by(Incident.incident_id.desc())
            .first()
        )
        if latest:
            try:
                max_num = int(latest[0].split("-")[-1])
            except (ValueError, IndexError):
                pass
        next_num = max_num + 1
        return f"INC-{current_year}-{next_num:04d}"

    # ------------------------------------------------------------------
    # Playbook execution
    # ------------------------------------------------------------------
    def process_incident(self, incident_id: str) -> Incident:
        """
        Execute the playbook assigned to the incident.
        Returns the updated Incident object.
        """
        session = self._get_session()
        try:
            incident = session.query(Incident).filter_by(incident_id=incident_id).first()
            if not incident:
                raise ValueError(f"Incident {incident_id} not found")

            playbook_id = incident.playbook_id
            if not playbook_id:
                logger.warning(f"No playbook assigned to incident {incident_id}")
                return incident

            playbook = self.playbook_loader.get_by_id(playbook_id)
            if not playbook:
                raise ValueError(f"Playbook {playbook_id} not found")

            # Build initial context
            context = self._build_context(incident)

            # Mark incident as triaging
            incident.status = "triaging"
            session.commit()

            # Execute steps
            for idx, step in enumerate(playbook.steps):
                # Update current step on incident
                incident.current_step = idx

                # Create execution record (running)
                execution = PlaybookExecution(
                    incident_id=incident.id,
                    step_name=step.name,
                    step_action=step.action,
                    status="running",
                    started_at=datetime.datetime.utcnow(),
                    mock=False,          # using real enricher/containment
                )
                session.add(execution)
                session.commit()

                try:
                    # Render step parameters
                    params = self._render_params(step.params, context)

                    # Dispatch to handler
                    result = self._dispatch(step.action, params, context, session, incident)

                    # Update context
                    if isinstance(result, dict):
                        for k, v in result.items():
                            if k != "step_results":
                                context[k] = v
                        # Append step result to context
                        context.setdefault("step_results", []).append({
                            "step": step.name,
                            "action": step.action,
                            "result": result,
                            "status": "success",
                        })
                    else:
                        # For non-dict results, treat as string
                        context.setdefault("step_results", []).append({
                            "step": step.name,
                            "action": step.action,
                            "result": str(result),
                            "status": "success",
                        })

                    # Mark execution completed
                    execution.status = "completed"
                    execution.result = json.dumps(result)
                    execution.completed_at = datetime.datetime.utcnow()

                except Exception as e:
                    logger.exception(f"Step '{step.name}' failed: {e}")
                    execution.status = "failed"
                    execution.result = json.dumps({"error": str(e)})
                    execution.completed_at = datetime.datetime.utcnow()

                    # Update context with failure
                    context.setdefault("step_results", []).append({
                        "step": step.name,
                        "action": step.action,
                        "result": {"error": str(e)},
                        "status": "failed",
                    })

                    # Optionally abort on failure (simple abort)
                    incident.status = "eradicating"  # still unresolved, but stopped
                    session.commit()
                    # Save context
                    incident.context = json.dumps(context)
                    session.commit()
                    return incident

                # Save context after successful step
                incident.context = json.dumps(context)
                session.commit()

            # All steps completed successfully
            incident.status = "closed"
            incident.resolved_at = datetime.datetime.utcnow()
            session.commit()
            session.refresh(incident)
            return incident
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _build_context(self, incident: Incident) -> Dict[str, Any]:
        """Initial shared context dictionary."""
        return {
            "incident_id": incident.incident_id,
            "type": incident.type,
            "severity": incident.severity,
            "affected_host": incident.affected_host,
            "affected_user": incident.affected_user,
            "source_ip": incident.source_ip,
            "description": incident.description,
            "raw_logs": json.loads(incident.raw_logs) if incident.raw_logs else [],
            "step_results": [],
        }

    def _render_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Jinja2 render all string values that contain templates."""
        rendered = {}
        for key, value in params.items():
            if isinstance(value, str) and "{{" in value:
                template = jinja2.Template(value)
                rendered[key] = template.render(**context)
            else:
                rendered[key] = value
        return rendered

    # ------------------------------------------------------------------
    # Step dispatch map
    # ------------------------------------------------------------------
    def _dispatch(self, action: str, params: Dict[str, Any],
                  context: Dict[str, Any], session: Session,
                  incident: Incident) -> Any:
        handlers = {
            "classify_severity": self._handle_classify,
            "lookup_hash": self._handle_hash_lookup,
            "lookup_ip": self._handle_ip_lookup,
            "lookup_url": self._handle_url_lookup,
            "geoip": self._handle_geoip,
            "isolate_host": self._handle_isolate,
            "disable_user": self._handle_disable_user,
            "block_ip": self._handle_block_ip,
            "kill_process": self._handle_kill_process,
            "snapshot_vm": self._handle_snapshot_vm,
            "quarantine_file": self._handle_quarantine_file,
            "send_alert": self._handle_notify,
            "collect_evidence": self._handle_evidence,
            "create_ticket": self._handle_ticket,
        }
        handler = handlers.get(action)
        if not handler:
            raise NotImplementedError(f"Unknown playbook action: {action}")
        return handler(params, context, session, incident)

    # ------------------------------------------------------------------
    # Action handlers (use enricher / containment)
    # ------------------------------------------------------------------
    def _handle_classify(self, params, context, session, incident):
        # Simple severity escalation check
        escalate_if = params.get("escalate_if")
        result = {"action": "classify_severity", "escalated": False}
        if escalate_if and context["severity"] == escalate_if:
            incident.status = "containing"   # immediate escalation
            result["escalated"] = True
            result["message"] = f"Severity {escalate_if}, escalating."
        else:
            result["message"] = "Severity unchanged."
        return result

    def _handle_hash_lookup(self, params, context, session, incident):
        enricher = Enricher(session)
        hash_field = params.get("hash_field", "file_hash")
        file_hash = context.get(hash_field, "unknown_hash")
        result = enricher.lookup_hash(file_hash)
        # Record as evidence
        self._add_evidence(session, incident.id, "hash_lookup",
                           params.get("source", "virustotal"),
                           json.dumps(result))
        return result

    def _handle_ip_lookup(self, params, context, session, incident):
        enricher = Enricher(session)
        ip_field = params.get("ip_field", "source_ip")
        ip = context.get(ip_field, "0.0.0.0")
        result = enricher.lookup_ip(ip)
        self._add_evidence(session, incident.id, "ip_lookup",
                           "ip_reputation", json.dumps(result))
        return result

    def _handle_url_lookup(self, params, context, session, incident):
        enricher = Enricher(session)
        url_field = params.get("url_field", "url")
        url = context.get(url_field, "")
        result = enricher.lookup_url(url)
        self._add_evidence(session, incident.id, "url_lookup",
                           "url_reputation", json.dumps(result))
        return result

    def _handle_geoip(self, params, context, session, incident):
        enricher = Enricher(session)
        ip_field = params.get("ip_field", "source_ip")
        ip = context.get(ip_field, "0.0.0.0")
        result = enricher.geoip(ip)
        self._add_evidence(session, incident.id, "geoip",
                           "geoip", json.dumps(result))
        return result

    def _handle_isolate(self, params, context, session, incident):
        simulator = ContainmentSimulator(self.Session)
        target = params.get("target", context["affected_host"])
        result = simulator.isolate_host(incident.incident_id, target)
        # already logged in containment module; but we can add evidence
        return result

    def _handle_disable_user(self, params, context, session, incident):
        simulator = ContainmentSimulator(self.Session)
        username = params.get("username", context.get("affected_user", "unknown"))
        result = simulator.disable_user(incident.incident_id, username)
        return result

    def _handle_block_ip(self, params, context, session, incident):
        simulator = ContainmentSimulator(self.Session)
        ip = params.get("ip", context.get("source_ip", "0.0.0.0"))
        result = simulator.block_ip(incident.incident_id, ip)
        return result

    def _handle_kill_process(self, params, context, session, incident):
        simulator = ContainmentSimulator(self.Session)
        pid = int(params.get("pid", 0))
        host = params.get("host", context["affected_host"])
        result = simulator.kill_process(incident.incident_id, pid, host)
        return result

    def _handle_snapshot_vm(self, params, context, session, incident):
        simulator = ContainmentSimulator(self.Session)
        host = params.get("host", context["affected_host"])
        result = simulator.snapshot_vm(incident.incident_id, host)
        return result

    def _handle_quarantine_file(self, params, context, session, incident):
        simulator = ContainmentSimulator(self.Session)
        filepath = params.get("filepath")
        host = params.get("host", context["affected_host"])
        result = simulator.quarantine_file(incident.incident_id, filepath, host)
        return result

    def _handle_notify(self, params, context, session, incident):
        # Mock notification: record as evidence
        channel = params.get("channel", "general")
        message_template = params.get("message", "")
        template = jinja2.Template(message_template)
        message = template.render(**context)
        result = {
            "action": "send_alert",
            "channel": channel,
            "message": message,
            "status": "sent"
        }
        self._add_evidence(session, incident.id, "notification",
                           channel, json.dumps(result))
        return result

    def _handle_evidence(self, params, context, session, incident):
        # Generic evidence collector
        evidence_type = params.get("type", "generic")
        source = params.get("source", "playbook")
        target = params.get("target", context["affected_host"])
        # Build mock content
        content = {
            "type": evidence_type,
            "source": source,
            "target": target,
            "note": "Mock evidence collected."
        }
        evidence = Evidence(
            incident_id=incident.id,
            evidence_type=evidence_type,
            source=source,
            data=json.dumps(content),
        )
        session.add(evidence)
        return {"action": "collect_evidence", "type": evidence_type, "status": "collected"}

    def _handle_ticket(self, params, context, session, incident):
        # Simulate creating an external ticket
        ticket_id = f"TICK-{context['incident_id']}-01"
        result = {
            "action": "create_ticket",
            "ticket_id": ticket_id,
            "status": "created"
        }
        self._add_evidence(session, incident.id, "ticket", "servicenow",
                           json.dumps(result))
        return result

    def _add_evidence(self, session, incident_id: int,
                      evidence_type: str, source: str, data: str):
        evidence = Evidence(
            incident_id=incident_id,
            evidence_type=evidence_type,
            source=source,
            data=data,
        )
        session.add(evidence)
        # commit will happen later in the outer transaction

    # ------------------------------------------------------------------
    # Timeline & report
    # ------------------------------------------------------------------
    def get_timeline(self, incident_id: str, format: str = "dict") -> Any:
        """
        Build and return timeline in the requested format:
        'dict' – list of event dicts
        'html' – rendered HTML string
        'markdown' – Markdown string
        'ascii' – ASCII art string
        """
        session = self._get_session()
        try:
            builder = TimelineBuilder(session)
            events = builder.build_timeline(incident_id)

            if format == "html":
                # Get incident summary for header
                incident = session.query(Incident).filter_by(incident_id=incident_id).first()
                incident_data = {
                    "incident_id": incident.incident_id,
                    "type": incident.type,
                    "severity": incident.severity,
                    "status": incident.status,
                }
                renderer = TimelineRenderer()
                return renderer.to_html(events, incident_data)
            elif format == "markdown":
                renderer = TimelineRenderer()
                return renderer.to_markdown(events)
            elif format == "ascii":
                renderer = TimelineRenderer()
                return renderer.to_ascii(events)
            else:  # dict
                return [e.to_dict() for e in events]
        finally:
            session.close()

    def get_report(self, incident_id: str) -> Dict[str, Any]:
        """
        Return a comprehensive incident report.
        """
        session = self._get_session()
        try:
            incident = session.query(Incident).filter_by(incident_id=incident_id).first()
            if not incident:
                raise ValueError(f"Incident {incident_id} not found")

            executions = (
                session.query(PlaybookExecution)
                .filter_by(incident_id=incident.id)
                .order_by(PlaybookExecution.started_at)
                .all()
            )
            evidence = (
                session.query(Evidence)
                .filter_by(incident_id=incident.id)
                .order_by(Evidence.collected_at)
                .all()
            )
            # Build timeline dict
            builder = TimelineBuilder(session)
            timeline_events = [e.to_dict() for e in builder.build_timeline(incident_id)]

            return {
                "incident": {
                    "incident_id": incident.incident_id,
                    "type": incident.type,
                    "severity": incident.severity,
                    "status": incident.status,
                    "affected_host": incident.affected_host,
                    "affected_user": incident.affected_user,
                    "source_ip": incident.source_ip,
                    "description": incident.description,
                    "created_at": incident.created_at.isoformat(),
                    "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                },
                "executions": [
                    {
                        "step_name": e.step_name,
                        "action": e.step_action,
                        "status": e.status,
                        "started_at": e.started_at.isoformat() if e.started_at else None,
                        "completed_at": e.completed_at.isoformat() if e.completed_at else None,
                        "result": json.loads(e.result) if e.result else None,
                    }
                    for e in executions
                ],
                "evidence": [
                    {
                        "type": e.evidence_type,
                        "source": e.source,
                        "data": e.data,   # JSON string
                        "collected_at": e.collected_at.isoformat(),
                    }
                    for e in evidence
                ],
                "timeline": timeline_events,
            }
        finally:
            session.close()