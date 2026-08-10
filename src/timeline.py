# src/timeline.py
from __future__ import annotations

import datetime
import json
from typing import Any, Dict, List, Optional

import jinja2
from sqlalchemy.orm import Session

from src.models import Evidence, Incident, PlaybookExecution

# ---------------------------------------------------------------------------
# Timeline Event representation (plain dict, can easily map to Pydantic if needed)
# ---------------------------------------------------------------------------
class TimelineEvent:
    def __init__(self, timestamp: datetime.datetime, event_type: str,
                 description: str, actor: str, metadata: Optional[Dict] = None):
        self.timestamp = timestamp
        self.event_type = event_type
        self.description = description
        self.actor = actor
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "description": self.description,
            "actor": self.actor,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Timeline Builder
# ---------------------------------------------------------------------------
class TimelineBuilder:
    """Assembles timeline events from incident, raw logs, playbook steps, and evidence."""

    def __init__(self, session: Session):
        self.session = session

    def build_timeline(self, incident_id: str) -> List[TimelineEvent]:
        """Return all events for the given incident, sorted by timestamp ascending."""
        incident = self.session.query(Incident).filter_by(incident_id=incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        events: List[TimelineEvent] = []

        # 1. Incident creation event
        events.append(TimelineEvent(
            timestamp=incident.created_at,
            event_type="Incident Reported",
            description=f"Incident {incident.incident_id} created: {incident.type}",
            actor="system",
            metadata={"severity": incident.severity, "status": incident.status}
        ))

        # 2. Raw logs (stored as JSON string)
        if incident.raw_logs:
            try:
                raw_logs = json.loads(incident.raw_logs) if isinstance(incident.raw_logs, str) else incident.raw_logs
            except Exception:
                raw_logs = []
            for entry in raw_logs:
                # Expect each entry to have at least a 'timestamp' field
                ts_str = entry.get("timestamp") or entry.get("time")
                if ts_str:
                    try:
                        ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except Exception:
                        ts = incident.timestamp  # fallback
                else:
                    ts = incident.timestamp
                events.append(TimelineEvent(
                    timestamp=ts,
                    event_type="Raw Log",
                    description=entry.get("message", json.dumps(entry)),
                    actor="system",
                    metadata=entry
                ))

        # 3. Playbook executions
        executions = (
            self.session.query(PlaybookExecution)
            .filter_by(incident_id=incident.id)
            .order_by(PlaybookExecution.started_at)
            .all()
        )
        for exec in executions:
            events.append(TimelineEvent(
                timestamp=exec.started_at or incident.created_at,
                event_type="Playbook Action",
                description=f"{exec.step_name} ({exec.step_action}) → {exec.status}",
                actor="playbook",
                metadata={
                    "step_action": exec.step_action,
                    "status": exec.status,
                    "result": json.loads(exec.result) if exec.result else None
                }
            ))

        # 4. Evidence collection
        evidence_records = (
            self.session.query(Evidence)
            .filter_by(incident_id=incident.id)
            .order_by(Evidence.collected_at)
            .all()
        )
        for ev in evidence_records:
            events.append(TimelineEvent(
                timestamp=ev.collected_at,
                event_type="Evidence Collected",
                description=f"{ev.evidence_type} from {ev.source}",
                actor="system",
                metadata={
                    "evidence_type": ev.evidence_type,
                    "source": ev.source,
                    "data_preview": str(ev.data)[:100]
                }
            ))

        # Sort all events by timestamp
        events.sort(key=lambda e: e.timestamp)
        return events


# ---------------------------------------------------------------------------
# Timeline Renderer
# ---------------------------------------------------------------------------
class TimelineRenderer:
    """Renders a list of TimelineEvent to different formats (HTML, Markdown, ASCII)."""

    def __init__(self, template_dir: str = "templates"):
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(["html"])
        )

    def to_html(self, events: List[TimelineEvent], incident: Dict[str, Any]) -> str:
        """
        Render HTML using the timeline template.
        :param events: list of TimelineEvent objects.
        :param incident: dict with keys: incident_id, type, severity, status (to display header).
        """
        template = self.template_env.get_template("timeline.html")
        events_dict = [e.to_dict() for e in events]
        return template.render(incident=incident, events=events_dict)

    def to_markdown(self, events: List[TimelineEvent]) -> str:
        """Return a Markdown representation of the timeline."""
        lines = ["# Incident Timeline\n"]
        for e in events:
            lines.append(f"- **{e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}** [{e.event_type}] {e.description}  ")
            lines.append(f"  _Actor: {e.actor}_  ")
            if e.metadata:
                lines.append(f"  ```json\n  {json.dumps(e.metadata, indent=2)}\n  ```")
        return "\n".join(lines)

    def to_ascii(self, events: List[TimelineEvent]) -> str:
        """Return a simple ASCII art timeline (vertical)."""
        lines = []
        lines.append("╔══════════════════════════════════════════╗")
        lines.append("║         INCIDENT TIMELINE (ASCII)        ║")
        lines.append("╚══════════════════════════════════════════╝")
        for i, e in enumerate(events):
            icon = "●" if e.event_type != "Raw Log" else "○"
            lines.append(f"  {icon} {e.timestamp.strftime('%H:%M:%S')}  {e.event_type}")
            lines.append(f"    {e.description}")
            if e.metadata:
                meta_str = json.dumps(e.metadata)
                if len(meta_str) > 60:
                    meta_str = meta_str[:60] + "..."
                lines.append(f"    └─ {meta_str}")
            if i < len(events) - 1:
                lines.append("  │")
        return "\n".join(lines)