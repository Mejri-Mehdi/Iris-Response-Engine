# src/schemas.py
from __future__ import annotations  # for forward references (Python 3.10+ style)

from datetime import datetime
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request schema — what the API accepts when creating an incident
# ---------------------------------------------------------------------------
class IncidentCreate(BaseModel):
    type: str
    severity: Optional[str] = "medium"
    affected_host: str
    affected_user: Optional[str] = None
    source_ip: Optional[str] = None
    description: str
    raw_logs: Optional[List[Dict[str, Any]]] = []


# ---------------------------------------------------------------------------
# Step result — returned as part of an incident’s execution history
# ---------------------------------------------------------------------------
class PlaybookStepResult(BaseModel):
    step_name: str
    action: str
    status: str                     # pending, running, completed, failed, skipped
    result: Dict[str, Any]          # free‑form dict with step output
    duration_ms: int                # execution time in milliseconds

    model_config = {
        "from_attributes": True     # enables ORM‑mode (maps from DB row dicts)
    }


# ---------------------------------------------------------------------------
# Timeline event — displayed in the incident timeline
# ---------------------------------------------------------------------------
class TimelineEvent(BaseModel):
    timestamp: str                  # ISO‑format datetime string
    event_type: str
    description: str
    actor: str                      # "system", "analyst", or "playbook"

    model_config = {
        "from_attributes": True
    }


# ---------------------------------------------------------------------------
# Response schema — what the API returns for an incident
# ---------------------------------------------------------------------------
class IncidentResponse(BaseModel):
    # Core fields mapped from the Incident DB model
    id: int
    incident_id: str
    type: str
    severity: str
    status: str
    timestamp: datetime
    affected_host: str
    affected_user: Optional[str]
    source_ip: Optional[str]
    description: Optional[str]
    raw_logs: Optional[List[Dict[str, Any]]]    # stored as JSON string in DB, returned parsed
    current_step: int
    playbook_id: Optional[str]
    context: Optional[Dict[str, Any]]           # stored as JSON string in DB, returned parsed
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]

    # Enriched collections
    executions: List[PlaybookStepResult] = []    # steps already executed
    evidence: List[Dict[str, Any]] = []          # evidence artifacts (simplified for now)

    model_config = {
        "from_attributes": True,
        "json_encoders": {
            # Ensure datetime fields are serialized as ISO strings
            datetime: lambda v: v.isoformat()
        }
    }