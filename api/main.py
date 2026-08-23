# api/main.py
from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session, sessionmaker

from src.models import (
    Evidence,
    get_engine,
    get_session,
    Incident,
    PlaybookExecution,
)
from src.playbook_engine import PlaybookLoader
from src.schemas import IncidentCreate, IncidentResponse, PlaybookStepResult, TimelineEvent
from src.triage import IncidentTriage

logger = logging.getLogger(__name__)

app = FastAPI(
    title="IRIS - Incident Response Playbook Automation Engine",
    description="SOAR-like engine for automated incident response",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = get_engine()
SessionLocal = get_session(engine)

def get_db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@app.on_event("startup")
def on_startup():
    from src.models import init_db
    init_db(engine)
    logger.info("Database tables created (if not exist).")
    loader = PlaybookLoader()
    playbooks = loader.load_all()
    logger.info(f"Loaded {len(playbooks)} playbooks.")

@app.exception_handler(404)
async def not_found_exception_handler(request, exc):
    return JSONResponse(status_code=404, content={"detail": "Resource not found"})

@app.exception_handler(500)
async def internal_exception_handler(request, exc):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

def incident_to_response(incident: Incident, session: Session) -> IncidentResponse:
    executions = (
        session.query(PlaybookExecution)
        .filter_by(incident_id=incident.id)
        .order_by(PlaybookExecution.started_at)
        .all()
    )
    evidence_records = (
        session.query(Evidence)
        .filter_by(incident_id=incident.id)
        .all()
    )

    raw_logs = None
    if incident.raw_logs:
        try:
            raw_logs = json.loads(incident.raw_logs)
        except Exception:
            raw_logs = []

    context = None
    if incident.context:
        try:
            context = json.loads(incident.context)
        except Exception:
            context = {}

    # Convert execution durations to int
    execution_responses = []
    for ex in executions:
        if ex.started_at and ex.completed_at:
            duration = int((ex.completed_at - ex.started_at).total_seconds() * 1000)
        else:
            duration = 0
        execution_responses.append(
            PlaybookStepResult(
                step_name=ex.step_name,
                action=ex.step_action,
                status=ex.status,
                result=json.loads(ex.result) if ex.result else {},
                duration_ms=duration,
            )
        )

    return IncidentResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        type=incident.type,
        severity=incident.severity,
        status=incident.status,
        timestamp=incident.timestamp,
        affected_host=incident.affected_host,
        affected_user=incident.affected_user,
        source_ip=incident.source_ip,
        description=incident.description,
        raw_logs=raw_logs,
        current_step=incident.current_step,
        playbook_id=incident.playbook_id,
        context=context,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        executions=execution_responses,
        evidence=[
            {
                "type": ev.evidence_type,
                "source": ev.source,
                "data": ev.data,
                "collected_at": ev.collected_at.isoformat(),
            }
            for ev in evidence_records
        ],
    )

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False

    loader = PlaybookLoader()
    playbook_count = len(loader.load_all())
    return {
        "status": "ok" if db_ok else "degraded",
        "db_connected": db_ok,
        "playbooks_loaded": playbook_count,
    }

@app.get("/playbooks")
def list_playbooks():
    loader = PlaybookLoader()
    playbooks = loader.load_all()
    return [
        {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "step_count": len(pb.steps),
        }
        for pb in playbooks
    ]

@app.post("/incidents", status_code=202)
def create_incident(
    data: IncidentCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    triage = IncidentTriage(SessionLocal)
    incident = triage.create_incident(data)
    background_tasks.add_task(triage.process_incident, incident.incident_id)
    response = incident_to_response(incident, db)
    return {
        **response.model_dump(),
        "processing": True,
        "status": "accepted",
    }

@app.get("/incidents", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if type:
        query = query.filter(Incident.type == type)
    incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()
    return [incident_to_response(inc, db) for inc in incidents]

@app.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter_by(incident_id=incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_to_response(incident, db)

@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: str,
    format: str = Query("json", pattern="^(json|html|ascii)$"),
    db: Session = Depends(get_db),
):
    triage = IncidentTriage(SessionLocal)
    try:
        if format == "html":
            html_content = triage.get_timeline(incident_id, format="html")
            return HTMLResponse(content=html_content)
        elif format == "ascii":
            ascii_content = triage.get_timeline(incident_id, format="ascii")
            return PlainTextResponse(content=ascii_content)
        else:
            events = triage.get_timeline(incident_id, format="dict")
            return events
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/incidents/{incident_id}/report")
def get_incident_report(incident_id: str, db: Session = Depends(get_db)):
    triage = IncidentTriage(SessionLocal)
    try:
        report = triage.get_report(incident_id)
        execs = report.get("executions", [])
        evidence = report.get("evidence", [])
        summary = {
            "total_steps": len(execs),
            "completed": sum(1 for e in execs if e["status"] == "completed"),
            "failed": sum(1 for e in execs if e["status"] == "failed"),
            "containment_actions": sum(
                1 for e in evidence if e["type"] in ["containment_action", "isolate_host"]
            ),
            "enrichment_actions": sum(
                1 for e in evidence if e["type"] in ["hash_lookup", "ip_lookup", "url_lookup", "geoip"]
            ),
        }
        report["summary"] = summary
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/incidents/{incident_id}/retry", status_code=202)
def retry_incident(
    incident_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter_by(incident_id=incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = "triaging"
    incident.current_step = max(0, incident.current_step)
    db.commit()
    triage = IncidentTriage(SessionLocal)
    background_tasks.add_task(triage.process_incident, incident.incident_id)
    return {
        "incident_id": incident_id,
        "message": "Retry scheduled",
        "status": "accepted",
    }