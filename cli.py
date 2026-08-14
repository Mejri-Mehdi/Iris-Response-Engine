# cli.py
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import sessionmaker

from src.models import Evidence, get_engine, get_session, Incident, PlaybookExecution
from src.playbook_engine import PlaybookLoader
from src.schemas import IncidentCreate
from src.triage import IncidentTriage

# ---------------------------------------------------------------------------
# Global setup
# ---------------------------------------------------------------------------
engine = get_engine()               # iris.db
SessionLocal = get_session(engine)  # session factory

# Ensure tables exist (for standalone use)
from src.models import init_db
init_db(engine)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
def clear_screen():
    """Clear terminal screen (cross-platform)."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_json(obj):
    """Pretty-print a JSON object."""
    print(json.dumps(obj, indent=2, default=str))


def format_duration(start, end):
    """Return human-readable duration string."""
    if not start or not end:
        return "N/A"
    delta = end - start
    seconds = delta.total_seconds()
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def create_incident(args):
    """Create a new incident and start playbook processing in background."""
    triage = IncidentTriage(SessionLocal)

    # Build IncidentCreate schema
    data = IncidentCreate(
        type=args.type,
        severity=args.severity or "medium",
        affected_host=args.host,
        affected_user=args.user,
        source_ip=args.source_ip,
        description=args.description,
        raw_logs=json.loads(args.raw_logs) if args.raw_logs else [],
    )

    incident = triage.create_incident(data)
    print(f"✅ Incident created: {incident.incident_id}")
    print(f"   Type: {incident.type}, Severity: {incident.severity}")
    print(f"   Playbook: {incident.playbook_id or 'None'}")

    # Start processing in background thread
    t = threading.Thread(
        target=triage.process_incident,
        args=(incident.incident_id,),
        daemon=True
    )
    t.start()
    print("   Playbook execution started in background.")
    print(f"   Use 'python cli.py watch --incident-id {incident.incident_id}' to monitor.")


def watch_incident(args):
    """Watch playbook execution live until completion."""
    session = SessionLocal()
    incident_id = args.incident_id

    # Clear screen and print initial header
    while True:
        clear_screen()
        incident = session.query(Incident).filter_by(incident_id=incident_id).first()
        if not incident:
            print(f"❌ Incident {incident_id} not found.")
            return

        # Header
        print("=" * 70)
        print(f"  IRIS - Incident Watch: {incident.incident_id}")
        print(f"  Type: {incident.type:15} Severity: {incident.severity}")
        print(f"  Status: {incident.status:12} Current Step: {incident.current_step}")
        print("=" * 70)

        # Fetch executions
        executions = (
            session.query(PlaybookExecution)
            .filter_by(incident_id=incident.id)
            .order_by(PlaybookExecution.started_at)
            .all()
        )

        if not executions:
            print("No playbook steps recorded yet...")
        else:
            print(f"{'Step':<4} {'Action':<20} {'Status':<12} {'Duration':<10}")
            print("-" * 70)
            for idx, ex in enumerate(executions, 1):
                if ex.status == "completed":
                    icon = "✅"
                elif ex.status == "running":
                    icon = "⏳"
                elif ex.status == "failed":
                    icon = "❌"
                else:
                    icon = "⏸️ "
                duration = format_duration(ex.started_at, ex.completed_at)
                print(f"{idx:<4} {ex.step_action:<20} {icon} {ex.status:<10} {duration}")
            print("-" * 70)

        # Check termination condition
        all_done = all(
            ex.status in ("completed", "failed", "skipped")
            for ex in executions
        )
        if incident.status == "closed" or all_done:
            print("\n🎯 Playbook execution finished.")
            if incident.status == "closed":
                print("   Incident closed successfully.")
            else:
                print("   Incident did not close (may have failures).")
            break

        time.sleep(2)  # poll interval

    session.close()


def list_incidents(args):
    """List incidents with optional filters."""
    session = SessionLocal()
    query = session.query(Incident)

    if args.status:
        query = query.filter(Incident.status == args.status)
    if args.type:
        query = query.filter(Incident.type == args.type)

    incidents = query.order_by(Incident.created_at.desc()).limit(args.limit).all()

    if not incidents:
        print("No incidents found.")
        return

    print(f"{'Incident ID':<16} {'Type':<12} {'Severity':<10} {'Status':<12} {'Host':<15} {'Created At'}")
    print("-" * 90)
    for inc in incidents:
        created = inc.created_at.strftime("%Y-%m-%d %H:%M")
        print(f"{inc.incident_id:<16} {inc.type:<12} {inc.severity:<10} {inc.status:<12} "
              f"{inc.affected_host:<15} {created}")
    print(f"\nTotal: {len(incidents)}")

    session.close()


def show_incident(args):
    """Show detailed information about a single incident."""
    session = SessionLocal()
    incident = session.query(Incident).filter_by(incident_id=args.incident_id).first()
    if not incident:
        print(f"❌ Incident {args.incident_id} not found.")
        return

    print("=" * 70)
    print(f"  Incident: {incident.incident_id}")
    print("=" * 70)
    print(f"Type:        {incident.type}")
    print(f"Severity:    {incident.severity}")
    print(f"Status:      {incident.status}")
    print(f"Host:        {incident.affected_host}")
    if incident.affected_user:
        print(f"User:        {incident.affected_user}")
    if incident.source_ip:
        print(f"Source IP:   {incident.source_ip}")
    print(f"Description: {incident.description}")
    print(f"Playbook:    {incident.playbook_id or 'None'}")
    print(f"Created:     {incident.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
    if incident.resolved_at:
        print(f"Resolved:    {incident.resolved_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Current Step: {incident.current_step}")
    print()

    # Executions
    executions = (
        session.query(PlaybookExecution)
        .filter_by(incident_id=incident.id)
        .order_by(PlaybookExecution.started_at)
        .all()
    )
    if executions:
        print("Playbook Steps:")
        for i, ex in enumerate(executions, 1):
            print(f"  {i}. {ex.step_name} ({ex.step_action}) - {ex.status}")
            if ex.result:
                result_str = ex.result
                try:
                    result_dict = json.loads(result_str)
                    print(f"     Result: {json.dumps(result_dict, indent=4)}")
                except:
                    print(f"     Result: {result_str[:200]}")
    else:
        print("No playbook steps executed yet.")
    print()

    # Evidence
    evidence = (
        session.query(Evidence)
        .filter_by(incident_id=incident.id)
        .order_by(Evidence.collected_at)
        .all()
    )
    if evidence:
        print("Evidence Collected:")
        for ev in evidence:
            print(f"  - [{ev.collected_at.strftime('%H:%M:%S')}] {ev.evidence_type} from {ev.source}")
            # Show brief data preview
            data_preview = ev.data[:100] if ev.data else ""
            print(f"      {data_preview}")
    else:
        print("No evidence collected.")

    session.close()


def report_incident(args):
    """Generate and print the full IR report."""
    triage = IncidentTriage(SessionLocal)
    try:
        report = triage.get_report(args.incident_id)
    except ValueError as e:
        print(f"❌ {e}")
        return

    if args.format == "json":
        print_json(report)
    elif args.format == "text":
        # Text summary
        inc = report["incident"]
        print("=" * 70)
        print(f"  INCIDENT REPORT: {inc['incident_id']}")
        print("=" * 70)
        print(f"Type:      {inc['type']}")
        print(f"Severity:  {inc['severity']}")
        print(f"Status:    {inc['status']}")
        print(f"Host:      {inc['affected_host']}")
        print(f"Created:   {inc['created_at']}")
        if inc['resolved_at']:
            print(f"Resolved:  {inc['resolved_at']}")
        print()

        # Summary stats
        summary = report.get("summary", {})
        if summary:
            print("Summary:")
            print(f"  Total steps: {summary.get('total_steps', 0)}")
            print(f"  Completed:   {summary.get('completed', 0)}")
            print(f"  Failed:      {summary.get('failed', 0)}")
            print(f"  Containment: {summary.get('containment_actions', 0)}")
            print(f"  Enrichment:  {summary.get('enrichment_actions', 0)}")
            print()

        # Timeline
        timeline = report.get("timeline", [])
        if timeline:
            print("Timeline:")
            for event in timeline[:10]:  # show first 10
                print(f"  [{event['timestamp']}] {event['event_type']}: {event['description']}")
        print()

        # Evidence
        evidence = report.get("evidence", [])
        if evidence:
            print(f"Evidence ({len(evidence)} items):")
            for ev in evidence:
                print(f"  - {ev['type']} from {ev['source']} at {ev['collected_at']}")
    else:
        print(f"Unsupported format: {args.format}. Use 'json' or 'text'.")


def timeline_incident(args):
    """Print the incident timeline in the requested format."""
    triage = IncidentTriage(SessionLocal)
    try:
        if args.format == "ascii":
            output = triage.get_timeline(args.incident_id, format="ascii")
            print(output)
        elif args.format == "json":
            events = triage.get_timeline(args.incident_id, format="dict")
            print_json(events)
        else:
            print("Supported formats: ascii, json")
    except ValueError as e:
        print(f"❌ {e}")


# ---------------------------------------------------------------------------
# Argument parser setup
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="IRIS - Incident Response Playbook Automation Engine CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-incident
    p_create = subparsers.add_parser("create-incident", help="Create a new incident")
    p_create.add_argument("--type", required=True, help="Incident type (malware, phishing, etc.)")
    p_create.add_argument("--host", required=True, help="Affected hostname")
    p_create.add_argument("--severity", default="medium", help="Severity (low/medium/high/critical)")
    p_create.add_argument("--description", required=True, help="Incident description")
    p_create.add_argument("--source-ip", dest="source_ip", help="Source IP address")
    p_create.add_argument("--user", dest="user", help="Affected user")
    p_create.add_argument("--raw-logs", dest="raw_logs", help="JSON string of raw logs")
    p_create.set_defaults(func=create_incident)

    # watch
    p_watch = subparsers.add_parser("watch", help="Watch playbook execution live")
    p_watch.add_argument("--incident-id", required=True, help="Incident ID to watch")
    p_watch.set_defaults(func=watch_incident)

    # list
    p_list = subparsers.add_parser("list", help="List incidents")
    p_list.add_argument("--status", help="Filter by status")
    p_list.add_argument("--type", help="Filter by type")
    p_list.add_argument("--limit", type=int, default=50, help="Maximum number to show (default 50)")
    p_list.set_defaults(func=list_incidents)

    # show
    p_show = subparsers.add_parser("show", help="Show incident details")
    p_show.add_argument("--incident-id", required=True, help="Incident ID")
    p_show.set_defaults(func=show_incident)

    # report
    p_report = subparsers.add_parser("report", help="Generate incident report")
    p_report.add_argument("--incident-id", required=True, help="Incident ID")
    p_report.add_argument("--format", choices=["json", "text"], default="json",
                          help="Output format (default: json)")
    p_report.set_defaults(func=report_incident)

    # timeline
    p_timeline = subparsers.add_parser("timeline", help="Show incident timeline")
    p_timeline.add_argument("--incident-id", required=True, help="Incident ID")
    p_timeline.add_argument("--format", choices=["ascii", "json"], default="ascii",
                            help="Output format (default: ascii)")
    p_timeline.set_defaults(func=timeline_incident)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()