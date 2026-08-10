# src/containment.py
from __future__ import annotations

import datetime
import json
import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session, sessionmaker

from src.models import Incident, PlaybookExecution

logger = logging.getLogger(__name__)


class ContainmentSimulator:
    """
    Simulates common containment actions.
    Each method creates a PlaybookExecution audit record and returns a result dict.
    """

    def __init__(self, session_factory: sessionmaker[Session]):
        self.Session = session_factory

    # ------------------------------------------------------------------
    # Public containment methods
    # ------------------------------------------------------------------

    def isolate_host(self, incident_id: str, hostname: str) -> Dict[str, Any]:
        """Simulate network isolation of a host."""
        result = {
            "action": "isolate_host",
            "target": hostname,
            "status": "success",
            "network_segment": "SEG-PROD-01",
            "isolated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "estimated_restore_time": "2 hours",
        }
        self._log_action(incident_id, "isolate_host", hostname, result)
        return result

    def disable_user(self, incident_id: str, username: str) -> Dict[str, Any]:
        """Simulate disabling a user account."""
        result = {
            "action": "disable_user",
            "target": username,
            "status": "success",
            "disabled_at": datetime.datetime.utcnow().isoformat() + "Z",
            "ticket_required": "TICKET-1001",
        }
        self._log_action(incident_id, "disable_user", username, result)
        return result

    def block_ip(self, incident_id: str, ip_address: str) -> Dict[str, Any]:
        """Simulate adding a firewall rule to block an IP."""
        result = {
            "action": "block_ip",
            "target": ip_address,
            "status": "success",
            "firewall_rule_id": f"FW-RULE-{hash(ip_address) % 10000:04d}",
            "blocked_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        self._log_action(incident_id, "block_ip", ip_address, result)
        return result

    def kill_process(self, incident_id: str, pid: int, host: str) -> Dict[str, Any]:
        """Simulate killing a process on a host."""
        result = {
            "action": "kill_process",
            "target": f"{host}:{pid}",
            "status": "success",
            "process_terminated": True,
            "terminated_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        self._log_action(incident_id, "kill_process", f"{host}:{pid}", result)
        return result

    def snapshot_vm(self, incident_id: str, hostname: str) -> Dict[str, Any]:
        """Simulate taking a snapshot of a VM for forensic analysis."""
        snapshot_id = f"SNAP-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        result = {
            "action": "snapshot_vm",
            "target": hostname,
            "status": "success",
            "snapshot_id": snapshot_id,
            "snapshot_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        self._log_action(incident_id, "snapshot_vm", hostname, result)
        return result

    def quarantine_file(self, incident_id: str, filepath: str, host: str) -> Dict[str, Any]:
        """Simulate moving a file to quarantine on a host."""
        result = {
            "action": "quarantine_file",
            "target": f"{host}:{filepath}",
            "status": "success",
            "quarantine_location": f"/var/quarantine/{hash(filepath)}",
            "quarantined_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        self._log_action(incident_id, "quarantine_file", f"{host}:{filepath}", result)
        return result

    # ------------------------------------------------------------------
    # Internal audit logger
    # ------------------------------------------------------------------

    def _log_action(
        self,
        incident_id: str,
        action: str,
        target: str,
        result: Dict[str, Any],
    ) -> None:
        """Create a PlaybookExecution record to audit the containment action."""
        session = self.Session()
        try:
            # Find the incident to get its internal id
            incident = session.query(Incident).filter_by(incident_id=incident_id).first()
            if not incident:
                logger.error(f"Incident {incident_id} not found; cannot log containment action.")
                return

            execution = PlaybookExecution(
                incident_id=incident.id,
                step_name=f"Containment: {action}",
                step_action=action,
                status="completed",
                started_at=datetime.datetime.utcnow(),
                completed_at=datetime.datetime.utcnow(),
                result=json.dumps(result),
                mock=True,
            )
            session.add(execution)
            session.commit()
            logger.info(f"Containment action '{action}' logged for incident {incident_id}")
        except Exception as e:
            session.rollback()
            logger.exception(f"Failed to log containment action: {e}")
            raise
        finally:
            session.close()