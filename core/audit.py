"""Audit log and investigation lifecycle management.

Supports append-only recording, cryptographic verification,
structured JSON export, and user-initiated deletion with audit trail.
"""
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from core.state import InvestigationState

logger = logging.getLogger("email_threat_platform.audit")


class AuditEntry:
    def __init__(
        self,
        action: str,
        investigation_id: str,
        details: Dict[str, Any],
        state_hash: Optional[str] = None,
    ):
        self.action = action
        self.investigation_id = investigation_id
        self.details = details
        self.state_hash = state_hash
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "investigation_id": self.investigation_id,
            "details": self.details,
            "state_hash": self.state_hash,
            "timestamp": self.timestamp,
        }


class InvestigationAuditStore:
    """Manages active investigations, historical audit log, exports, and deletions."""

    def __init__(self):
        self._investigations: Dict[str, InvestigationState] = {}
        self._audit_log: List[AuditEntry] = []

    def store(self, state: InvestigationState) -> None:
        """Store or update an investigation state and record audit log entry."""
        if not state.verify_integrity():
            raise ValueError(f"Cannot store investigation {state.investigation_id}: State integrity verification failed.")

        is_new = state.investigation_id not in self._investigations
        self._investigations[state.investigation_id] = state

        action = "INVESTIGATION_CREATED" if is_new else "INVESTIGATION_UPDATED"
        entry = AuditEntry(
            action=action,
            investigation_id=state.investigation_id,
            details={
                "email_sha256": state.email_sha256,
                "evidence_count": len(state.evidence),
                "reports_count": len(state.reports),
                "verdict": state.final_result.final_verdict.value if state.final_result else None,
            },
            state_hash=state.state_hash,
        )
        self._audit_log.append(entry)
        logger.info(f"Audit log: {action} id={state.investigation_id} hash={state.state_hash[:12]}...")

    def get(self, investigation_id: str) -> Optional[InvestigationState]:
        """Retrieve an investigation, verifying its integrity on access."""
        state = self._investigations.get(investigation_id)
        if state:
            if not state.verify_integrity():
                raise ValueError(f"Investigation {investigation_id} integrity corrupted: Hash mismatch.")
            entry = AuditEntry(
                action="INVESTIGATION_ACCESSED",
                investigation_id=investigation_id,
                details={"verified": True},
                state_hash=state.state_hash,
            )
            self._audit_log.append(entry)
        return state

    def list_all(self) -> List[Dict[str, Any]]:
        """List summary of active investigations."""
        summaries = []
        for inv_id, state in self._investigations.items():
            summaries.append({
                "investigation_id": inv_id,
                "email_sha256": state.email_sha256,
                "receipt_time_utc": state.receipt_time_utc,
                "source": state.source,
                "final_verdict": state.final_result.final_verdict.value if state.final_result else None,
                "confidence": state.final_result.confidence if state.final_result else None,
                "evidence_count": len(state.evidence),
                "state_hash": state.state_hash,
            })
        return sorted(summaries, key=lambda x: x["receipt_time_utc"], reverse=True)

    def export_json(self, investigation_id: str) -> str:
        """Export full investigation state as formatted JSON string."""
        state = self.get(investigation_id)
        if not state:
            raise KeyError(f"Investigation {investigation_id} not found")

        export_data = {
            "export_metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "format_version": "1.0.0",
                "state_hash_verified": state.verify_integrity(),
            },
            "investigation": state.model_dump(),
        }

        self._audit_log.append(AuditEntry(
            action="INVESTIGATION_EXPORTED",
            investigation_id=investigation_id,
            details={"format": "json"},
            state_hash=state.state_hash,
        ))

        return json.dumps(export_data, indent=2, default=str)

    def delete(self, investigation_id: str, reason: str = "User initiated delete") -> bool:
        """User-initiated deletion of an investigation state.
        
        Removes active payload while preserving tombstone audit entry for chain of custody.
        """
        state = self._investigations.get(investigation_id)
        if not state:
            return False

        saved_hash = state.state_hash
        del self._investigations[investigation_id]

        self._audit_log.append(AuditEntry(
            action="INVESTIGATION_DELETED",
            investigation_id=investigation_id,
            details={"reason": reason},
            state_hash=saved_hash,
        ))
        logger.info(f"Audit log: INVESTIGATION_DELETED id={investigation_id} reason='{reason}'")
        return True

    def get_audit_trail(self, investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve audit log entries, optionally filtered by investigation ID."""
        entries = self._audit_log
        if investigation_id:
            entries = [e for e in entries if e.investigation_id == investigation_id]
        return [e.to_dict() for e in entries]


# Global default audit store instance
audit_store = InvestigationAuditStore()
