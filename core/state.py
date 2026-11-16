"""Append-only Investigation State with cryptographic integrity verification.

All additions are recorded as immutable history. Any attempt to cite
nonexistent evidence IDs or mutate historical state is rejected.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from core.models import (
    AgentReport,
    ConsensusResult,
    DebateMessage,
    EvidenceItem,
    PARSER_VERSION,
)


def compute_state_hash(
    email_sha256: str,
    receipt_time_utc: str,
    evidence: List[EvidenceItem],
    reports: List[AgentReport],
    debate_messages: List[DebateMessage],
    final_result: Optional[ConsensusResult],
) -> str:
    """Compute deterministic SHA-256 checksum over state components."""
    data = {
        "email_sha256": email_sha256,
        "receipt_time_utc": receipt_time_utc,
        "evidence": [e.model_dump() for e in evidence],
        "reports": [r.model_dump() for r in reports],
        "debate_messages": [d.model_dump() for d in debate_messages],
        "final_result": final_result.model_dump() if final_result else None,
    }
    dumped = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(dumped).hexdigest()


class InvestigationState(BaseModel):
    """Cryptographically verifiable, append-only investigation log."""
    investigation_id: str
    email_sha256: str
    receipt_time_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = "email_upload"
    parser_version: str = PARSER_VERSION
    evidence: List[EvidenceItem] = Field(default_factory=list)
    reports: List[AgentReport] = Field(default_factory=list)
    debate_messages: List[DebateMessage] = Field(default_factory=list)
    final_result: Optional[ConsensusResult] = None
    state_hash: Optional[str] = None

    def get_evidence_ids(self) -> Set[str]:
        return {e.evidence_id for e in self.evidence}

    def add_evidence(self, items: List[EvidenceItem]) -> None:
        """Add newly discovered evidence items."""
        existing = self.get_evidence_ids()
        for it in items:
            if it.evidence_id in existing:
                raise ValueError(f"Duplicate evidence ID: {it.evidence_id}")
            self.evidence.append(it)
            existing.add(it.evidence_id)
        self.update_hash()

    def append_report(self, report: AgentReport) -> None:
        """Append an agent report.
        
        Strictly rejects reports that cite nonexistent evidence IDs.
        """
        valid_ids = self.get_evidence_ids()
        for f in report.findings:
            for eid in f.evidence_ids:
                if eid not in valid_ids:
                    raise ValueError(
                        f"Report from agent '{report.agent_id}' rejected: "
                        f"cites nonexistent evidence ID '{eid}'. Known: {sorted(list(valid_ids))}"
                    )
        self.reports.append(report)
        self.update_hash()

    def append_debate_message(self, msg: DebateMessage) -> None:
        """Append a structured sanitized debate message."""
        valid_ids = self.get_evidence_ids()
        for eid in msg.cited_evidence_ids:
            if eid not in valid_ids:
                raise ValueError(
                    f"Debate message from '{msg.from_agent}' references invalid evidence ID '{eid}'"
                )
        self.debate_messages.append(msg)
        self.update_hash()

    def set_consensus(self, consensus: ConsensusResult) -> None:
        """Set the final consensus outcome."""
        self.final_result = consensus
        self.update_hash()

    def update_hash(self) -> str:
        """Compute and set the current state hash."""
        h = compute_state_hash(
            self.email_sha256,
            self.receipt_time_utc,
            self.evidence,
            self.reports,
            self.debate_messages,
            self.final_result,
        )
        self.state_hash = h
        return h

    def verify_integrity(self) -> bool:
        """Verify that current state matches the stored state_hash."""
        if not self.state_hash:
            return False
        expected = compute_state_hash(
            self.email_sha256,
            self.receipt_time_utc,
            self.evidence,
            self.reports,
            self.debate_messages,
            self.final_result,
        )
        return self.state_hash == expected
