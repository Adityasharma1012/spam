"""Core module for Email Threat Detection Platform."""
from core.models import (
    AgentReport,
    AvailabilityStatus,
    CalibrationStatus,
    ConsensusResult,
    ConsensusVerdict,
    DebateMessage,
    EvidenceCategory,
    EvidenceItem,
    Finding,
    Verdict,
    PROTOCOL_VERSION,
    PARSER_VERSION,
)
from core.parser import EmailParser
from core.state import InvestigationState

__all__ = [
    "AgentReport",
    "AvailabilityStatus",
    "CalibrationStatus",
    "ConsensusResult",
    "ConsensusVerdict",
    "DebateMessage",
    "EvidenceCategory",
    "EvidenceItem",
    "Finding",
    "Verdict",
    "PROTOCOL_VERSION",
    "PARSER_VERSION",
    "EmailParser",
    "InvestigationState",
]
