"""Core Pydantic v2 data models for the Email Threat Detection Platform.

Implements the strict shared agent protocol, evidence schemas,
and append-only investigation state with cryptographic integrity.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


PROTOCOL_VERSION = "1.0.0"
PARSER_VERSION = "1.0.0"


class Verdict(str, Enum):
    PHISHING = "PHISHING"
    SPAM = "SPAM"
    SUSPICIOUS = "SUSPICIOUS"
    LEGITIMATE = "LEGITIMATE"
    ABSTAIN = "ABSTAIN"


class ConsensusVerdict(str, Enum):
    PHISHING = "PHISHING"
    SPAM = "SPAM"
    SUSPICIOUS = "SUSPICIOUS"
    LEGITIMATE = "LEGITIMATE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class CalibrationStatus(str, Enum):
    UNVALIDATED = "UNVALIDATED"
    DEMO_ONLY = "DEMO_ONLY"
    VALIDATED = "VALIDATED"


class AvailabilityStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class EvidenceCategory(str, Enum):
    HEADER_MISMATCH = "HEADER_MISMATCH"
    RECEIVED_CHAIN = "RECEIVED_CHAIN"
    AUTH_RESULTS = "AUTH_RESULTS"
    URL_ANALYSIS = "URL_ANALYSIS"
    ATTACHMENT_ANALYSIS = "ATTACHMENT_ANALYSIS"
    IP_REPUTATION = "IP_REPUTATION"
    CONTENT_ANOMALY = "CONTENT_ANOMALY"
    PROMPT_INJECTION = "PROMPT_INJECTION"


class EvidenceItem(BaseModel):
    """An individual piece of deterministic evidence extracted by the parser."""
    evidence_id: str = Field(..., description="Unique evidence ID e.g. EV-001")
    category: EvidenceCategory
    description: str
    source: str = Field(..., description="Field or header source, e.g. 'Authentication-Results'")
    parser_version: str = Field(default=PARSER_VERSION)
    provenance: str = Field(..., description="Extraction explanation, e.g. 'Parsed RFC 5322 header'")
    raw_data: Optional[Dict[str, Any]] = None
    defanged_data: Optional[Dict[str, Any]] = None
    severity: str = Field(default="INFO", description="INFO | LOW | MEDIUM | HIGH | CRITICAL")

    @field_validator("evidence_id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not v.startswith("EV-"):
            raise ValueError(f"Evidence ID must start with 'EV-', got '{v}'")
        return v


class Finding(BaseModel):
    """A claim made by an agent backed by explicit evidence IDs."""
    text: str = Field(..., min_length=1)
    evidence_ids: List[str] = Field(default_factory=list)

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, v: List[str]) -> List[str]:
        for eid in v:
            if not eid.startswith("EV-"):
                raise ValueError(f"Finding references invalid evidence ID format: '{eid}'")
        return v


class AgentReport(BaseModel):
    """Shared agent protocol report (Pydantic v2).
    
    Appended as new records; never overwritten.
    """
    agent_id: str = Field(..., description="ml | gemini | laya")
    round: int = Field(..., ge=1, le=2, description="1 for independent analysis, 2 for post-debate revision")
    protocol_version: str = Field(default=PROTOCOL_VERSION)
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    calibration_status: CalibrationStatus
    findings: List[Finding] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    availability: AvailabilityStatus = AvailabilityStatus.AVAILABLE
    availability_reason: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    model_identifiers: Dict[str, Any] = Field(
        default_factory=dict,
        description="Model name, checkpoint revision, weights SHA, etc."
    )
    raw_output: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Raw typed questions/probabilities for Laya, raw JSON for Gemini, etc."
    )
    revised_from_round1: Optional[bool] = Field(
        default=None,
        description="For Round 2: True if verdict or confidence changed, False otherwise"
    )

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        valid = {"ml", "gemini", "laya"}
        if v.lower() not in valid:
            raise ValueError(f"agent_id must be one of {valid}, got '{v}'")
        return v.lower()


class DebateMessage(BaseModel):
    """A structured summary shared with other agents for Round 2 deliberation.
    
    Never carries raw untrusted email text.
    """
    from_agent: str
    round: int = 2
    summary: str
    cited_evidence_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ConsensusResult(BaseModel):
    """The final synthesized platform verdict."""
    final_verdict: ConsensusVerdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    partial: bool = Field(default=False, description="True if one or more agents were unavailable or degraded")
    matched_rule_id: str = Field(..., description="Identifier of the decision table rule matched")
    agent_verdicts: Dict[str, Optional[Verdict]] = Field(default_factory=dict)
    prompt_injection_detected: bool = False
    risk_indicator: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Deterministic threat risk indicator on 0-100 scale (not a probability)",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
