"""Tests for append-only investigation state and hash integrity."""
import pytest
from core.models import (
    AgentReport,
    AvailabilityStatus,
    CalibrationStatus,
    DebateMessage,
    EvidenceCategory,
    EvidenceItem,
    Finding,
    Verdict,
)
from core.state import InvestigationState


def test_investigation_state_integrity():
    state = InvestigationState(
        investigation_id="INV-001",
        email_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    ev1 = EvidenceItem(
        evidence_id="EV-001",
        category=EvidenceCategory.HEADER_MISMATCH,
        description="From/Reply-To mismatch",
        source="Headers",
        provenance="Parser test",
        severity="HIGH",
    )
    state.add_evidence([ev1])
    assert state.verify_integrity()

    # Append valid report
    report = AgentReport(
        agent_id="ml",
        round=1,
        verdict=Verdict.PHISHING,
        confidence=0.85,
        calibration_status=CalibrationStatus.DEMO_ONLY,
        findings=[Finding(text="Suspicious headers", evidence_ids=["EV-001"])],
        availability=AvailabilityStatus.AVAILABLE,
    )
    state.append_report(report)
    assert state.verify_integrity()
    assert len(state.reports) == 1

    # Appending a report citing nonexistent evidence ID must be rejected!
    bad_report = AgentReport(
        agent_id="gemini",
        round=1,
        verdict=Verdict.PHISHING,
        confidence=0.9,
        calibration_status=CalibrationStatus.VALIDATED,
        findings=[Finding(text="Hallucinated claim", evidence_ids=["EV-999"])],
        availability=AvailabilityStatus.AVAILABLE,
    )
    with pytest.raises(ValueError, match="nonexistent evidence ID 'EV-999'"):
        state.append_report(bad_report)

    # Append valid debate message
    msg = DebateMessage(
        from_agent="ml",
        round=2,
        summary="Concur with suspicious sender indicator",
        cited_evidence_ids=["EV-001"],
    )
    state.append_debate_message(msg)
    assert state.verify_integrity()
    assert len(state.debate_messages) == 1
