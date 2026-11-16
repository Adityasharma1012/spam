"""Tests for shared agent protocol validation and integrity."""
import pytest
from pydantic import ValidationError
from core.models import (
    AgentReport,
    AvailabilityStatus,
    CalibrationStatus,
    Finding,
    Verdict,
)


def test_valid_agent_report():
    report = AgentReport(
        agent_id="ml",
        round=1,
        verdict=Verdict.PHISHING,
        confidence=0.88,
        calibration_status=CalibrationStatus.DEMO_ONLY,
        findings=[
            Finding(text="Detected high credential harvesting keyword frequency", evidence_ids=["EV-001"])
        ],
        limitations=["Trained on small synthetic demo corpus"],
        availability=AvailabilityStatus.AVAILABLE,
        model_identifiers={"model": "TFIDF_MultinomialNB", "version": "1.0"},
    )
    assert report.agent_id == "ml"
    assert report.verdict == Verdict.PHISHING
    assert report.confidence == 0.88
    assert report.findings[0].evidence_ids == ["EV-001"]


def test_reject_invalid_agent_id():
    with pytest.raises(ValidationError):
        AgentReport(
            agent_id="unknown_agent",
            round=1,
            verdict=Verdict.PHISHING,
            confidence=0.5,
            calibration_status=CalibrationStatus.UNVALIDATED,
        )


def test_reject_invalid_confidence():
    with pytest.raises(ValidationError):
        AgentReport(
            agent_id="ml",
            round=1,
            verdict=Verdict.PHISHING,
            confidence=1.5,  # must be <= 1.0
            calibration_status=CalibrationStatus.DEMO_ONLY,
        )


def test_reject_finding_invalid_evidence_id():
    with pytest.raises(ValidationError):
        Finding(text="Some claim", evidence_ids=["INVALID-ID-123"])
