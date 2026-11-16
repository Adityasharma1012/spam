"""Tests for Agent 1 (scikit-learn TF-IDF demo model)."""
import pytest
from agents.ml_agent import MLAgent
from core.models import (
    CalibrationStatus,
    DebateMessage,
    EvidenceCategory,
    EvidenceItem,
    Verdict,
)


@pytest.mark.asyncio
async def test_ml_agent_round1_phishing_detection():
    agent = MLAgent()
    avail, reason = agent.check_availability()
    assert avail.value == "AVAILABLE"

    parsed_meta = {
        "subject": "URGENT: Verify your account immediately",
        "body_plain": "Your corporate account access will be terminated within 2 hours. Click here to verify credentials.",
        "from": "alert@fake.com",
    }
    evidence = [
        EvidenceItem(
            evidence_id="EV-001",
            category=EvidenceCategory.URL_ANALYSIS,
            description="Suspicious URL",
            source="Body",
            provenance="Parser",
            severity="CRITICAL",
        )
    ]

    report = await agent.analyze_round1(parsed_meta, evidence)
    assert report.agent_id == "ml"
    assert report.round == 1
    assert report.calibration_status == CalibrationStatus.DEMO_ONLY
    assert report.verdict == Verdict.PHISHING
    assert report.confidence > 0.5
    assert len(report.findings) > 0
    assert "EV-001" in report.findings[0].evidence_ids


@pytest.mark.asyncio
async def test_ml_agent_round2_revision():
    agent = MLAgent()
    parsed_meta = {
        "subject": "Notice regarding your inquiry",
        "body_plain": "We received your message and will follow up.",
    }
    evidence = [
        EvidenceItem(
            evidence_id="EV-001",
            category=EvidenceCategory.URL_ANALYSIS,
            description="Brand spoof url",
            source="Body",
            provenance="Parser",
            severity="CRITICAL",
        )
    ]
    r1_report = await agent.analyze_round1(parsed_meta, evidence)

    # In round 2, peer flags critical brand spoofing
    debate_msg = DebateMessage(
        from_agent="gemini",
        round=2,
        summary="Detected severe brand spoofing and credential theft",
        cited_evidence_ids=["EV-001"],
    )

    r2_report = await agent.analyze_round2(
        parsed_metadata=parsed_meta,
        evidence=evidence,
        round1_reports=[r1_report],
        debate_messages=[debate_msg],
    )

    assert r2_report.round == 2
    assert r2_report.agent_id == "ml"
    assert r2_report.calibration_status == CalibrationStatus.DEMO_ONLY
