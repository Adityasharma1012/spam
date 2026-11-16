"""Tests for Gemini and Laya adapters (availability, redaction, offline handling)."""
import pytest
from agents.gemini_adapter import GeminiAdapter, redact_email_content
from agents.laya_agent import LayaAgent, is_laya_model_cached
from core.models import AvailabilityStatus, CalibrationStatus, Verdict


def test_gemini_disabled_by_default():
    # When ENABLE_GEMINI is false or not set
    adapter = GeminiAdapter(enable_gemini=False)
    avail, reason = adapter.check_availability()
    assert avail == AvailabilityStatus.UNAVAILABLE
    assert "disabled" in reason.lower()


def test_gemini_redaction():
    text = "Contact victim test.user@example.com from host 198.51.100.22"
    redacted = redact_email_content(text)
    assert "test.user@example.com" not in redacted
    assert "198.51.100.22" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_IP]" in redacted


@pytest.mark.asyncio
async def test_gemini_unavailable_report():
    adapter = GeminiAdapter(enable_gemini=False)
    report = await adapter.analyze_round1(
        parsed_metadata={"subject": "test", "body_plain": "test"},
        evidence=[],
    )
    assert report.agent_id == "gemini"
    assert report.verdict == Verdict.ABSTAIN
    assert report.confidence == 0.0
    assert report.availability == AvailabilityStatus.UNAVAILABLE


def test_laya_availability_and_unvalidated_calibration():
    agent = LayaAgent(auto_load=True)
    avail, reason = agent.check_availability()
    if is_laya_model_cached():
        assert avail == AvailabilityStatus.AVAILABLE
        assert reason is None
    else:
        assert avail == AvailabilityStatus.UNAVAILABLE
    assert agent.device in {"cuda", "cpu"}


@pytest.mark.asyncio
async def test_laya_real_inference_round1():
    agent = LayaAgent(auto_load=True)
    avail, _ = agent.check_availability()
    if avail == AvailabilityStatus.AVAILABLE:
        report = await agent.analyze_round1(
            parsed_metadata={
                "subject": "Important Account Update",
                "body_plain": "Please confirm your password to prevent account closure.",
                "from": "security@alert.com",
            },
            evidence=[],
        )
        assert report.agent_id == "laya"
        assert report.calibration_status == CalibrationStatus.UNVALIDATED
        assert report.verdict in {Verdict.PHISHING, Verdict.SUSPICIOUS, Verdict.SPAM, Verdict.LEGITIMATE}
        assert report.confidence >= 0.0
        assert report.raw_output is not None


def test_laya_unavailable_when_config_missing():
    agent = LayaAgent(config_path="/nonexistent/path/questions.json", auto_load=False)
    avail, reason = agent.check_availability()
    assert avail == AvailabilityStatus.UNAVAILABLE
