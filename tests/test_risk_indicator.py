"""Unit tests for deterministic threat risk indicator in ConsensusResult."""
import pytest
from consensus.engine import compute_deterministic_risk_indicator
from core.models import ConsensusVerdict, EvidenceCategory, EvidenceItem, PARSER_VERSION


def create_test_evidence(category: EvidenceCategory, severity: str) -> EvidenceItem:
    return EvidenceItem(
        evidence_id="EV-001",
        category=category,
        description="Test evidence",
        source="test",
        parser_version=PARSER_VERSION,
        provenance="test provenance",
        raw_data={},
        defanged_data={},
        severity=severity,
    )


def test_phishing_full_risk_indicator():
    # Base 85 + critical (5) + auth fail (5) + header mismatch (3) -> capped at 98.0
    ev = [
        create_test_evidence(EvidenceCategory.URL_ANALYSIS, "CRITICAL"),
        create_test_evidence(EvidenceCategory.AUTH_RESULTS, "CRITICAL"),
        create_test_evidence(EvidenceCategory.HEADER_MISMATCH, "HIGH"),
    ]
    score = compute_deterministic_risk_indicator(ConsensusVerdict.PHISHING, 0.95, False, ev)
    assert score == 98.0


def test_phishing_partial_capped_at_60():
    # When partial is True, phishing score must be capped at 60.0
    ev = [create_test_evidence(EvidenceCategory.URL_ANALYSIS, "CRITICAL")]
    score = compute_deterministic_risk_indicator(ConsensusVerdict.PHISHING, 0.95, True, ev)
    assert score == 60.0


def test_needs_review_strictly_bounded_never_high():
    # NEEDS_REVIEW must never report high confidence/risk
    ev = [create_test_evidence(EvidenceCategory.URL_ANALYSIS, "HIGH")]
    score = compute_deterministic_risk_indicator(ConsensusVerdict.NEEDS_REVIEW, 0.50, False, ev)
    assert score == 40.0


def test_legitimate_clean_vs_partial():
    # Fully clean -> 5.0
    score_clean = compute_deterministic_risk_indicator(ConsensusVerdict.LEGITIMATE, 0.85, False, [])
    assert score_clean == 5.0

    # Partial analysis on LEGITIMATE -> 30.0 (never plain green safe)
    score_partial = compute_deterministic_risk_indicator(ConsensusVerdict.LEGITIMATE, 0.85, True, [])
    assert score_partial == 30.0


def test_spam_risk_indicator():
    ev = [create_test_evidence(EvidenceCategory.AUTH_RESULTS, "HIGH")]
    score = compute_deterministic_risk_indicator(ConsensusVerdict.SPAM, 0.70, False, ev)
    assert score == 70.0  # 65 + 5
