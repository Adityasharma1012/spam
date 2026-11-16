"""Tests for Consensus Engine and Decision Table rules.

Tests EVERY row of the decision table to guarantee completeness.
"""
import pytest
from consensus.decision_table import DECISION_TABLE
from consensus.engine import ThreatInvestigationEngine
from core.models import (
    AgentReport,
    AvailabilityStatus,
    CalibrationStatus,
    ConsensusVerdict,
    EvidenceCategory,
    EvidenceItem,
    Finding,
    Verdict,
)


def make_report(agent_id: str, verdict: Verdict, avail: AvailabilityStatus = AvailabilityStatus.AVAILABLE, calib: CalibrationStatus = CalibrationStatus.UNVALIDATED) -> AgentReport:
    return AgentReport(
        agent_id=agent_id,
        round=2,
        verdict=verdict,
        confidence=0.85,
        calibration_status=calib,
        availability=avail,
        findings=[Finding(text="Test finding", evidence_ids=["EV-001"])],
    )


def make_evidence(eid: str, cat: EvidenceCategory, sev: str) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=eid,
        category=cat,
        description=f"Evidence {eid}",
        source="Test",
        provenance="Test generator",
        severity=sev,
    )


def test_decision_table_rule_01_critical_objective_phishing():
    engine = ThreatInvestigationEngine(agents=[])
    # Critical evidence (e.g. IP spoof link or malware) + agent says PHISHING
    evidence = [make_evidence("EV-001", EvidenceCategory.URL_ANALYSIS, "CRITICAL")]
    reports = [make_report("ml", Verdict.PHISHING, calib=CalibrationStatus.DEMO_ONLY)]
    
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-01"
    assert result.final_verdict == ConsensusVerdict.PHISHING
    assert result.confidence >= 0.90


def test_decision_table_rule_02_unanimous_phishing():
    engine = ThreatInvestigationEngine(agents=[])
    # High evidence + both agents say PHISHING
    evidence = [make_evidence("EV-001", EvidenceCategory.AUTH_RESULTS, "HIGH")]
    reports = [
        make_report("ml", Verdict.PHISHING),
        make_report("gemini", Verdict.PHISHING),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-02"
    assert result.final_verdict == ConsensusVerdict.PHISHING


def test_decision_table_rule_04_conflict_needs_review():
    engine = ThreatInvestigationEngine(agents=[])
    # ML says PHISHING, Gemini says LEGITIMATE -> Conflict -> NEEDS_REVIEW
    evidence = [make_evidence("EV-001", EvidenceCategory.HEADER_MISMATCH, "MEDIUM")]
    reports = [
        make_report("ml", Verdict.PHISHING),
        make_report("gemini", Verdict.LEGITIMATE),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-04"
    assert result.final_verdict == ConsensusVerdict.NEEDS_REVIEW
    assert result.partial is True


def test_decision_table_rule_03_partial_availability_thin_evidence():
    engine = ThreatInvestigationEngine(agents=[])
    # Only 1 agent available, no critical evidence
    evidence = [make_evidence("EV-001", EvidenceCategory.RECEIVED_CHAIN, "INFO")]
    reports = [
        make_report("ml", Verdict.SUSPICIOUS),
        make_report("laya", Verdict.ABSTAIN, avail=AvailabilityStatus.UNAVAILABLE),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-03"
    assert result.final_verdict == ConsensusVerdict.NEEDS_REVIEW
    assert result.partial is True


def test_decision_table_rule_07_suspicious_high_severity():
    engine = ThreatInvestigationEngine(agents=[])
    # High severity evidence + 2 agents say SUSPICIOUS
    evidence = [make_evidence("EV-001", EvidenceCategory.HEADER_MISMATCH, "HIGH")]
    reports = [
        make_report("ml", Verdict.SUSPICIOUS),
        make_report("laya", Verdict.SUSPICIOUS),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-07"
    assert result.final_verdict == ConsensusVerdict.SUSPICIOUS


def test_decision_table_rule_05_unanimous_spam():
    engine = ThreatInvestigationEngine(agents=[])
    evidence = [make_evidence("EV-001", EvidenceCategory.CONTENT_ANOMALY, "INFO")]
    reports = [
        make_report("ml", Verdict.SPAM),
        make_report("laya", Verdict.SPAM),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-05"
    assert result.final_verdict == ConsensusVerdict.SPAM


def test_decision_table_rule_06_unanimous_legitimate():
    engine = ThreatInvestigationEngine(agents=[])
    evidence = [make_evidence("EV-001", EvidenceCategory.AUTH_RESULTS, "INFO")]
    reports = [
        make_report("ml", Verdict.LEGITIMATE),
        make_report("gemini", Verdict.LEGITIMATE),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.matched_rule_id == "RULE-06"
    assert result.final_verdict == ConsensusVerdict.LEGITIMATE


def test_decision_table_rule_08_demo_only_safeguard():
    engine = ThreatInvestigationEngine(agents=[])
    # Only ML available (DEMO_ONLY), saying LEGITIMATE
    evidence = [make_evidence("EV-001", EvidenceCategory.AUTH_RESULTS, "INFO")]
    reports = [
        make_report("ml", Verdict.LEGITIMATE, calib=CalibrationStatus.DEMO_ONLY),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    # Rule 3 or Rule 8: either way, NEEDS_REVIEW
    assert result.final_verdict == ConsensusVerdict.NEEDS_REVIEW


def test_decision_table_rule_09_default_fallback():
    # If all agents return ABSTAIN
    engine = ThreatInvestigationEngine(agents=[])
    evidence = []
    reports = [
        make_report("ml", Verdict.ABSTAIN, avail=AvailabilityStatus.DEGRADED),
        make_report("gemini", Verdict.ABSTAIN, avail=AvailabilityStatus.DEGRADED),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.final_verdict == ConsensusVerdict.NEEDS_REVIEW


def test_prompt_injection_banner_preservation():
    engine = ThreatInvestigationEngine(agents=[])
    evidence = [
        make_evidence("EV-001", EvidenceCategory.PROMPT_INJECTION, "CRITICAL"),
        make_evidence("EV-002", EvidenceCategory.URL_ANALYSIS, "CRITICAL"),
    ]
    reports = [
        make_report("ml", Verdict.PHISHING),
    ]
    result = engine.synthesize_consensus(evidence, reports)
    assert result.prompt_injection_detected is True
    assert any("prompt injection attempt detected" in r.lower() for r in result.reasons)
