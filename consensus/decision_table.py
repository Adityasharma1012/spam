"""Consensus Decision Table and rules documentation.

Implements the multi-agent consensus synthesis rules.
Rules weigh:
1. Deterministic evidence severity (provenance)
2. Agent availability (partial vs complete)
3. Model agreement vs conflict
4. Calibration status (DEMO_ONLY, UNVALIDATED)

Strict constraints:
- Confidences are NEVER averaged.
- Agreeing models are NOT treated as independent mathematical proof.
- Returns NEEDS_REVIEW when evidence is thin, critical agents are unavailable, or findings conflict.
- Outputs explicit reasons[] and partial: true where appropriate.
"""
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from core.models import (
    AgentReport,
    AvailabilityStatus,
    CalibrationStatus,
    ConsensusVerdict,
    EvidenceCategory,
    EvidenceItem,
    Verdict,
)


@dataclass
class DecisionRule:
    rule_id: str
    name: str
    description: str
    outcome: ConsensusVerdict
    confidence: float
    partial: bool
    predicate: Callable[[List[EvidenceItem], List[AgentReport]], bool]
    reason_generator: Callable[[List[EvidenceItem], List[AgentReport]], List[str]]


def has_prompt_injection(evidence: List[EvidenceItem]) -> bool:
    return any(e.category == EvidenceCategory.PROMPT_INJECTION for e in evidence)


def get_available_reports(reports: List[AgentReport]) -> List[AgentReport]:
    return [r for r in reports if r.availability == AvailabilityStatus.AVAILABLE]


def get_evidence_severity_counts(evidence: List[EvidenceItem]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for e in evidence:
        sev = e.severity.upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# --- Rule Predicates ---

def rule_1_critical_objective_phishing(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-01: Critical objective indicator (e.g., brand-spoofed link or executable attachment)
    plus at least one available agent indicating PHISHING or SUSPICIOUS."""
    sev = get_evidence_severity_counts(evidence)
    avail = get_available_reports(reports)
    has_crit_ev = (sev["CRITICAL"] > 0)
    has_agent_alert = any(r.verdict in {Verdict.PHISHING, Verdict.SUSPICIOUS} for r in avail)
    return has_crit_ev and has_agent_alert


def rule_2_unanimous_phishing(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-02: All available agents (at least 2) independently flag PHISHING, corroborated by High/Medium evidence."""
    avail = get_available_reports(reports)
    if len(avail) < 2:
        return False
    sev = get_evidence_severity_counts(evidence)
    all_phish = all(r.verdict == Verdict.PHISHING for r in avail)
    has_corrob = (sev["HIGH"] > 0 or sev["MEDIUM"] > 0 or sev["CRITICAL"] > 0)
    return all_phish and has_corrob


def rule_3_critical_agent_unavailable_thin_evidence(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-03: Critical agents unavailable (e.g. fewer than 2 agents available) and evidence is thin/ambiguous."""
    avail = get_available_reports(reports)
    sev = get_evidence_severity_counts(evidence)
    # Fewer than 2 agents available and no definitive critical evidence
    if len(avail) < 2 and sev["CRITICAL"] == 0:
        return True
    return False


def rule_4_adversarial_conflict(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-04: Strong disagreement between available agents (e.g. one PHISHING, another LEGITIMATE)."""
    avail = get_available_reports(reports)
    if len(avail) < 2:
        return False
    verdicts = {r.verdict for r in avail}
    has_phish = Verdict.PHISHING in verdicts
    has_legit = Verdict.LEGITIMATE in verdicts
    return has_phish and has_legit


def rule_5_unanimous_spam(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-05: Available agents agree on SPAM with no critical credential or malware threats."""
    avail = get_available_reports(reports)
    sev = get_evidence_severity_counts(evidence)
    if not avail or sev["CRITICAL"] > 0 or sev["HIGH"] > 0:
        return False
    return all(r.verdict == Verdict.SPAM for r in avail)


def rule_6_unanimous_legitimate_verified_auth(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-06: All available agents (at least 2) find LEGITIMATE, with valid authentication and no high/critical alerts."""
    avail = get_available_reports(reports)
    sev = get_evidence_severity_counts(evidence)
    if len(avail) < 2 or sev["CRITICAL"] > 0 or sev["HIGH"] > 0:
        return False
    return all(r.verdict == Verdict.LEGITIMATE for r in avail)


def rule_7_suspicious_anomalies(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-07: High severity anomalies present (e.g. SPF/DKIM fail or header mismatch), agents flag SUSPICIOUS."""
    sev = get_evidence_severity_counts(evidence)
    avail = get_available_reports(reports)
    if sev["HIGH"] > 0 and any(r.verdict in {Verdict.SUSPICIOUS, Verdict.PHISHING} for r in avail):
        return True
    return False


def rule_8_demo_only_calibration_insufficient(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-08: Only demo/unvalidated agents available (e.g. ML only) and verdict is non-threat. Cannot certify legitimate without human review."""
    avail = get_available_reports(reports)
    if len(avail) == 1 and avail[0].calibration_status == CalibrationStatus.DEMO_ONLY:
        return True
    return False


def rule_9_default_needs_review(evidence: List[EvidenceItem], reports: List[AgentReport]) -> bool:
    """RULE-09: Fallback rule when evidence is indeterminate or agent verdicts diverge."""
    return True


# --- Complete Documented Decision Table ---

DECISION_TABLE: List[DecisionRule] = [
    DecisionRule(
        rule_id="RULE-01",
        name="Critical Objective Evidence Corroboration",
        description="Deterministic critical indicators (malicious attachment/spoofed link) corroborated by agent findings",
        outcome=ConsensusVerdict.PHISHING,
        confidence=0.95,
        partial=False,
        predicate=rule_1_critical_objective_phishing,
        reason_generator=lambda ev, rep: [
            "Deterministic parser identified CRITICAL threat evidence (e.g. credential harvesting link or executable attachment).",
            "At least one available agent confirmed active threat patterns.",
            "Objective cryptographic and structural evidence supersedes pure probabilistic heuristics.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-02",
        name="Unanimous Agent Threat Agreement",
        description="Multiple available agents independently flag phishing with corroborating structural anomalies",
        outcome=ConsensusVerdict.PHISHING,
        confidence=0.90,
        partial=False,
        predicate=rule_2_unanimous_phishing,
        reason_generator=lambda ev, rep: [
            "All available agents independently identified phishing characteristics in Round 1 and Round 2.",
            "Corroborated by header mismatches or delivery anomalies.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-04",
        name="Direct Agent Conflict",
        description="Divergent agent findings (one PHISHING vs one LEGITIMATE) indicate ambiguity or evasion",
        outcome=ConsensusVerdict.NEEDS_REVIEW,
        confidence=0.50,
        partial=True,
        predicate=rule_4_adversarial_conflict,
        reason_generator=lambda ev, rep: [
            "Critical conflict detected: available agents returned contradictory verdicts (PHISHING vs LEGITIMATE).",
            "Potential evasion technique or borderline content requires tier-2 human security analyst review.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-03",
        name="Partial Availability with Thin Evidence",
        description="Fewer than 2 agents available with no definitive critical indicators",
        outcome=ConsensusVerdict.NEEDS_REVIEW,
        confidence=0.40,
        partial=True,
        predicate=rule_3_critical_agent_unavailable_thin_evidence,
        reason_generator=lambda ev, rep: [
            "Critical agent(s) unavailable or degraded; consensus quorum not achieved.",
            "Underlying deterministic evidence lacks definitive critical signals.",
            "Marked NEEDS_REVIEW to prevent uncalibrated false positives or negatives.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-07",
        name="High Severity Header/Auth Anomalies",
        description="SPF/DKIM/DMARC failure or From/Reply-To divergence flagged as suspicious",
        outcome=ConsensusVerdict.SUSPICIOUS,
        confidence=0.80,
        partial=False,
        predicate=rule_7_suspicious_anomalies,
        reason_generator=lambda ev, rep: [
            "High-severity authentication failure or sender address divergence detected.",
            "Agent analysis confirms suspicious delivery chain anomalies.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-05",
        name="Unanimous Bulk Promotional (Spam)",
        description="Available agents agree email is unsolicited commercial spam without exploit intent",
        outcome=ConsensusVerdict.SPAM,
        confidence=0.85,
        partial=False,
        predicate=rule_5_unanimous_spam,
        reason_generator=lambda ev, rep: [
            "No credential solicitation, malware, or brand spoofing observed.",
            "Unsolicited commercial marketing patterns matched across available evaluators.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-06",
        name="Unanimous Verified Legitimate",
        description="Multiple agents concur email is legitimate, with clean authentication and zero critical/high alerts",
        outcome=ConsensusVerdict.LEGITIMATE,
        confidence=0.88,
        partial=False,
        predicate=rule_6_unanimous_legitimate_verified_auth,
        reason_generator=lambda ev, rep: [
            "Multi-agent consensus confirms legitimate business correspondence.",
            "All email authentication checks (SPF/DKIM/DMARC) passed without header divergence.",
            "No suspicious URLs, attachments, or coercion heuristics identified.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-08",
        name="Single Unvalidated / Demo Agent Safeguard",
        description="Only demo-calibrated agent available; cannot declare benign status without human oversight",
        outcome=ConsensusVerdict.NEEDS_REVIEW,
        confidence=0.35,
        partial=True,
        predicate=rule_8_demo_only_calibration_insufficient,
        reason_generator=lambda ev, rep: [
            "Only the TF-IDF demonstration model (DEMO_ONLY) evaluated this email.",
            "Demo models are strictly unvalidated for production benign certification.",
            "Human analyst review required.",
        ],
    ),
    DecisionRule(
        rule_id="RULE-09",
        name="Default Inconclusive Safeguard",
        description="Default fallback when heuristics do not satisfy confident thresholds",
        outcome=ConsensusVerdict.NEEDS_REVIEW,
        confidence=0.50,
        partial=True,
        predicate=rule_9_default_needs_review,
        reason_generator=lambda ev, rep: [
            "Evidence and agent evaluation returned an inconclusive distribution.",
            "Escalated to human review.",
        ],
    ),
]
