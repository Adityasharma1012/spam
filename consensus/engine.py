"""Multi-agent Deliberation and Consensus Orchestration Engine.

Orchestrates:
1. Deterministic parsing & evidence collection
2. Round 1 independent agent evaluation
3. Structured, sanitized debate message construction
4. Round 2 revised evaluation
5. Decision table consensus synthesis
6. Append-only state verification
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional
import uuid

from agents.base import BaseAgent
from agents.gemini_adapter import GeminiAdapter
from agents.laya_agent import LayaAgent
from agents.ml_agent import MLAgent
from consensus.decision_table import DECISION_TABLE, has_prompt_injection
from core.models import (
    AgentReport,
    AvailabilityStatus,
    ConsensusResult,
    ConsensusVerdict,
    DebateMessage,
    EvidenceCategory,
    EvidenceItem,
    Verdict,
)
from core.parser import EmailParser
from core.state import InvestigationState

logger = logging.getLogger("email_threat_platform.consensus")


def compute_deterministic_risk_indicator(
    verdict: ConsensusVerdict,
    confidence: float,
    partial: bool,
    evidence: List[EvidenceItem],
) -> float:
    """Compute deterministic threat risk indicator on a 0-100 scale (NOT a probability).

    Documented Formula:
    - PHISHING: Base 85.0 + (5.0 if any CRITICAL evidence) + (5.0 if auth failure) + (3.0 if header mismatch).
      Capped at 98.0.
      If partial analysis: capped at 60.0.
    - SPAM: Base 65.0 + (5.0 if auth issue / multi-hop). Capped at 75.0.
      If partial analysis: capped at 50.0.
    - SUSPICIOUS: Base 55.0 + (5.0 if HIGH/CRITICAL severity). Capped at 70.0.
      If partial analysis: capped at 45.0.
    - NEEDS_REVIEW: Always strictly bounded to 40.0 (reflects human triage required; never high confidence).
    - LEGITIMATE: Base 5.0. If partial analysis (unvalidated or unavailable agents): 30.0 (never plain safe).
    """
    has_critical = any(e.severity == "CRITICAL" for e in evidence)
    has_auth_fail = any(
        e.category == EvidenceCategory.AUTH_RESULTS and e.severity in {"HIGH", "CRITICAL"}
        for e in evidence
    )
    has_header_mismatch = any(
        e.category == EvidenceCategory.HEADER_MISMATCH and e.severity in {"HIGH", "CRITICAL"}
        for e in evidence
    )

    if verdict == ConsensusVerdict.PHISHING:
        score = 85.0
        if has_critical:
            score += 5.0
        if has_auth_fail:
            score += 5.0
        if has_header_mismatch:
            score += 3.0
        score = min(score, 98.0)
        if partial:
            score = min(score, 60.0)
        return round(score, 1)

    elif verdict == ConsensusVerdict.SPAM:
        score = 65.0
        if has_auth_fail or has_header_mismatch:
            score += 5.0
        score = min(score, 75.0)
        if partial:
            score = min(score, 50.0)
        return round(score, 1)

    elif verdict == ConsensusVerdict.SUSPICIOUS:
        score = 55.0
        if has_critical or has_auth_fail:
            score += 5.0
        score = min(score, 70.0)
        if partial:
            score = min(score, 45.0)
        return round(score, 1)

    elif verdict == ConsensusVerdict.NEEDS_REVIEW:
        # Never high confidence on NEEDS_REVIEW or partial results
        return 40.0

    elif verdict == ConsensusVerdict.LEGITIMATE:
        # A LEGITIMATE result under partial analysis must never look plain green safe
        if partial:
            return 30.0
        return 5.0

    return 50.0


class ThreatInvestigationEngine:
    """Orchestrates 2-round multi-agent investigation and consensus."""

    def __init__(
        self,
        agents: Optional[List[BaseAgent]] = None,
        parser: Optional[EmailParser] = None,
    ):
        self.parser = parser or EmailParser()
        if agents is not None:
            self.agents = agents
        else:
            self.agents = [
                MLAgent(),
                GeminiAdapter(),
                LayaAgent(),
            ]

    def get_agent_by_id(self, agent_id: str) -> Optional[BaseAgent]:
        for a in self.agents:
            if a.agent_id == agent_id:
                return a
        return None

    async def run_investigation(
        self,
        raw_email: str | bytes,
        source: str = "email_upload",
    ) -> InvestigationState:
        """Run full 2-round threat investigation pipeline."""
        # 1. Deterministic Parsing
        parsed_meta, evidence_items = self.parser.parse(raw_email)
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"

        state = InvestigationState(
            investigation_id=inv_id,
            email_sha256=parsed_meta["email_sha256"],
            source=source,
            parser_version=self.parser.parser_version,
        )
        state.add_evidence(evidence_items)

        # 2. Round 1: Independent Agent Analysis
        round1_tasks = []
        for agent in self.agents:
            round1_tasks.append(agent.analyze_round1(parsed_meta, state.evidence))

        round1_reports: List[AgentReport] = await asyncio.gather(*round1_tasks)
        for r in round1_reports:
            state.append_report(r)

        # 3. Formulate Structured Sanitized Debate Messages for Round 2
        # Never sends raw untrusted email text
        debate_messages: List[DebateMessage] = []
        for r in round1_reports:
            if r.availability == AvailabilityStatus.AVAILABLE and r.verdict != Verdict.ABSTAIN:
                cited_ids = []
                for f in r.findings:
                    cited_ids.extend(f.evidence_ids)
                unique_cited = sorted(list(set(cited_ids)))

                summary_text = f"Evaluated verdict {r.verdict.value} (conf {r.confidence:.2f}). Claims: " + "; ".join(
                    f.text for f in r.findings[:2]
                )
                msg = DebateMessage(
                    from_agent=r.agent_id,
                    round=2,
                    summary=summary_text,
                    cited_evidence_ids=unique_cited,
                )
                debate_messages.append(msg)
                state.append_debate_message(msg)

        # 4. Round 2: Revised Deliberation
        round2_tasks = []
        for agent in self.agents:
            round2_tasks.append(
                agent.analyze_round2(
                    parsed_metadata=parsed_meta,
                    evidence=state.evidence,
                    round1_reports=round1_reports,
                    debate_messages=debate_messages,
                )
            )

        round2_reports: List[AgentReport] = await asyncio.gather(*round2_tasks)
        for r in round2_reports:
            state.append_report(r)

        # 5. Synthesize Consensus from Decision Table
        active_reports = round2_reports if round2_reports else round1_reports
        consensus = self.synthesize_consensus(state.evidence, active_reports)
        state.set_consensus(consensus)

        return state

    def synthesize_consensus(
        self,
        evidence: List[EvidenceItem],
        reports: List[AgentReport],
    ) -> ConsensusResult:
        """Evaluate reports and evidence against deterministic decision table."""
        prompt_inj = has_prompt_injection(evidence)

        matched_rule = None
        for rule in DECISION_TABLE:
            if rule.predicate(evidence, reports):
                matched_rule = rule
                break

        if not matched_rule:
            matched_rule = DECISION_TABLE[-1]

        reasons = list(matched_rule.reason_generator(evidence, reports))

        if prompt_inj:
            reasons.insert(
                0,
                "Adversarial prompt injection attempt detected and neutralized: "
                "untrusted email content cannot alter security verdicts."
            )

        # Map agent verdicts for reporting
        agent_verdicts = {}
        for r in reports:
            if r.availability == AvailabilityStatus.AVAILABLE:
                agent_verdicts[r.agent_id] = r.verdict
            else:
                agent_verdicts[r.agent_id] = None

        # Check if any agent was unavailable to mark partial
        is_partial = matched_rule.partial or any(
            r.availability != AvailabilityStatus.AVAILABLE for r in reports
        )

        # Calculate deterministic risk indicator
        risk_ind = compute_deterministic_risk_indicator(
            matched_rule.outcome,
            matched_rule.confidence,
            is_partial,
            evidence,
        )

        return ConsensusResult(
            final_verdict=matched_rule.outcome,
            confidence=matched_rule.confidence,
            reasons=reasons,
            partial=is_partial,
            matched_rule_id=matched_rule.rule_id,
            agent_verdicts=agent_verdicts,
            prompt_injection_detected=prompt_inj,
            risk_indicator=risk_ind,
        )
