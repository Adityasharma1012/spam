"""End-to-end integration test for full ThreatInvestigationEngine 2-round pipeline."""
import pytest
from consensus.engine import ThreatInvestigationEngine
from core.models import ConsensusVerdict, Verdict


SAMPLE_RAW_EMAIL = """From: Fake IT Desk <admin@fake-update.com>
Reply-To: attacker@harvester-drop.net
To: employee@corp.internal
Subject: Mandatory System Security Upgrade
Date: Mon, 16 Nov 2026 01:00:00 +0000
Message-ID: <sec-1122@fake-update.com>
Authentication-Results: mx.corp.internal; spf=fail; dkim=fail
Content-Type: text/plain; charset="utf-8"

Immediate action required:
Your workplace account is scheduled for deactivation due to security compliance failures.
Go to http://198.51.100.99/auth/login to confirm your identity and prevent shutdown.
"""


@pytest.mark.asyncio
async def test_full_investigation_pipeline_runs_and_verifies_integrity():
    engine = ThreatInvestigationEngine()
    state = await engine.run_investigation(SAMPLE_RAW_EMAIL)

    # 1. State integrity must be cryptographically valid
    assert state.verify_integrity() is True
    assert len(state.investigation_id) > 0
    assert len(state.email_sha256) == 64

    # 2. Evidence must be extracted
    assert len(state.evidence) >= 3
    ev_ids = state.get_evidence_ids()
    assert "EV-001" in ev_ids

    # 3. Reports must have been generated for Round 1 and Round 2
    r1_reports = [r for r in state.reports if r.round == 1]
    r2_reports = [r for r in state.reports if r.round == 2]
    assert len(r1_reports) == 3  # ML, Gemini, Laya
    assert len(r2_reports) == 3

    # 4. Final consensus result must exist and have reasons
    assert state.final_result is not None
    assert state.final_result.final_verdict in {ConsensusVerdict.PHISHING, ConsensusVerdict.SUSPICIOUS, ConsensusVerdict.NEEDS_REVIEW}
    assert len(state.final_result.reasons) > 0
    assert state.final_result.matched_rule_id.startswith("RULE-")

    # 5. Debate messages must exist for available agents
    assert len(state.debate_messages) >= 1
    for msg in state.debate_messages:
        assert msg.round == 2
        # Citing valid evidence IDs
        assert all(eid in ev_ids for eid in msg.cited_evidence_ids)
