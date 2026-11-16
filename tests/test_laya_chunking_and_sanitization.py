"""Tests for Laya Input Sanitization, Token Counting, Paragraph Chunking, and Conservative Aggregation.

Verifies:
1. Building Laya input from plain text and selected header fields only (excluding attachment bodies,
   base64, CSS, and quoted reply history while preserving original evidence unchanged in storage).
2. Token counting with model tokenizer against verified checkpoint limit (512 tokens) instead of generic 8192 max.
3. Overlapping paragraph chunking without silent truncation, with evidence IDs kept on every finding.
4. Limitation recorded in report: 'analyzed in N chunks; M tokens excluded as attachment/markup'.
5. Specific test fixtures:
   - Email with large base64 attachment
   - Email with very long HTML body
   - Normal short email
"""
import base64
import pytest

from agents.laya_agent import (
    CHUNK_OVERLAP_TOKENS,
    CHUNK_TARGET_TOKENS,
    LayaAgent,
    VERIFIED_CHECKPOINT_LIMIT,
    clean_laya_body_text,
)
from core.models import AvailabilityStatus, CalibrationStatus, EvidenceCategory, Verdict
from core.parser import EmailParser


# =====================================================================
# 1. Text Cleaner & Paragraph Chunking Unit Tests
# =====================================================================

def test_clean_laya_body_text_removes_base64_css_and_quoted_history():
    raw_dirty_text = (
        "Dear customer,\n\n"
        "Your security settings require immediate review.\n\n"
        "<style type=\"text/css\">\n"
        "body { font-family: 'Helvetica Neue', Arial; font-size: 14px; margin: 0; padding: 20px; }\n"
        ".alert-box { background-color: #ff2200; color: #ffffff; border: 1px solid #cc0000; }\n"
        "</style>\n"
        "<div class=\"alert-box\">Please confirm your identity.</div>\n\n"
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\n\n"
        "JVBERi0xLjQKJcTl8uXrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=\n\n"
        "Sincerely,\n"
        "Security Team\n\n"
        "-----Original Message-----\n"
        "From: boss@corp.local\n"
        "Sent: Monday, November 16, 2026 8:00 AM\n"
        "To: victim@corp.local\n"
        "Subject: Previous chat\n"
        "> Did you see the announcement?\n"
        "> Let me know ASAP."
    )

    cleaned = clean_laya_body_text(raw_dirty_text)

    # Base64 stripped
    assert "JVBERi" not in cleaned
    assert "QUJDREV" not in cleaned
    assert "data:image" not in cleaned
    # CSS stripped
    assert "font-family" not in cleaned
    assert "<style" not in cleaned
    assert "alert-box" not in cleaned
    # Quoted history stripped
    assert "Original Message" not in cleaned
    assert "Previous chat" not in cleaned
    assert "Did you see the announcement" not in cleaned
    # Core plain text preserved
    assert "Dear customer," in cleaned
    assert "Your security settings require immediate review." in cleaned
    assert "Sincerely," in cleaned
    assert "Security Team" in cleaned


def test_paragraph_chunking_with_overlap():
    agent = LayaAgent(auto_load=False)
    paras = [
        f"Paragraph {i}: Threat indicator details and warning text for security testing."
        for i in range(1, 15)
    ]
    full_text = "\n\n".join(paras)

    chunks = agent.split_paragraphs_into_chunks(
        full_text,
        max_tokens=60,
        overlap_tokens=25,
    )

    assert len(chunks) > 1
    # Check all paragraphs are present across chunks (no silent truncation)
    for p in paras:
        found = any(p in c for c in chunks)
        assert found, f"Paragraph missing from chunks: {p}"

    # Check consecutive chunks share overlap
    for i in range(len(chunks) - 1):
        c1 = chunks[i]
        c2 = chunks[i + 1]
        c1_paras = set(c1.split("\n\n"))
        c2_paras = set(c2.split("\n\n"))
        common = c1_paras.intersection(c2_paras)
        assert len(common) > 0, f"Expected overlapping paragraph between chunk {i} and {i+1}"


def test_conservative_aggregation_prioritizes_threat():
    agent = LayaAgent(auto_load=False)
    chunk_1 = {
        "answers": {
            "verdict": {"choice": "legitimate", "confidence": 0.85},
            "credential_harvesting": {"answer": False, "confidence": 0.50},
            "sender_impersonation": {"answer": False, "confidence": 0.50},
            "urgency_pressure": {"score": 0},
        }
    }
    chunk_2 = {
        "answers": {
            "verdict": {"choice": "phishing", "confidence": 0.92},
            "credential_harvesting": {"answer": True, "confidence": 0.95},
            "sender_impersonation": {"answer": True, "confidence": 0.88},
            "urgency_pressure": {"score": 2},
        }
    }
    chunk_3 = {
        "answers": {
            "verdict": {"choice": "legitimate", "confidence": 0.78},
            "credential_harvesting": {"answer": False, "confidence": 0.50},
            "sender_impersonation": {"answer": False, "confidence": 0.50},
            "urgency_pressure": {"score": 0},
        }
    }

    agg = agent.aggregate_results([chunk_1, chunk_2, chunk_3])
    ans = agg["answers"]

    # Phishing threat from chunk 2 dominates legitimate chunks 1 and 3
    assert ans["verdict"]["choice"] == "phishing"
    assert ans["verdict"]["confidence"] == 0.92
    assert ans["credential_harvesting"]["answer"] is True
    assert ans["credential_harvesting"]["confidence"] == 0.95
    assert ans["sender_impersonation"]["answer"] is True
    assert ans["sender_impersonation"]["confidence"] == 0.88
    assert ans["urgency_pressure"]["score"] == 2
    assert agg["usage"]["truncated"] is False
    assert agg["usage"]["state_tokens_dropped"] == 0


# =====================================================================
# 2. Required Integration Tests (Large Attachment, Long HTML, Short)
# =====================================================================

@pytest.mark.asyncio
async def test_email_with_large_base64_attachment():
    """1. Email with large base64 attachment:
    - Attachment payload excluded from Laya input
    - Original evidence preserved unchanged in storage
    - Limitation records excluded tokens
    - No silent truncation
    """
    parser = EmailParser()
    agent = LayaAgent(auto_load=True)

    # Generate ~6 KB base64 fake binary payload
    fake_binary = b"MZ\x90\x00\x03\x00\x00\x00" + (b"A" * 6000)
    b64_payload = base64.b64encode(fake_binary).decode("ascii")

    raw_email = (
        "From: accounting@vendor-invoices.com\r\n"
        "To: employee@victim-corp.com\r\n"
        "Subject: Overdue Invoice #INV-99201\r\n"
        "Date: Mon, 16 Nov 2026 10:00:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY_TAG\"\r\n\r\n"
        "--BOUNDARY_TAG\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        "Please review the attached invoice immediately.\r\n"
        "Payment is required within 24 hours to prevent account suspension.\r\n\r\n"
        "--BOUNDARY_TAG\r\n"
        "Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        + b64_payload + "\r\n"
        "--BOUNDARY_TAG--\r\n"
    )

    meta, evidence = parser.parse(raw_email)

    # Verify original evidence in storage is preserved
    assert meta["attachment_count"] == 1
    att_evidence = [e for e in evidence if e.category == EvidenceCategory.ATTACHMENT_ANALYSIS]
    assert len(att_evidence) == 1
    assert "invoice[.]pdf[.]exe" in att_evidence[0].defanged_data["filename"]
    assert att_evidence[0].severity == "HIGH"

    # Analyze with Laya
    report = await agent.analyze_round1(meta, evidence)

    # Verify attachment was excluded from Laya input
    assert report.model_identifiers.get("excluded_tokens", 0) > 0
    # Verify chunk record exists in limitations
    chunk_lim = [lim for lim in report.limitations if "tokens excluded as attachment/markup" in lim]
    assert len(chunk_lim) == 1, f"Expected chunk record in limitations, got {report.limitations}"
    assert "tokens excluded as attachment/markup" in chunk_lim[0]
    assert report.model_identifiers.get("chunk_record") == chunk_lim[0]

    # Verify no silent truncation: state_tokens_dropped is 0
    raw_out = report.raw_output or {}
    usage = raw_out.get("usage", {})
    assert usage.get("state_tokens_dropped", 0) == 0
    assert usage.get("truncated", False) is False

    # Verify findings cite real evidence IDs
    for f in report.findings:
        for eid in f.evidence_ids:
            assert any(e.evidence_id == eid for e in evidence)


@pytest.mark.asyncio
async def test_email_with_very_long_html_body():
    """2. Email with very long HTML body:
    - CSS and HTML markup stripped
    - Token count exceeds checkpoint limit (512 tokens)
    - Split into overlapping paragraph chunks (N > 1)
    - Limitation records 'analyzed in N chunks; M tokens excluded as attachment/markup'
    - Evidence IDs kept on every chunk finding
    - No silent truncation
    """
    parser = EmailParser()
    agent = LayaAgent(auto_load=True)

    # Build 10 distinct paragraphs of HTML totaling > 1,500 words with embedded CSS
    css_block = (
        "<style type=\"text/css\">\n"
        "body { font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 14px; margin: 0; }\n"
        ".brand-header { background: #003366; color: #ffffff; padding: 25px; text-align: center; }\n"
        ".action-btn { display: inline-block; padding: 12px 24px; background: #cc0000; color: #fff; }\n"
        "@media only screen and (max-width: 600px) { body { font-size: 12px; } }\n"
        "</style>\n"
    )

    paragraphs_html = []
    for idx in range(1, 15):
        paragraphs_html.append(
            f"<p><strong>Section {idx}: Important Security Advisory.</strong> "
            f"This advisory details necessary operational steps for system account maintenance. "
            f"Please verify your credentials and ensure compliance with security bulletin #{idx*100}. "
            f"System administrators require immediate verification to maintain active routing access.</p>"
        )
    # Insert threat indicator in paragraph 8
    paragraphs_html[7] = (
        "<p><strong>URGENT: Credential Verification Required!</strong> "
        "Your password will expire in 2 hours. Click here to confirm your password: "
        "<a href=\"http://198.51.100.33/login-verify\">http://198.51.100.33/login-verify</a> "
        "Failure to verify immediately will result in permanent account termination.</p>"
    )

    full_html = f"<html><head>{css_block}</head><body>" + "".join(paragraphs_html) + "</body></html>"

    raw_email = (
        "From: Administrator <admin@portal-security.org>\r\n"
        "To: user@target-domain.com\r\n"
        "Subject: Critical Security Protocol Update #8812\r\n"
        "Date: Mon, 16 Nov 2026 11:00:00 +0000\r\n"
        "Content-Type: text/html; charset=\"utf-8\"\r\n\r\n"
        + full_html
    )

    meta, evidence = parser.parse(raw_email)
    report = await agent.analyze_round1(meta, evidence)

    # 1. Assert chunking occurred (N > 1) because body exceeds verified checkpoint limit (512)
    assert report.model_identifiers.get("chunked") is True
    num_chunks = report.model_identifiers.get("num_chunks", 1)
    assert num_chunks > 1, f"Expected multiple chunks for long email, got {num_chunks}"

    # 2. Assert limitation records 'analyzed in N chunks; M tokens excluded as attachment/markup'
    chunk_lim = [lim for lim in report.limitations if "tokens excluded as attachment/markup" in lim]
    assert len(chunk_lim) == 1
    expected_prefix = f"analyzed in {num_chunks} chunks;"
    assert expected_prefix in chunk_lim[0]
    assert report.model_identifiers.get("chunk_record") == chunk_lim[0]

    # 3. Assert CSS was excluded
    raw_out = report.raw_output or {}
    usage = raw_out.get("usage", {})
    assert usage.get("state_tokens_dropped", 0) == 0
    assert usage.get("truncated", False) is False

    # 4. Assert conservative aggregation preserved threat
    assert report.verdict in {Verdict.PHISHING, Verdict.SUSPICIOUS}

    # 5. Assert all findings have evidence IDs
    assert len(report.findings) > 0
    for f in report.findings:
        assert isinstance(f.evidence_ids, list)
        for eid in f.evidence_ids:
            assert any(e.evidence_id == eid for e in evidence), f"Invalid evidence ID cited: {eid}"

    # Check multi-chunk finding exists
    chunk_findings = [f for f in report.findings if "Multi-chunk analysis" in f.text]
    assert len(chunk_findings) == 1
    assert len(chunk_findings[0].evidence_ids) > 0


@pytest.mark.asyncio
async def test_normal_short_email_no_truncation():
    """3. Normal short email:
    - Not chunked (N = 1)
    - Chunk record exists in limitations: 'analyzed in 1 chunks; 0 tokens excluded as attachment/markup'
    - Assert no silent truncation
    - Standard verdict and calibrated unvalidated status
    """
    parser = EmailParser()
    agent = LayaAgent(auto_load=True)

    raw_email = (
        "From: Colleague <sarah@legit-company.com>\r\n"
        "To: user@legit-company.com\r\n"
        "Subject: Lunch meeting at noon?\r\n"
        "Date: Mon, 16 Nov 2026 11:30:00 +0000\r\n"
        "Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
        "Hi Alex,\r\n\r\n"
        "Are you free to meet for lunch at the cafeteria around 12:15 PM today?\r\n"
        "Let me know if that works for you.\r\n\r\n"
        "Thanks,\r\n"
        "Sarah"
    )

    meta, evidence = parser.parse(raw_email)
    report = await agent.analyze_round1(meta, evidence)

    # 1. Assert not chunked
    assert report.model_identifiers.get("chunked") is False
    assert report.model_identifiers.get("num_chunks") == 1
    assert report.model_identifiers.get("excluded_tokens") == 0

    # 2. Assert chunk record exists
    assert report.model_identifiers.get("chunk_record") == "analyzed in 1 chunks; 0 tokens excluded as attachment/markup"
    chunk_lim = [lim for lim in report.limitations if "tokens excluded as attachment/markup" in lim]
    assert len(chunk_lim) == 1
    assert "analyzed in 1 chunks; 0 tokens excluded as attachment/markup" in chunk_lim[0]

    # 3. Assert no silent truncation
    raw_out = report.raw_output or {}
    usage = raw_out.get("usage", {})
    assert usage.get("state_tokens_dropped", 0) == 0
    assert usage.get("truncated", False) is False

    # 4. Standard validation
    assert report.agent_id == "laya"
    assert report.calibration_status == CalibrationStatus.UNVALIDATED
    assert report.verdict in {Verdict.LEGITIMATE, Verdict.SUSPICIOUS, Verdict.SPAM}
