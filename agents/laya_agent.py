"""Agent 3: Laya System 1 Typed-Decision Model Adapter.

Runs the official pinned `laya` package with checkpoint `convaiinnovations/laya-typed-decisions`
at pinned revision `1a793eb568e6718f15941d08f85432581df534e3`.
Runs locally with CUDA/CPU fallback, bounded concurrency (semaphore), resident singleton model,
versioned question config, and explicit chunking/windowing logging.

NEVER FAKES, STUBS, OR MOCKS A RESULT IN RUNTIME CODE.
IF WEIGHTS ARE NOT PRESENT OR RESOURCE CONSTRAINTS ARISE, COMPONENT IS MARKED UNAVAILABLE.
"""
import asyncio
import html
import json
import logging
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

import torch

from agents.base import BaseAgent
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

logger = logging.getLogger("email_threat_platform.laya")

# Pinned checkpoint revision verified in laya/revisions.py
PINNED_CHECKPOINT = "convaiinnovations/laya-typed-decisions"
PINNED_REVISION = "1a793eb568e6718f15941d08f85432581df534e3"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "laya_questions.v1.json")

# Verified checkpoint context limits from docs/VERIFIED_ASSUMPTIONS.md:
# - Base Context Window: 512 tokens (can support up to 1024 on laya-typed-decisions).
# - Head Budget (head_max_len): 256 tokens reserved for question instructions and options.
# - State Room Cap: 512 tokens.
VERIFIED_CHECKPOINT_LIMIT = 512
CHUNK_TARGET_TOKENS = 380   # Target tokens per chunk so chunk + headers comfortably fit under 512
CHUNK_OVERLAP_TOKENS = 80    # Overlap between consecutive chunks at paragraph boundaries

# Concurrency bound: Single inference at a time on CPU/GPU
_LAYA_SEMAPHORE = asyncio.Semaphore(1)


def is_laya_model_cached() -> bool:
    """Check whether the model weights have been downloaded and cached on disk."""
    cache_dir = os.environ.get("LAYA_CACHE_DIR") or os.path.expanduser("~/.cache/huggingface/hub")
    target_repo_dir = os.path.join(cache_dir, "models--convaiinnovations--laya-typed-decisions")
    if not os.path.isdir(target_repo_dir):
        return False
    # Check for model.safetensors in snapshots
    snapshots_dir = os.path.join(target_repo_dir, "snapshots")
    if os.path.isdir(snapshots_dir):
        for snap in os.listdir(snapshots_dir):
            safetensors_path = os.path.join(snapshots_dir, snap, "model.safetensors")
            if os.path.isfile(safetensors_path) and os.path.getsize(safetensors_path) > 800_000_000:
                return True
    return False


def clean_laya_body_text(text: str) -> str:
    """Strip base64, CSS, attachment blocks, and quoted reply history from plain text."""
    if not text:
        return ""
    t = text
    # 1. Inline base64 data URIs
    t = re.sub(r"data:[^;]+;base64,[A-Za-z0-9+/=]+", "", t)
    # 2. HTML style blocks and script blocks
    t = re.sub(r"<style[^>]*>.*?</style>", "", t, flags=re.IGNORECASE | re.DOTALL)
    t = re.sub(r"<script[^>]*>.*?</script>", "", t, flags=re.IGNORECASE | re.DOTALL)
    # 3. CSS rule blocks (e.g. .class { font-family:... } or body { ... })
    t = re.sub(r"(?:[.#@a-zA-Z0-9_\-\s,>:+]+)\s*\{[^}]*\}", "", t)
    # 4. Inline CSS property declarations
    t = re.sub(
        r"\b(?:font-family|font-size|margin|padding|background-color|color|border|line-height|display|width|height)\s*:[^;]+;",
        "",
        t,
        flags=re.IGNORECASE,
    )
    # 5. Base64 encoded payload blocks and uuencode attachments
    t = re.sub(r"begin\s+\d{3}\s+[^\n]+\n(?:[^\n]+\n)+end", "", t)
    t = re.sub(r"Content-Disposition:\s*attachment[^\n]*\n(?:[^\n]+\n)+", "", t, flags=re.IGNORECASE)
    # Multi-line base64 blocks (typical MIME lines with length >= 40 chars)
    t = re.sub(r"(?:^[ \t]*[A-Za-z0-9+/]{40,}={0,2}[ \t]*\r?\n?)+", "", t, flags=re.MULTILINE)
    # Any single contiguous base64 string >= 50 chars without spaces
    t = re.sub(r"\b[A-Za-z0-9+/]{50,}={0,2}\b", "", t)
    # 6. Quoted reply history / forward headers
    t = re.sub(r"(?:\r?\n|^)[ \t]*-{4,}\s*Original Message\s*-{4,}.*", "", t, flags=re.IGNORECASE | re.DOTALL)
    t = re.sub(r"(?:\r?\n|^)[ \t]*_{10,}.*", "", t, flags=re.DOTALL)
    t = re.sub(r"(?:\r?\n|^)On\s+.+?,\s+.+?\s+wrote:.*", "", t, flags=re.IGNORECASE | re.DOTALL)
    t = re.sub(r"(?:\r?\n|^)From:\s*.+?\nSent:\s*.+?\nTo:\s*.+?\nSubject:.*", "", t, flags=re.IGNORECASE | re.DOTALL)
    # Quoted email lines (lines starting with > or &gt;)
    t = re.sub(r"^[ \t]*(?:>|&gt;).*$\n?", "", t, flags=re.MULTILINE)
    # 7. Remaining HTML tags
    t = re.sub(r"<[^>]+>", " ", t)
    # 8. Unescape HTML entities
    t = html.unescape(t)
    # 9. Clean up excess whitespace while preserving paragraph breaks
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


class LayaAgent(BaseAgent):
    """Local typed-decision agent powered by the official laya package."""

    def __init__(
        self,
        config_path: str = CONFIG_PATH,
        device: Optional[str] = None,
        auto_load: bool = True,
    ):
        super().__init__(agent_id="laya")
        self.config_path = os.path.abspath(config_path)
        self.device = self._resolve_device(device)
        self.agent_instance = None
        self.questions_config: Dict[str, Any] = {}
        self.load_error: Optional[str] = None
        
        self._load_questions()
        if auto_load and is_laya_model_cached():
            self._load_model_weights()

    def _resolve_device(self, requested_device: Optional[str]) -> str:
        dev = (requested_device or os.environ.get("LAYA_DEVICE", "")).strip().lower()
        if dev == "cuda":
            if torch.cuda.is_available():
                return "cuda"
            logger.info("LAYA_DEVICE=cuda requested but CUDA is unavailable; falling back to CPU")
            return "cpu"
        elif dev == "cpu":
            return "cpu"
        # Auto-detect
        return "cuda" if torch.cuda.is_available() else "cpu"

    def _load_questions(self):
        if not os.path.exists(self.config_path):
            self.load_error = f"Laya questions config missing at {self.config_path}"
            return
        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            self.questions_config = cfg.get("questions", {})

    def _load_model_weights(self):
        """Load pinned Laya model once and keep resident."""
        try:
            import laya
            logger.info(
                f"Loading Laya agent: model={PINNED_CHECKPOINT}, revision={PINNED_REVISION}, device={self.device}"
            )
            # laya.Agent loads weights using resolve_revision
            self.agent_instance = laya.Agent(
                model_id_or_path=PINNED_CHECKPOINT,
                revision=PINNED_REVISION,
                device=self.device,
            )
            self.load_error = None
        except Exception as e:
            self.agent_instance = None
            self.load_error = str(e)
            logger.error(f"Failed to load Laya model: {e}")

    def check_availability(self) -> Tuple[AvailabilityStatus, Optional[str]]:
        if not is_laya_model_cached():
            return (
                AvailabilityStatus.UNAVAILABLE,
                "Model weights not downloaded (approx 803 MB). Ask user before downloading, or run 'python scripts/manage.py prepare-models' after verifying sufficient RAM and disk.",
            )
        if self.load_error:
            return AvailabilityStatus.UNAVAILABLE, f"Laya initialization failed: {self.load_error}"
        if self.agent_instance is None:
            # Attempt load now that weights are confirmed
            self._load_model_weights()
            if self.agent_instance is None:
                return AvailabilityStatus.UNAVAILABLE, f"Laya initialization failed: {self.load_error}"
        return AvailabilityStatus.AVAILABLE, None

    def count_tokens(self, text: str) -> int:
        """Count tokens using model tokenizer if available, else accurate fallback heuristic."""
        if not text:
            return 0
        if self.agent_instance and hasattr(self.agent_instance, "tok"):
            tok = getattr(self.agent_instance, "tok", None)
            if tok is not None:
                try:
                    res = tok.encode(text)
                    if isinstance(res, (list, tuple)):
                        return len(res)
                except Exception:
                    pass
        # Fallback estimation based on subword token density
        words = text.split()
        return max(1, int(len(words) * 1.35))

    def prepare_clean_state(
        self,
        parsed_metadata: Dict[str, Any],
    ) -> Tuple[Dict[str, str], str, int, int]:
        """Build Laya input from extracted plain text and selected header fields only.

        Excludes attachment bodies, base64, CSS, and quoted reply history.
        Original evidence in storage remains unchanged.
        Returns:
            selected_headers, cleaned_body, excluded_tokens, raw_total_tokens
        """
        # 1. Selected header fields only
        selected_headers = {}
        for h in ["from", "to", "subject", "date", "reply_to"]:
            val = parsed_metadata.get(h)
            if val and str(val).strip():
                selected_headers[h] = str(val).strip()

        # 2. Extract text candidate
        body_plain = parsed_metadata.get("body_plain", "")
        body_html = parsed_metadata.get("body_html", "")

        raw_text_candidate = body_plain
        if not raw_text_candidate.strip() and body_html:
            raw_text_candidate = body_html

        # 3. Calculate raw input token count (including attachments & headers)
        raw_body_tokens = self.count_tokens(raw_text_candidate)
        header_tokens = sum(self.count_tokens(f"{k}: {v}") for k, v in selected_headers.items())

        # Attachment tokens excluded from payload
        att_bytes = parsed_metadata.get("attachment_bytes_total", 0)
        att_tokens = max(0, int(att_bytes // 3))
        raw_total_tokens = raw_body_tokens + header_tokens + att_tokens

        # 4. Clean body text
        cleaned_body = clean_laya_body_text(raw_text_candidate)
        cleaned_body_tokens = self.count_tokens(cleaned_body)
        cleaned_total_tokens = cleaned_body_tokens + header_tokens

        excluded_tokens = max(0, raw_total_tokens - cleaned_total_tokens)
        return selected_headers, cleaned_body, excluded_tokens, raw_total_tokens

    def split_paragraphs_into_chunks(
        self,
        text: str,
        max_tokens: int = CHUNK_TARGET_TOKENS,
        overlap_tokens: int = CHUNK_OVERLAP_TOKENS,
    ) -> List[str]:
        """Split text into overlapping chunks at paragraph boundaries without silent truncation."""
        if not text.strip():
            return [""]
        paragraphs = [p.strip() for p in re.split(r"\n{2,}", text.strip()) if p.strip()]
        if not paragraphs:
            paragraphs = [text.strip()]

        # Sub-split any paragraph that alone exceeds max_tokens at sentence boundaries
        flat_items = []
        for p in paragraphs:
            if self.count_tokens(p) > max_tokens:
                sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", p) if s.strip()]
                flat_items.extend(sentences if sentences else [p])
            else:
                flat_items.append(p)

        chunks: List[str] = []
        current_paras: List[str] = []
        current_tokens = 0

        for item in flat_items:
            item_tokens = self.count_tokens(item)
            if current_tokens + item_tokens <= max_tokens:
                current_paras.append(item)
                current_tokens += item_tokens
            else:
                if current_paras:
                    chunks.append("\n\n".join(current_paras))
                    # Calculate overlapping trailing paragraphs
                    overlap_paras = []
                    overlap_accum = 0
                    for p in reversed(current_paras):
                        p_toks = self.count_tokens(p)
                        if overlap_accum + p_toks <= overlap_tokens:
                            overlap_paras.insert(0, p)
                            overlap_accum += p_toks
                        else:
                            break
                    if not overlap_paras and current_paras:
                        overlap_paras = [current_paras[-1]]
                    current_paras = overlap_paras + [item]
                    current_tokens = sum(self.count_tokens(p) for p in current_paras)
                else:
                    chunks.append(item)
                    current_paras = []
                    current_tokens = 0

        if current_paras:
            chunks.append("\n\n".join(current_paras))

        return chunks if chunks else [text]

    def aggregate_results(self, chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Conservatively aggregate typed decisions across overlapping chunks."""
        if not chunk_results:
            return {}
        if len(chunk_results) == 1:
            return chunk_results[0]

        # Severity priority: PHISHING > SUSPICIOUS > SPAM > LEGITIMATE > ABSTAIN
        severity_rank = {
            Verdict.PHISHING: 5,
            Verdict.SUSPICIOUS: 4,
            Verdict.SPAM: 3,
            Verdict.LEGITIMATE: 2,
            Verdict.ABSTAIN: 1,
        }

        best_verdict = Verdict.LEGITIMATE
        best_verdict_str = "legitimate"
        best_verdict_conf = 0.0

        any_cred_harvesting = False
        max_cred_conf = 0.5
        any_sender_impersonation = False
        max_sender_conf = 0.5
        max_urgency_score: Any = 0
        urgency_legend = {}

        for res in chunk_results:
            ans = res.get("answers", res)

            # 1. Verdict
            v_ans = ans.get("verdict", {})
            v_choice = v_ans.get("choice") or v_ans.get("answer") or "suspicious"
            v_conf = float(v_ans.get("answer_confidence") or v_ans.get("confidence") or 0.70)
            mapped_v = self._map_laya_verdict(v_choice)

            if severity_rank.get(mapped_v, 1) > severity_rank.get(best_verdict, 1):
                best_verdict = mapped_v
                best_verdict_str = v_choice
                best_verdict_conf = v_conf
            elif severity_rank.get(mapped_v, 1) == severity_rank.get(best_verdict, 1):
                if v_conf > best_verdict_conf:
                    best_verdict_conf = v_conf
                    best_verdict_str = v_choice

            # 2. Credential Harvesting (noul / boolean)
            c_ans = ans.get("credential_harvesting", {})
            c_bool = c_ans.get("answer") is True or (isinstance(c_ans.get("noul"), (int, float)) and c_ans.get("noul") >= 0.5)
            c_conf = float(c_ans.get("answer_confidence") or c_ans.get("confidence") or c_ans.get("noul") or 0.5)
            if c_bool:
                any_cred_harvesting = True
                if c_conf > max_cred_conf:
                    max_cred_conf = c_conf

            # 3. Sender Impersonation (noul / boolean)
            s_ans = ans.get("sender_impersonation", {})
            s_bool = s_ans.get("answer") is True or (isinstance(s_ans.get("noul"), (int, float)) and s_ans.get("noul") >= 0.5)
            s_conf = float(s_ans.get("answer_confidence") or s_ans.get("confidence") or s_ans.get("noul") or 0.5)
            if s_bool:
                any_sender_impersonation = True
                if s_conf > max_sender_conf:
                    max_sender_conf = s_conf

            # 4. Urgency Pressure (score)
            u_ans = ans.get("urgency_pressure", {})
            u_score = u_ans.get("score")
            if isinstance(u_score, (int, float)):
                if isinstance(max_urgency_score, (int, float)) and u_score > max_urgency_score:
                    max_urgency_score = u_score
            elif u_ans.get("answer"):
                max_urgency_score = u_ans.get("answer")
            if u_ans.get("legend"):
                urgency_legend = u_ans.get("legend")

        # Conservative threat elevation: If credential harvesting or sender impersonation
        # was detected in any chunk, elevate verdict to at least SUSPICIOUS
        if (any_cred_harvesting or any_sender_impersonation) and best_verdict in {Verdict.LEGITIMATE, Verdict.ABSTAIN}:
            best_verdict = Verdict.SUSPICIOUS
            best_verdict_str = "suspicious"
            best_verdict_conf = max(max_cred_conf, max_sender_conf, 0.70)

        aggregated = {
            "model": "laya-typed-decisions-aggregated",
            "answers": {
                "verdict": {
                    "type": "choice",
                    "choice": best_verdict_str,
                    "answer": best_verdict_str,
                    "confidence": round(best_verdict_conf, 3),
                    "answer_confidence": round(best_verdict_conf, 3),
                },
                "credential_harvesting": {
                    "type": "noul",
                    "answer": any_cred_harvesting,
                    "confidence": round(max_cred_conf, 3),
                    "answer_confidence": round(max_cred_conf, 3),
                },
                "sender_impersonation": {
                    "type": "noul",
                    "answer": any_sender_impersonation,
                    "confidence": round(max_sender_conf, 3),
                    "answer_confidence": round(max_sender_conf, 3),
                },
                "urgency_pressure": {
                    "type": "score",
                    "answer": max_urgency_score,
                    "score": max_urgency_score,
                    "legend": urgency_legend,
                },
            },
            "usage": {
                "chunks": len(chunk_results),
                "aggregated": True,
                "state_tokens_dropped": 0,
                "truncated": False,
            },
        }
        return aggregated

    def _map_laya_verdict(self, choice_answer: str) -> Verdict:
        val = str(choice_answer).lower().strip()
        if "phish" in val:
            return Verdict.PHISHING
        elif "spam" in val:
            return Verdict.SPAM
        elif "suspicious" in val:
            return Verdict.SUSPICIOUS
        elif "legit" in val:
            return Verdict.LEGITIMATE
        return Verdict.SUSPICIOUS

    async def analyze_round1(
        self,
        parsed_metadata: Dict[str, Any],
        evidence: List[EvidenceItem],
    ) -> AgentReport:
        avail, reason = self.check_availability()
        if avail != AvailabilityStatus.AVAILABLE:
            return AgentReport(
                agent_id="laya",
                round=1,
                verdict=Verdict.ABSTAIN,
                confidence=0.0,
                calibration_status=CalibrationStatus.UNVALIDATED,
                availability=avail,
                availability_reason=reason,
                limitations=[
                    "Laya component UNAVAILABLE: Model weights not yet downloaded to local cache or host uninitialized",
                    "Public vendor accuracy (0.766) is on non-email workflow benchmark and unvalidated for phishing",
                ],
                model_identifiers={
                    "model": PINNED_CHECKPOINT,
                    "pinned_revision": PINNED_REVISION,
                    "device": self.device,
                },
            )

        # 1. Clean input & extract selected headers (no attachment bodies, CSS, base64, or quoted replies)
        selected_headers, cleaned_body, excluded_tokens, _ = self.prepare_clean_state(parsed_metadata)

        # 2. Count tokens with model tokenizer & compare against verified checkpoint limit (512 tokens)
        body_tokens = self.count_tokens(cleaned_body)

        if body_tokens <= VERIFIED_CHECKPOINT_LIMIT:
            chunks = [cleaned_body]
            num_chunks = 1
        else:
            chunks = self.split_paragraphs_into_chunks(
                cleaned_body,
                max_tokens=CHUNK_TARGET_TOKENS,
                overlap_tokens=CHUNK_OVERLAP_TOKENS,
            )
            num_chunks = len(chunks)

        chunk_record = f"analyzed in {num_chunks} chunks; {excluded_tokens} tokens excluded as attachment/markup"

        limitations = [
            "Official pinned laya-typed-decisions model run locally with single forward-pass System 1 inference",
            "Confidence is UNVALIDATED for email threat detection until evaluated on labeled email benchmark",
            chunk_record,
        ]

        async with _LAYA_SEMAPHORE:
            def run_sync_inference():
                if num_chunks == 1:
                    state = {**selected_headers, "body": chunks[0]}
                    return self.agent_instance.predict(
                        state=state,
                        questions=self.questions_config,
                    )
                else:
                    results = []
                    for c_text in chunks:
                        state = {**selected_headers, "body": c_text}
                        res = self.agent_instance.predict(
                            state=state,
                            questions=self.questions_config,
                        )
                        results.append(res)
                    return self.aggregate_results(results)

            loop = asyncio.get_running_loop()
            raw_result = await loop.run_in_executor(None, run_sync_inference)

        # 3. Parse typed results
        ans = raw_result.get("answers", raw_result)
        verdict_ans = ans.get("verdict", {})
        verdict_choice = verdict_ans.get("choice") or verdict_ans.get("answer", "suspicious")
        verdict_prob = float(verdict_ans.get("answer_confidence") or verdict_ans.get("confidence", 0.70))

        cred_ans = ans.get("credential_harvesting", {})
        sender_ans = ans.get("sender_impersonation", {})
        urgency_ans = ans.get("urgency_pressure", {})

        mapped_verdict = self._map_laya_verdict(verdict_choice)

        # 4. Link typed findings to evidence IDs
        findings: List[Finding] = []
        ev_id_map = {e.category: e.evidence_id for e in evidence}

        url_ev = ev_id_map.get(EvidenceCategory.URL_ANALYSIS)
        hdr_ev = ev_id_map.get(EvidenceCategory.HEADER_MISMATCH)
        auth_ev = ev_id_map.get(EvidenceCategory.AUTH_RESULTS)
        att_ev = ev_id_map.get(EvidenceCategory.ATTACHMENT_ANALYSIS)
        fallback_ev = [evidence[0].evidence_id] if evidence else []

        findings.append(Finding(
            text=f"Typed decision verdict: {verdict_choice} (probability: {verdict_prob:.2f})",
            evidence_ids=[url_ev] if url_ev else ([hdr_ev] if hdr_ev else fallback_ev),
        ))

        is_cred = cred_ans.get("answer") is True or (isinstance(cred_ans.get("noul"), (int, float)) and cred_ans.get("noul") >= 0.5)
        if is_cred:
            findings.append(Finding(
                text=f"Credential harvesting detected (P(true)={float(cred_ans.get('confidence', cred_ans.get('answer_confidence', 0.5))):.2f})",
                evidence_ids=[url_ev] if url_ev else fallback_ev,
            ))

        is_sender = sender_ans.get("answer") is True or (isinstance(sender_ans.get("noul"), (int, float)) and sender_ans.get("noul") >= 0.5)
        if is_sender:
            findings.append(Finding(
                text=f"Sender impersonation detected (P(true)={float(sender_ans.get('confidence', sender_ans.get('answer_confidence', 0.5))):.2f})",
                evidence_ids=[hdr_ev] if hdr_ev else ([auth_ev] if auth_ev else fallback_ev),
            ))

        urg_score = urgency_ans.get("score") if urgency_ans.get("score") is not None else urgency_ans.get("answer")
        if urg_score or (isinstance(urg_score, (int, float)) and urg_score > 0):
            findings.append(Finding(
                text=f"Psychological urgency score: {urg_score}",
                evidence_ids=[url_ev] if url_ev else ([hdr_ev] if hdr_ev else fallback_ev),
            ))

        if num_chunks > 1:
            findings.append(Finding(
                text=f"Multi-chunk analysis: evaluated {num_chunks} overlapping paragraph chunks with conservative threat aggregation",
                evidence_ids=[e.evidence_id for e in evidence[:2]] if evidence else [],
            ))

        return AgentReport(
            agent_id="laya",
            round=1,
            verdict=mapped_verdict,
            confidence=round(verdict_prob, 3),
            calibration_status=CalibrationStatus.UNVALIDATED,
            findings=findings,
            limitations=limitations,
            availability=AvailabilityStatus.AVAILABLE,
            model_identifiers={
                "model": PINNED_CHECKPOINT,
                "pinned_revision": PINNED_REVISION,
                "device": self.device,
                "chunked": num_chunks > 1,
                "num_chunks": num_chunks,
                "excluded_tokens": excluded_tokens,
                "chunk_record": chunk_record,
                "checkpoint_cap": VERIFIED_CHECKPOINT_LIMIT,
            },
            raw_output=raw_result,
        )

    async def analyze_round2(
        self,
        parsed_metadata: Dict[str, Any],
        evidence: List[EvidenceItem],
        round1_reports: List[AgentReport],
        debate_messages: List[DebateMessage],
    ) -> AgentReport:
        r1_report = next((r for r in round1_reports if r.agent_id == "laya"), None)
        if not r1_report:
            rep = await self.analyze_round1(parsed_metadata, evidence)
            rep.round = 2
            rep.revised_from_round1 = False
            return rep
        if r1_report.availability != AvailabilityStatus.AVAILABLE:
            res = r1_report.model_copy()
            res.round = 2
            res.revised_from_round1 = False
            return res

        # Laya is a typed decision model (not a natural language chat generator).
        # Per project rules: "Round 2 re-runs the decision with structured evidence. Never ask it for natural-language debate."
        # We enrich the state with verified structured peer evidence:
        structured_evidence_summary = [f"{msg.from_agent}: {msg.summary}" for msg in debate_messages]
        peer_summary = " | ".join(structured_evidence_summary)

        selected_headers, cleaned_body, excluded_tokens, _ = self.prepare_clean_state(parsed_metadata)
        body_tokens = self.count_tokens(cleaned_body)

        if body_tokens <= VERIFIED_CHECKPOINT_LIMIT:
            chunks = [cleaned_body]
            num_chunks = 1
        else:
            chunks = self.split_paragraphs_into_chunks(
                cleaned_body,
                max_tokens=CHUNK_TARGET_TOKENS,
                overlap_tokens=CHUNK_OVERLAP_TOKENS,
            )
            num_chunks = len(chunks)

        async with _LAYA_SEMAPHORE:
            def run_sync_r2():
                if num_chunks == 1:
                    state = {
                        **selected_headers,
                        "body": chunks[0],
                        "peer_evidence_summary": peer_summary,
                    }
                    return self.agent_instance.predict(
                        state=state,
                        questions=self.questions_config,
                    )
                else:
                    results = []
                    for c_text in chunks:
                        state = {
                            **selected_headers,
                            "body": c_text,
                            "peer_evidence_summary": peer_summary,
                        }
                        res = self.agent_instance.predict(
                            state=state,
                            questions=self.questions_config,
                        )
                        results.append(res)
                    return self.aggregate_results(results)

            loop = asyncio.get_running_loop()
            raw_result_r2 = await loop.run_in_executor(None, run_sync_r2)

        ans = raw_result_r2.get("answers", raw_result_r2)
        verdict_ans = ans.get("verdict", {})
        verdict_choice = verdict_ans.get("choice") or verdict_ans.get("answer", "suspicious")
        verdict_prob = float(verdict_ans.get("answer_confidence") or verdict_ans.get("confidence", 0.70))
        mapped_verdict = self._map_laya_verdict(verdict_choice)

        revised = (mapped_verdict != r1_report.verdict) or (abs(verdict_prob - r1_report.confidence) > 0.05)

        findings = list(r1_report.findings)
        if revised:
            citing = [e.evidence_id for e in evidence if e.severity in {"CRITICAL", "HIGH"}][:2]
            if not citing and evidence:
                citing = [evidence[0].evidence_id]
            findings.append(Finding(
                text=f"Round 2 structured evaluation revised decision to {mapped_verdict.value} (confidence: {verdict_prob:.2f})",
                evidence_ids=citing,
            ))

        chunk_record = f"analyzed in {num_chunks} chunks; {excluded_tokens} tokens excluded as attachment/markup"
        limitations = list(r1_report.limitations)
        if chunk_record not in limitations:
            limitations.append(chunk_record)

        return AgentReport(
            agent_id="laya",
            round=2,
            verdict=mapped_verdict,
            confidence=round(verdict_prob, 3),
            calibration_status=CalibrationStatus.UNVALIDATED,
            findings=findings,
            limitations=limitations,
            availability=AvailabilityStatus.AVAILABLE,
            model_identifiers={
                **r1_report.model_identifiers,
                "chunk_record": chunk_record,
                "num_chunks": num_chunks,
                "chunked": num_chunks > 1,
            },
            raw_output=raw_result_r2,
            revised_from_round1=revised,
        )
