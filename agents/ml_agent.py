"""Agent 1: Scikit-learn TF-IDF + Naive Bayes baseline on labeled demo dataset.

CALIBRATION STATUS: ALWAYS DEMO_ONLY. NEVER CALL IT PRODUCTION-GRADE.
"""
import json
import os
from typing import Any, Dict, List, Optional, Tuple
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np

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

DEMO_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "demo_dataset.json")
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
MODEL_PATH = os.path.join(MODEL_DIR, "ml_baseline.joblib")


class MLAgent(BaseAgent):
    """TF-IDF + Multinomial Naive Bayes classifier on synthetic demo data."""

    def __init__(self, data_path: str = DEMO_DATA_PATH, model_path: str = MODEL_PATH):
        super().__init__(agent_id="ml")
        self.data_path = os.path.abspath(data_path)
        self.model_path = os.path.abspath(model_path)
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english", max_features=1000)
        self.classifier = MultinomialNB(alpha=0.5)
        self.is_trained = False
        self.sample_count = 0
        self.data_origin = "Synthetic demo dataset"
        self._load_or_train_demo_model()

    def _load_or_train_demo_model(self):
        # Check if saved model already exists
        if os.path.exists(self.model_path):
            try:
                artifact = joblib.load(self.model_path)
                self.vectorizer = artifact["vectorizer"]
                self.classifier = artifact["classifier"]
                self.sample_count = artifact.get("sample_count", 14)
                self.data_origin = artifact.get("data_origin", "Synthetic demo dataset (data/demo_dataset.json)")
                self.is_trained = True
                return
            except Exception:
                # If loading fails, train from raw data
                pass

        if not os.path.exists(self.data_path):
            self.is_trained = False
            return

        with open(self.data_path, "r", encoding="utf-8") as f:
            demo_items = json.load(f)

        self.sample_count = len(demo_items)
        self.data_origin = "Synthetic demo dataset (data/demo_dataset.json)"
        texts = [item["text"] for item in demo_items]
        labels = [item["label"] for item in demo_items]

        X = self.vectorizer.fit_transform(texts)
        self.classifier.fit(X, labels)
        self.is_trained = True

        # Store trained model artifact
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({
                "vectorizer": self.vectorizer,
                "classifier": self.classifier,
                "sample_count": self.sample_count,
                "data_origin": self.data_origin,
                "calibration_status": "DEMO_ONLY",
            }, self.model_path)
        except Exception:
            pass

    def check_availability(self) -> Tuple[AvailabilityStatus, Optional[str]]:
        if not self.is_trained:
            return AvailabilityStatus.UNAVAILABLE, "Demo training dataset missing or uninitialized"
        return AvailabilityStatus.AVAILABLE, None

    def _map_label_to_verdict(self, label: str) -> Verdict:
        label = label.upper()
        if label == "PHISHING":
            return Verdict.PHISHING
        elif label == "SPAM":
            return Verdict.SPAM
        elif label == "SUSPICIOUS":
            return Verdict.SUSPICIOUS
        elif label == "LEGITIMATE":
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
                agent_id="ml",
                round=1,
                verdict=Verdict.ABSTAIN,
                confidence=0.0,
                calibration_status=CalibrationStatus.DEMO_ONLY,
                availability=avail,
                availability_reason=reason,
                limitations=["Agent unavailable"],
                model_identifiers={"model": "TFIDF_MultinomialNB", "status": "untrained"},
            )

        text_to_eval = f"{parsed_metadata.get('subject', '')} {parsed_metadata.get('body_plain', '')}"
        X_test = self.vectorizer.transform([text_to_eval])
        probs = self.classifier.predict_proba(X_test)[0]
        classes = self.classifier.classes_

        top_idx = int(np.argmax(probs))
        predicted_label = classes[top_idx]
        top_prob = float(probs[top_idx])

        # Link findings to available evidence IDs
        findings: List[Finding] = []
        ev_id_map = {e.evidence_id: e for e in evidence}

        # Check for matching evidence items
        url_evs = [e.evidence_id for e in evidence if e.category == EvidenceCategory.URL_ANALYSIS]
        hdr_evs = [e.evidence_id for e in evidence if e.category == EvidenceCategory.HEADER_MISMATCH]
        att_evs = [e.evidence_id for e in evidence if e.category == EvidenceCategory.ATTACHMENT_ANALYSIS]

        verdict = self._map_label_to_verdict(predicted_label)

        if verdict == Verdict.PHISHING:
            cited = (url_evs + hdr_evs + att_evs)[:2]
            findings.append(Finding(
                text=f"TF-IDF lexical model detected phishing patterns (prob: {top_prob:.2f})",
                evidence_ids=cited,
            ))
        elif verdict == Verdict.SPAM:
            findings.append(Finding(
                text=f"Lexical frequency matches bulk promotional or unsolicited spam profile (prob: {top_prob:.2f})",
                evidence_ids=url_evs[:1],
            ))
        elif verdict == Verdict.LEGITIMATE:
            findings.append(Finding(
                text=f"Email vocabulary aligns with benign operational communications (prob: {top_prob:.2f})",
                evidence_ids=[],
            ))
        else:
            findings.append(Finding(
                text=f"Ambiguous lexical features resulted in suspicious classification (prob: {top_prob:.2f})",
                evidence_ids=(hdr_evs or url_evs)[:1],
            ))

        return AgentReport(
            agent_id="ml",
            round=1,
            verdict=verdict,
            confidence=round(top_prob, 3),
            calibration_status=CalibrationStatus.DEMO_ONLY,
            findings=findings,
            limitations=[
                f"Trained exclusively on small synthetic demo corpus ({self.sample_count} samples from {self.data_origin}); DEMO_ONLY; never use in production",
                "Bag-of-words / TF-IDF lacks semantic understanding of spoofing or context",
            ],
            availability=AvailabilityStatus.AVAILABLE,
            model_identifiers={
                "model": "scikit-learn TF-IDF + MultinomialNB",
                "training_samples": self.sample_count,
                "training_origin": self.data_origin,
                "classes": list(classes),
                "features": int(X_test.shape[1]),
                "calibration_status": "DEMO_ONLY",
                "storage_path": self.model_path,
            },
            raw_output={c: round(float(p), 4) for c, p in zip(classes, probs)},
        )

    async def analyze_round2(
        self,
        parsed_metadata: Dict[str, Any],
        evidence: List[EvidenceItem],
        round1_reports: List[AgentReport],
        debate_messages: List[DebateMessage],
    ) -> AgentReport:
        # Fetch round 1 ML report
        r1_report = next((r for r in round1_reports if r.agent_id == "ml"), None)
        if not r1_report or r1_report.availability != AvailabilityStatus.AVAILABLE:
            return await self.analyze_round1(parsed_metadata, evidence)

        initial_verdict = r1_report.verdict
        initial_conf = r1_report.confidence
        new_verdict = initial_verdict
        new_conf = initial_conf
        revised = False

        # In Round 2, review peer findings and cited evidence
        critical_evidence_cited = []
        for msg in debate_messages:
            for eid in msg.cited_evidence_ids:
                matching_ev = next((e for e in evidence if e.evidence_id == eid), None)
                if matching_ev and matching_ev.severity in {"CRITICAL", "HIGH"}:
                    critical_evidence_cited.append(eid)

        # If peer agents identified severe objective evidence (e.g. auth fail, brand spoof url)
        # and ML initially labeled it LEGITIMATE or SPAM, revise toward SUSPICIOUS or PHISHING
        if critical_evidence_cited:
            if initial_verdict in {Verdict.LEGITIMATE, Verdict.SPAM}:
                new_verdict = Verdict.SUSPICIOUS
                new_conf = max(initial_conf, 0.70)
                revised = True

        findings = list(r1_report.findings)
        if revised:
            findings.append(Finding(
                text=f"Round 2 revision: adjusted verdict to {new_verdict.value} due to corroborated high-severity peer evidence",
                evidence_ids=critical_evidence_cited[:2],
            ))

        return AgentReport(
            agent_id="ml",
            round=2,
            verdict=new_verdict,
            confidence=round(new_conf, 3),
            calibration_status=CalibrationStatus.DEMO_ONLY,
            findings=findings,
            limitations=r1_report.limitations,
            availability=AvailabilityStatus.AVAILABLE,
            model_identifiers=r1_report.model_identifiers,
            raw_output=r1_report.raw_output,
            revised_from_round1=revised,
        )
