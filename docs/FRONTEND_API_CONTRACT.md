# Frontend API Contract: Email Threat Detection Platform

**Version:** 1.0.0  
**Base URL:** `/api` (proxied by Vite to `http://127.0.0.1:8000/api` during local development)  
**Security & Privacy:** Server binds strictly to `127.0.0.1`. Never transmits unredacted data without user disclosure. All email content is untrusted data.

---

## 1. Core Enumerations

### Verdict (Agent-level)
| Value | Meaning | UI Display Label |
|---|---|---|
| `PHISHING` | Malicious credential harvesting, account takeover, or spoofing | Phishing |
| `SPAM` | Unsolicited bulk marketing or commercial solicitation | Spam |
| `SUSPICIOUS` | Anomalies, inconclusive intent, or unverified sender domain | Suspicious |
| `LEGITIMATE` | Authentic normal communication without detected indicators | No threat indicators found |
| `ABSTAIN` | Agent unavailable, privacy-gated, or abstained | Abstained / Unavailable |

### ConsensusVerdict (Platform-level)
| Value | Meaning | UI Display Label |
|---|---|---|
| `PHISHING` | Conclusive phishing attempt corroborated by evidence | Phishing |
| `SPAM` | Unsolicited bulk email or scam solicitation | Spam |
| `SUSPICIOUS` | High-severity behavioral/technical anomalies | Suspicious |
| `LEGITIMATE` | Clean, verified authentication, zero threat findings | No threat indicators found |
| `NEEDS_REVIEW` | Ambiguous evidence, agent conflict, or partial availability | Needs review |

### CalibrationStatus
- `UNVALIDATED`: Experimental or uncalibrated model scores (e.g. Laya without labeled email validation). Label: *"Unvalidated score, not a probability"*.
- `DEMO_ONLY`: Demonstration model trained on synthetic demo data (e.g. ML baseline). Label: *"Demo model only"*.
- `VALIDATED`: Calibrated against representative labeled benchmark corpus.

### AvailabilityStatus
- `AVAILABLE`: Agent resident, initialized, and operational.
- `DEGRADED`: Operational with transient upstream rate-limits, chunking limits, or degraded latency.
- `UNAVAILABLE`: Offline, uninitialized, or disabled (e.g. privacy-gated or weights missing).

### EvidenceCategory
- `HEADER_MISMATCH`: From vs Reply-To vs Return-Path discrepancies.
- `AUTH_RESULTS`: SPF, DKIM, and DMARC authentication verdicts.
- `RECEIVED_CHAIN`: Delivery hop count and MTA candidate routing IPs.
- `ATTACHMENT_ANALYSIS`: SHA-256 hashes, file types, and extension hazards.
- `URL_ANALYSIS`: Defanged URLs, raw IP hosts, brand spoofing heuristics.
- `PROMPT_INJECTION`: Adversarial instruction override attempts in email text.
- `IP_REPUTATION`: Public IP network geolocation and ASN metadata.

### EvidenceSeverity
- `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

## 2. API Endpoints

### 2.1 System Health & Readiness

#### `GET /api/health`
Retrieves agent availability, calibration status, and system info.
- **Request:** None
- **Response (200 OK):**
```json
{
  "status": "ok",
  "agents": [
    {
      "agent_id": "ml",
      "name": "Scikit-Learn TF-IDF + Naive Bayes",
      "availability": "AVAILABLE",
      "availability_reason": null,
      "calibration_status": "DEMO_ONLY",
      "details": {
        "trained": true,
        "training_samples": 14,
        "data_origin": "Synthetic demo dataset",
        "note": "Always DEMO_ONLY; never production-grade."
      }
    },
    {
      "agent_id": "gemini",
      "name": "Google Gemini API Adapter",
      "availability": "UNAVAILABLE",
      "availability_reason": "Gemini agent disabled (ENABLE_GEMINI=false).",
      "calibration_status": "UNVALIDATED",
      "details": {
        "enabled": false,
        "model": "gemini-2.5-flash",
        "disclosure": "Sends redacted email data to Google Generative Language API when enabled."
      }
    },
    {
      "agent_id": "laya",
      "name": "Laya System 1 Decision Model",
      "availability": "AVAILABLE",
      "availability_reason": null,
      "calibration_status": "UNVALIDATED",
      "details": {
        "checkpoint": "convaiinnovations/laya-typed-decisions",
        "pinned_revision": "1a793eb568e6718f15941d08f85432581df534e3",
        "device": "cuda",
        "weights_cached": true,
        "note": "Local System 1 typed-decision inference."
      }
    }
  ],
  "system_info": {
    "host": "127.0.0.1",
    "weights_cached": true
  }
}
```

#### `GET /api/ready`
Verifies runtime readiness across all components (including a local Laya typed decision smoke test).
- **Request:** None
- **Response (200 OK):**
```json
{
  "ready": true,
  "timestamp_utc": "2026-11-16T12:00:00Z",
  "agents": {
    "ml": { "ready": true, "trained": true },
    "gemini": { "ready": false, "enabled": false, "disclosure_required": false },
    "laya": { "ready": true, "cached": true, "smoke_test_verdict": "suspicious", "error": null }
  }
}
```

---

### 2.2 Investigation Execution

#### `POST /api/investigate`
Synchronous threat analysis from raw RFC 5322/2822 email text.
- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
```json
{
  "raw_email": "From: security@alert.com\r\nSubject: Urgent...\r\n...",
  "source_label": "ui_text_input",
  "redact_gemini": true
}
```
- **Response (200 OK):** `InvestigationState` (see Schema section below).
- **Errors:**
  - `400 Bad Request`: `{ "detail": "Email size exceeds limit / parse error" }`
  - `500 Internal Server Error`: `{ "detail": "Investigation failed: <error>" }`

#### `POST /api/investigate/file`
Synchronous threat analysis from uploaded `.eml`, `.txt`, or `.msg` file.
- **Request:** `multipart/form-data` with field `file`
- **Response (200 OK):** `InvestigationState`
- **Errors:**
  - `400 Bad Request`: `{ "detail": "Invalid file type..." }`
  - `413 Payload Too Large`: `{ "detail": "File size exceeds maximum allowed limit of 10 MB." }`

#### `POST /api/submit`
Asynchronous job queue submission for large investigations or background processing.
- **Request:** Same as `POST /api/investigate`
- **Response (200 OK):**
```json
{
  "task_id": "TASK-a1b2c3d4e5f6",
  "status": "queued",
  "message": "Investigation job submitted successfully."
}
```

#### `GET /api/progress/{task_id}`
Poll execution progress of an asynchronously submitted job.
- **Request:** None
- **Response (200 OK):**
```json
{
  "status": "processing | completed | failed",
  "progress_pct": 50,
  "stage": "Executing Round 1 multi-agent analysis",
  "investigation_id": "INV-A1B2C3D4",
  "final_verdict": "PHISHING",
  "confidence": 0.95,
  "error": null
}
```
- **Polling Strategy:** Client polls every 750ms while `status === 'processing' || status === 'queued'`. When `status === 'completed'`, navigates to `/investigations/{investigation_id}`.

---

### 2.3 Investigation Audit, Retrieval, Export & Deletion

#### `GET /api/investigations`
List historical investigations ordered newest first.
- **Response (200 OK):** `List[InvestigationSummary]`
```json
[
  {
    "investigation_id": "INV-786015D4",
    "email_sha256": "3cb047913e617d3d...",
    "received_at": "2026-11-16T12:00:00Z",
    "source": "upload:phishing_sample.eml",
    "parser_version": "1.0.0",
    "final_verdict": "PHISHING",
    "confidence": 0.95,
    "partial": false,
    "matched_rule_id": "RULE-01",
    "prompt_injection_detected": false,
    "evidence_count": 7,
    "reports_count": 6
  }
]
```

#### `GET /api/investigations/{investigation_id}`
Retrieves complete investigation state, cryptographically verifying its SHA-256 integrity hash before delivery.
- **Response (200 OK):** `InvestigationState`
- **Errors:**
  - `404 Not Found`: `{ "detail": "Investigation not found" }`
  - `409 Conflict`: `{ "detail": "Investigation state integrity check FAILED: Hash mismatch detected." }`

#### `GET /api/investigations/{investigation_id}/export`
Downloads the verified state as a structured JSON file attachment.
- **Response (200 OK):** File download (`application/json`, header `Content-Disposition: attachment; filename="investigation_INV-XXX.json"`)

#### `DELETE /api/investigations/{investigation_id}`
Permanently deletes an active investigation while recording an audit tombstone.
- **Response (200 OK):**
```json
{
  "status": "deleted",
  "investigation_id": "INV-786015D4",
  "message": "Investigation successfully removed from active store. Tombstone recorded in audit log."
}
```

---

### 2.4 Reference & Documentation Endpoints

#### `GET /api/samples`
Lists available synthetic test samples (`.eml` files).
- **Response (200 OK):** `List[{ "id": string, "filename": string, "category": string }]`

#### `GET /api/samples/{sample_id}`
Retrieves text content of a synthetic sample for testing.
- **Response (200 OK):** `{ "id": string, "content": string }`

#### `GET /api/decision-table`
Returns the 9 documented deterministic consensus rules.
- **Response (200 OK):** `List[{ "rule_id": string, "name": string, "description": string, "outcome": string, "confidence": number, "partial": boolean }]`

---

## 3. Detailed Schemas

### `InvestigationState`
```json
{
  "investigation_id": "INV-A1B2C3D4",
  "email_sha256": "64_hex_chars",
  "received_at": "ISO_UTC_timestamp",
  "source": "string",
  "parser_version": "1.0.0",
  "evidence": [
    {
      "evidence_id": "EV-001",
      "category": "HEADER_MISMATCH | AUTH_RESULTS | ...",
      "description": "string",
      "source": "string",
      "parser_version": "1.0.0",
      "provenance": "string",
      "raw_data": {},
      "defanged_data": {},
      "severity": "INFO | LOW | MEDIUM | HIGH | CRITICAL",
      "created_at": "ISO_UTC_timestamp"
    }
  ],
  "reports": [
    {
      "agent_id": "ml | gemini | laya",
      "round": 1 | 2,
      "protocol_version": "1.0.0",
      "verdict": "PHISHING | SPAM | SUSPICIOUS | LEGITIMATE | ABSTAIN",
      "confidence": 0.85,
      "calibration_status": "UNVALIDATED | DEMO_ONLY | VALIDATED",
      "findings": [
        {
          "text": "string",
          "evidence_ids": ["EV-001", "EV-002"],
          "severity": "CRITICAL"
        }
      ],
      "limitations": [
        "analyzed in 3 chunks; 277 tokens excluded as attachment/markup"
      ],
      "availability": "AVAILABLE | DEGRADED | UNAVAILABLE",
      "availability_reason": null,
      "model_identifiers": {
        "model": "string",
        "pinned_revision": "string",
        "device": "cuda | cpu",
        "chunked": true,
        "num_chunks": 3,
        "excluded_tokens": 277,
        "chunk_record": "analyzed in 3 chunks; 277 tokens excluded as attachment/markup"
      },
      "raw_output": {},
      "revised_from_round1": false
    }
  ],
  "debate_messages": [
    {
      "from_agent": "ml",
      "round": 2,
      "summary": "string",
      "cited_evidence_ids": ["EV-001"],
      "created_at": "ISO_UTC_timestamp"
    }
  ],
  "final_result": {
    "final_verdict": "PHISHING | SPAM | SUSPICIOUS | LEGITIMATE | NEEDS_REVIEW",
    "confidence": 0.95,
    "reasons": ["string"],
    "partial": false,
    "matched_rule_id": "RULE-01",
    "agent_verdicts": { "ml": "PHISHING", "laya": "SUSPICIOUS", "gemini": null },
    "prompt_injection_detected": false,
    "risk_indicator": 95.0,
    "created_at": "ISO_UTC_timestamp"
  },
  "state_hash": "64_hex_chars"
}
```

---

## 4. UI Rules & Display Invariants
1. **Zero Mocking:** No hardcoded sample findings or placeholder scores in production code. Empty means empty.
2. **Defanging:** Defanged URLs (`hxxps://...[.]...`) are rendered as plain text nodes with a "Copy" button. Never clickable hyperlinks.
3. **Prompt Injection:** Renders as a prominent warning banner with evidence details. Never influences verdict display.
4. **Partial Analysis Badge:** Whenever `partial === true` or any agent is unavailable or calibration is unvalidated, a prominent amber "Partial analysis" badge is shown with `reasons[]`.
5. **No Broken Pages:** Runtime response validation (Zod) ensures that schema variations display a recoverable error card with a retry button instead of a white-screen crash.
