"""FastAPI routes for the Email Threat Detection Platform.

Provides endpoints for:
- Health and per-agent readiness inspection (/health, /ready)
- Synchronous and asynchronous investigation (/investigate, /investigate/file, /submit, /progress)
- Cryptographically verified investigation retrieval, audit listing, JSON export, and deletion
- Synthetic test samples and documented consensus decision table
"""
import asyncio
from datetime import datetime, timezone
import hashlib
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field

from consensus.decision_table import DECISION_TABLE
from consensus.engine import ThreatInvestigationEngine
from core.audit import audit_store
from core.models import (
    AvailabilityStatus,
    CalibrationStatus,
    ConsensusVerdict,
    Verdict,
)
from core.state import InvestigationState
from agents.laya_agent import PINNED_CHECKPOINT, PINNED_REVISION, is_laya_model_cached

router = APIRouter()
engine = ThreatInvestigationEngine()

# In-memory storage for investigations during session
INVESTIGATION_STORE: Dict[str, InvestigationState] = {}
# Async job progress store
ASYNC_PROGRESS: Dict[str, Dict[str, Any]] = {}

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "samples"))
MAX_EMAIL_TEXT_BYTES = 10 * 1024 * 1024  # 10 MB


class InvestigateTextRequest(BaseModel):
    raw_email: str = Field(..., min_length=10, max_length=MAX_EMAIL_TEXT_BYTES, description="Raw RFC 5322/2822 email text")
    source_label: str = Field(default="text_input")
    redact_gemini: bool = Field(default=True)


class AgentStatusInfo(BaseModel):
    agent_id: str
    name: str
    availability: AvailabilityStatus
    availability_reason: Optional[str]
    calibration_status: CalibrationStatus
    details: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    agents: List[AgentStatusInfo]
    system_info: Dict[str, Any]


# =====================================================================
# 1. Health & Readiness Endpoints
# =====================================================================

@router.get("/health", response_model=HealthResponse)
async def get_health_status():
    """Retrieve operational status, availability, and privacy settings of all agents."""
    agents_info = []

    # 1. ML Agent
    ml_agent = engine.get_agent_by_id("ml")
    if ml_agent:
        avail, reason = ml_agent.check_availability()
        agents_info.append(AgentStatusInfo(
            agent_id="ml",
            name="Scikit-Learn TF-IDF + Naive Bayes",
            availability=avail,
            availability_reason=reason,
            calibration_status=CalibrationStatus.DEMO_ONLY,
            details={
                "trained": ml_agent.is_trained,
                "training_samples": getattr(ml_agent, "sample_count", 14),
                "data_origin": getattr(ml_agent, "data_origin", "Synthetic demo dataset"),
                "note": "Always DEMO_ONLY; never production-grade.",
            },
        ))

    # 2. Gemini Agent
    gemini_agent = engine.get_agent_by_id("gemini")
    if gemini_agent:
        avail, reason = gemini_agent.check_availability()
        agents_info.append(AgentStatusInfo(
            agent_id="gemini",
            name="Google Gemini API Adapter",
            availability=avail,
            availability_reason=reason,
            calibration_status=CalibrationStatus.UNVALIDATED,
            details={
                "enabled": gemini_agent.enable_gemini,
                "model": gemini_agent.model_name,
                "disclosure": "Sends redacted email data to Google Generative Language API when enabled.",
            },
        ))

    # 3. Laya Agent
    laya_agent = engine.get_agent_by_id("laya")
    if laya_agent:
        avail, reason = laya_agent.check_availability()
        agents_info.append(AgentStatusInfo(
            agent_id="laya",
            name="Laya System 1 Decision Model",
            availability=avail,
            availability_reason=reason,
            calibration_status=CalibrationStatus.UNVALIDATED,
            details={
                "checkpoint": PINNED_CHECKPOINT,
                "pinned_revision": PINNED_REVISION,
                "device": laya_agent.device,
                "weights_cached": is_laya_model_cached(),
                "note": "Local System 1 typed-decision inference (CPU fallback). Calibration UNVALIDATED for email.",
            },
        ))

    return HealthResponse(
        status="ok",
        agents=agents_info,
        system_info={
            "host": "127.0.0.1",
            "weights_cached": is_laya_model_cached(),
        },
    )


@router.get("/ready")
async def get_readiness_status():
    """Verify system readiness across all components.
    
    Laya reports ready only after a real local typed decision test succeeds.
    """
    ml_agent = engine.get_agent_by_id("ml")
    laya_agent = engine.get_agent_by_id("laya")
    gemini_agent = engine.get_agent_by_id("gemini")

    ml_ready = bool(ml_agent and ml_agent.is_trained)
    gemini_ready = bool(gemini_agent and gemini_agent.enable_gemini and gemini_agent.api_key)

    laya_ready = False
    laya_details = {"cached": is_laya_model_cached(), "error": None}

    if laya_agent and is_laya_model_cached():
        # Ensure weights are resident
        if laya_agent.agent_instance is None:
            laya_agent._load_model_weights()

        if laya_agent.agent_instance is not None:
            try:
                # Real local typed decision readiness smoke test
                test_state = {"subject": "Readiness Verification", "body": "Verify local resident decision inference."}
                res = laya_agent.agent_instance.predict(test_state, laya_agent.questions_config)
                answers = res.get("answers", res) if isinstance(res, dict) else {}
                if answers and "verdict" in answers:
                    laya_ready = True
                    verdict_dict = answers.get("verdict", {})
                    laya_details["smoke_test_verdict"] = verdict_dict.get("choice") or verdict_dict.get("answer")
            except Exception as e:
                laya_details["error"] = f"Local smoke test failed: {e}"
        else:
            laya_details["error"] = laya_agent.load_error or "Model failed to load into memory."
    else:
        laya_details["error"] = "Model weights not downloaded or Laya agent uninitialized."

    # System is ready if required local analytical components (ML + Laya) are operational
    system_ready = ml_ready and (laya_ready or not is_laya_model_cached())

    return {
        "ready": system_ready,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "agents": {
            "ml": {
                "ready": ml_ready,
                "trained": ml_agent.is_trained if ml_agent else False,
            },
            "gemini": {
                "ready": gemini_ready,
                "enabled": gemini_agent.enable_gemini if gemini_agent else False,
                "disclosure_required": bool(gemini_agent and gemini_agent.enable_gemini),
            },
            "laya": {
                "ready": laya_ready,
                **laya_details,
            },
        },
    }


# =====================================================================
# 2. Investigation Execution Endpoints
# =====================================================================

@router.post("/investigate", response_model=InvestigationState)
async def investigate_raw_text(payload: InvestigateTextRequest):
    """Run full threat analysis pipeline on raw email text synchronously."""
    try:
        state = await engine.run_investigation(payload.raw_email, source=payload.source_label)
        INVESTIGATION_STORE[state.investigation_id] = state
        audit_store.store(state)
        return state
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Investigation failed: {e}")


@router.post("/investigate/file", response_model=InvestigationState)
async def investigate_file_upload(file: UploadFile = File(...)):
    """Run full threat analysis on uploaded .eml or .txt email file."""
    if not (file.filename.endswith(".eml") or file.filename.endswith(".txt") or file.filename.endswith(".msg")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Only .eml, .txt, and .msg files are accepted.",
        )

    content = await file.read()
    if len(content) > MAX_EMAIL_TEXT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum allowed limit of {MAX_EMAIL_TEXT_BYTES // (1024*1024)} MB.",
        )

    try:
        state = await engine.run_investigation(content, source=f"upload:{file.filename}")
        INVESTIGATION_STORE[state.investigation_id] = state
        audit_store.store(state)
        return state
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Investigation failed: {e}")


async def _run_async_investigation_task(task_id: str, raw_email: str, source: str):
    """Worker task executing async investigation and updating progress."""
    try:
        ASYNC_PROGRESS[task_id] = {
            "status": "processing",
            "progress_pct": 20,
            "stage": "Parsing email headers, attachments, URLs, and authentication",
        }
        await asyncio.sleep(0.05)

        ASYNC_PROGRESS[task_id] = {
            "status": "processing",
            "progress_pct": 50,
            "stage": "Executing Round 1 multi-agent analysis",
        }
        state = await engine.run_investigation(raw_email, source=source)

        INVESTIGATION_STORE[state.investigation_id] = state
        audit_store.store(state)

        ASYNC_PROGRESS[task_id] = {
            "status": "completed",
            "progress_pct": 100,
            "stage": "Consensus resolved and state cryptographically hashed",
            "investigation_id": state.investigation_id,
            "final_verdict": state.final_result.final_verdict.value if state.final_result else None,
            "confidence": state.final_result.confidence if state.final_result else None,
        }
    except Exception as e:
        ASYNC_PROGRESS[task_id] = {
            "status": "failed",
            "progress_pct": 100,
            "stage": "Error during analysis",
            "error": str(e),
        }


@router.post("/submit")
async def submit_investigation_async(payload: InvestigateTextRequest, background_tasks: BackgroundTasks):
    """Submit an email investigation asynchronously for polling."""
    task_id = f"TASK-{uuid.uuid4().hex[:12]}"
    ASYNC_PROGRESS[task_id] = {
        "status": "queued",
        "progress_pct": 0,
        "stage": "Task queued for processing",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    background_tasks.add_task(_run_async_investigation_task, task_id, payload.raw_email, payload.source_label)
    return {
        "task_id": task_id,
        "status": "queued",
        "message": "Investigation job submitted successfully.",
    }


@router.get("/progress/{task_id}")
async def get_investigation_progress(task_id: str):
    """Poll execution progress of an asynchronously submitted investigation."""
    info = ASYNC_PROGRESS.get(task_id)
    if not info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task ID not found")
    return info


# =====================================================================
# 3. Investigation Audit, Retrieval, Export, & Deletion
# =====================================================================

@router.get("/investigations")
async def list_investigations():
    """List all recorded investigations with summary metrics from audit store."""
    return audit_store.list_all()


@router.get("/investigations/{investigation_id}", response_model=InvestigationState)
async def get_investigation(investigation_id: str):
    """Retrieve an existing investigation and verify its cryptographic integrity."""
    state = audit_store.get(investigation_id) or INVESTIGATION_STORE.get(investigation_id)
    if not state:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    if not state.verify_integrity():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Investigation state integrity check FAILED: Hash mismatch detected.",
        )
    return state


@router.get("/investigations/{investigation_id}/export")
async def export_investigation_json(investigation_id: str):
    """Export complete investigation state as structured JSON with audit metadata."""
    try:
        json_content = audit_store.export_json(investigation_id)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="investigation_{investigation_id}.json"'},
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")


@router.delete("/investigations/{investigation_id}")
async def delete_investigation(investigation_id: str):
    """User-initiated deletion of an investigation with permanent tombstone audit log."""
    success = audit_store.delete(investigation_id, reason="User initiated deletion via API")
    if not success and investigation_id not in INVESTIGATION_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    INVESTIGATION_STORE.pop(investigation_id, None)
    return {
        "status": "deleted",
        "investigation_id": investigation_id,
        "message": "Investigation successfully removed from active store. Tombstone recorded in audit log.",
    }


# =====================================================================
# 4. Samples & Decision Table Endpoints
# =====================================================================

@router.get("/samples")
async def list_sample_emails():
    """List available synthetic test sample emails."""
    samples = []
    if os.path.isdir(SAMPLES_DIR):
        for fn in sorted(os.listdir(SAMPLES_DIR)):
            if fn.endswith(".eml"):
                label = fn.replace("sample_", "").replace(".eml", "").upper()
                samples.append({
                    "id": fn,
                    "filename": fn,
                    "category": label,
                })
    return samples


@router.get("/samples/{sample_id}")
async def get_sample_content(sample_id: str):
    """Load text content of a synthetic sample email for quick testing."""
    safe_name = os.path.basename(sample_id)
    target_path = os.path.join(SAMPLES_DIR, safe_name)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found")

    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    return {
        "id": safe_name,
        "content": content,
    }


@router.get("/decision-table")
async def get_decision_table():
    """Get the full documented consensus decision table rules."""
    rules_data = []
    for r in DECISION_TABLE:
        rules_data.append({
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "outcome": r.outcome.value,
            "confidence": r.confidence,
            "partial": r.partial,
        })
    return rules_data
