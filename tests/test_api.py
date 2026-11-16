"""Tests for FastAPI backend routes and API behavior (Phase 4):
- Health & Readiness endpoints (/health, /ready)
- Synchronous & Asynchronous investigation flows (/investigate, /submit, /progress)
- Investigation retrieval with integrity check (/investigations/{id})
- Audit listing (/investigations), JSON export (/export), and user-initiated deletion (/investigations/{id})
- Input validation and limits
"""
import asyncio
import pytest
from httpx import ASGITransport, AsyncClient
from backend.app import app


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        agents = {a["agent_id"]: a for a in data["agents"]}
        assert "ml" in agents
        assert "gemini" in agents
        assert "laya" in agents


@pytest.mark.asyncio
async def test_ready_endpoint():
    """Verify readiness check endpoint tests all agents and runs Laya smoke test."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert "ready" in data
        assert "agents" in data
        assert "ml" in data["agents"]
        assert "gemini" in data["agents"]
        assert "laya" in data["agents"]
        assert data["agents"]["ml"]["ready"] is True
        # If weights are cached locally, Laya local smoke test succeeds
        if data["agents"]["laya"]["cached"]:
            assert data["agents"]["laya"]["ready"] is True


@pytest.mark.asyncio
async def test_samples_endpoints():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/samples")
        assert resp.status_code == 200
        samples = resp.json()
        assert len(samples) >= 4
        sample_ids = [s["id"] for s in samples]
        assert "sample_phishing.eml" in sample_ids

        # Fetch individual sample content
        sample_resp = await ac.get("/api/samples/sample_phishing.eml")
        assert sample_resp.status_code == 200
        assert "PayPal" in sample_resp.json()["content"]


@pytest.mark.asyncio
async def test_decision_table_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/decision-table")
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) >= 8
        rule_ids = [r["rule_id"] for r in rules]
        assert "RULE-01" in rule_ids
        assert "RULE-04" in rule_ids


@pytest.mark.asyncio
async def test_investigate_text_and_retrieve():
    sample_text = """From: attacker@evil.org
To: victim@company.com
Subject: Test phishing email
Content-Type: text/plain

Please verify credentials at http://198.51.100.12/login
"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        post_resp = await ac.post("/api/investigate", json={"raw_email": sample_text})
        assert post_resp.status_code == 200
        inv_data = post_resp.json()
        inv_id = inv_data["investigation_id"]
        assert inv_id.startswith("INV-")
        assert len(inv_data["evidence"]) >= 1
        assert len(inv_data["reports"]) == 6  # 3 in round 1, 3 in round 2
        assert inv_data["final_result"] is not None

        # Retrieve investigation by ID and verify integrity
        get_resp = await ac.get(f"/api/investigations/{inv_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["investigation_id"] == inv_id


@pytest.mark.asyncio
async def test_async_submit_and_progress():
    """Verify async submission and progress polling."""
    sample_text = """From: security@trustedbank.com
To: customer@example.com
Subject: Monthly Statement Ready
Content-Type: text/plain

Your monthly statement is ready for review in your online banking portal.
"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        submit_resp = await ac.post("/api/submit", json={"raw_email": sample_text})
        assert submit_resp.status_code == 200
        submit_data = submit_resp.json()
        task_id = submit_data["task_id"]
        assert task_id.startswith("TASK-")

        # Poll progress
        for _ in range(30):
            prog_resp = await ac.get(f"/api/progress/{task_id}")
            assert prog_resp.status_code == 200
            prog_data = prog_resp.json()
            if prog_data["status"] == "completed":
                assert prog_data["progress_pct"] == 100
                assert "investigation_id" in prog_data
                break
            await asyncio.sleep(0.5)
        else:
            pytest.fail("Async investigation timed out without completing")


@pytest.mark.asyncio
async def test_audit_list_export_delete_lifecycle():
    """Verify investigation listing, JSON export, and user-initiated deletion."""
    sample_text = """From: ops@example.com
To: user@example.com
Subject: Benign Routine Communication
Content-Type: text/plain

All systems operating within normal parameters.
"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create an investigation
        res = await ac.post("/api/investigate", json={"raw_email": sample_text})
        assert res.status_code == 200
        inv_id = res.json()["investigation_id"]

        # 2. List investigations
        list_resp = await ac.get("/api/investigations")
        assert list_resp.status_code == 200
        inv_list = list_resp.json()
        matching = [inv for inv in inv_list if inv["investigation_id"] == inv_id]
        assert len(matching) == 1

        # 3. Export JSON
        export_resp = await ac.get(f"/api/investigations/{inv_id}/export")
        assert export_resp.status_code == 200
        assert export_resp.headers["content-type"].startswith("application/json")
        export_data = export_resp.json()
        assert "export_metadata" in export_data
        assert export_data["export_metadata"]["state_hash_verified"] is True
        assert export_data["investigation"]["investigation_id"] == inv_id

        # 4. User-initiated delete
        del_resp = await ac.delete(f"/api/investigations/{inv_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "deleted"

        # 5. Accessing deleted investigation returns 404
        get_again = await ac.get(f"/api/investigations/{inv_id}")
        assert get_again.status_code == 404


@pytest.mark.asyncio
async def test_invalid_file_upload_rejected():
    """Verify invalid file extensions are rejected with 400 Bad Request."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        files = {"file": ("malicious.exe", b"MZ fake executable content", "application/octet-stream")}
        resp = await ac.post("/api/investigate/file", files=files)
        assert resp.status_code == 400
        assert "Invalid file type" in resp.json()["detail"]
