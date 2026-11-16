"""FastAPI Application entry point for Email Threat Detection Platform.

Configured with:
- Strict 127.0.0.1 / localhost bindings
- Explicit CORS allowlist
- Structured request logging (IDs and hashes only, no email content or secrets)
"""
import logging
import os
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.routes import router

# Configure structured logging: IDs and hashes only, NEVER email body content or secrets
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("email_threat_platform")

app = FastAPI(
    title="Email Threat Detection Platform",
    description="Multi-agent email threat detection with typed decisions, deterministic parsing, and consensus engine.",
    version="1.0.0",
)

# Explicit CORS: allow only local development origins
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests_safely(request: Request, call_next):
    """Structured request logger ensuring zero secret and zero email body leakage."""
    start_time = time.time()
    path = request.url.path
    method = request.method
    client_host = request.client.host if request.client else "unknown"

    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000

    # Log only method, path, status, and duration (never headers or body)
    logger.info(
        f"HTTP {method} {path} status={response.status_code} "
        f"duration={duration_ms:.1f}ms client={client_host}"
    )
    return response


app.include_router(router, prefix="/api")

# Serve frontend build if present
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.isdir(frontend_dist):
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.isdir(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        if full_path.startswith("api"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        target_file = os.path.join(frontend_dist, full_path)
        if os.path.isfile(target_file):
            return FileResponse(target_file)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    async def root():
        return {
            "service": "Email Threat Detection Platform",
            "status": "operational",
            "binding": "127.0.0.1",
            "docs_url": "/docs",
        }
