"""FastAPI application for the agentsec dashboard."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from agentsec.dashboard.routes import probes, scans, sse, targets
from agentsec.dashboard.scan_manager import ScanManager
from agentsec.dashboard.store import ScanStore

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise shared resources on startup."""
    store = ScanStore()
    manager = ScanManager(store)

    # Inject dependencies into route modules
    scans.configure(manager, store)
    sse.configure(manager)

    yield


app = FastAPI(
    title="agentsec",
    description="Red-team and harden multi-agent LLM systems",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS for Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(targets.router)
app.include_router(probes.router)
app.include_router(scans.router)
app.include_router(sse.router)

# Serve frontend build with SPA fallback
_frontend_dist = Path(__file__).parent / "frontend" / "dist"


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    """Serve the SPA index.html for all non-API routes, static assets directly."""
    _not_built_msg = {
        "message": "Dashboard frontend not built. Run: "
        "cd src/agentsec/dashboard/frontend && npm run build"
    }
    if not _frontend_dist.exists():
        return _not_built_msg
    dist_resolved = _frontend_dist.resolve()
    # Serve static assets directly if they exist (JS, CSS, images)
    # Resolve to prevent path traversal (e.g. ../../etc/passwd)
    static_file = (dist_resolved / full_path).resolve()
    if static_file.is_file() and dist_resolved in static_file.parents:
        return FileResponse(static_file)
    # Fall back to index.html for SPA routing
    index = dist_resolved / "index.html"
    if index.exists():
        return FileResponse(index)
    return _not_built_msg
