"""FastAPI application for the agentsec dashboard."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

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

# Serve frontend build if it exists
_frontend_dist = Path(__file__).parent / "frontend" / "dist"
if _frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")
