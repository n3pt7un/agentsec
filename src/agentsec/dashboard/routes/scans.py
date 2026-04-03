"""Scan CRUD endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/scans", tags=["scans"])

# These will be set by app.py during lifespan
_scan_manager = None
_store = None


def configure(scan_manager, store) -> None:
    """Inject dependencies from app lifespan."""
    global _scan_manager, _store
    _scan_manager = scan_manager
    _store = store


class ScanRequest(BaseModel):
    """Request body for triggering a new scan."""

    target: str
    adapter: str = "langgraph"
    categories: list[str] | None = None
    vulnerable: bool = True
    smart: bool = False
    live: bool = False
    target_model: str | None = None
    llm_model: str = "anthropic/claude-sonnet-4.6"
    openrouter_api_key: str | None = None
    fallback_llm_model: str | None = None
    detection_confidence_threshold: float = 0.8
    detection_mode: str = "marker_then_llm"
    pricing: dict[str, dict[str, float]] = {}


@router.post("")
async def create_scan(request: ScanRequest) -> dict:
    """Trigger a new scan in the background."""
    job = _scan_manager.start_scan(
        target=request.target,
        adapter=request.adapter,
        categories=request.categories,
        vulnerable=request.vulnerable,
        smart=request.smart,
        live=request.live,
        target_model=request.target_model,
        llm_model=request.llm_model,
        openrouter_api_key=request.openrouter_api_key,
        fallback_llm_model=request.fallback_llm_model,
        detection_confidence_threshold=request.detection_confidence_threshold,
        detection_mode=request.detection_mode,
        pricing=request.pricing,
    )
    return {
        "scan_id": job.scan_id,
        "status": job.status,
        "stream_url": f"/api/scans/{job.scan_id}/stream",
    }


@router.get("")
async def list_scans(limit: int = 50, offset: int = 0) -> dict:
    """List completed scans."""
    scans = _store.list_scans(limit=limit, offset=offset)
    return {"scans": scans, "total": len(scans)}


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    """Get full scan result."""
    # Check running jobs first
    job = _scan_manager.get_job(scan_id)
    if job and job.result:
        return job.result.model_dump(mode="json")

    result = _store.load(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return result.model_dump(mode="json")


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """Delete a scan result."""
    if not _store.delete(scan_id):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {"deleted": True, "scan_id": scan_id}
