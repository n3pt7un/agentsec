"""Scan CRUD endpoints."""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from agentsec.reporters.json_report import generate_json
from agentsec.reporters.markdown import generate_markdown
from agentsec.reporters.sarif import generate_sarif

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
    probes: list[str] | None = None
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


class ExportRequest(BaseModel):
    """Request body for batch scan export."""

    scan_ids: list[str] | Literal["all"]
    format: Literal["md", "json", "sarif"]


@router.post("")
async def create_scan(request: ScanRequest) -> dict:
    """Trigger a new scan in the background."""
    job = _scan_manager.start_scan(
        target=request.target,
        adapter=request.adapter,
        categories=request.categories,
        probes=request.probes,
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


@router.post("/export")
async def batch_export_scans(request: ExportRequest) -> StreamingResponse:
    """Export multiple scans as a ZIP archive."""
    if request.scan_ids == "all":
        summaries = _store.list_scans(limit=10_000)
        scan_ids = [s["scan_id"] for s in summaries]
    else:
        scan_ids = request.scan_ids

    if request.format == "md":
        generate = generate_markdown
        ext = "md"
    elif request.format == "sarif":
        generate = generate_sarif
        ext = "sarif"
    else:
        generate = generate_json
        ext = "json"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for scan_id in scan_ids:
            result = _store.load(scan_id)
            if result is None:
                continue
            zf.writestr(f"scan-{scan_id}.{ext}", generate(result))

    buf.seek(0)
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    filename = f"agentsec-export-{date_str}.zip"

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("")
async def list_scans(limit: int = 50, offset: int = 0) -> dict:
    """List completed scans."""
    scans = _store.list_scans(limit=limit, offset=offset)
    return {"scans": scans, "total": len(scans)}


@router.get("/{scan_id}/export")
async def export_scan(scan_id: str, format: str = "md") -> Response:
    """Export a single scan result as a downloadable file."""
    if format not in ("md", "json", "sarif"):
        raise HTTPException(status_code=400, detail="format must be 'md', 'json', or 'sarif'")

    job = _scan_manager.get_job(scan_id)
    result = job.result if job and job.result else _store.load(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if format == "md":
        content = generate_markdown(result)
        media_type = "text/markdown"
        filename = f"scan-{scan_id}.md"
    elif format == "sarif":
        content = generate_sarif(result)
        media_type = "application/sarif+json"
        filename = f"scan-{scan_id}.sarif"
    else:
        content = generate_json(result)
        media_type = "application/json"
        filename = f"scan-{scan_id}.json"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
