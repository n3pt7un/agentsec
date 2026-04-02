"""Server-Sent Events endpoint for live scan progress."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/scans", tags=["sse"])

_scan_manager = None


def configure(scan_manager) -> None:
    """Inject scan manager from app lifespan."""
    global _scan_manager
    _scan_manager = scan_manager


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    """Stream scan progress as Server-Sent Events."""
    job = _scan_manager.get_job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found or not running")

    async def event_generator():
        while True:
            try:
                event = await asyncio.wait_for(job.queue.get(), timeout=30.0)
                event_type = event.pop("event", "message")
                data = json.dumps(event)
                yield f"event: {event_type}\ndata: {data}\n\n"

                if event_type in ("scan_complete", "scan_error"):
                    break
            except TimeoutError:
                # Send keepalive
                yield ": keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
