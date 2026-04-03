"""Background scan orchestration with SSE event publishing."""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from uuid import uuid4

from agentsec.core.config import ScanConfig
from agentsec.core.finding import Finding
from agentsec.core.loader import load_graph, make_adapter
from agentsec.core.scanner import Scanner, ScanResult
from agentsec.dashboard.store import ScanStore

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    """Tracks a running or completed scan."""

    scan_id: str
    target: str
    status: str = "running"  # running | completed | failed
    task: asyncio.Task | None = None
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    result: ScanResult | None = None
    error: str | None = None


class ScanManager:
    """Manages background scan execution and publishes progress events.

    Each scan runs as an asyncio Task. Progress events are pushed to a
    per-scan asyncio.Queue that SSE endpoints consume.
    """

    def __init__(self, store: ScanStore) -> None:
        self.store = store
        self._jobs: dict[str, ScanJob] = {}

    def start_scan(
        self,
        target: str,
        adapter: str = "langgraph",
        categories: list[str] | None = None,
        vulnerable: bool = True,
        smart: bool = False,
        live: bool = False,
        target_model: str | None = None,
        llm_model: str = "anthropic/claude-sonnet-4.6",
        openrouter_api_key: str | None = None,
        fallback_llm_model: str | None = None,
        detection_confidence_threshold: float = 0.8,
        detection_mode: str = "marker_then_llm",
        pricing: dict | None = None,
    ) -> ScanJob:
        """Launch a scan in the background.

        Args:
            target: Path to the target harness file.
            adapter: Adapter name.
            categories: OWASP categories to scan (None = all).
            vulnerable: Pass to the target builder.
            smart: Enable LLM-powered payloads.
            live: Use real LLMs for target agents.
            target_model: Model ID for live target agents.
            llm_model: Model for smart probes.
            openrouter_api_key: API key for smart/live mode.
            detection_mode: 'marker_then_llm' or 'llm_only'.

        Returns:
            The ScanJob with scan_id and queue for SSE streaming.
        """
        from agentsec.core.config import DetectionMode

        scan_id = uuid4().hex[:12]
        job = ScanJob(scan_id=scan_id, target=target)
        self._jobs[scan_id] = job

        config = ScanConfig(
            categories=categories,
            smart=smart,
            llm_model=llm_model,
            openrouter_api_key=openrouter_api_key,
            fallback_llm_model=fallback_llm_model,
            detection_confidence_threshold=detection_confidence_threshold,
            detection_mode=DetectionMode(detection_mode),
            pricing_data=pricing or {},
        )

        job.task = asyncio.create_task(
            self._run_scan(job, target, adapter, config, vulnerable, live, target_model)
        )
        return job

    def get_job(self, scan_id: str) -> ScanJob | None:
        """Get a running or recently completed job."""
        return self._jobs.get(scan_id)

    async def _run_scan(
        self,
        job: ScanJob,
        target: str,
        adapter_name: str,
        config: ScanConfig,
        vulnerable: bool,
        live: bool,
        target_model: str | None,
    ) -> None:
        """Execute the scan, publishing events to the job's queue."""
        try:
            if config.openrouter_api_key:
                os.environ["OPENROUTER_API_KEY"] = config.openrouter_api_key

            graph = load_graph(target, vulnerable=vulnerable, live=live, target_model=target_model)
            adapter = make_adapter(adapter_name, graph)

            scanner = Scanner(adapter, config)

            def progress_callback(probe_id: str, status: str, finding: Finding | None) -> None:
                event: dict = {"probe_id": probe_id}
                if status == "started":
                    event["event"] = "probe_started"
                    meta = None
                    for cls in scanner._registry.probe_classes():
                        m = cls().metadata()
                        if m.id == probe_id:
                            meta = m
                            break
                    event["probe_name"] = meta.name if meta else probe_id
                else:
                    event["event"] = "probe_completed"
                    if finding:
                        event["status"] = finding.status.value
                        event["severity"] = finding.severity.value
                        event["duration_ms"] = finding.duration_ms
                        event["probe_name"] = finding.probe_name

                job.queue.put_nowait(event)

            result = await scanner.run(target=target, progress_callback=progress_callback)
            job.result = result
            job.status = "completed"

            self.store.save(job.scan_id, result)

            job.queue.put_nowait(
                {
                    "event": "scan_complete",
                    "scan_id": job.scan_id,
                    "total": result.total_probes,
                    "vulnerable": result.vulnerable_count,
                    "resistant": result.resistant_count,
                    "error": result.error_count,
                }
            )

        except Exception as exc:
            logger.exception("Scan %s failed", job.scan_id)
            job.status = "failed"
            job.error = str(exc)
            job.queue.put_nowait(
                {
                    "event": "scan_error",
                    "scan_id": job.scan_id,
                    "error": str(exc),
                }
            )
