"""Tests for the JSON file scan store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agentsec.core.finding import Finding, FindingStatus, OWASPCategory, Remediation, Severity
from agentsec.core.scanner import ScanResult


def _make_result(scan_id: str = "test-001", target: str = "test_harness") -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target=target,
        findings=[
            Finding(
                probe_id="ASI01-TEST",
                probe_name="Test",
                category=OWASPCategory.ASI01,
                status=FindingStatus.VULNERABLE,
                severity=Severity.HIGH,
                description="test",
                remediation=Remediation(summary="fix"),
            )
        ],
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        total_probes=1,
        vulnerable_count=1,
        resistant_count=0,
        error_count=0,
    )


class TestStore:
    def test_save_and_load(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        result = _make_result()
        store.save("test-001", result)
        loaded = store.load("test-001")
        assert loaded.target == "test_harness"
        assert len(loaded.findings) == 1

    def test_load_nonexistent_returns_none(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        assert store.load("nonexistent") is None

    def test_list_scans_returns_summaries(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("scan-a", _make_result("scan-a", "target_a"))
        store.save("scan-b", _make_result("scan-b", "target_b"))
        scans = store.list_scans()
        assert len(scans) == 2

    def test_list_scans_ordered_by_date_desc(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("old", _make_result("old"))
        store.save("new", _make_result("new"))
        scans = store.list_scans()
        assert scans[0]["scan_id"] in ("old", "new")

    def test_list_scans_with_limit(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        for i in range(5):
            store.save(f"scan-{i}", _make_result(f"scan-{i}"))
        scans = store.list_scans(limit=3)
        assert len(scans) == 3

    def test_delete_removes_file(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("to-delete", _make_result())
        assert store.delete("to-delete") is True
        assert store.load("to-delete") is None

    def test_delete_nonexistent_returns_false(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        assert store.delete("nope") is False

    def test_save_creates_directory(self, tmp_path):
        from agentsec.dashboard.store import ScanStore

        nested = tmp_path / "deep" / "nested"
        store = ScanStore(base_dir=nested)
        store.save("test", _make_result())
        assert store.load("test") is not None
