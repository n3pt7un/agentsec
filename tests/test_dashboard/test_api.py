"""Integration tests for the dashboard API endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from agentsec.core.finding import Finding, FindingStatus, OWASPCategory, Remediation, Severity
from agentsec.core.scanner import ScanResult
from agentsec.dashboard.app import app


def _make_export_result() -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target="tests/targets/email_automation_harness.py",
        findings=[
            Finding(
                probe_id="ASI01-TEST",
                probe_name="Test Probe",
                category=OWASPCategory.ASI01,
                status=FindingStatus.VULNERABLE,
                severity=Severity.HIGH,
                description="test vulnerability",
                remediation=Remediation(summary="fix it"),
            )
        ],
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        total_probes=1,
        vulnerable_count=1,
        resistant_count=0,
        error_count=0,
    )


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestProbesEndpoint:
    def test_list_probes(self, client):
        resp = client.get("/api/probes")
        assert resp.status_code == 200
        data = resp.json()
        assert "probes" in data
        assert len(data["probes"]) >= 6
        probe = data["probes"][0]
        assert "id" in probe
        assert "category" in probe
        assert "severity" in probe


class TestTargetsEndpoint:
    def test_list_targets(self, client):
        resp = client.get("/api/targets?directory=tests/targets")
        assert resp.status_code == 200
        data = resp.json()
        assert "targets" in data
        assert len(data["targets"]) >= 1

    def test_nonexistent_directory(self, client):
        resp = client.get("/api/targets?directory=/nonexistent")
        assert resp.status_code == 200
        assert resp.json()["targets"] == []


class TestScansEndpoint:
    def test_list_scans_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data

    def test_get_nonexistent_scan(self, client):
        resp = client.get("/api/scans/nonexistent")
        assert resp.status_code == 404

    def test_delete_nonexistent_scan(self, client):
        resp = client.delete("/api/scans/nonexistent")
        assert resp.status_code == 404

    def test_create_scan_returns_scan_id(self, client):
        resp = client.post(
            "/api/scans",
            json={
                "target": "tests/targets/email_automation_harness.py",
                "adapter": "langgraph",
                "vulnerable": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "running"
        assert "stream_url" in data


class TestExportEndpoints:
    def test_export_individual_not_found(self, client):
        resp = client.get("/api/scans/nonexistent-xyz/export?format=md")
        assert resp.status_code == 404

    def test_export_individual_invalid_format(self, client):
        resp = client.get("/api/scans/nonexistent-xyz/export?format=bad")
        assert resp.status_code == 400

    def test_export_individual_md(self, client, monkeypatch, tmp_path):
        import agentsec.dashboard.routes.scans as scans_mod
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("export-md-001", _make_export_result())
        monkeypatch.setattr(scans_mod, "_store", store)

        resp = client.get("/api/scans/export-md-001/export?format=md")
        assert resp.status_code == 200
        assert "text/markdown" in resp.headers["content-type"]
        assert 'filename="scan-export-md-001.md"' in resp.headers["content-disposition"]
        assert "# agentsec Scan Report" in resp.text

    def test_export_individual_json(self, client, monkeypatch, tmp_path):
        import agentsec.dashboard.routes.scans as scans_mod
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("export-json-001", _make_export_result())
        monkeypatch.setattr(scans_mod, "_store", store)

        resp = client.get("/api/scans/export-json-001/export?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]
        assert 'filename="scan-export-json-001.json"' in resp.headers["content-disposition"]
        data = resp.json()
        assert "scan_result" in data
        assert "metadata" in data

    def test_batch_export_empty_list(self, client):
        import io
        import zipfile

        resp = client.post("/api/scans/export", json={"scan_ids": [], "format": "md"})
        assert resp.status_code == 200
        assert "application/zip" in resp.headers["content-type"]
        buf = io.BytesIO(resp.content)
        with zipfile.ZipFile(buf) as zf:
            assert zf.namelist() == []

    def test_batch_export_selected(self, client, monkeypatch, tmp_path):
        import io
        import zipfile

        import agentsec.dashboard.routes.scans as scans_mod
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("batch-001", _make_export_result())
        monkeypatch.setattr(scans_mod, "_store", store)

        resp = client.post(
            "/api/scans/export",
            json={"scan_ids": ["batch-001"], "format": "md"},
        )
        assert resp.status_code == 200
        assert "application/zip" in resp.headers["content-type"]
        buf = io.BytesIO(resp.content)
        with zipfile.ZipFile(buf) as zf:
            assert "scan-batch-001.md" in zf.namelist()
            content = zf.read("scan-batch-001.md").decode()
            assert "# agentsec Scan Report" in content

    def test_batch_export_all(self, client, monkeypatch, tmp_path):
        import io
        import zipfile

        import agentsec.dashboard.routes.scans as scans_mod
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("all-001", _make_export_result())
        store.save("all-002", _make_export_result())
        monkeypatch.setattr(scans_mod, "_store", store)

        resp = client.post(
            "/api/scans/export",
            json={"scan_ids": "all", "format": "json"},
        )
        assert resp.status_code == 200
        buf = io.BytesIO(resp.content)
        with zipfile.ZipFile(buf) as zf:
            names = zf.namelist()
            assert len(names) == 2
            assert "scan-all-001.json" in names
            assert "scan-all-002.json" in names

    def test_batch_export_skips_missing_ids(self, client, monkeypatch, tmp_path):
        import io
        import zipfile

        import agentsec.dashboard.routes.scans as scans_mod
        from agentsec.dashboard.store import ScanStore

        store = ScanStore(base_dir=tmp_path)
        store.save("exists-001", _make_export_result())
        monkeypatch.setattr(scans_mod, "_store", store)

        resp = client.post(
            "/api/scans/export",
            json={"scan_ids": ["exists-001", "does-not-exist"], "format": "md"},
        )
        assert resp.status_code == 200
        buf = io.BytesIO(resp.content)
        with zipfile.ZipFile(buf) as zf:
            assert zf.namelist() == ["scan-exists-001.md"]
