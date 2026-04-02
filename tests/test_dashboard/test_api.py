"""Integration tests for the dashboard API endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentsec.dashboard.app import app


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
