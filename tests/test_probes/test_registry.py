"""Tests for ProbeRegistry auto-discovery and manual registration."""

import pytest

from agentsec.core.exceptions import RegistryError
from agentsec.core.finding import OWASPCategory, Severity
from agentsec.core.probe_base import BaseProbe, ProbeMetadata
from agentsec.probes.registry import ProbeRegistry

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_probe_cls(probe_id: str) -> type[BaseProbe]:
    """Dynamically create a minimal concrete BaseProbe subclass."""
    from agentsec.core.finding import Remediation

    class _Probe(BaseProbe):
        def metadata(self) -> ProbeMetadata:
            return ProbeMetadata(
                id=probe_id,
                name=f"Test probe {probe_id}",
                category=OWASPCategory.ASI01,
                default_severity=Severity.HIGH,
                description="Test probe",
            )

        def remediation(self) -> Remediation:
            return Remediation(summary="Fix it")

        async def attack(self, adapter):
            raise NotImplementedError

    # Give each generated class a unique __qualname__ so the registry can
    # distinguish them if we create two with different IDs.
    _Probe.__qualname__ = f"_Probe_{probe_id}"
    return _Probe


# ------------------------------------------------------------------
# Auto-discovery
# ------------------------------------------------------------------


class TestDiscover:
    """Tests for discover_probes() scanning the probes/ package."""

    def test_discover_finds_indirect_inject(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI01-INDIRECT-INJECT" in registry

    def test_discover_populates_registry(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert len(registry) >= 1

    def test_discover_is_idempotent(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        count_after_first = len(registry)
        registry.discover_probes()
        assert len(registry) == count_after_first

    def test_list_all_returns_metadata(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        metas = registry.list_all()
        assert len(metas) >= 1
        for meta in metas:
            assert isinstance(meta, ProbeMetadata)
            assert meta.id
            assert meta.name

    def test_indirect_inject_metadata(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        meta = registry.get("ASI01-INDIRECT-INJECT")().metadata()
        assert meta.category == OWASPCategory.ASI01
        assert meta.default_severity == Severity.CRITICAL
        assert "injection" in meta.tags


# ------------------------------------------------------------------
# Manual registration
# ------------------------------------------------------------------


class TestRegister:
    """Tests for manually registering probes."""

    def test_register_adds_probe(self):
        registry = ProbeRegistry()
        cls = _make_probe_cls("TEST-PROBE-001")
        registry.register(cls)
        assert "TEST-PROBE-001" in registry

    def test_register_same_class_twice_is_ok(self):
        registry = ProbeRegistry()
        cls = _make_probe_cls("TEST-PROBE-002")
        registry.register(cls)
        registry.register(cls)  # identical class — no error
        assert len(registry) == 1

    def test_register_duplicate_id_different_class_raises(self):
        registry = ProbeRegistry()
        cls_a = _make_probe_cls("TEST-PROBE-003")
        cls_b = _make_probe_cls("TEST-PROBE-003")
        # Make them distinct classes so the registry can tell them apart
        cls_b.__qualname__ = "SomeOtherProbe"
        registry.register(cls_a)
        with pytest.raises(RegistryError, match="TEST-PROBE-003"):
            registry.register(cls_b)


# ------------------------------------------------------------------
# Lookup helpers
# ------------------------------------------------------------------


class TestLookup:
    """Tests for get(), probe_classes(), list_all(), __len__, __contains__."""

    def test_get_returns_class(self):
        registry = ProbeRegistry()
        cls = _make_probe_cls("TEST-LOOKUP-001")
        registry.register(cls)
        assert registry.get("TEST-LOOKUP-001") is cls

    def test_get_missing_returns_none(self):
        registry = ProbeRegistry()
        assert registry.get("DOES-NOT-EXIST") is None

    def test_probe_classes_returns_list(self):
        registry = ProbeRegistry()
        cls = _make_probe_cls("TEST-LOOKUP-002")
        registry.register(cls)
        classes = registry.probe_classes()
        assert cls in classes

    def test_len_empty(self):
        assert len(ProbeRegistry()) == 0

    def test_len_after_register(self):
        registry = ProbeRegistry()
        registry.register(_make_probe_cls("TEST-LEN-001"))
        registry.register(_make_probe_cls("TEST-LEN-002"))
        assert len(registry) == 2

    def test_contains_true(self):
        registry = ProbeRegistry()
        registry.register(_make_probe_cls("TEST-CONTAINS-001"))
        assert "TEST-CONTAINS-001" in registry

    def test_contains_false(self):
        assert "NOT-THERE" not in ProbeRegistry()
