"""Tests for ScanConfig."""

from agentsec.core.config import ScanConfig


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig()
        assert config.categories is None
        assert config.probes is None
        assert config.verbose is False
        assert config.timeout_per_probe == 120
        assert config.llm_provider == "anthropic"
        assert config.llm_model == "claude-sonnet-4-20250514"
        assert config.output_file is None
        assert config.output_format == "markdown"

    def test_from_env_vars(self, monkeypatch):
        monkeypatch.setenv("AGENTSEC_VERBOSE", "true")
        monkeypatch.setenv("AGENTSEC_TIMEOUT_PER_PROBE", "60")
        monkeypatch.setenv("AGENTSEC_OUTPUT_FORMAT", "json")
        config = ScanConfig()
        assert config.verbose is True
        assert config.timeout_per_probe == 60
        assert config.output_format == "json"

    def test_explicit_values(self):
        config = ScanConfig(
            categories=["ASI01", "ASI03"],
            probes=["ASI01-INDIRECT-INJECT"],
            verbose=True,
            timeout_per_probe=30,
        )
        assert config.categories == ["ASI01", "ASI03"]
        assert config.probes == ["ASI01-INDIRECT-INJECT"]
        assert config.verbose is True
        assert config.timeout_per_probe == 30

    def test_env_prefix(self):
        # Confirm env_prefix is set correctly
        assert ScanConfig.model_config.get("env_prefix") == "AGENTSEC_"
