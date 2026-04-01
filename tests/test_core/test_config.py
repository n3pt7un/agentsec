"""Tests for ScanConfig."""

from agentsec.core.config import ScanConfig


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig()
        assert config.categories is None
        assert config.probes is None
        assert config.verbose is False
        assert config.timeout_per_probe == 120
        assert config.smart is False
        assert config.llm_model == "anthropic/claude-sonnet-4.6"
        assert config.openrouter_api_key is None
        assert config.output_file is None
        assert config.output_format == "markdown"

    def test_from_env_vars(self, monkeypatch):
        monkeypatch.setenv("AGENTSEC_VERBOSE", "true")
        monkeypatch.setenv("AGENTSEC_TIMEOUT_PER_PROBE", "60")
        monkeypatch.setenv("AGENTSEC_OUTPUT_FORMAT", "json")
        monkeypatch.setenv("AGENTSEC_SMART", "true")
        monkeypatch.setenv("AGENTSEC_OPENROUTER_API_KEY", "sk-or-test")
        config = ScanConfig()
        assert config.verbose is True
        assert config.timeout_per_probe == 60
        assert config.output_format == "json"
        assert config.smart is True
        assert config.openrouter_api_key == "sk-or-test"

    def test_explicit_values(self):
        config = ScanConfig(
            categories=["ASI01", "ASI03"],
            probes=["ASI01-INDIRECT-INJECT"],
            verbose=True,
            timeout_per_probe=30,
            smart=True,
            openrouter_api_key="sk-or-key",
            llm_model="google/gemini-2.5-pro",
        )
        assert config.categories == ["ASI01", "ASI03"]
        assert config.probes == ["ASI01-INDIRECT-INJECT"]
        assert config.verbose is True
        assert config.timeout_per_probe == 30
        assert config.smart is True
        assert config.openrouter_api_key == "sk-or-key"
        assert config.llm_model == "google/gemini-2.5-pro"

    def test_env_prefix(self):
        assert ScanConfig.model_config.get("env_prefix") == "AGENTSEC_"
