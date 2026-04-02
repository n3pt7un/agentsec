"""Tests for PricingTable."""
import pytest


class TestModelPricing:
    def test_fields(self):
        from agentsec.core.pricing import ModelPricing
        p = ModelPricing(input_per_1m=3.0, output_per_1m=15.0)
        assert p.input_per_1m == 3.0
        assert p.output_per_1m == 15.0


class TestPricingTable:
    def test_compute_cost_known_model(self):
        from agentsec.core.finding import LLMUsage
        from agentsec.core.pricing import ModelPricing, PricingTable
        table = PricingTable(models={
            "test/model": ModelPricing(input_per_1m=3.0, output_per_1m=15.0)
        })
        usage = [
            LLMUsage(
                model="test/model", role="payload", input_tokens=1_000_000, output_tokens=1_000_000
            )
        ]
        cost = table.compute_cost(usage)
        assert cost == pytest.approx(18.0)

    def test_compute_cost_unknown_model_contributes_zero(self):
        from agentsec.core.finding import LLMUsage
        from agentsec.core.pricing import ModelPricing, PricingTable
        table = PricingTable(models={
            "known/model": ModelPricing(input_per_1m=1.0, output_per_1m=1.0)
        })
        usage = [
            LLMUsage(model="known/model", role="payload", input_tokens=1_000_000, output_tokens=0),
            LLMUsage(model="unknown/model", role="detection", input_tokens=999, output_tokens=999),
        ]
        cost = table.compute_cost(usage)
        assert cost == pytest.approx(1.0)

    def test_compute_cost_empty_usage(self):
        from agentsec.core.pricing import PricingTable
        table = PricingTable(models={})
        assert table.compute_cost([]) == pytest.approx(0.0)

    def test_load_from_yaml(self, tmp_path):
        import yaml

        from agentsec.core.pricing import PricingTable
        pricing_file = tmp_path / "pricing.yaml"
        pricing_file.write_text(yaml.dump({
            "models": {
                "my/model": {"input_per_1m": 2.5, "output_per_1m": 10.0}
            }
        }))
        table = PricingTable.load(pricing_file)
        assert "my/model" in table.models
        assert table.models["my/model"].input_per_1m == 2.5

    def test_load_returns_empty_if_file_absent(self, tmp_path):
        from agentsec.core.pricing import PricingTable
        table = PricingTable.load(tmp_path / "nonexistent.yaml")
        assert table.models == {}


class TestLoadPricing:
    def test_inline_data_takes_precedence(self):
        from agentsec.core.pricing import load_pricing
        data = {"my/model": {"input_per_1m": 1.0, "output_per_1m": 2.0}}
        table = load_pricing(pricing_data=data)
        assert table is not None
        assert "my/model" in table.models

    def test_returns_none_when_no_source(self, tmp_path, monkeypatch):
        from agentsec.core.pricing import load_pricing
        # Change cwd so default agentsec-pricing.yaml is not found
        monkeypatch.chdir(tmp_path)
        result = load_pricing()
        assert result is None
