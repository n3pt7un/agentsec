# Detection Mode per Scan — Design Spec

**Date:** 2026-04-03
**Status:** Approved

## Overview

Add a per-scan `detection_mode` option that controls how probes decide whether a response is vulnerable. The current two-stage flow (marker check → LLM fallback) becomes one named mode. A new `llm_only` mode skips the marker stage entirely and relies solely on the LLM for verdict.

## Motivation

Marker-based detection is fast and cheap, but it is a proxy signal — the marker appearing in a response is evidence of vulnerability, not proof. Some users want higher-confidence verdicts and are willing to pay the extra LLM calls. Others run targeted red-team sessions where they know the marker heuristic is insufficient. `llm_only` mode makes that a first-class option rather than a workaround.

---

## Data Model — `config.py`

### `DetectionMode` StrEnum

```python
class DetectionMode(StrEnum):
    MARKER_THEN_LLM = "marker_then_llm"
    LLM_ONLY = "llm_only"
```

Lives in `src/agentsec/core/config.py`, alongside `ScanConfig`.

### `ScanConfig` additions

```python
detection_mode: DetectionMode = Field(
    default=DetectionMode.MARKER_THEN_LLM,
    description="Detection strategy: marker_then_llm (default) or llm_only",
)
```

Add a `@model_validator(mode="after")` that raises `ValueError` when
`detection_mode == DetectionMode.LLM_ONLY` and `smart is False`:

```
detection_mode=llm_only requires smart=True (an LLM provider must be configured)
```

Validation runs at config construction time, before any probes are loaded or run.

---

## Threading

### `Scanner._run_probe()` → `probe.attack()`

`scanner.py` passes one additional kwarg to every probe:

```python
probe.attack(
    self.adapter,
    self._provider,
    confidence_threshold=self.config.detection_confidence_threshold,
    fallback_model=self.config.fallback_llm_model,
    detection_mode=self.config.detection_mode,   # new
)
```

### `BaseProbe.attack()` abstract signature

```python
@abstractmethod
async def attack(
    self,
    adapter,
    provider=None,
    confidence_threshold: float = 0.8,
    fallback_model: str | None = None,
    detection_mode: DetectionMode = DetectionMode.MARKER_THEN_LLM,  # new
) -> Finding:
```

All six concrete probes accept `detection_mode` and pass it to `_run_detection()`. No other logic changes in the probe bodies.

### `BaseProbe._run_detection()`

```python
async def _run_detection(
    self,
    fast_vulnerable: bool,
    provider,
    response: str,
    detection_type: DetectionType,
    confidence_threshold: float = 0.8,
    attack_marker: str | None = None,
    detection_mode: DetectionMode = DetectionMode.MARKER_THEN_LLM,  # new
    **detection_context,
) -> tuple[bool, str | None, list[LLMUsage]]:
```

Behaviour by mode:

| Mode | Stage 1 (marker) | Stage 2 (LLM) |
|---|---|---|
| `marker_then_llm` | Run as today; fall through to LLM only if marker in refusal | Run if Stage 1 not conclusive and provider available |
| `llm_only` | **Skipped entirely** | Always run (provider guaranteed by validator) |

When `llm_only`, `fast_vulnerable` and `attack_marker` are accepted but ignored so call sites in probe bodies need no changes.

---

## CLI

The `scan` command in `src/agentsec/cli/` gains:

```
--detection-mode [marker-then-llm|llm-only]
```

Default: `marker-then-llm`. Typer resolves the StrEnum values automatically. If the user passes `--detection-mode llm-only` without `--smart`, the `ScanConfig` validator fires before any probes run and prints:

```
Error: detection_mode=llm_only requires smart=True
```

---

## What does NOT change

- `ScanResult` — no new fields; `detection_confidence_threshold` already recorded.
- `Evidence.detection_method` — already records `"marker"` | `"llm"` | `None` per finding; this continues to be the per-finding source of truth.
- Report formats — no changes; the per-finding `detection_method` already surfaces in reports.
- Probe bodies — only signature change (new param with default); no logic changes inside `attack()`.

---

## Files changed

| File | Change |
|---|---|
| `src/agentsec/core/config.py` | Add `DetectionMode` StrEnum; add `detection_mode` field + validator to `ScanConfig` |
| `src/agentsec/core/probe_base.py` | Add `detection_mode` param to `attack()` and `_run_detection()`; skip Stage 1 when `llm_only` |
| `src/agentsec/core/scanner.py` | Pass `detection_mode` to `probe.attack()` |
| `src/agentsec/probes/asi01_goal_hijack/indirect_inject.py` | Accept + forward `detection_mode` |
| `src/agentsec/probes/asi01_goal_hijack/role_confusion.py` | Accept + forward `detection_mode` |
| `src/agentsec/probes/asi03_identity_abuse/impersonation.py` | Accept + forward `detection_mode` |
| `src/agentsec/probes/asi03_identity_abuse/cred_extraction.py` | Accept + forward `detection_mode` |
| `src/agentsec/probes/asi06_memory_manipulation/context_leak.py` | Accept + forward `detection_mode` |
| `src/agentsec/probes/asi06_memory_manipulation/memory_poison.py` | Accept + forward `detection_mode` |
| `src/agentsec/cli/<scan command>` | Add `--detection-mode` option |
