<!-- AUTO-GENERATED — do not edit directly. Re-run scripts/wiki/generate_api_reference.py -->

# API: Reporters

Output format generators. Source: `src/agentsec/reporters/`

Each reporter is a top-level function that accepts a `ScanResult` and returns a `str`.

## `generate_markdown(result: 'ScanResult') -> 'str'`

Generate a full markdown report from a ScanResult.

Args:
    result: The scan result to render.

Returns:
    A complete markdown string.

---

## `generate_json(result: 'ScanResult') -> 'str'`

Serialize a ScanResult as pretty-printed JSON with metadata wrapper.

Args:
    result: The scan result to serialize.

Returns:
    A JSON string with metadata and the full scan result.

---

## `generate_sarif(result: 'ScanResult') -> 'str'`

Generate SARIF 2.1.0 JSON from a ScanResult.

Rules cover all probes that ran (all statuses). Results cover only
VULNERABLE and PARTIAL findings — RESISTANT findings are excluded.

Args:
    result: The scan result to render.

Returns:
    A SARIF 2.1.0 JSON string.

---

