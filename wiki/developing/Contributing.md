# Contributing

Thank you for contributing to agentsec. This page covers setup, conventions, and the PR workflow.

## Dev setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/agentsec.git
cd agentsec

# 2. Install all dependencies (including dev extras)
uv sync

# 3. Verify the setup
uv run pytest          # all tests should pass
uv run ruff check src/ # no lint errors
uv run agentsec --help # CLI should print the help page
```

If `uv` is not installed, follow the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).

## Commit style

Every commit message must start with one of these prefixes. This is enforced by code review.

| Prefix | When to use |
|--------|-------------|
| `FEAT` | A wholly new capability that did not exist before (new probe, new adapter, new CLI command) |
| `ENH` | An enhancement to an existing capability (new option, better output, improved heuristic) |
| `BUG` | A bug fix — something that was broken and now works correctly |
| `MAINT` | Maintenance work — dependency bumps, CI config, refactoring with no behaviour change |
| `TEST` | Adding or updating tests only, no production code changes |
| `DOCS` | Documentation only — wiki pages, docstrings, README |
| `REFACTOR` | Structural code change with no functional change (rename, extract method, reorganise) |

Examples:

```
FEAT: add ASI04 privilege escalation probe
ENH: add --timeout-per-probe flag to scan command
BUG: fix false positive in refusal guard when marker appears mid-sentence
MAINT: bump httpx to 0.28.1
TEST: add resistant test case for OrchestratorHijackProbe
DOCS: add adapter authoring guide to wiki
REFACTOR: extract _run_detection into BaseProbe
```

## PR workflow

### Step 1 — Open an issue first

Before starting work, open a GitHub issue describing the problem or feature. This avoids duplicated effort and lets maintainers flag design concerns early.

For bug fixes: describe the current behaviour, expected behaviour, and steps to reproduce.
For new probes: describe the OWASP category, the attack pattern, and why existing probes do not cover it.

### Step 2 — Create a feature branch

Branch off `main`. Use a short, descriptive name:

```bash
git checkout -b feat/asi04-privilege-escalation
git checkout -b bug/false-positive-refusal-guard
git checkout -b docs/adapter-authoring-wiki
```

### Step 3 — Implement, test, lint, and open a PR

1. Implement the change.
2. Add or update tests. All new probes must have at least three test cases (vulnerable, resistant, skipped).
3. Pass lint and format checks:

```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
uv run pytest -x
```

4. Open a pull request against `main`. Fill in the PR template — link the related issue, describe what changed and why, and list any testing you did.

## Adding a new probe: checklist

Use this checklist before marking a probe PR as ready for review:

- [ ] Directory created at `src/agentsec/probes/asi<NN>_<name>/` with an empty `__init__.py`
- [ ] Probe class subclasses `BaseProbe` and is in its own `.py` file
- [ ] `metadata()` returns a valid `ProbeMetadata` with a unique `id` (format: `ASI<NN>-<SLUG>`)
- [ ] `remediation()` returns a `Remediation` with a non-empty `summary`, `code_before`, `code_after`, and at least one `reference`
- [ ] `attack()` is `async def` and returns a `Finding` in all code paths (VULNERABLE, RESISTANT, SKIPPED)
- [ ] Tests cover all three status outcomes (VULNERABLE, RESISTANT, SKIPPED)
- [ ] `uv run agentsec probes list` shows the new probe ID

## Code style rules

1. **Use ruff for lint and format.** Run `uv run ruff check src/` and `uv run ruff format src/` before every commit. The CI pipeline will reject PRs that fail these checks.

2. **Google-style docstrings on every public class and method.** Include `Args:`, `Returns:`, and `Raises:` sections where applicable. One-liners are fine for trivial methods.

3. **Type hints everywhere.** Use Python 3.12+ syntax: `list[str]` not `List[str]`, `X | None` not `Optional[X]`. Annotate all function parameters and return types.

4. **Async-first.** All probe `attack()` methods, adapter methods, and scanner internals are `async def`. Do not write synchronous versions "for simplicity".

5. **No bare `except:`.** Always catch specific exception types. Use `except Exception as exc:` only when you genuinely need to catch all exceptions and always re-raise or log.

6. **No `os.environ` in production code.** Read configuration through `ScanConfig` (a Pydantic Settings model with the `AGENTSEC_` prefix). Direct `os.environ` access bypasses validation and makes testing harder.

7. **No `print()` statements.** Use `rich.console.Console` for user-facing output in CLI commands, or Python `logging` for internal diagnostic messages.
