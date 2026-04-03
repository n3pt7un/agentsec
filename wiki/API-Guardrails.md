<!-- AUTO-GENERATED — do not edit directly. Re-run scripts/wiki/generate_api_reference.py -->

# API: Guardrails

Defensive guardrail components. See [Guardrails usage guide](Guardrails).

## `InputBoundaryEnforcer`

Prevents goal hijacking via tool output or user input injection.

Works on any string — the caller decides what to pass. Three modes:
- tag: wraps content in XML delimiters with a system instruction prepend
- strip: removes matched injection patterns from content
- reject: raises InjectionDetectedError if any pattern matches

Args:
    mode: One of "tag", "strip", or "reject". Defaults to "tag".
    extra_patterns: Additional regex strings appended to the defaults.

Example:
    enforcer = InputBoundaryEnforcer(mode="tag")
    safe = enforcer.sanitize(untrusted_tool_output)

### Methods

#### `detect(self, content: 'str') -> 'list[str]'`

Return list of injection pattern matches found in content.

Mode-agnostic — useful for logging regardless of configured mode.

Args:
    content: String to scan.

Returns:
    List of matched substrings; empty list if none found.

#### `protect(self, func)`

Decorator that sanitizes the last HumanMessage before the node runs.

Extracts state["messages"], finds the last message with type == "human",
sanitizes its content, and calls func with the modified state. All other
state keys pass through unchanged. If there is no "messages" key or no
HumanMessage, calls func(state) unchanged.

Args:
    func: A LangGraph node function (state: dict) -> dict.

Returns:
    Wrapped function.

#### `sanitize(self, content: 'str') -> 'str'`

Sanitize untrusted content based on the configured mode.

Args:
    content: String to sanitize.

Returns:
    Sanitized string (tag/strip modes) or original if clean (reject mode).

Raises:
    InjectionDetectedError: In reject mode when injection is detected.

---

## `CredentialIsolator`

Prevents credential leakage in agent context and output.

Scans strings for credential-like patterns and redacts them. Designed as
a defence-in-depth layer for agent output — complements (does not replace)
architectural patterns like credential vaults.

Args:
    extra_patterns: Additional (regex_str, replacement) tuples appended to
        the defaults. Compiled at init time.

Example:
    isolator = CredentialIsolator()
    safe_output = isolator.redact(agent_response)

### Methods

#### `contains_credentials(self, content: 'str') -> 'bool'`

Check if content contains credential-like patterns.

Does not modify content.

Args:
    content: String to check.

Returns:
    True if any pattern matches, False otherwise.

#### `filter_output(self, func)`

Decorator that redacts credentials from node output messages.

Calls the wrapped LangGraph node, then redacts credentials from any
message with type == "ai" in result["messages"]. Other state keys and
non-AI messages pass through unchanged. If the result has no "messages"
key, returns result unchanged.

Args:
    func: A LangGraph node function (state: dict) -> dict.

Returns:
    Wrapped function.

#### `redact(self, content: 'str') -> 'str'`

Redact credential patterns from content.

Applies all patterns in order. Returns the redacted string.

Args:
    content: String to scan and redact.

Returns:
    String with credentials replaced by redaction placeholders.

---

## `CircuitBreaker`

Prevents cascading failures by opening after repeated agent errors.

Implements the standard three-state circuit breaker pattern:
CLOSED (normal) → OPEN (tripped, returns fallback) → HALF_OPEN (trial) → CLOSED

Args:
    failure_threshold: Consecutive failures before opening the circuit.
        Defaults to 3.
    recovery_timeout: Seconds to wait in OPEN state before allowing a
        trial call (HALF_OPEN transition). Defaults to 60.0.
    fallback_message: Content returned in the ``messages`` list when the
        circuit is open. Defaults to a generic unavailability message.

Example:
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=30.0)

    @cb.protect("my_agent")
    def my_agent_node(state: dict) -> dict:
        ...

### Methods

#### `circuit_state(self, agent_name: 'str') -> 'str'`

Return the current circuit state for agent_name.

Args:
    agent_name: The name passed to protect().

Returns:
    One of ``"closed"``, ``"open"``, or ``"half_open"``.

Raises:
    KeyError: If agent_name has never been registered via protect().

#### `protect(self, agent_name: 'str')`

Decorator factory that wraps a LangGraph node with circuit breaker logic.

When the circuit is OPEN, the node is not called and a fallback AI
message is returned immediately.  When the circuit trips (failure count
reaches ``failure_threshold``), ``CircuitOpenError`` is raised with the
original exception chained as ``__cause__``.

Args:
    agent_name: Identifier for the agent — state tracked independently
        per name.

Returns:
    A decorator that wraps sync or async node functions.

---

## `ExecutionLimiter`

Prevents unbounded autonomous execution by enforcing per-agent limits.

Tracks step count, elapsed time, and token usage per named agent.
Any combination of limits can be enabled; a limit of ``None`` is never checked.

Args:
    max_steps: Maximum invocations before raising. ``None`` = unlimited.
    max_seconds: Maximum wall-clock seconds from first invocation.
        ``None`` = unlimited.
    max_tokens: Maximum cumulative ``token_usage`` across invocations.
        The node's return dict is checked for a ``"token_usage"`` key (int).
        ``None`` = unlimited.

Example:
    limiter = ExecutionLimiter(max_steps=10, max_seconds=30.0)

    @limiter.enforce("my_agent")
    def my_agent_node(state: dict) -> dict:
        ...

### Methods

#### `enforce(self, agent_name: 'str')`

Decorator factory that enforces execution limits on a LangGraph node.

Checks step and time limits **before** calling the node.  Checks token
limits **after** the node returns (requires a ``"token_usage"`` key in
the result dict).  Steps are incremented after a successful call.

Args:
    agent_name: Identifier for the agent — state tracked independently
        per name.

Returns:
    A decorator that wraps sync or async node functions.

#### `reset(self, agent_name: 'str') -> 'None'`

Reset all counters for agent_name to their initial state.

Args:
    agent_name: The agent to reset.

Raises:
    KeyError: If agent_name has never been registered via enforce().

---

