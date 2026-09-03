"""ToolYard — disciplined execution of model-directed tool calls.

Register handlers in code at startup, execute one call at a time, get a structured result back and
a record for every call. The one thing a new caller gets wrong: **a refusal is a result, not an
exception**. A tool that does not exist, a name outside the allowlist, arguments that fail the
schema, a path that escapes its root, a handler that raises, a call that runs long — every one of
those returns a :class:`~toolyard.types.ToolResult` with a status and a machine-readable reason.
Exceptions are for caller bugs: a duplicate registration, an invalid spec, a broken store
([ADR-0053](https://github.com/JPKell/OpenWeight-Gym/blob/main/adr/0053-a-refused-tool-call-is-a-result-not-an-exception.md)).

The shape is register → execute → record::

    registry = ToolRegistry()
    registry.register(spec, handler)

    executor = ToolExecutor(
        registry, PathContainment(), allowlist=frozenset({"read_notes"}), store=store
    )
    result = executor.execute(
        ToolCallRequest(name="read_notes", args={"path": "today.md"}),
        ToolContext(invocation_id="inv-1", workspace=SandboxPaths(write_root=root)),
    )

and the five checks between the second line and the third run in one fixed order — registry →
allowlist → schema → egress → containment — reporting the **first** that fails, so a refusal is
diagnosable from the record alone.

**Status: Phase 2, unreleased.** The vocabulary, the registry, the executor's refusal order, path
containment, the record, and the tiered isolation ladder — container → bwrap → refuse, probed with
a canary and never degraded silently — are built and gated. The five built-in tools (Phase 3) are
not here yet; ``toolyard 0.1.0`` is published at the end of Phase 3. Nothing in this package is on
PyPI.
"""

from __future__ import annotations

from toolyard.__about__ import __version__
from toolyard.containment import (
    IsolationTier,
    PathAccess,
    PathContainment,
    PathEscape,
    Sandbox,
    SandboxPaths,
    SubprocessResult,
)
from toolyard.errors import DuplicateTool, InvalidToolSpec, StoreFailure, ToolYardError
from toolyard.executor import (
    DEFAULT_MAX_ARGS_JSON_BYTES,
    DEFAULT_MAX_CONTENT_BYTES,
    DEFAULT_MAX_SUMMARY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    REFUSAL_ORDER,
    ToolExecutor,
)
from toolyard.registry import ToolRegistry
from toolyard.sandbox import (
    DEFAULT_CONTAINER_IMAGE,
    DEFAULT_MAX_OUTPUT_BYTES,
    LIMIT_NAMES,
    PROBE_TIMEOUT_SECONDS,
    UNLAUNCHABLE_EXIT_CODE,
    ResourceLimits,
    TieredSandbox,
    TierReport,
)
from toolyard.store import InMemoryToolCallStore, ToolCallStore
from toolyard.types import (
    MAX_RECORDED_NAME_CHARS,
    REFUSAL_REASONS,
    TOOL_NAME_PATTERN,
    EgressClass,
    Reason,
    RegisteredTool,
    RiskClass,
    ToolCallRecord,
    ToolCallRequest,
    ToolContext,
    ToolHandler,
    ToolOutput,
    ToolResult,
    ToolSpec,
    ToolStatus,
)
from toolyard.validation import MAX_ARGS_DEPTH, MAX_ARGS_NODES, ArgsValidator

__all__ = [
    "DEFAULT_CONTAINER_IMAGE",
    "DEFAULT_MAX_ARGS_JSON_BYTES",
    "DEFAULT_MAX_CONTENT_BYTES",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_MAX_SUMMARY_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "LIMIT_NAMES",
    "MAX_ARGS_DEPTH",
    "MAX_ARGS_NODES",
    "MAX_RECORDED_NAME_CHARS",
    "PROBE_TIMEOUT_SECONDS",
    "REFUSAL_ORDER",
    "REFUSAL_REASONS",
    "TOOL_NAME_PATTERN",
    "UNLAUNCHABLE_EXIT_CODE",
    "ArgsValidator",
    "DuplicateTool",
    "EgressClass",
    "InMemoryToolCallStore",
    "InvalidToolSpec",
    "IsolationTier",
    "PathAccess",
    "PathContainment",
    "PathEscape",
    "Reason",
    "RegisteredTool",
    "ResourceLimits",
    "RiskClass",
    "Sandbox",
    "SandboxPaths",
    "StoreFailure",
    "SubprocessResult",
    "TierReport",
    "TieredSandbox",
    "ToolCallRecord",
    "ToolCallRequest",
    "ToolCallStore",
    "ToolContext",
    "ToolExecutor",
    "ToolHandler",
    "ToolOutput",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "ToolStatus",
    "ToolYardError",
    "__version__",
]
