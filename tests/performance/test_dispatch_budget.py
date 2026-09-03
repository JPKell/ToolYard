"""Spec §15's budgets, behind the ``performance`` marker: excluded by default, run nightly.

Two kinds of assertion, and the second is the one that keeps working. An **absolute** budget
(≤ 10 ms of dispatch) is what the spec states, and it is asserted — but it is also the assertion
that turns amber on a loaded CI runner and gets its threshold quietly raised until it means nothing.
A **shape** assertion says what must stay true regardless of how fast the machine is: dispatch must
not become quadratic in the size of a model's arguments, and a refusal must never cost more than a
successful call. Those hold on a slow machine and fail on a fast one that has grown an accidental
loop.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest

from fakes import EchoTool, FixedOutputTool, spec
from toolyard import (
    PathContainment,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolRegistry,
    ToolStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from toolyard import SandboxPaths

pytestmark = pytest.mark.performance

DISPATCH_BUDGET_MS = 10.0
"""Spec §15: validate + authorize + record, excluding the handler."""

WIDE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"value": {"type": "string"}, "rows": {"type": "array", "items": {}}},
    "required": ["value"],
    "additionalProperties": False,
}


def _median_ms(work: Callable[[], object], *, repeats: int = 200) -> float:
    """Median wall time of ``work``, in milliseconds. Median, so one scheduling hiccup is not the
    measurement."""
    timings = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        work()
        timings.append((time.perf_counter_ns() - start) / 1_000_000)
    timings.sort()
    return timings[len(timings) // 2]


@pytest.fixture
def dispatch(workspace: SandboxPaths) -> tuple[ToolExecutor, ToolContext]:
    """An executor over a no-op handler, so what is measured is dispatch and nothing else."""
    registry = ToolRegistry()
    registry.register(spec("echo", args_schema=WIDE_SCHEMA), FixedOutputTool("ok"))
    registry.register(spec("plain"), EchoTool())
    executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"echo", "plain"}))
    return executor, ToolContext(invocation_id="inv-perf", workspace=workspace)


def test_dispatch_overhead_is_within_the_budget(
    dispatch: tuple[ToolExecutor, ToolContext],
) -> None:
    """The absolute figure spec §15 states."""
    executor, context = dispatch
    call = ToolCallRequest(name="plain", args={"value": "x"})
    assert executor.execute(call, context).status is ToolStatus.OK
    median = _median_ms(lambda: executor.execute(call, context))
    assert median < DISPATCH_BUDGET_MS, f"dispatch median {median:.3f} ms"


def test_a_refusal_never_costs_more_than_a_successful_call(
    dispatch: tuple[ToolExecutor, ToolContext],
) -> None:
    """A shape, not a number: an unknown tool exits at the first rung and does no other work.

    Would catch a refusal path that builds the whole record twice, or one that resolves paths
    before deciding it is refusing.
    """
    executor, context = dispatch
    ok = _median_ms(
        lambda: executor.execute(ToolCallRequest(name="plain", args={"value": "x"}), context)
    )
    refused = _median_ms(
        lambda: executor.execute(ToolCallRequest(name="ghost", args={"value": "x"}), context)
    )
    assert refused <= ok * 2 + 0.5, f"refusal {refused:.3f} ms against success {ok:.3f} ms"


def test_dispatch_is_not_quadratic_in_the_size_of_the_arguments(
    dispatch: tuple[ToolExecutor, ToolContext],
) -> None:
    """A shape that holds on any machine: ten times the arguments must not cost a hundred times.

    Would catch a containment or sanitization walk that is re-run per argument, or a digest taken
    once per node — both of which look linear until a model sends a list.
    """
    executor, context = dispatch
    small = ToolCallRequest(name="echo", args={"value": "x", "rows": list(range(100))})
    large = ToolCallRequest(name="echo", args={"value": "x", "rows": list(range(1_000))})
    small_ms = _median_ms(lambda: executor.execute(small, context), repeats=40)
    large_ms = _median_ms(lambda: executor.execute(large, context), repeats=40)
    assert large_ms < small_ms * 30 + 1.0, f"{small_ms:.3f} ms -> {large_ms:.3f} ms"


def test_containment_resolution_is_within_its_budget(workspace: SandboxPaths) -> None:
    """Spec §15: path resolution plus the containment check, ≤ 1 ms."""
    containment = PathContainment()
    median = _median_ms(lambda: containment.resolve_read("sub/../notes.md", workspace))
    assert median < 1.0, f"containment median {median:.3f} ms"
