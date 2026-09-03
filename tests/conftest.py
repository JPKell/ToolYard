"""Shared fixtures: a registry, a workspace on disk, a store, and a deterministic executor."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from fakes import EchoTool, FrozenClock, SteppingMonotonic, spec
from toolyard import (
    InMemoryToolCallStore,
    PathContainment,
    SandboxPaths,
    ToolContext,
    ToolExecutor,
    ToolRegistry,
)

if TYPE_CHECKING:
    from pathlib import Path

FIXED_MOMENT = datetime(2026, 9, 3, 4, 5, 6, 250_000, tzinfo=UTC)
"""One instant, so every record built with the fixture clock is byte-comparable."""


@pytest.fixture
def workspace(tmp_path: Path) -> SandboxPaths:
    """A write root and one read root, both real directories."""
    write_root = tmp_path / "work"
    read_root = tmp_path / "reference"
    write_root.mkdir()
    read_root.mkdir()
    return SandboxPaths(write_root=write_root, read_roots=(read_root,))


@pytest.fixture
def registry() -> ToolRegistry:
    """A registry holding one harmless echo tool."""
    built = ToolRegistry()
    built.register(spec("echo"), EchoTool())
    return built


@pytest.fixture
def store() -> InMemoryToolCallStore:
    """A store whose records a test can read back."""
    return InMemoryToolCallStore()


@pytest.fixture
def executor(registry: ToolRegistry, store: InMemoryToolCallStore) -> ToolExecutor:
    """An executor over the echo tool, with a deterministic duration source."""
    return ToolExecutor(
        registry,
        PathContainment(),
        allowlist=frozenset({"echo"}),
        store=store,
        monotonic_ns=SteppingMonotonic(),
    )


@pytest.fixture
def context(workspace: SandboxPaths) -> ToolContext:
    """A context with a frozen clock, so ``started_at`` is a constant."""
    return ToolContext(invocation_id="inv-1", workspace=workspace, clock=FrozenClock(FIXED_MOMENT))
