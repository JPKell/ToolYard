"""Harmless fake tools and sandbox doubles. The only tools in this repository until Phase 3.

Every handler here is in-process and side-effect-free apart from the one that writes to a list.
None of them touches the filesystem, spawns a process or opens a socket: Phase 1 builds the
discipline, and a fake that did real work would be a built-in tool arriving two phases early.

The sandbox doubles implement :class:`~toolyard.containment.Sandbox` rather than subclassing
anything, which is the point of the port: the executor depends on the Protocol, so a test can hand
it a host that reports a tier without Phase 2 existing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from toolyard import (
    EgressClass,
    IsolationTier,
    PathAccess,
    PathContainment,
    RiskClass,
    SubprocessResult,
    ToolOutput,
    ToolSpec,
)
from toolyard.sandbox import Captured

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from toolyard import SandboxPaths, ToolContext

OBJECT_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {"value": {"type": "string"}},
    "required": ["value"],
    "additionalProperties": False,
}

PATH_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}

EMPTY_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}


def spec(
    name: str = "echo",
    *,
    args_schema: Mapping[str, Any] | None = None,
    risk_class: RiskClass = RiskClass.READ_ONLY,
    egress: EgressClass = EgressClass.NONE,
    redact_args: bool = False,
    path_args: Mapping[str, PathAccess] | None = None,
    requires_isolation: bool = False,
) -> ToolSpec:
    """Build a valid spec with sensible defaults, so a test states only what it is about."""
    return ToolSpec(
        name=name,
        description=f"A harmless fake named {name}.",
        args_schema=dict(OBJECT_SCHEMA if args_schema is None else args_schema),
        result_schema=None,
        risk_class=risk_class,
        egress=egress,
        redact_args=redact_args,
        path_args=dict(path_args or {}),
        requires_isolation=requires_isolation,
    )


class EchoTool:
    """Returns its arguments as text. The baseline successful call."""

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Return the ``value`` argument, or the whole mapping when there is none."""
        del context
        return ToolOutput(content=str(args.get("value", sorted(args))))


@dataclass
class RecordingTool:
    """Records the arguments it was handed, so a test can assert what the executor substituted."""

    seen: list[Mapping[str, Any]] = field(default_factory=list)

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Record and echo."""
        del context
        self.seen.append(dict(args))
        return ToolOutput(content="recorded")


@dataclass
class FixedOutputTool:
    """Returns a fixed string, however long."""

    text: str = "ok"

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Return the configured text."""
        del args, context
        return ToolOutput(content=self.text)


@dataclass
class RaisingTool:
    """Raises a configurable exception. The ``FAILED`` path."""

    error: BaseException = field(default_factory=lambda: ValueError("handler said no"))

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Raise whatever was configured."""
        del args, context
        raise self.error


@dataclass
class ReturningTool:
    """Returns whatever it was told to, including things that are not a :class:`ToolOutput`."""

    value: object = None

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Return the configured value, whatever its type."""
        del args, context
        return self.value  # type: ignore[return-value]  # deliberately breaks the handler contract


@dataclass
class SleepingTool:
    """Sleeps past its limit. The ``TIMEOUT`` path, in process, with no subprocess to kill."""

    seconds: float = 0.02

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Sleep, then return."""
        del args, context
        time.sleep(self.seconds)
        return ToolOutput(content="slept")


class ArgumentMutatingTool:
    """Mutates the mapping it was handed. Must not affect the record, which hashes the request."""

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Mutate and return."""
        del context
        if isinstance(args, dict):
            args["injected"] = "by the handler"
            args.pop("value", None)
        return ToolOutput(content="mutated")


class UnrenderableError(Exception):
    """An exception whose ``__str__`` raises, because a handler may define one."""

    def __str__(self) -> str:
        """Raise, deliberately."""
        raise RuntimeError("this message cannot be rendered")


@dataclass
class FixedTierSandbox:
    """A sandbox double: real path containment, and whichever isolation tier the test wants.

    It answers the tier it was given without probing anything, so an executor test can say "a host
    with a tier" or "a host without" in one argument. Phase 2's real implementation is
    :class:`toolyard.sandbox.TieredSandbox`, exercised in ``tests/unit/test_sandbox.py``.
    """

    tier: IsolationTier = IsolationTier.BWRAP
    containment: PathContainment = field(default_factory=PathContainment)

    def resolve_read(self, candidate: str, paths: SandboxPaths) -> Path:
        """Delegate to real containment."""
        return self.containment.resolve_read(candidate, paths)

    def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
        """Delegate to real containment."""
        return self.containment.resolve_write(candidate, paths)

    def isolation_tier(self) -> IsolationTier:
        """Report the configured tier."""
        return self.tier

    def run_isolated(
        self,
        argv: Sequence[str],
        *,
        paths: SandboxPaths,
        timeout_seconds: float,
        env: Mapping[str, str] | None = None,
        network: bool = False,
    ) -> SubprocessResult:
        """Report a trivial success without running anything. Never reached by the executor."""
        del argv, paths, timeout_seconds, env, network
        return SubprocessResult(exit_code=0, stdout="", stderr="", duration_ms=0, tier=self.tier)


@dataclass
class ExplodingSandbox:
    """A sandbox whose every method raises. A broken port must still produce a result."""

    error: type[BaseException] = RuntimeError

    def resolve_read(self, candidate: str, paths: SandboxPaths) -> Path:
        """Raise."""
        del candidate, paths
        raise self.error("resolve_read exploded")

    def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
        """Raise."""
        del candidate, paths
        raise self.error("resolve_write exploded")

    def isolation_tier(self) -> IsolationTier:
        """Raise."""
        raise self.error("probe exploded")

    def run_isolated(
        self,
        argv: Sequence[str],
        *,
        paths: SandboxPaths,
        timeout_seconds: float,
        env: Mapping[str, str] | None = None,
        network: bool = False,
    ) -> SubprocessResult:
        """Raise."""
        del argv, paths, timeout_seconds, env, network
        raise self.error("run_isolated exploded")


class BreakingStore:
    """A store that refuses every record, so the ``StoreFailure`` contract can be asserted."""

    def append(self, record: object) -> None:
        """Raise, as a broken store does."""
        del record
        raise OSError("disk on fire")


class FrozenClock:
    """A wall clock that never moves, so records are byte-comparable."""

    __slots__ = ("_moment",)

    def __init__(self, moment: Any) -> None:
        """Hold one instant."""
        self._moment = moment

    def __call__(self) -> Any:
        """Return that instant."""
        return self._moment


class SteppingMonotonic:
    """A monotonic source that advances a fixed amount per reading, in nanoseconds."""

    __slots__ = ("_now", "_step_ns")

    def __init__(self, *, step_ns: int = 1_000_000, start_ns: int = 0) -> None:
        """Start at ``start_ns`` and advance ``step_ns`` on every call."""
        self._now = start_ns
        self._step_ns = step_ns

    def __call__(self) -> int:
        """Return the current reading and advance."""
        current = self._now
        self._now += self._step_ns
        return current


# -- Phase 2 doubles: the launch boundary and the probe's view of the host -------------------------


@dataclass(frozen=True, slots=True)
class Launch:
    """One call the scripted runner saw: what the sandbox asked the launcher to run, and how."""

    argv: tuple[str, ...]
    env: dict[str, str]
    timeout_seconds: float
    max_output_bytes: int


def captured(
    *,
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
    output_truncated: bool = False,
) -> Captured:
    """Build a :class:`~toolyard.sandbox.Captured` with a successful, silent default."""
    return Captured(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


@dataclass
class ScriptedRunner:
    """A runner double: answers by the launched binary's basename, and records every launch.

    ``outcomes`` is keyed three ways, most specific first. A probe's canary — recognisable by the
    temporary workspace it binds — answers to ``"<basename> canary"`` and otherwise succeeds, so a
    scripted *run* outcome never leaks into the probe. Any other launch answers to
    ``"<basename> <argv[1]>"`` (``"docker run"`` versus ``"docker rm"``), then ``"<basename>"``,
    then a silent success. An exception as an outcome is raised, which is how a launcher that cannot
    start the binary is simulated. Nothing here starts a process: the integration suite is where
    the real launcher runs under real tiers.
    """

    outcomes: dict[str, Captured | BaseException] = field(default_factory=dict)
    calls: list[Launch] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> Captured:
        """Record the launch and answer from the script."""
        self.calls.append(
            Launch(
                argv=tuple(argv),
                env=dict(env),
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        )
        name = PurePosixPath(argv[0]).name
        if any("toolyard-probe-" in item for item in argv):
            outcome = self.outcomes.get(f"{name} canary", captured())
        else:
            specific = f"{name} {argv[1]}" if len(argv) > 1 else name
            outcome = self.outcomes.get(specific, self.outcomes.get(name, captured()))
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


FULL_HOST: Mapping[str, str] = {
    "podman": "/usr/bin/podman",
    "docker": "/usr/bin/docker",
    "bwrap": "/usr/bin/bwrap",
    "prlimit": "/usr/bin/prlimit",
}
"""A host with every rung's binary, as the probe's ``which`` would see it."""

BWRAP_HOST: Mapping[str, str] = {"bwrap": "/usr/bin/bwrap", "prlimit": "/usr/bin/prlimit"}
"""A host with no container runtime — the common deployment this package exists to serve."""

DOCKER_HOST: Mapping[str, str] = {"docker": "/usr/bin/docker", "bwrap": "/usr/bin/bwrap"}
"""A host with docker but no podman, and no prlimit."""


def which_for(available: Mapping[str, str]) -> Callable[[str], str | None]:
    """An executable lookup that sees exactly ``available`` — the probe's injected view."""
    return lambda name: available.get(name)
