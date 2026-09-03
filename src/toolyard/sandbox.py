"""The sandbox — ADR-0018's ladder applied to tools: container → bwrap → refuse, nothing below.

Phase 1 left a port, :class:`~toolyard.containment.Sandbox`, with an honest half-implementation:
:class:`~toolyard.containment.PathContainment` resolves and checks paths and reports that it has no
isolation tier. This module supplies the other half. :class:`TieredSandbox` **composes** that
containment for the path half — ``resolve_read`` and ``resolve_write`` are delegated verbatim,
because a second resolution-then-check implementation would be a second chance to compare before
resolving — and adds the tier probe and ``run_isolated``.

**The probe executes a canary; it never trusts a version string.** Installed is not functional: a
kernel with unprivileged user namespaces disabled leaves a ``bwrap`` binary that fails every
invocation, a container runtime whose daemon is down still answers ``--version``, and an image that
was never pulled is a rung that cannot run anything. So each rung is probed by running the exact
argv :meth:`TieredSandbox.run_isolated` would build — the same flags, the same limits, a temporary
workspace bound the same way — around ``/bin/true``. A rung whose canary fails is reported with the
reason and the next rung is tried; when none passes the tier is
:attr:`~toolyard.containment.IsolationTier.UNAVAILABLE`, and the executor refuses every tool that
requires isolation before any handler runs.

**What each rung guarantees.**

* *Container* (``podman`` preferred, then ``docker``): ``--network=none`` unless the caller asks
  for network, a read-only root filesystem, a private ``noexec`` ``/tmp``, cgroup memory and pid
  limits, CPU-time and file-size rlimits, every capability dropped, ``no-new-privileges``, the
  calling user's uid and gid, and ``--pull=never`` — a probe that pulled an image would be an
  outbound fetch originating in a tier probe, in the package whose purpose is that egress passes
  one checked door.
* *bwrap*: ``--unshare-all`` (network included unless asked for), ``--die-with-parent``,
  ``--new-session``, ``--clearenv``, read-only binds of the minimal runtime (``/usr``, ``/bin``,
  ``/sbin``, ``/lib``, ``/lib64`` and six named ``/etc`` entries — never ``/etc`` whole, never a
  home directory), a fresh ``/proc`` and ``/dev``, a private ``/tmp``, and rlimits applied
  **inside** the sandbox by ``prlimit``.
* *Refuse*: :meth:`TieredSandbox.run_isolated` raises rather than running anything, and the
  executor never reaches it because check #5 refuses first. There is no host-execution tier and no
  flag that creates one.

On both rungs the workspace is bound **in place** — ``write_root`` read-write and each read root
read-only, at their resolved host paths — so an argv means the same thing on either rung, and a
relative path resolves against the write root, which is also the working directory.

**Why ``prlimit`` and not :mod:`resource` in a ``preexec_fn``.** Two reasons, both learned rather
than guessed. ``preexec_fn`` is documented as unsafe in a threaded process, and the consumer is a
threaded server. And ``RLIMIT_NPROC`` is checked against the user's task count at every level of
the user-namespace hierarchy, so a limit small enough to bound a fork bomb, applied *before*
``bwrap`` creates its namespace, makes that creation fail on any busy desktop — FreeWeight hit
exactly this. Applied *inside* the namespace, after it exists, the same limit bounds the sandbox and
nothing else. When ``prlimit`` is absent the rung still runs and every result names the four limits
it could not apply in ``limits_unenforced`` — ADR-0016's rule: an unenforceable limit is reported,
never assumed. The container rung reports its two cgroup-enforced limits the same way when the
runtime warns that the kernel cannot apply them.

**The environment.** ``env=None`` is the empty allowlist. The child sees exactly what the caller
named — under bwrap after ``--clearenv``, under a container through ``--env`` — and never this
process's environment. The sandbox binary itself (``bwrap``, ``docker``, ``podman``) is launched
with a fixed ``PATH`` and nothing else, so a credential in the application's environment has no
route into a tool, not even through the launcher.

**Timeouts kill the tree.** The launcher starts every child in its own session; on the deadline the
whole process group is terminated and, if it survives the grace period, killed. Under bwrap a new
pid namespace and ``--die-with-parent`` take the grandchildren with it. Under a container the
runtime's CLI dying does not stop the container, so a timed-out or output-capped container is
removed by name afterwards. An output bomb is the same case: reading stops at the cap, the tree is
killed, and the text carries the truncation label.
"""

from __future__ import annotations

import logging
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING, Final, Protocol

from baseaicore import ValidationError, monotonic_ns

from toolyard._safe import clean_text, truncate_text
from toolyard.containment import IsolationTier, PathContainment, SandboxPaths, SubprocessResult
from toolyard.errors import ToolYardError

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "DEFAULT_CONTAINER_IMAGE",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "LIMIT_NAMES",
    "MAX_ARGV_BYTES",
    "MAX_ARGV_ITEMS",
    "MIN_OUTPUT_BYTES",
    "PROBE_TIMEOUT_SECONDS",
    "UNLAUNCHABLE_EXIT_CODE",
    "Captured",
    "ResourceLimits",
    "Runner",
    "TierReport",
    "TieredSandbox",
]

_LOGGER: Final[logging.Logger] = logging.getLogger("toolyard.sandbox")

DEFAULT_CONTAINER_IMAGE: Final[str] = "python:3.12-slim"
"""The image the container rung runs commands in, unless the caller names another.

The suite's Python baseline, and the image FreeWeight's tier-1 sandbox already uses. It must be
present locally: the rung is probed with ``--pull=never``, so an absent image is a rung that reports
itself unavailable rather than a probe that reaches the network.
"""

DEFAULT_MAX_OUTPUT_BYTES: Final[int] = 1_048_576
"""How many bytes of each stream the runner keeps before it stops reading and kills the tree.

Per stream, and a memory bound rather than what the model sees — the executor caps that separately
at :data:`~toolyard.executor.DEFAULT_MAX_CONTENT_BYTES`. An output bomb ends here, labelled.
"""

PROBE_TIMEOUT_SECONDS: Final[float] = 20.0
"""How long one rung's canary may take before that rung is reported non-functional.

Generous, because a container runtime's first run after boot can be slow, and a probe that gives
up on a working rung would send every command to a weaker one for the life of the process.
"""

LIMIT_NAMES: Final[tuple[str, ...]] = (
    "cpu_seconds",
    "memory_bytes",
    "file_size_bytes",
    "process_count",
)
"""The names a result's ``limits_unenforced`` can hold — :class:`ResourceLimits`'s fields."""

MIN_OUTPUT_BYTES: Final[int] = 256
"""The floor for an output cap, so a truncation label always fits inside one."""

MAX_ARGV_ITEMS: Final[int] = 1_024
"""The most items an argv may hold. Beyond it the command is refused as a result, unlaunched."""

MAX_ARGV_BYTES: Final[int] = 131_072
"""The most bytes an argv may total. Far below ``ARG_MAX``, so a launch never fails for size."""

UNLAUNCHABLE_EXIT_CODE: Final[int] = 127
"""The exit code a result carries when the argv was refused before anything was launched.

The shell convention for "command not found", and the one code a caller can rely on meaning "this
never ran": a model that sends an empty argv, a non-string item, or a NUL gets a result rather than
an exception (ADR-0053 decision 4), and the result has to say what happened.
"""

_CONTAINER_RUNTIMES: Final[tuple[str, ...]] = ("podman", "docker")
_CANARY_ARGV: Final[tuple[str, ...]] = ("/bin/true",)
_RUNTIME_BINDS: Final[tuple[str, ...]] = ("/usr", "/bin", "/sbin", "/lib", "/lib64")
_ETC_ENTRIES: Final[tuple[str, ...]] = (
    "alternatives",
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "localtime",
    "nsswitch.conf",
)
"""The only entries of ``/etc`` the bwrap rung binds, read-only, each by name.

Enough to run a dynamically linked binary through Debian's alternatives symlinks and nothing more.
``/etc`` whole would carry the host's users, hostname, and any world-readable configuration into a
sandbox whose argv a model wrote. Widening this tuple is a security review item, not a convenience.
"""
_LAUNCHER_ENV: Final[dict[str, str]] = {"PATH": "/usr/bin:/bin"}
_CGROUP_LIMITS: Final[tuple[str, ...]] = ("memory_bytes", "process_count")
_CONTAINER_TMPFS: Final[str] = "/tmp:rw,noexec,nosuid,size=256m"  # noqa: S108 — the container's /tmp, not the host's
_TERMINATE_GRACE_SECONDS: Final[float] = 2.0
_REMOVE_TIMEOUT_SECONDS: Final[float] = 10.0
_PROBE_OUTPUT_BYTES: Final[int] = 4_096
_MAX_EXCERPT_CHARS: Final[int] = 200
_READ_CHUNK_BYTES: Final[int] = 65_536
_ENV_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IMAGE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """The limits every isolated command runs under. Units are in the names.

    Applied as rlimits inside the sandbox on the bwrap rung, and as cgroup limits (memory, pids)
    plus rlimits (CPU time, file size) on the container rung. A limit the rung cannot apply is named
    in the result's ``limits_unenforced``; it is never assumed.

    Attributes:
        cpu_seconds: Total CPU time, not wall time — a sleeping command consumes none of it. The
            wall-clock limit is ``run_isolated``'s ``timeout_seconds``, which is separate and
            mandatory.
        memory_bytes: Address-space size under bwrap (``RLIMIT_AS``); the cgroup memory limit,
            swap included, under a container. Docker refuses values below 6 MiB.
        file_size_bytes: The largest file the command may write (``RLIMIT_FSIZE``).
        process_count: The most processes the sandbox may hold (``RLIMIT_NPROC`` inside the user
            namespace under bwrap; ``--pids-limit`` under a container). Bounds a fork bomb.
    """

    cpu_seconds: int = 60
    memory_bytes: int = 1 << 30
    file_size_bytes: int = 64 << 20
    process_count: int = 64

    def __post_init__(self) -> None:
        """Refuse a limit that is not a positive integer.

        Raises:
            ValidationError: If any limit is not an ``int`` of at least 1. Limits are the caller's,
                and a zero or negative one would either refuse every command or mean "unlimited",
                neither of which is a limit.
        """
        for name in LIMIT_NAMES:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValidationError(
                    f"ResourceLimits.{name} must be an int of at least 1; got {value!r}.",
                    details={"field": name},
                )


@dataclass(frozen=True, slots=True)
class Captured:
    """What the launcher saw one process do. Bytes, uncapped by the model's caps, raw.

    Attributes:
        exit_code: The exit status, or the negative signal number when the process died to one.
        stdout: At most ``max_output_bytes + 1`` bytes of standard output — one byte over the cap
            is kept so that a labelled truncation can say the text stopped rather than ended.
        stderr: The same for standard error.
        timed_out: The wall-clock deadline passed and the process group was killed.
        output_truncated: A stream passed the cap; reading stopped and the process group was
            killed. Distinct from ``timed_out`` because the caller should say which happened.
    """

    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_truncated: bool


class Runner(Protocol):
    """The process-launch boundary, injected so every rung can be exercised without a process.

    The default is this module's private launcher, the one place in the package a process starts.
    A test supplies a recording double and asserts the argv the sandbox built; the integration
    suite leaves the default in place and runs real commands under real tiers.
    """

    def __call__(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> Captured:
        """Run ``argv`` to completion under the limits and report what happened.

        Args:
            argv: The complete argument list, sandbox wrapper included. Never a shell string.
            env: The **complete** environment of the launched process. Nothing is inherited.
            timeout_seconds: Wall-clock deadline, after which the process group is killed.
            max_output_bytes: Per-stream cap, after which reading stops and the group is killed.

        Returns:
            The capture. Everything the process did is data; nothing it did raises.

        Raises:
            OSError: If ``argv[0]`` cannot be started at all — it does not exist or is not
                executable. That is a fact about the host, not about the command.
        """
        ...


@dataclass(frozen=True, slots=True)
class TierReport:
    """What the probe found: the rung that will run commands, and why that one.

    Cached for the life of a :class:`TieredSandbox`, recorded on every result through ``tier`` and
    ``limits_unenforced``, and the thing an application's ``doctor`` command shows.

    Attributes:
        tier: The rung. :attr:`~toolyard.containment.IsolationTier.UNAVAILABLE` is a real answer:
            every tool requiring isolation is refused by the executor, and ``run_isolated`` raises.
        runtime: ``"podman"``, ``"docker"``, ``"bwrap"``, or ``None`` when unavailable.
        runtime_path: The absolute path the runtime was found at, used as ``argv[0]`` so the
            launcher's fixed ``PATH`` never has to find it again.
        reason: Every rung the probe visited, in order — each skipped one with why, then the one
            that ran the canary — so a report reading ``bwrap`` says whether that is because no
            container runtime exists or because one exists and failed. Operator-facing: it names
            paths and the tail of a failed canary's stderr, and it never reaches a model.
        limits_unenforced: The :data:`LIMIT_NAMES` this rung could not apply on this host.
        limiter_path: The absolute path of ``prlimit`` on the bwrap rung, or ``None`` when it is
            absent (and the four limits are unenforced) or the rung is not bwrap.
    """

    tier: IsolationTier
    runtime: str | None
    runtime_path: str | None
    reason: str
    limits_unenforced: tuple[str, ...] = ()
    limiter_path: str | None = None


@dataclass(frozen=True, slots=True)
class _Mounts:
    """The resolved workspace as the rungs bind it: ancestors first, so the nearest root wins."""

    write_root: Path
    ordered: tuple[tuple[Path, bool], ...]


class TieredSandbox:
    """Phase 2's sandbox: Phase 1's path containment, plus the probe and the ladder.

    One instance serves one executor and every handler that runs commands, so the tier the executor
    checked at containment is the tier the handler's command runs under. The probe runs once, on
    the first call that needs it, and is cached; an application that wants to pay that cost at
    startup — and show the result in ``doctor`` — calls :meth:`report` then.

    Everything configurable is a constructor argument (spec §12). There is no argument that skips
    resolution, widens a root, or adds a rung below refusal.
    """

    __slots__ = (
        "_container_image",
        "_containment",
        "_limits",
        "_lock",
        "_max_output_bytes",
        "_monotonic_ns",
        "_platform",
        "_probe_timeout_seconds",
        "_report",
        "_runner",
        "_which",
    )

    def __init__(
        self,
        *,
        container_image: str = DEFAULT_CONTAINER_IMAGE,
        limits: ResourceLimits | None = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        probe_timeout_seconds: float = PROBE_TIMEOUT_SECONDS,
        which: Callable[[str], str | None] = shutil.which,
        platform: str = sys.platform,
        runner: Runner | None = None,
        monotonic_ns: Callable[[], int] = monotonic_ns,
    ) -> None:
        """Build a sandbox over this host, with every boundary injectable.

        Args:
            container_image: The image the container rung runs commands in. Must already be
                present: the rung is probed and used with ``--pull=never``.
            limits: The resource limits every command runs under. ``None`` means the defaults.
            max_output_bytes: The per-stream cap on captured output.
            probe_timeout_seconds: How long one rung's canary may take.
            which: Executable lookup. Injected so a test — or an operator forcing a lower rung —
                can shape the probe's view of the host without mutating the host: a lookup that
                answers ``None`` for ``podman`` and ``docker`` makes bwrap the top of the ladder.
            platform: ``sys.platform``, injected. Anything but Linux has no tier (spec §16).
            runner: The process-launch boundary. ``None`` means the real launcher.
            monotonic_ns: The duration source, for ``duration_ms``.

        Raises:
            ValidationError: If the image is not a plausible image reference, a cap is below
                :data:`MIN_OUTPUT_BYTES`, the probe timeout is not a finite positive number, or a
                boundary is not callable. Caller bugs, surfaced at startup.
        """
        if not isinstance(container_image, str) or not _IMAGE_PATTERN.fullmatch(container_image):
            raise ValidationError(
                f"container_image must be an image reference such as {DEFAULT_CONTAINER_IMAGE!r}; "
                f"got {container_image!r}.",
                details={"field": "container_image"},
            )
        if limits is not None and not isinstance(limits, ResourceLimits):
            raise ValidationError(
                f"limits must be a ResourceLimits or None; got {type(limits).__name__}.",
                details={"field": "limits"},
            )
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or max_output_bytes < MIN_OUTPUT_BYTES
        ):
            raise ValidationError(
                f"max_output_bytes must be an int of at least {MIN_OUTPUT_BYTES}; got "
                f"{max_output_bytes!r}.",
                details={"field": "max_output_bytes", "minimum": MIN_OUTPUT_BYTES},
            )
        _require_timeout("probe_timeout_seconds", probe_timeout_seconds)
        if not callable(which) or (runner is not None and not callable(runner)):
            raise ValidationError(
                "which and runner must be callable; they are the probe's and the launcher's "
                "boundaries.",
                details={"field": "which" if not callable(which) else "runner"},
            )
        if not isinstance(platform, str):
            raise ValidationError(
                f"platform must be a string such as sys.platform; got {type(platform).__name__}.",
                details={"field": "platform"},
            )
        self._container_image = container_image
        self._containment = PathContainment()
        self._limits = ResourceLimits() if limits is None else limits
        self._max_output_bytes = max_output_bytes
        self._probe_timeout_seconds = float(probe_timeout_seconds)
        self._which = which
        self._platform = platform
        self._runner: Runner = _launch if runner is None else runner
        self._monotonic_ns = monotonic_ns
        self._lock = threading.Lock()
        self._report: TierReport | None = None

    # -- the path half: Phase 1's, delegated, never re-derived ------------------------------------

    def resolve_read(self, candidate: str, paths: SandboxPaths) -> Path:
        """Resolve for reading. Delegates to :class:`~toolyard.containment.PathContainment`."""
        return self._containment.resolve_read(candidate, paths)

    def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
        """Resolve for writing. Delegates to :class:`~toolyard.containment.PathContainment`."""
        return self._containment.resolve_write(candidate, paths)

    # -- the isolation half ------------------------------------------------------------------------

    def report(self) -> TierReport:
        """Probe the host once and return what was found; later calls return the same report.

        Returns:
            The :class:`TierReport`. The probe runs on the first call, under a lock, and is cached
            for the life of this object: a decided rung is never re-decided, so a runtime that
            disappears afterwards fails the command it was running — loudly, as a non-zero result
            or a raised launch error — and is never quietly replaced by a weaker rung.
        """
        with self._lock:
            if self._report is None:
                self._report = self._probe()
                _LOGGER.debug("isolation tier %s: %s", self._report.tier.value, self._report.reason)
            return self._report

    def isolation_tier(self) -> IsolationTier:
        """Report the highest tier whose canary passed on this host. See :class:`Sandbox`."""
        return self.report().tier

    def run_isolated(
        self,
        argv: Sequence[str],
        *,
        paths: SandboxPaths,
        timeout_seconds: float,
        env: Mapping[str, str] | None = None,
        network: bool = False,
    ) -> SubprocessResult:
        """Run ``argv`` under the probed rung, or refuse. See :class:`Sandbox` for the contract.

        The argv is the model's, so nothing about it raises: an argv that is empty, holds a
        non-string, a NUL, or too much, comes back as a result with
        :data:`UNLAUNCHABLE_EXIT_CODE` and a ``stderr`` naming the problem, and nothing is
        launched. Everything else here — the workspace, the timeout, the environment — is the
        caller's, and a mistake in it raises.

        Args:
            argv: The command, already split. Relative paths in it resolve against the write root,
                which is the working directory on both rungs.
            paths: The workspace. The write root must exist as a directory; a read root that does
                not is skipped, since a directory that does not exist contains nothing.
            timeout_seconds: The wall-clock limit. On expiry the whole tree is killed and the
                result says ``timed_out``.
            env: The explicit allowlist. ``None`` is the empty mapping, never ``os.environ``.
            network: Whether the sandbox keeps a network namespace. ``run_command`` never passes
                ``True``; only a tool declaring ``NETWORK`` may.

        Returns:
            What the command did, with the rung that ran it and the limits that rung could not
            apply recorded on the result. Output is decoded as UTF-8 with replacement, cleaned,
            and capped with the truncation label when a stream hit the cap.

        Raises:
            ToolYardError: If the tier is ``UNAVAILABLE`` — a caller bug, because the executor
                refuses such a tool before a handler exists to call this; arriving here means a
                handler reached for a subprocess without declaring ``requires_isolation`` — or if
                the probed runtime can no longer be launched. Never an unisolated run.
            ValidationError: If ``timeout_seconds`` is not a finite positive number, ``env`` is not
                a mapping of valid variable names to strings, or the write root is not a directory.
        """
        report = self.report()
        if report.tier is IsolationTier.UNAVAILABLE:
            raise ToolYardError(
                "No isolation tier is available on this host and there is no unisolated rung: "
                f"{report.reason} The executor refuses tools declaring `requires_isolation` before "
                "any handler runs, so reaching this means a handler reached for a subprocess "
                "without declaring it.",
                details={"isolation_tier": report.tier.value},
            )
        _require_timeout("timeout_seconds", timeout_seconds)
        child_env = _checked_env(env)
        rejection = _argv_rejection(argv)
        if rejection is not None:
            return SubprocessResult(
                exit_code=UNLAUNCHABLE_EXIT_CODE,
                stdout="",
                stderr=f"toolyard: argv refused before launch: {rejection}",
                duration_ms=0,
                tier=report.tier,
                timed_out=False,
                limits_unenforced=report.limits_unenforced,
            )
        mounts = _mounts(paths)
        command = tuple(argv)
        name = _container_name()
        if report.tier is IsolationTier.CONTAINER:
            assert report.runtime is not None and report.runtime_path is not None  # noqa: S101 — the probe set both; mypy needs the fact
            full = _container_argv(
                runtime=report.runtime,
                runtime_path=report.runtime_path,
                image=self._container_image,
                name=name,
                limits=self._limits,
                mounts=mounts,
                env=child_env,
                network=network,
                argv=command,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        else:
            assert report.runtime_path is not None  # noqa: S101 — the probe set it; mypy needs the fact
            full = _bwrap_argv(
                bwrap_path=report.runtime_path,
                limiter_path=report.limiter_path,
                limits=self._limits,
                mounts=mounts,
                env=child_env,
                network=network,
                argv=command,
            )
        start_ns = self._monotonic_ns()
        try:
            captured = self._runner(
                full,
                env=dict(_LAUNCHER_ENV),
                timeout_seconds=float(timeout_seconds),
                max_output_bytes=self._max_output_bytes,
            )
        except OSError as exc:
            raise ToolYardError(
                f"The {report.runtime} runtime probed at {report.runtime_path!r} could not be "
                f"launched ({type(exc).__name__}). The tier was decided once and is not "
                "re-decided: a runtime that vanished after the probe is a host fault, never a "
                "reason to run the command unisolated.",
                details={"isolation_tier": report.tier.value, "runtime": report.runtime},
            ) from exc
        duration_ms = _elapsed_ms(start_ns, self._monotonic_ns())
        if report.tier is IsolationTier.CONTAINER and (
            captured.timed_out or captured.output_truncated
        ):
            self._remove_container(report, name)
        _LOGGER.debug(
            "run_isolated under %s: exit %d, timed_out=%s, truncated=%s",
            report.tier.value,
            captured.exit_code,
            captured.timed_out,
            captured.output_truncated,
        )
        return SubprocessResult(
            exit_code=captured.exit_code,
            stdout=_decode(captured.stdout, self._max_output_bytes),
            stderr=_decode(captured.stderr, self._max_output_bytes),
            duration_ms=duration_ms,
            tier=report.tier,
            timed_out=captured.timed_out,
            limits_unenforced=report.limits_unenforced,
        )

    # -- the probe ---------------------------------------------------------------------------------

    def _probe(self) -> TierReport:
        """Walk the ladder, top rung first, running each rung's real argv around the canary."""
        if not self._platform.startswith("linux"):
            return TierReport(
                tier=IsolationTier.UNAVAILABLE,
                runtime=None,
                runtime_path=None,
                reason=(
                    f"platform {self._platform!r} has no isolation tier; tools requiring isolation "
                    "refuse here until a platform tier exists (spec §16)."
                ),
            )
        findings: list[str] = []
        with tempfile.TemporaryDirectory(prefix="toolyard-probe-") as scratch:
            mounts = _mounts(SandboxPaths(write_root=Path(scratch)))
            for runtime in _CONTAINER_RUNTIMES:
                runtime_path = self._which(runtime)
                if not runtime_path:
                    findings.append(f"{runtime}: not installed")
                    continue
                argv = _container_argv(
                    runtime=runtime,
                    runtime_path=runtime_path,
                    image=self._container_image,
                    name=_container_name(),
                    limits=self._limits,
                    mounts=mounts,
                    env={},
                    network=False,
                    argv=_CANARY_ARGV,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )
                passed, excerpt, captured = self._canary(argv)
                if passed:
                    warned = captured is not None and captured.stderr.strip() != b""
                    findings.append(
                        f"{runtime} at {runtime_path} ran the canary under the container tier's "
                        f"flags with image {self._container_image!r}"
                        + (
                            "; the runtime warned on stderr, so the cgroup limits are reported "
                            "unenforced"
                            if warned
                            else ""
                        )
                    )
                    return TierReport(
                        tier=IsolationTier.CONTAINER,
                        runtime=runtime,
                        runtime_path=runtime_path,
                        reason="; ".join(findings) + ".",
                        limits_unenforced=_CGROUP_LIMITS if warned else (),
                    )
                findings.append(
                    f"{runtime}: installed at {runtime_path} but the canary failed ({excerpt})"
                )
            bwrap_path = self._which("bwrap")
            if not bwrap_path:
                findings.append("bwrap: not installed")
            else:
                limiter_path = self._which("prlimit")
                argv = _bwrap_argv(
                    bwrap_path=bwrap_path,
                    limiter_path=limiter_path,
                    limits=self._limits,
                    mounts=mounts,
                    env={},
                    network=False,
                    argv=_CANARY_ARGV,
                )
                passed, excerpt, _ = self._canary(argv)
                if passed:
                    findings.append(
                        f"bwrap at {bwrap_path} ran the canary under the bwrap tier's flags"
                        + (
                            f" with rlimits applied inside the sandbox by {limiter_path}"
                            if limiter_path
                            else "; prlimit is absent, so every rlimit is reported unenforced"
                        )
                    )
                    return TierReport(
                        tier=IsolationTier.BWRAP,
                        runtime="bwrap",
                        runtime_path=bwrap_path,
                        reason="; ".join(findings) + ".",
                        limits_unenforced=() if limiter_path else LIMIT_NAMES,
                        limiter_path=limiter_path or None,
                    )
                findings.append(
                    f"bwrap: installed at {bwrap_path} but the canary failed ({excerpt})"
                )
        return TierReport(
            tier=IsolationTier.UNAVAILABLE,
            runtime=None,
            runtime_path=None,
            reason=(
                "no isolation tier is available: "
                + "; ".join(findings)
                + ". Tools requiring isolation are refused, never run unisolated (ADR-0018)."
            ),
        )

    def _canary(self, argv: Sequence[str]) -> tuple[bool, str, Captured | None]:
        """Run one rung's argv around the canary and say whether, and if not why not."""
        try:
            captured = self._runner(
                argv,
                env=dict(_LAUNCHER_ENV),
                timeout_seconds=self._probe_timeout_seconds,
                max_output_bytes=_PROBE_OUTPUT_BYTES,
            )
        except OSError as exc:
            return False, f"{type(exc).__name__}: {_excerpt(str(exc))}", None
        if captured.timed_out:
            return False, f"timed out after {self._probe_timeout_seconds:g} s", captured
        if captured.exit_code != 0:
            detail = _excerpt(captured.stderr.decode("utf-8", errors="replace"))
            return False, f"exit {captured.exit_code}: {detail or '(no stderr)'}", captured
        return True, "", captured

    def _remove_container(self, report: TierReport, name: str) -> None:
        """Kill and remove a container whose CLI was killed, so the tree does not outlive the call.

        Best effort, with its own timeout, because a container the runtime will not remove is a
        host fault to log rather than a reason to hide the result the command already produced.
        """
        assert report.runtime_path is not None  # noqa: S101 — only called on the container rung
        try:
            outcome = self._runner(
                (report.runtime_path, "rm", "-f", name),
                env=dict(_LAUNCHER_ENV),
                timeout_seconds=_REMOVE_TIMEOUT_SECONDS,
                max_output_bytes=_PROBE_OUTPUT_BYTES,
            )
        except OSError as exc:
            _LOGGER.debug("container %s could not be removed: %s", name, type(exc).__name__)
            return
        if outcome.exit_code != 0:
            _LOGGER.debug("container %s removal exited %d", name, outcome.exit_code)


# -- argv builders: one per rung, every flag ADR-0018's -------------------------------------------


def _bwrap_argv(
    *,
    bwrap_path: str,
    limiter_path: str | None,
    limits: ResourceLimits,
    mounts: _Mounts,
    env: Mapping[str, str],
    network: bool,
    argv: Sequence[str],
) -> tuple[str, ...]:
    """Build the bwrap rung's argv: ADR-0018's tier-2 flags, the workspace, then the command."""
    built: list[str] = [
        bwrap_path,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    if network:
        built.append("--share-net")
    for root in _RUNTIME_BINDS:
        built.extend(("--ro-bind-try", root, root))
    for entry in _ETC_ENTRIES:
        path = f"/etc/{entry}"
        built.extend(("--ro-bind-try", path, path))
    built.extend(("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"))  # noqa: S108 — the sandbox's private tmpfs, not the host's /tmp
    for mount_root, writable in mounts.ordered:
        rendered = str(mount_root)
        built.extend(("--bind" if writable else "--ro-bind", rendered, rendered))
    built.extend(("--chdir", str(mounts.write_root)))
    for name, value in env.items():
        built.extend(("--setenv", name, value))
    built.append("--")
    if limiter_path is not None:
        built.extend(
            (
                limiter_path,
                f"--cpu={limits.cpu_seconds}",
                f"--as={limits.memory_bytes}",
                f"--fsize={limits.file_size_bytes}",
                f"--nproc={limits.process_count}",
                "--",
            )
        )
    built.extend(argv)
    return tuple(built)


def _container_argv(
    *,
    runtime: str,
    runtime_path: str,
    image: str,
    name: str,
    limits: ResourceLimits,
    mounts: _Mounts,
    env: Mapping[str, str],
    network: bool,
    argv: Sequence[str],
    uid: int,
    gid: int,
) -> tuple[str, ...]:
    """Build the container rung's argv: ADR-0018's tier-1 flags, the workspace, then the command.

    Raises:
        ValidationError: If a workspace root's path holds a colon, which the ``--volume`` syntax
            cannot carry. The root is the caller's, so this is theirs to rename.
    """
    built: list[str] = [runtime_path, "run", "--rm", "--pull=never", "--name", name]
    if not network:
        built.append("--network=none")
    built.extend(
        (
            "--read-only",
            "--tmpfs",
            _CONTAINER_TMPFS,
            "--memory",
            str(limits.memory_bytes),
            "--memory-swap",
            str(limits.memory_bytes),
            "--pids-limit",
            str(limits.process_count),
            "--ulimit",
            f"cpu={limits.cpu_seconds}:{limits.cpu_seconds}",
            "--ulimit",
            f"fsize={limits.file_size_bytes}:{limits.file_size_bytes}",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{uid}:{gid}",
        )
    )
    if runtime == "podman":
        # Rootless podman maps the caller's uid to a subordinate uid unless told to keep it, and a
        # workspace owned by the caller would then be unwritable from inside.
        built.append("--userns=keep-id")
    built.extend(("--workdir", str(mounts.write_root)))
    for root, writable in mounts.ordered:
        rendered = str(root)
        if ":" in rendered:
            raise ValidationError(
                f"A workspace root holds a colon, which a container volume spec cannot carry: "
                f"{rendered!r}.",
                details={"field": "paths"},
            )
        built.extend(("--volume", f"{rendered}:{rendered}:{'rw' if writable else 'ro'}"))
    for variable, value in env.items():
        built.extend(("--env", f"{variable}={value}"))
    built.append(image)
    built.extend(argv)
    return tuple(built)


def _mounts(paths: SandboxPaths) -> _Mounts:
    """Resolve the workspace into the binds both rungs make, nearest root winning.

    The roots are bound at their **resolved** paths — the world a handler operates in is already
    the resolved one, because containment hands it resolved paths. Binds are ordered ancestors
    first: on both rungs the later, deeper mount wins, so a read root inside the write root is
    read-only and a write root inside a read root is writable, and the two rungs agree.

    Raises:
        ValidationError: If the write root cannot be resolved or is not a directory.
    """
    try:
        write_root = paths.write_root.resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        raise ValidationError(
            f"The workspace write root {str(paths.write_root)!r} cannot be resolved.",
            details={"field": "write_root"},
        ) from exc
    if not write_root.is_dir():
        raise ValidationError(
            f"The workspace write root {str(write_root)!r} is not a directory; a command needs a "
            "working directory to be bound read-write.",
            details={"field": "write_root"},
        )
    read_roots: list[Path] = []
    for root in paths.read_roots:
        try:
            resolved = root.resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        if not resolved.is_dir() or resolved == write_root or resolved in read_roots:
            continue
        read_roots.append(resolved)
    ordered = [(root, False) for root in read_roots] + [(write_root, True)]
    ordered.sort(key=lambda mount: len(mount[0].parts))
    return _Mounts(write_root=write_root, ordered=tuple(ordered))


# -- the model's argv and the caller's inputs ------------------------------------------------------


def _argv_rejection(argv: object) -> str | None:
    """Say why an argv cannot be launched, or ``None`` when it can. Never raises: the model's."""
    if isinstance(argv, str | bytes) or not isinstance(argv, Sequence):
        return "argv must be a sequence of strings, never a command string"
    if len(argv) == 0:
        return "argv is empty"
    if len(argv) > MAX_ARGV_ITEMS:
        return f"argv holds {len(argv)} items; the limit is {MAX_ARGV_ITEMS}"
    total = 0
    for index, item in enumerate(argv):
        if not isinstance(item, str):
            return f"argv[{index}] is {type(item).__name__}, not a string"
        if clean_text(item) != item:
            return f"argv[{index}] holds a NUL or an unencodable character"
        total += len(item.encode("utf-8"))
    if not argv[0].strip():
        return "argv[0] is blank"
    if total > MAX_ARGV_BYTES:
        return f"argv totals {total} bytes; the limit is {MAX_ARGV_BYTES}"
    return None


def _checked_env(env: Mapping[str, str] | None) -> dict[str, str]:
    """Return the allowlist as a private dict, or raise for a caller's malformed one."""
    if env is None:
        return {}
    if not isinstance(env, Mapping):
        raise ValidationError(
            f"env must be a mapping of variable names to strings or None; got "
            f"{type(env).__name__}. None means the empty allowlist, never os.environ.",
            details={"field": "env"},
        )
    checked: dict[str, str] = {}
    for name, value in env.items():
        if not isinstance(name, str) or not _ENV_NAME_PATTERN.fullmatch(name):
            raise ValidationError(
                f"env holds an invalid variable name {name!r}; names are [A-Za-z_][A-Za-z0-9_]*.",
                details={"field": "env"},
            )
        if not isinstance(value, str) or clean_text(value) != value:
            raise ValidationError(
                f"env[{name!r}] must be a string with no NUL and no lone surrogate.",
                details={"field": "env", "variable": name},
            )
        checked[name] = value
    return checked


def _require_timeout(field_name: str, value: float) -> None:
    """Refuse a timeout that is not a finite positive number; there is no way to say "none"."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValidationError(
            f"{field_name} must be a number of seconds; got {type(value).__name__}.",
            details={"field": field_name},
        )
    if not value > 0 or value != value or value in (float("inf"), float("-inf")):  # noqa: PLR0124
        raise ValidationError(
            f"{field_name} must be finite and greater than zero; got {value!r}. A timeout is "
            "mandatory (spec §11.8).",
            details={"field": field_name},
        )


def _container_name() -> str:
    """A fresh, unguessable container name, so a timed-out container can be removed by name."""
    return f"toolyard-{uuid.uuid4().hex}"


def _decode(raw: bytes, max_output_bytes: int) -> str:
    """Turn a captured stream into the cleaned, capped, labelled text a result carries."""
    text, _ = truncate_text(raw.decode("utf-8", errors="replace"), max_bytes=max_output_bytes)
    return text


def _excerpt(text: str) -> str:
    """The tail of a stream, cleaned and capped, for an operator-facing reason."""
    cleaned = clean_text(text).strip()
    return cleaned[-_MAX_EXCERPT_CHARS:]


def _elapsed_ms(start_ns: int, end_ns: int) -> int:
    """Milliseconds between two readings, tolerating a source that misbehaves."""
    if not isinstance(end_ns, int) or end_ns < start_ns:
        return 0
    return int(round((end_ns - start_ns) / 1_000_000))


# -- the launcher: the one place in the package a process starts -----------------------------------


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the process group; escalate to SIGKILL if it outlives the grace period."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + _TERMINATE_GRACE_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return
        time.sleep(0.02)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _reap(process: subprocess.Popen[bytes]) -> None:
    """Wait for a killed process, but not forever.

    A process SIGKILL cannot reap is in uninterruptible sleep on a hung mount or device; waiting on
    it would hang the tool call, and through it the agent loop, which is a stop condition nobody
    controls. The result then reports exit code ``-1`` — the process was killed and never reaped.
    """
    try:
        process.wait(timeout=_TERMINATE_GRACE_SECONDS * 2)
    except subprocess.TimeoutExpired:
        _LOGGER.debug("process %d survived SIGKILL; not waiting further", process.pid)


def _launch(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> Captured:
    """Start ``argv`` in its own session, capture both streams under a cap, kill on the deadline.

    The only ``Popen`` in the package (``tests/unit/test_boundaries.py`` counts them). An argument
    list, never a shell; the complete environment passed in, never inherited; raw pipes read through
    a selector so a flood on one stream cannot block the other; and a kill that takes the whole
    process group, because the child was started as the leader of a new session.

    Args:
        argv: The complete argument list.
        env: The complete environment.
        timeout_seconds: The wall-clock deadline.
        max_output_bytes: The per-stream cap. One byte over it is kept so the caller can label the
            truncation; past it, reading stops and the group is killed.

    Returns:
        The capture. Nothing the process does raises.

    Raises:
        OSError: If ``argv[0]`` cannot be started. A fact about the host.
    """
    process = subprocess.Popen(  # noqa: S603 — argv list, never a shell; the package's one launch site
        list(argv),
        bufsize=0,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        start_new_session=True,
        close_fds=True,
    )
    assert process.stdout is not None and process.stderr is not None  # noqa: S101 — PIPE above
    streams: dict[str, IO[bytes]] = {"stdout": process.stdout, "stderr": process.stderr}
    captured: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    sizes: dict[str, int] = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    truncated = False
    selector = selectors.DefaultSelector()
    for name, stream in streams.items():
        selector.register(stream, selectors.EVENT_READ, name)
    try:
        open_streams = len(streams)
        while open_streams and not truncated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                name = str(key.data)
                chunk = streams[name].read(_READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(streams[name])
                    open_streams -= 1
                    continue
                room = max_output_bytes + 1 - sizes[name]
                kept = chunk[:room]
                captured[name].append(kept)
                sizes[name] += len(kept)
                if sizes[name] > max_output_bytes:
                    truncated = True
                    break
        if timed_out or truncated:
            _kill_group(process)
            _reap(process)
        else:
            process.wait(timeout=max(deadline - time.monotonic(), 0.0))
    except subprocess.TimeoutExpired:
        # Both streams closed, and the process kept running past the deadline anyway.
        timed_out = True
        _kill_group(process)
        _reap(process)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return Captured(
        exit_code=process.returncode if process.returncode is not None else -1,
        stdout=b"".join(captured["stdout"]),
        stderr=b"".join(captured["stderr"]),
        timed_out=timed_out,
        output_truncated=truncated,
    )
