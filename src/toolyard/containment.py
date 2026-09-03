"""Containment — the sandbox port, its vocabulary, and the Phase-1 implementation of its path half.

This module is the seam Phase 2 (row D1) implements into, and it is deliberately split so that the
seam is not a stub. Two halves:

* **Path containment is real here, now.** :class:`PathContainment` resolves a candidate fully —
  symlinks, ``..``, relative components — and *then* compares it against the roots, which is the
  order spec §11.3 fixes and the only order that is safe. It is the executor's fifth check, and
  ``path_escape`` is reachable and tested in this phase, because the development plan's ordering
  rule is that the refusal machinery exists before anything that could do harm.
* **Isolation is honestly absent.** :meth:`PathContainment.isolation_tier` returns
  :attr:`IsolationTier.UNAVAILABLE`, because this implementation has no container tier and no
  bwrap tier — it has no tier at all. ADR-0018's ladder ends in refusal, so an implementation
  with no rungs refuses, and the executor refuses any tool declaring ``requires_isolation`` before
  a handler runs. A permissive stand-in that reported a tier it did not have would be the "warning
  instead of a containment" the ADR rejects verbatim.

**What Phase 2 must do, and must not.** D1 adds ``toolyard.sandbox`` with the tier probe and
``run_isolated``, and composes or subclasses :class:`PathContainment` for the path half rather than
re-deriving it — a second resolution-then-check implementation is a second chance to compare before
resolving. ``tests/unit/test_containment.py`` is the contract; extend it, never relax it. The
vocabulary below (:class:`SandboxPaths`, :class:`IsolationTier`, :class:`SubprocessResult`,
:class:`PathAccess`) is Phase 1's and is imported from here, never redefined.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

from toolyard._safe import clean_text
from toolyard.errors import ToolYardError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

__all__ = [
    "IsolationTier",
    "PathAccess",
    "PathContainment",
    "PathEscape",
    "Sandbox",
    "SandboxPaths",
    "SubprocessResult",
]

MAX_CANDIDATE_CHARS: Final[int] = 4_096
"""How long a path a model may propose before it is refused unresolved.

Longer than any real path (``PATH_MAX`` is 4096 on Linux) and short enough that the refusal itself
cannot be used to write a megabyte into a record.
"""


class PathAccess(StrEnum):
    """Which root a declared path argument is checked against.

    A :class:`~toolyard.types.ToolSpec` names its path arguments and the access each needs; the
    executor resolves them through the sandbox before the handler runs. The two are separate
    checks against separate roots (spec §11.3): a write candidate that lands inside a *read* root
    is an escape, because a read root is mounted to be read.
    """

    READ = "read"
    """Resolved against the read roots and the write root, which is readable too."""

    WRITE = "write"
    """Resolved against the write root alone."""


class IsolationTier(StrEnum):
    """The subprocess isolation available on this host — ADR-0018's ladder, applied to tools.

    The order is the ADR's, verbatim, and the lowest rung is refusal rather than "run it anyway":
    the deployment with no tier available is exactly the one nobody is watching. Nothing probes for
    a tier until Phase 2; the vocabulary is here so that phase finds it waiting.
    """

    CONTAINER = "container"
    """``podman`` or ``docker``: no network, read-only rootfs, dropped capabilities, rlimits."""

    BWRAP = "bwrap"
    """``bubblewrap``: unshared namespaces, the roots bound and nothing else from the host."""

    UNAVAILABLE = "unavailable"
    """Neither. A tool requiring isolation refuses with ``isolation_unavailable``, always."""


@dataclass(frozen=True, slots=True)
class SandboxPaths:
    """The filesystem a single trajectory or stage may touch.

    Read and write are separate roots because they are separate questions. A single root would make
    "may this tool read the file it is about to overwrite" and "may this tool write into the
    directory it was allowed to read" the same check, and they are not.

    Attributes:
        write_root: The one directory a ``WRITE`` path argument may resolve inside. Also readable.
        read_roots: Additional directories a ``READ`` path argument may resolve inside. Empty by
            default, which means "the write root and nothing else" — closed, like every default in
            this package.
    """

    write_root: Path
    read_roots: tuple[Path, ...] = ()


@dataclass(frozen=True, slots=True)
class SubprocessResult:
    """What an isolated command did. Produced by Phase 2's ``run_isolated``; defined here.

    Attributes:
        exit_code: The child's exit status.
        stdout: Captured standard output, already capped by the runner.
        stderr: Captured standard error, already capped by the runner.
        duration_ms: Wall time the child ran for, from a monotonic source.
        tier: Which rung of the ladder actually ran it. Recorded on every result that executed a
            command, because correctness is comparable across tiers and performance is not.
        timed_out: Whether the process tree was killed for exceeding its limit.
        limits_unenforced: The names of resource limits this platform could not apply — ADR-0016's
            rule, in the place Phase 2 needs it: an unenforceable limit is *reported*, never
            assumed. An empty tuple means every declared limit was applied; it never means "no
            limits were asked for", which is what a ``None`` here would have been unable to
            distinguish.
    """

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    tier: IsolationTier
    timed_out: bool = False
    limits_unenforced: tuple[str, ...] = ()


class PathEscape(Exception):
    """A candidate path resolved outside every root it was checked against.

    Deliberately **not** a :class:`~toolyard.errors.ToolYardError`: that hierarchy is caller bugs
    only, and a path escape is the opposite — it is the model doing precisely what the threat model
    says it will. This is an internal signal between containment and the executor, which converts
    it into a ``REFUSED`` result before it can leave
    :meth:`~toolyard.executor.ToolExecutor.execute`. Phase 3's file tools catch it for the same
    reason, which is why it is exported.

    Attributes:
        candidate: What was asked for, cleaned and capped. Safe to show a model — it is the model's
            own string.
        root_role: ``"write_root"`` or ``"read_roots"``: *which kind* of root was violated. This is
            what reaches the model. The roots' actual paths do not (ADR-0053's last consequence:
            refusal text is part of the prompt surface).
        root: The root the check was made against, for the record and the operator. ``None`` when
            the candidate was refused before a root was reached — an empty string, a NUL byte, or a
            length no real path has.
    """

    def __init__(self, candidate: str, *, root_role: str, root: Path | None = None) -> None:
        """Build the signal around what was asked for and what it was measured against."""
        super().__init__(f"path escapes {root_role}")
        self.candidate = candidate
        self.root_role = root_role
        self.root = root


class Sandbox(Protocol):
    """The port the executor holds: containment now, isolation from Phase 2.

    The executor depends on this Protocol and never on a concrete class, so D1 can supply the full
    implementation without touching :mod:`toolyard.executor`. There is deliberately no ``None``
    option and no default: an executor without a sandbox would be an executor whose fifth check
    does nothing, and a check that does nothing is worse than an absent one because the fixed
    refusal order would then be a claim rather than a fact.
    """

    def resolve_read(self, candidate: str, paths: SandboxPaths) -> Path:
        """Resolve a candidate for reading and confirm it lands inside a readable root.

        Args:
            candidate: A model-supplied path string. Untrusted, in every sense.
            paths: The roots this invocation may touch.

        Returns:
            The fully resolved path. Callers operate on *this* value and never on ``candidate``.

        Raises:
            PathEscape: If the resolved path is outside the write root and every read root.
        """
        ...

    def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
        """Resolve a candidate for writing and confirm it lands inside the write root.

        Args:
            candidate: A model-supplied path string. Untrusted, in every sense.
            paths: The roots this invocation may touch.

        Returns:
            The fully resolved path. Callers operate on *this* value and never on ``candidate``.

        Raises:
            PathEscape: If the resolved path is outside the write root — including when it is
                inside a read root, which is readable and not writable.
        """
        ...

    def isolation_tier(self) -> IsolationTier:
        """Report the highest isolation tier available on this host.

        Returns:
            The tier. :attr:`IsolationTier.UNAVAILABLE` means a tool declaring
            ``requires_isolation`` refuses; it never means "run it unisolated" (ADR-0018).
        """
        ...

    def run_isolated(
        self,
        argv: Sequence[str],
        *,
        paths: SandboxPaths,
        timeout_seconds: float,
        env: Mapping[str, str] | None = None,
        network: bool = False,
    ) -> SubprocessResult:
        """Run an argv under the highest available tier. Phase 2's work.

        Args:
            argv: The command and its arguments, already split. Never a shell string; there is no
                ``shell=True`` anywhere in this package and a test greps for it.
            paths: Bound read-write at the write root and read-only at the read roots. Nothing else
                from the host is visible to the child.
            timeout_seconds: A wall-clock limit after which the whole process tree is killed.
            env: An explicit allowlist of environment variables. ``None`` means the empty mapping —
                never ``os.environ``, which would hand a child every credential the application
                holds (ADR-0053 decision 5).
            network: Whether the child may reach the network. Only tools declaring
                :attr:`~toolyard.types.EgressClass.NETWORK` may pass ``True``, and ``run_command``
                never does in v1.

        Returns:
            What the child did, with the tier that ran it recorded on the result.
        """
        ...


@dataclass(frozen=True, slots=True)
class PathContainment:
    """Phase 1's honest sandbox: real path containment, and no isolation because there is none.

    Resolution-then-check, in that order and never the reverse (spec §11.3). A candidate is turned
    into an absolute, symlink-free path *first*, and only the result is compared against the roots.
    Comparing before resolving is the classic containment bug: ``root/../../etc/passwd`` has the
    root as a string prefix, and a symlink inside the root has the root as its whole ancestry.

    Containment is by path *ancestry*, never by string prefix, which is what makes ``/data`` and
    ``/database`` distinct roots rather than one root and its apparent child.

    A relative candidate resolves against ``paths.write_root``, not against the process's working
    directory. The process CWD is wherever the application happened to start; it is not the
    trajectory's workspace, and resolving against it would silently place a tool outside the
    containment its caller configured. This class never calls :meth:`pathlib.Path.cwd`.

    **The TOCTOU boundary, stated rather than hidden.** Resolution and use are two moments; a
    symlink swapped between them defeats a resolved path. This class narrows that window to nothing
    it can control — it returns the resolved path so a caller never re-resolves the candidate — but
    closing it entirely needs ``O_NOFOLLOW`` and directory file descriptors at the point of use,
    which is Phase 2's work in ``toolyard.sandbox`` and is named as that phase's likely failure
    mode.

    Attributes:
        follow_symlinks_note: Not a setting. There is no option here to skip resolution, to compare
            before resolving, or to allow a root to be widened per call — an implementation with a
            "just this once" flag is an implementation whose containment is advisory.
    """

    follow_symlinks_note: str = field(
        default="resolution is unconditional; there is no flag that skips it",
        init=False,
        repr=False,
    )

    def resolve_read(self, candidate: str, paths: SandboxPaths) -> Path:
        """Resolve for reading, against the read roots and the write root. See :class:`Sandbox`."""
        roots = (paths.write_root, *paths.read_roots)
        return self._resolve_within(candidate, roots, role="read_roots")

    def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
        """Resolve for writing, against the write root alone. See :class:`Sandbox`."""
        return self._resolve_within(candidate, (paths.write_root,), role="write_root")

    def isolation_tier(self) -> IsolationTier:
        """Report :attr:`IsolationTier.UNAVAILABLE`, because this implementation has no tier.

        Returns:
            :attr:`IsolationTier.UNAVAILABLE`, always. Phase 1 probes nothing and runs nothing, and
            reporting a tier it does not have is the one thing ADR-0018 forbids outright.
        """
        return IsolationTier.UNAVAILABLE

    def run_isolated(
        self,
        argv: Sequence[str],
        *,
        paths: SandboxPaths,
        timeout_seconds: float,
        env: Mapping[str, str] | None = None,
        network: bool = False,
    ) -> SubprocessResult:
        """Refuse: this implementation runs no processes. See :class:`Sandbox` for the contract.

        Raises:
            ToolYardError: Always, and it is a caller bug rather than a refusal, because it is
                unreachable through :meth:`~toolyard.executor.ToolExecutor.execute`. The executor
                refuses any tool declaring ``requires_isolation`` at its containment check, before
                a handler exists to call this — so arriving here means calling it directly, which
                means an application built a command tool against a containment object that has no
                tiers. Phase 2's ``toolyard.sandbox`` is what implements this.
        """
        del argv, paths, timeout_seconds, env, network
        raise ToolYardError(
            "PathContainment implements no process isolation; it is Phase 1's path-containment "
            "half of the sandbox port. Register no tool that requires isolation against it, or "
            "supply toolyard.sandbox's implementation (Phase 2). The executor already refuses "
            "such tools with `isolation_unavailable` before any handler runs.",
            details={"isolation_tier": IsolationTier.UNAVAILABLE.value},
        )

    def _resolve_within(self, candidate: str, roots: tuple[Path, ...], *, role: str) -> Path:
        """Resolve ``candidate`` and confirm it is one of ``roots`` or a descendant of one."""
        cleaned = self._clean_candidate(candidate, role=role)
        base = roots[0]
        try:
            proposed = Path(cleaned)
            absolute = proposed if proposed.is_absolute() else base / proposed
            resolved = absolute.resolve()
        except (OSError, ValueError, RuntimeError) as exc:
            # A path the operating system will not even parse is an escape, not a crash: the model
            # chose the string, so this resolves to a refusal like every other thing it chose.
            raise PathEscape(cleaned, root_role=role) from exc
        for root in roots:
            try:
                resolved_root = root.resolve()
            except (OSError, ValueError, RuntimeError):
                continue
            if resolved == resolved_root or resolved_root in resolved.parents:
                return resolved
        raise PathEscape(cleaned, root_role=role, root=base)

    @staticmethod
    def _clean_candidate(candidate: str, *, role: str) -> str:
        """Refuse a candidate that is not a usable path string, before touching the filesystem."""
        if not isinstance(candidate, str):
            raise PathEscape(f"<{type(candidate).__name__}>", root_role=role)
        cleaned = clean_text(candidate)
        if cleaned != candidate or not cleaned.strip():
            # A NUL byte truncates a path at the C boundary, so a candidate that changed under
            # cleaning is a candidate whose resolved form would not be the one that was checked.
            raise PathEscape(cleaned[:MAX_CANDIDATE_CHARS], root_role=role)
        if len(cleaned) > MAX_CANDIDATE_CHARS or "\x00" in cleaned:
            raise PathEscape(cleaned[:MAX_CANDIDATE_CHARS], root_role=role)
        return cleaned
