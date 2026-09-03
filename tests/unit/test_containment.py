"""Containment: resolution-then-check, hostile input first, and honest absence of isolation.

This file is the containment contract. Every path case runs against **both** implementations of
the port — Phase 1's :class:`PathContainment` and Phase 2's :class:`TieredSandbox`, which composes
it — so the second cannot drift from the first: a resolution-then-check that only held for one of
them would fail here. Extend it; never relax it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from baseaicore import ValidationError

from fakes import ScriptedRunner, which_for
from toolyard import (
    IsolationTier,
    PathContainment,
    PathEscape,
    Sandbox,
    SandboxPaths,
    TieredSandbox,
    ToolYardError,
)


@pytest.fixture
def roots(tmp_path: Path) -> SandboxPaths:
    """A write root, a read root, and a decoy that shares a string prefix with the write root."""
    (tmp_path / "data").mkdir()
    (tmp_path / "database").mkdir()
    (tmp_path / "reference").mkdir()
    return SandboxPaths(write_root=tmp_path / "data", read_roots=(tmp_path / "reference",))


@pytest.fixture(params=["phase-1", "phase-2"])
def containment(request: pytest.FixtureRequest) -> Sandbox:
    """Both implementations of the port, so every case below binds them to one behaviour."""
    if request.param == "phase-1":
        return PathContainment()
    return TieredSandbox(which=which_for({}), runner=ScriptedRunner(), platform="linux")


@pytest.fixture
def phase_one() -> PathContainment:
    """Phase 1's implementation alone, for the assertions about its honest absence of a tier."""
    return PathContainment()


class TestResolutionThenCheck:
    """Fully resolve, *then* compare. The reverse order is the classic containment bug."""

    def test_a_relative_candidate_resolves_against_the_write_root_not_the_process_cwd(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        assert containment.resolve_read("notes.md", roots) == roots.write_root / "notes.md"

    def test_a_traversal_escape_is_refused(self, containment: Sandbox, roots: SandboxPaths) -> None:
        with pytest.raises(PathEscape) as caught:
            containment.resolve_read("../../etc/passwd", roots)
        assert caught.value.root_role == "read_roots"

    def test_a_traversal_that_returns_inside_the_root_is_allowed(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        assert containment.resolve_read("sub/../notes.md", roots) == roots.write_root / "notes.md"

    def test_an_absolute_path_outside_every_root_is_refused(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        with pytest.raises(PathEscape):
            containment.resolve_read("/etc/passwd", roots)

    def test_a_symlink_pointing_out_of_the_root_is_refused_after_resolution(
        self, containment: Sandbox, roots: SandboxPaths, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (roots.write_root / "link").symlink_to(outside)
        with pytest.raises(PathEscape):
            containment.resolve_read("link", roots)

    def test_a_symlinked_directory_pointing_out_of_the_root_is_refused(
        self, containment: Sandbox, roots: SandboxPaths, tmp_path: Path
    ) -> None:
        (tmp_path / "elsewhere").mkdir()
        (roots.write_root / "hop").symlink_to(tmp_path / "elsewhere")
        with pytest.raises(PathEscape):
            containment.resolve_write("hop/file.txt", roots)

    def test_a_symlink_that_stays_inside_the_root_is_allowed(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        target = roots.write_root / "real.txt"
        target.write_text("fine", encoding="utf-8")
        (roots.write_root / "alias").symlink_to(target)
        assert containment.resolve_read("alias", roots) == target


class TestPrefixCollisionRoots:
    """``/data`` and ``/database`` are two roots, not a root and its child."""

    def test_a_sibling_sharing_a_string_prefix_is_outside(
        self, containment: Sandbox, roots: SandboxPaths, tmp_path: Path
    ) -> None:
        with pytest.raises(PathEscape):
            containment.resolve_read(str(tmp_path / "database" / "notes.md"), roots)

    def test_the_root_itself_is_inside_itself(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        assert containment.resolve_write(str(roots.write_root), roots) == roots.write_root


class TestReadAndWriteAreSeparateChecks:
    """Separate roots, separate questions."""

    def test_a_read_root_is_readable(self, containment: Sandbox, roots: SandboxPaths) -> None:
        assert containment.resolve_read("ref.md", roots) == roots.write_root / "ref.md"
        assert (
            containment.resolve_read(str(roots.read_roots[0] / "ref.md"), roots)
            == roots.read_roots[0] / "ref.md"
        )

    def test_a_read_root_is_not_writable(self, containment: Sandbox, roots: SandboxPaths) -> None:
        with pytest.raises(PathEscape) as caught:
            containment.resolve_write(str(roots.read_roots[0] / "ref.md"), roots)
        assert caught.value.root_role == "write_root"

    def test_the_write_root_is_readable(self, containment: Sandbox, roots: SandboxPaths) -> None:
        assert containment.resolve_read("inside.md", roots) == roots.write_root / "inside.md"

    def test_with_no_read_roots_only_the_write_root_is_readable(
        self, containment: Sandbox, tmp_path: Path
    ) -> None:
        only = SandboxPaths(write_root=tmp_path / "data")
        assert containment.resolve_read("a.md", only) == tmp_path / "data" / "a.md"
        with pytest.raises(PathEscape):
            containment.resolve_read(str(tmp_path / "reference" / "a.md"), only)


class TestUnusablesCandidates:
    """Refused before the filesystem is touched, because the model chose the string."""

    @pytest.mark.parametrize("candidate", ["", "   ", "\t\n"])
    def test_a_blank_candidate_is_refused(
        self, containment: Sandbox, roots: SandboxPaths, candidate: str
    ) -> None:
        with pytest.raises(PathEscape):
            containment.resolve_read(candidate, roots)

    def test_a_candidate_holding_a_nul_is_refused_rather_than_truncated(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        with pytest.raises(PathEscape):
            containment.resolve_read("notes.md\x00/../../etc/passwd", roots)

    def test_a_candidate_holding_a_lone_surrogate_is_refused(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        with pytest.raises(PathEscape):
            containment.resolve_read("notes\ud800.md", roots)

    def test_an_absurdly_long_candidate_is_refused(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        with pytest.raises(PathEscape):
            containment.resolve_read("a" * 10_000, roots)

    @pytest.mark.parametrize("candidate", [None, 17, b"bytes", ["list"], Path("/nonexistent")])
    def test_a_candidate_that_is_not_a_string_is_refused(
        self, containment: Sandbox, roots: SandboxPaths, candidate: object
    ) -> None:
        with pytest.raises(PathEscape) as caught:
            containment.resolve_read(candidate, roots)  # type: ignore[arg-type]
        assert caught.value.root is None

    def test_a_missing_root_does_not_admit_a_path(
        self, containment: Sandbox, tmp_path: Path
    ) -> None:
        """A root that does not exist resolves to nothing, and nothing contains nothing."""
        vanished = SandboxPaths(write_root=tmp_path / "never-created")
        assert containment.resolve_write("a.md", vanished) == tmp_path / "never-created" / "a.md"
        with pytest.raises(PathEscape):
            containment.resolve_write("/etc/passwd", vanished)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX path semantics")
    def test_a_symlink_loop_stays_inside_the_root_rather_than_crashing(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        """An unresolvable loop is admitted, and that is the right answer, not a gap.

        ``Path.resolve()`` gives up on a cycle and returns the path unresolved. The containment
        question is "does this land inside a root", and an unresolved path under the write root
        does — while the operating system refuses to open it (``ELOOP``), so nothing is reachable
        through it. Pinned here because it looks like a hole and is not, and because Phase 2's
        ``O_NOFOLLOW`` work is where the difference between "inside the root" and "openable" stops
        being academic.
        """
        loop = roots.write_root / "loop"
        loop.symlink_to(loop)
        assert containment.resolve_read("loop/x", roots) == loop / "x"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX path semantics")
    def test_a_loop_whose_first_hop_leaves_the_root_is_still_refused(
        self, containment: Sandbox, roots: SandboxPaths, tmp_path: Path
    ) -> None:
        """The dangerous half of a cycle — one that resolves *outward* — is refused as ever."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "b").symlink_to(outside / "c")
        (roots.write_root / "a").symlink_to(outside / "b")
        with pytest.raises(PathEscape):
            containment.resolve_read("a", roots)


class TestIsolationIsHonestlyAbsent:
    """ADR-0018's floor: no tier means refuse, and Phase 1 has no tier at all."""

    def test_the_phase_one_containment_reports_no_tier(self, phase_one: PathContainment) -> None:
        assert phase_one.isolation_tier() is IsolationTier.UNAVAILABLE

    def test_running_a_command_is_refused_rather_than_stubbed(
        self, phase_one: PathContainment, roots: SandboxPaths
    ) -> None:
        with pytest.raises(ToolYardError, match="Phase 2"):
            phase_one.run_isolated(["echo", "hi"], paths=roots, timeout_seconds=1.0)

    def test_there_is_no_flag_that_skips_resolution(self, phase_one: PathContainment) -> None:
        """A "just this once" option is what makes a containment advisory. There is none."""
        assert "unconditional" in phase_one.follow_symlinks_note
        assert not [
            name
            for name in dir(phase_one)
            if not name.startswith("_") and "skip" in name or "unsafe" in name
        ]


class TestTheTieredSandboxKeepsTheFloor:
    """Phase 2's implementation on a host with no rung: the same refusal, the same absence."""

    def test_a_host_with_no_rung_reports_no_tier(self, containment: Sandbox) -> None:
        assert containment.isolation_tier() is IsolationTier.UNAVAILABLE

    def test_running_a_command_without_a_rung_is_refused(
        self, containment: Sandbox, roots: SandboxPaths
    ) -> None:
        with pytest.raises(ToolYardError):
            containment.run_isolated(["echo", "hi"], paths=roots, timeout_seconds=1.0)

    def test_neither_implementation_grows_a_flag_that_skips_resolution(
        self, containment: Sandbox
    ) -> None:
        assert not [
            name
            for name in dir(containment)
            if not name.startswith("_")
            and any(word in name for word in ("skip", "unsafe", "widen", "allow", "host"))
        ]


class TestSandboxPathsAreValidatedAtConstruction:
    """Spec §7 (amended at D1): roots are absolute and do not overlap, or the workspace raises.

    Every field of ``SandboxPaths`` is the application's, so a bad one is a caller bug surfaced
    where the workspace is built — not on the one call that reached the overlapping directory.
    """

    def test_a_relative_root_is_refused(self) -> None:
        """A relative root would resolve against the process CWD, which spec §11.3 forbids."""
        with pytest.raises(ValidationError, match="absolute"):
            SandboxPaths(write_root=Path("work"))
        with pytest.raises(ValidationError, match="absolute"):
            SandboxPaths(write_root=Path("/srv/work"), read_roots=(Path("reference"),))

    def test_a_root_that_is_not_a_path_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="absolute"):
            SandboxPaths(write_root="/srv/work")  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="read_roots"):
            SandboxPaths(write_root=Path("/srv/work"), read_roots="/srv/reference")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("write_root", "read_roots"),
        [
            ("/srv/work", ("/srv/work",)),
            ("/srv/work", ("/srv/work/reference",)),
            ("/srv/project/out", ("/srv/project",)),
            ("/srv/work", ("/srv/reference", "/srv/reference")),
            ("/srv/work", ("/srv/reference", "/srv/reference/sub")),
            ("/", ("/srv/reference",)),
        ],
        ids=[
            "equal",
            "read-inside-write",
            "write-inside-read",
            "repeated",
            "read-inside-read",
            "root-of-everything",
        ],
    )
    def test_overlapping_roots_are_refused(
        self, write_root: str, read_roots: tuple[str, ...]
    ) -> None:
        with pytest.raises(ValidationError, match="overlap"):
            SandboxPaths(
                write_root=Path(write_root), read_roots=tuple(Path(root) for root in read_roots)
            )

    def test_a_string_prefix_is_not_an_overlap_and_a_list_is_accepted(self) -> None:
        """``/data`` and ``/database`` are two roots here as everywhere else."""
        paths = SandboxPaths(
            write_root=Path("/srv/data"),
            read_roots=[Path("/srv/database")],  # type: ignore[arg-type]  # a list is accepted and stored as a tuple
        )
        assert paths.read_roots == (Path("/srv/database"),)

    def test_the_comparison_is_lexical_and_touches_no_filesystem(self, tmp_path: Path) -> None:
        """Nothing is resolved at construction; roots need not exist yet."""
        never = tmp_path / "never-created"
        paths = SandboxPaths(write_root=never, read_roots=(tmp_path / "also-never",))
        assert paths.write_root == never
        assert not never.exists()
