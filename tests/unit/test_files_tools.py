"""``read_file``, ``write_file`` and ``list_dir`` — driven through ``execute()``, never directly.

Every refusal here is asserted as a :class:`ToolResult`, because that is the contract: nothing a
model can influence raises (ADR-0053 decision 4), and a test that called a handler directly would
prove the handler's shape while leaving the executor's conversion untested — which is the half a
consumer actually sees.

The suite that matters most is :class:`TestParentsAreCreatedInsideTheRoot`: the development plan
names *"``write_file`` creating parents outside the root via a symlinked intermediate directory"* as
this phase's likely failure mode, and ``mkdir(parents=True)`` is precisely how it happens.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from baseaicore import ValidationError

from toolyard import (
    PathContainment,
    Reason,
    SandboxPaths,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolRegistry,
    ToolStatus,
    list_dir_tool,
    read_file_tool,
    write_file_tool,
)
from toolyard.tools.files import MIN_LIST_ENTRIES, MIN_READ_BYTES

if TYPE_CHECKING:
    from toolyard import InMemoryToolCallStore, ToolResult

FILE_TOOLS = ("read_file", "write_file", "list_dir")


@pytest.fixture
def files_executor(workspace: SandboxPaths, store: InMemoryToolCallStore) -> ToolExecutor:
    """An executor holding all three file tools, with the caps at their defaults."""
    registry = ToolRegistry()
    registry.register(*read_file_tool())
    registry.register(*write_file_tool())
    registry.register(*list_dir_tool())
    del workspace
    return ToolExecutor(registry, PathContainment(), allowlist=frozenset(FILE_TOOLS), store=store)


def _call(executor: ToolExecutor, context: ToolContext, name: str, **args: object) -> ToolResult:
    """Drive one call through the executor, the way an application would."""
    return executor.execute(ToolCallRequest(name=name, args=args), context)


class TestTheDeclarationsThemselves:
    """What a model is shown, and what the executor is told to contain."""

    def test_each_tool_declares_its_path_argument_so_the_executor_resolves_it(self) -> None:
        """A handler that resolved its own path would be a second containment (spec §11.3)."""
        for factory in (read_file_tool, write_file_tool, list_dir_tool):
            spec, _handler = factory()
            assert "path" in spec.path_args, spec.name

    def test_only_write_file_is_mutating(self) -> None:
        assert write_file_tool()[0].risk_class.value == "mutating"
        assert read_file_tool()[0].risk_class.value == "read_only"
        assert list_dir_tool()[0].risk_class.value == "read_only"

    def test_no_file_tool_reaches_the_network(self) -> None:
        for factory in (read_file_tool, write_file_tool, list_dir_tool):
            assert factory()[0].egress.value == "none"

    def test_no_file_tool_requires_isolation(self) -> None:
        """They touch the filesystem through containment, not through a subprocess."""
        for factory in (read_file_tool, write_file_tool, list_dir_tool):
            assert factory()[0].requires_isolation is False

    @pytest.mark.parametrize(
        ("factory", "field", "floor"),
        [
            (read_file_tool, "max_bytes", MIN_READ_BYTES),
            (list_dir_tool, "max_entries", MIN_LIST_ENTRIES),
        ],
    )
    def test_a_cap_below_its_floor_raises_at_construction(
        self, factory: object, field: str, floor: int
    ) -> None:
        """Spec §12: a misconfigured tool fails at startup, not on the call that overflowed."""
        with pytest.raises(ValidationError):
            factory(**{field: floor - 1})  # type: ignore[operator]

    @pytest.mark.parametrize("value", [True, 4.0, "1024", None])
    def test_a_cap_that_is_not_an_int_raises(self, value: object) -> None:
        with pytest.raises(ValidationError):
            read_file_tool(max_bytes=value)  # type: ignore[arg-type]


class TestReadFile:
    """Reading, and the four ways a read does not happen."""

    def test_a_file_in_the_write_root_is_read_whole(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        (context.workspace.write_root / "notes.md").write_text("hello ☕", encoding="utf-8")
        result = _call(files_executor, context, "read_file", path="notes.md")
        assert result.status is ToolStatus.OK
        assert result.content == "hello ☕"

    def test_a_file_in_a_read_root_is_read(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        (context.workspace.read_roots[0] / "ref.md").write_text("reference", encoding="utf-8")
        result = _call(
            files_executor,
            context,
            "read_file",
            path=str(context.workspace.read_roots[0] / "ref.md"),
        )
        assert result.status is ToolStatus.OK
        assert result.content == "reference"

    def test_a_missing_file_is_failed_with_a_clean_reason_and_no_traceback(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """The dev plan's own wording. A traceback in a prompt is text an attacker can steer."""
        result = _call(files_executor, context, "read_file", path="absent.md")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.FILE_NOT_FOUND.value
        assert "Traceback" not in result.content
        assert "absent.md" in result.content

    def test_a_directory_is_not_a_file(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        (context.workspace.write_root / "sub").mkdir()
        result = _call(files_executor, context, "read_file", path="sub")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.NOT_A_REGULAR_FILE.value

    def test_a_file_over_the_cap_is_refused_whole_rather_than_read_in_part(
        self, workspace: SandboxPaths, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """A partial read would be recorded under the digest of the part (see the cap)."""
        registry = ToolRegistry()
        registry.register(*read_file_tool(max_bytes=MIN_READ_BYTES))
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"read_file"}), store=store
        )
        (workspace.write_root / "big.txt").write_bytes(b"x" * (MIN_READ_BYTES + 1))
        result = _call(executor, context, "read_file", path="big.txt")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.TOO_LARGE.value
        assert str(MIN_READ_BYTES) in (result.reason_detail or "")

    def test_a_file_exactly_at_the_cap_is_read(
        self, workspace: SandboxPaths, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        registry = ToolRegistry()
        registry.register(*read_file_tool(max_bytes=MIN_READ_BYTES))
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"read_file"}), store=store
        )
        (workspace.write_root / "exact.txt").write_bytes(b"x" * MIN_READ_BYTES)
        assert _call(executor, context, "read_file", path="exact.txt").status is ToolStatus.OK

    def test_binary_content_is_refused_rather_than_decoded_with_replacement(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """Mojibake reads like text; a model cannot tell it read a broken file."""
        (context.workspace.write_root / "image.bin").write_bytes(b"\xff\xfe\x00\x01binary")
        result = _call(files_executor, context, "read_file", path="image.bin")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.NOT_UTF8.value

    def test_a_path_outside_the_roots_is_refused_by_the_executor_not_the_handler(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """Containment is check 5; the handler is never reached."""
        result = _call(files_executor, context, "read_file", path="/etc/passwd")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.PATH_ESCAPE.value

    def test_a_refusal_names_the_root_to_the_record_and_never_to_the_model(
        self, files_executor: ToolExecutor, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """Refusal text is prompt surface (ADR-0053's last consequence); the record is not.

        The handler is handed the *resolved* path, so echoing its argument back would name the
        workspace root in a prompt. What the model sees is workspace-relative; the absolute path
        goes to the record, where the operator can diagnose from it.
        """
        result = _call(files_executor, context, "read_file", path="absent.md")
        root = str(context.workspace.write_root)
        assert root not in result.content
        assert root not in (result.reason_detail or "")
        assert root in store.records[-1].result_summary


class TestWriteFile:
    """Writing, replacing, and the roots a write may not reach."""

    def test_a_file_is_written_inside_the_write_root(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        result = _call(files_executor, context, "write_file", path="out.md", content="hello ☕")
        assert result.status is ToolStatus.OK
        assert (context.workspace.write_root / "out.md").read_text(encoding="utf-8") == "hello ☕"

    def test_a_write_replaces_rather_than_appends(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        (context.workspace.write_root / "out.md").write_text("old", encoding="utf-8")
        _call(files_executor, context, "write_file", path="out.md", content="new")
        assert (context.workspace.write_root / "out.md").read_text(encoding="utf-8") == "new"

    def test_a_write_into_a_read_root_is_refused(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """A read root is readable and not writable; the two checks are separate (spec §11.3)."""
        target = context.workspace.read_roots[0] / "no.md"
        result = _call(files_executor, context, "write_file", path=str(target), content="x")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.PATH_ESCAPE.value
        assert not target.exists()

    def test_a_write_outside_every_root_is_refused_and_writes_nothing(
        self, files_executor: ToolExecutor, context: ToolContext, tmp_path: Path
    ) -> None:
        target = tmp_path / "escaped.md"
        result = _call(files_executor, context, "write_file", path=str(target), content="x")
        assert result.status is ToolStatus.REFUSED
        assert not target.exists()

    def test_missing_parents_are_created_inside_the_write_root(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        result = _call(files_executor, context, "write_file", path="a/b/c.md", content="deep")
        assert result.status is ToolStatus.OK
        assert (context.workspace.write_root / "a" / "b" / "c.md").read_text() == "deep"


class TestParentsAreCreatedInsideTheRoot:
    """The development plan's named failure mode for this phase, from both directions."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
    def test_a_symlinked_intermediate_that_exists_at_resolution_is_caught_by_the_executor(
        self, files_executor: ToolExecutor, context: ToolContext, tmp_path: Path
    ) -> None:
        """The ordinary case, and the executor's, not the handler's.

        A link that exists when check 5 runs is resolved *through*, and the resolved path is
        outside the write root, so the call never reaches a handler. Pinned here so that a later
        change to the walk cannot be mistaken for what closes this — it was already closed.
        """
        outside = tmp_path / "outside"
        outside.mkdir()
        (context.workspace.write_root / "a").symlink_to(outside)
        result = _call(files_executor, context, "write_file", path="a/b/c.md", content="escaped")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.PATH_ESCAPE.value
        assert not (outside / "b").exists(), "a parent was created through the link"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
    def test_a_symlinked_intermediate_pointing_inside_the_root_is_followed_to_where_it_points(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """Containment resolves links; it does not forbid them.

        The write lands at the *resolved* location, which is inside the write root, and that is the
        right answer: refusing a link whose target is contained would make containment a rule about
        the shape of a path rather than about where it leads.
        """
        (context.workspace.write_root / "real").mkdir()
        (context.workspace.write_root / "a").symlink_to(context.workspace.write_root / "real")
        result = _call(files_executor, context, "write_file", path="a/b/c.md", content="x")
        assert result.status is ToolStatus.OK
        assert (context.workspace.write_root / "real" / "b" / "c.md").read_text() == "x"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
    def test_a_parent_swapped_for_a_link_after_resolution_is_refused_by_the_walk(
        self, context: ToolContext, store: InMemoryToolCallStore, tmp_path: Path
    ) -> None:
        """The development plan's named failure mode, at the only moment it can actually happen.

        A link that existed at resolution time is resolved through (above). The case the walk exists
        for is the one where a racing process creates the link *between* check 5 and the handler —
        and ``mkdir(parents=True)`` would follow it without comment. The race is simulated exactly,
        by a sandbox that plants the link as it hands back the resolved path, because a real race is
        not a thing a test can schedule.
        """
        outside = tmp_path / "outside"
        outside.mkdir()

        class RacingSandbox(PathContainment):
            """Containment that loses the race, deterministically."""

            def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
                """Resolve as ever, then let the attacker win the window."""
                resolved = super().resolve_write(candidate, paths)
                link = paths.write_root / "a"
                if not link.exists():
                    link.symlink_to(outside)
                return resolved

        registry = ToolRegistry()
        registry.register(*write_file_tool())
        executor = ToolExecutor(
            registry, RacingSandbox(), allowlist=frozenset({"write_file"}), store=store
        )
        result = _call(executor, context, "write_file", path="a/b/c.md", content="escaped")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.PATH_ESCAPE.value
        assert not (outside / "b").exists(), "a parent was created through the link"
        assert not (outside / "b" / "c.md").exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
    def test_writing_through_a_symlinked_final_component_is_refused(
        self, files_executor: ToolExecutor, context: ToolContext, tmp_path: Path
    ) -> None:
        """Following a link to write is how a contained path writes to an uncontained one."""
        outside = tmp_path / "target.md"
        (context.workspace.write_root / "link.md").symlink_to(outside)
        result = _call(files_executor, context, "write_file", path="link.md", content="escaped")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.PATH_ESCAPE.value
        assert not outside.exists()

    def test_a_file_where_a_directory_must_be_is_reported_and_not_overwritten(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        (context.workspace.write_root / "a").write_text("I am a file", encoding="utf-8")
        result = _call(files_executor, context, "write_file", path="a/b.md", content="x")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.NOT_A_REGULAR_FILE.value
        assert (context.workspace.write_root / "a").read_text() == "I am a file"


class TestListDir:
    """Listing, sorted, capped and labelled."""

    def test_entries_are_listed_sorted_by_name(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """Iteration order is the filesystem's; a model reading it would act on chance."""
        for name in ("zeta.md", "alpha.md", "mid.md"):
            (context.workspace.write_root / name).write_text("x", encoding="utf-8")
        (context.workspace.write_root / "sub").mkdir()
        result = _call(files_executor, context, "list_dir", path=".")
        names = [line.split()[1] for line in result.content.splitlines()[1:]]
        assert names == ["alpha.md", "mid.md", "sub/", "zeta.md"]

    def test_a_symlink_is_named_a_link_and_not_followed(
        self, files_executor: ToolExecutor, context: ToolContext, tmp_path: Path
    ) -> None:
        """A model told "file" about a link into another root has been told something untrue."""
        (context.workspace.write_root / "out").symlink_to(tmp_path)
        result = _call(files_executor, context, "list_dir", path=".")
        assert "link out" in result.content

    def test_an_empty_directory_says_so(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        assert "(empty)" in _call(files_executor, context, "list_dir", path=".").content

    def test_a_listing_over_the_cap_is_cut_and_says_how_many_were_omitted(
        self, workspace: SandboxPaths, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """Nothing is silently truncated — a listing is a rendering, so the label is enough."""
        registry = ToolRegistry()
        registry.register(*list_dir_tool(max_entries=2))
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"list_dir"}), store=store
        )
        for index in range(5):
            (workspace.write_root / f"f{index}.md").write_text("x", encoding="utf-8")
        result = _call(executor, context, "list_dir", path=".")
        assert "3 more entries not listed" in result.content

    def test_listing_a_file_is_reported_rather_than_raising(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        (context.workspace.write_root / "a.md").write_text("x", encoding="utf-8")
        result = _call(files_executor, context, "list_dir", path="a.md")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.NOT_A_REGULAR_FILE.value

    def test_listing_a_missing_directory_is_reported_rather_than_raising(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        result = _call(files_executor, context, "list_dir", path="nowhere")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.FILE_NOT_FOUND.value

    def test_a_dangling_symlink_renders_without_raising(
        self, files_executor: ToolExecutor, context: ToolContext, tmp_path: Path
    ) -> None:
        (context.workspace.write_root / "dangling").symlink_to(tmp_path / "never")
        result = _call(files_executor, context, "list_dir", path=".")
        assert result.status is ToolStatus.OK
        assert "dangling" in result.content


class TestTheFilesystemAnsweringBadly:
    """Every ``OSError`` the operations can raise becomes a result, with the row §13 gives it.

    These are the branches that separate a clean refusal from a traceback in a prompt. Several of
    them cannot be provoked by arranging files — a read that fails after ``is_file()`` said yes is a
    race — so the failure is injected at the one call that would raise it. Injecting is honest here:
    the question is what this module does with an ``OSError``, not whether the kernel produces one.
    """

    def test_a_permission_error_on_read_is_reported_and_not_raised(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (context.workspace.write_root / "secret.md").write_text("x", encoding="utf-8")

        def deny(_self: Path) -> bytes:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "read_bytes", deny)
        result = _call(files_executor, context, "read_file", path="secret.md")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.PERMISSION_DENIED.value

    def test_an_unclassified_os_error_still_produces_a_clean_reason(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No `OSError` subclass falls through to a traceback; the default row catches the rest."""
        (context.workspace.write_root / "odd.md").write_text("x", encoding="utf-8")

        def fail(_self: Path) -> bytes:
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(Path, "read_bytes", fail)
        result = _call(files_executor, context, "read_file", path="odd.md")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.PERMISSION_DENIED.value
        assert "Traceback" not in result.content

    def test_a_directory_error_raised_during_a_read_is_reported_as_the_wrong_kind_of_thing(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (context.workspace.write_root / "raced.md").write_text("x", encoding="utf-8")

        def swapped(_self: Path) -> bytes:
            raise IsADirectoryError(21, "Is a directory")

        monkeypatch.setattr(Path, "read_bytes", swapped)
        result = _call(files_executor, context, "read_file", path="raced.md")
        assert result.reason == Reason.NOT_A_REGULAR_FILE.value

    def test_a_file_that_vanishes_between_the_check_and_the_read_is_reported_as_missing(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (context.workspace.write_root / "gone.md").write_text("x", encoding="utf-8")

        def vanished(_self: Path) -> bytes:
            raise FileNotFoundError(2, "No such file or directory")

        monkeypatch.setattr(Path, "read_bytes", vanished)
        result = _call(files_executor, context, "read_file", path="gone.md")
        assert result.reason == Reason.FILE_NOT_FOUND.value

    def test_a_write_that_the_filesystem_refuses_is_reported(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def deny(_self: Path, *_args: object, **_kwargs: object) -> int:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "write_text", deny)
        result = _call(files_executor, context, "write_file", path="denied.md", content="x")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.PERMISSION_DENIED.value

    def test_a_listing_the_filesystem_refuses_is_reported(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def deny(_self: Path) -> object:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "iterdir", deny)
        result = _call(files_executor, context, "list_dir", path=".")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.PERMISSION_DENIED.value

    def test_an_entry_that_cannot_be_stated_renders_as_other_rather_than_ending_the_listing(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One unreadable entry must not cost the model the whole directory."""
        (context.workspace.write_root / "a.md").write_text("x", encoding="utf-8")

        def deny(_self: Path) -> bool:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "is_symlink", deny)
        result = _call(files_executor, context, "list_dir", path=".")
        assert result.status is ToolStatus.OK
        assert "other a.md" in result.content

    def test_a_parent_that_cannot_be_created_is_reported_rather_than_raised(
        self, files_executor: ToolExecutor, context: ToolContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def deny(_self: Path, *_args: object, **_kwargs: object) -> None:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "mkdir", deny)
        result = _call(files_executor, context, "write_file", path="a/b.md", content="x")
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.PERMISSION_DENIED.value

    def test_a_write_whose_target_is_not_under_the_write_root_creates_no_parents(
        self, workspace: SandboxPaths, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """A read root is not writable, so the parent walk has nothing to do and says so.

        Reachable only through a sandbox that admits the path for writing, which is why one is
        supplied: the point is that ``_make_parents`` declines rather than raising a
        ``ValueError`` out of ``relative_to``.
        """

        class PermissiveSandbox(PathContainment):
            """Resolves a write wherever the read rules allow. Not shipped, for good reason."""

            def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
                """Deliberately answer the read question to a write."""
                return self.resolve_read(candidate, paths)

        registry = ToolRegistry()
        registry.register(*write_file_tool())
        executor = ToolExecutor(
            registry, PermissiveSandbox(), allowlist=frozenset({"write_file"}), store=store
        )
        target = workspace.read_roots[0] / "a" / "b.md"
        result = _call(executor, context, "write_file", path=str(target), content="x")
        assert result.status is ToolStatus.FAILED
        assert not (workspace.read_roots[0] / "a").exists(), "a parent was created outside the root"

    def test_a_final_component_swapped_for_a_link_after_resolution_is_refused(
        self, context: ToolContext, store: InMemoryToolCallStore, tmp_path: Path
    ) -> None:
        """The same race as the parent walk's, at the last component instead of a middle one.

        The executor hands the handler a *resolved* path, which by construction contains no link —
        so this branch exists for exactly one case: a link planted in the window between check 5
        and the write. Following it is how a contained path writes to an uncontained one.
        """
        outside = tmp_path / "target.md"

        class RacingSandbox(PathContainment):
            """Containment that loses the race at the final component."""

            def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path:
                """Resolve as ever, then let the attacker win the window."""
                resolved = super().resolve_write(candidate, paths)
                if not resolved.exists():
                    resolved.symlink_to(outside)
                return resolved

        registry = ToolRegistry()
        registry.register(*write_file_tool())
        executor = ToolExecutor(
            registry, RacingSandbox(), allowlist=frozenset({"write_file"}), store=store
        )
        result = _call(executor, context, "write_file", path="out.md", content="escaped")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.PATH_ESCAPE.value
        assert not outside.exists(), "the write followed the link out of the root"

    def test_an_entry_that_is_neither_file_nor_directory_nor_link_renders_as_other(
        self, files_executor: ToolExecutor, context: ToolContext
    ) -> None:
        """A fifo is a real thing to find in a workspace and it is not a document."""
        os.mkfifo(context.workspace.write_root / "pipe")
        result = _call(files_executor, context, "list_dir", path=".")
        assert result.status is ToolStatus.OK
        assert "other pipe" in result.content
