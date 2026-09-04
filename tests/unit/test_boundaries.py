"""Structural guards: no shell, a pinned import allowlist, and the contracts later phases inherit.

These are written **now**, in Phase 1, precisely because they only become interesting later. The
``shell=True`` grep matters when Phase 2 adds ``subprocess``; the import allowlist matters when
Phase 3 adds ``httpx``. A guard added alongside the risk it guards is a guard someone wrote to pass;
a guard that was already failing when the risk arrived is a guard that bit.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "toolyard"

pytest_plugins: list[str] = []

ALLOWED_IMPORTS = frozenset(
    {
        # standard library
        "__future__",
        "dataclasses",
        "enum",
        "collections",
        "datetime",
        "errno",
        "hashlib",
        "logging",
        "math",
        "os",
        "pathlib",
        "re",
        "selectors",
        "shutil",
        "signal",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
        "time",
        "typing",
        "uuid",
        # the two suite/runtime dependencies gold standards §1.1 permits
        "baseaicore",
        "jsonschema",
        # the package itself
        "toolyard",
    }
)
"""Every top-level module ``src/toolyard`` may import today.

Phase 2 added ``subprocess`` and what ``toolyard.sandbox`` needs to probe a tier and kill a process
tree (``os``, ``selectors``, ``shutil``, ``signal``, ``sys``, ``tempfile``, ``threading``, ``time``,
``uuid``) — standard library, every one, and ``subprocess`` is separately constrained by
`.importlinter` to that one module. Phase 3 adds ``httpx``, the same way. What this list catches is
the *unexpected* one: a convenience dependency arriving with no ADR, in the package whose non-suite
runtime budget is two.
"""


def _modules() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _trees() -> list[tuple[Path, ast.Module]]:
    return [(path, ast.parse(path.read_text(encoding="utf-8"), str(path))) for path in _modules()]


class TestNoShell:
    """Spec §14 and ADR-0053 decision 5: commands are argv, never a shell string."""

    def test_no_call_anywhere_in_src_passes_a_shell_argument(self) -> None:
        """Written before Phase 2 exists, so D1 finds it already failing if it reaches for a shell.

        Asserted over the parsed tree rather than over the text, for two reasons: the text form
        matches this package's own prose about not doing it, and the AST form also catches
        ``shell=flag``, which a grep for ``shell=True`` would sail past.
        """
        offenders = [
            f"{path.name}:{node.lineno}"
            for path, tree in _trees()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for keyword in node.keywords
            if keyword.arg == "shell"
        ]
        assert offenders == [], (
            "shell=True appeared in ToolYard. Commands are argv, never a shell string "
            "(ADR-0053 decision 5); a model's argument reaching a shell is the failure this "
            "package exists to prevent."
        )

    @pytest.mark.parametrize(
        "forbidden", ["os.system", "os.popen", "commands.getoutput", "eval(", "exec("]
    )
    def test_no_other_route_to_a_shell_or_an_interpreter(self, forbidden: str) -> None:
        offenders = [
            str(path) for path in _modules() if forbidden in path.read_text(encoding="utf-8")
        ]
        assert offenders == []

    def test_exactly_one_process_is_ever_started_and_it_is_the_sandbox_launcher(self) -> None:
        """One door (ADR-0053 decision 5): every process the package starts goes through it.

        `.importlinter` keeps ``subprocess`` out of every module but ``toolyard.sandbox``; this
        pins the count *inside* that module to one, so a second launch site — a probe helper that
        forgot the cap, a cleanup that forgot the session — cannot arrive without this failing.
        """
        launch_sites = [
            f"{path.name}:{node.lineno}"
            for path, tree in _trees()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and (
                (isinstance(node.func, ast.Attribute) and node.func.attr == "Popen")
                or (isinstance(node.func, ast.Name) and node.func.id == "Popen")
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"run", "call", "check_call", "check_output"}
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                )
            )
        ]
        assert len(launch_sites) == 1, launch_sites
        assert launch_sites[0].startswith("sandbox.py:")


class TestImportAllowlist:
    """What the package imports is a decision, so it is written down and asserted."""

    def test_every_import_is_on_the_allowlist(self) -> None:
        seen: dict[str, set[str]] = {}
        for path, tree in _trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        seen.setdefault(alias.name.split(".")[0], set()).add(path.name)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    seen.setdefault(node.module.split(".")[0], set()).add(path.name)
        unexpected = {
            name: sorted(files) for name, files in seen.items() if name not in ALLOWED_IMPORTS
        }
        assert unexpected == {}, (
            f"New top-level imports in src/toolyard: {unexpected}. ToolYard's non-suite runtime "
            "budget is two (gold standards §1.1) and both are already spent — extend this list "
            "only alongside the phase that declares the dependency."
        )

    def test_hypothesis_is_a_development_dependency_only(self) -> None:
        for path in _modules():
            assert "hypothesis" not in path.read_text(encoding="utf-8")

    def test_nothing_imports_an_application_or_a_sibling_package(self) -> None:
        """`.importlinter` asserts this too; a second, cheaper guard costs nothing."""
        forbidden = {
            "freeweight",
            "loadcoach",
            "ideapress",
            "promptcadence",
            "setspec",
            "modelrack",
            "cutctx",
            "loadledger",
            "commissioner",
        }
        assert forbidden.isdisjoint(ALLOWED_IMPORTS)
        for path, tree in _trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module.split(".")[0] not in forbidden, path


class TestNoPromptTextAndNoDynamicLoading:
    """Two things this package must never grow, asserted rather than intended."""

    def test_no_module_holds_a_long_string_literal_that_could_be_a_prompt(self) -> None:
        """A prompt is named by ``prompt_id`` (ADR-0012). Docstrings exempt, literals not."""
        offenders: list[str] = []
        for path, tree in _trees():
            # Any bare string expression is documentation: a module, class or function docstring,
            # or the attribute docstring convention this package uses for module constants.
            docstrings = {
                id(node.value)
                for node in ast.walk(tree)
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
            }
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and len(node.value) > 500
                    and id(node) not in docstrings
                ):
                    offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []

    @pytest.mark.parametrize(
        "mechanism",
        ["importlib", "entry_points", "pkg_resources", "__import__", "importlib.metadata"],
    )
    def test_no_module_can_load_code_by_name(self, mechanism: str) -> None:
        """ADR-0053 rejects dynamic loading on the merits and expects it to stay rejected."""
        offenders = [
            str(path) for path in _modules() if mechanism in path.read_text(encoding="utf-8")
        ]
        assert offenders == []


class TestPublicSurface:
    """``__all__`` is the surface, and every name in it resolves."""

    def test_every_exported_name_exists(self) -> None:
        import toolyard

        for name in toolyard.__all__:
            assert hasattr(toolyard, name), name

    def test_the_export_list_holds_no_duplicates(self) -> None:
        import toolyard

        assert len(toolyard.__all__) == len(set(toolyard.__all__))

    def test_the_package_is_typed(self) -> None:
        assert (SRC / "py.typed").is_file()


class TestDefensiveBranches:
    """Guards that only fire when something else is already broken, asserted anyway.

    Each of these exists because the package promises totality, and a guard nobody has ever
    executed is a guard nobody knows works. They are reached by making a collaborator misbehave,
    which is exactly the situation they were written for.
    """

    def test_a_monotonic_source_that_runs_backwards_yields_a_zero_duration(
        self, workspace: object
    ) -> None:
        """Never a negative duration. ``baseaicore.elapsed_ms`` refuses one, so this must not
        produce it — a benchmark that reports a negative duration is worse than one reporting none.
        """
        from fakes import EchoTool, spec
        from toolyard import (
            PathContainment,
            ToolCallRequest,
            ToolContext,
            ToolExecutor,
            ToolRegistry,
        )

        readings = iter([1_000_000_000, 0, 0, 0])
        registry = ToolRegistry()
        registry.register(spec("echo"), EchoTool())
        executor = ToolExecutor(
            registry,
            PathContainment(),
            allowlist=frozenset({"echo"}),
            monotonic_ns=lambda: next(readings),
        )
        result = executor.execute(
            ToolCallRequest(name="echo", args={"value": "x"}),
            ToolContext(invocation_id="inv", workspace=workspace),  # type: ignore[arg-type]
        )
        assert result.duration_ms == 0

    def test_a_path_the_operating_system_cannot_resolve_is_a_refusal(
        self, monkeypatch: pytest.MonkeyPatch, workspace: object
    ) -> None:
        """``Path.resolve`` can raise ``OSError`` on some filesystems. The model chose the string,
        so that resolves to a refusal like everything else it chose."""
        from toolyard import PathContainment, PathEscape

        def explode(self: Path, strict: bool = False) -> Path:
            raise OSError(40, "too many levels of symbolic links")

        monkeypatch.setattr(Path, "resolve", explode)
        with pytest.raises(PathEscape):
            PathContainment().resolve_read("notes.md", workspace)  # type: ignore[arg-type]

    def test_a_root_that_cannot_be_resolved_is_skipped_rather_than_admitting_a_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An unresolvable root contains nothing, so a candidate measured against it escapes."""
        from toolyard import PathContainment, PathEscape, SandboxPaths

        real_resolve = Path.resolve
        roots = SandboxPaths(write_root=tmp_path / "work", read_roots=(tmp_path / "reference",))

        def selective(self: Path, strict: bool = False) -> Path:
            if self in (roots.write_root, *roots.read_roots):
                raise OSError(5, "input/output error")
            return real_resolve(self)

        monkeypatch.setattr(Path, "resolve", selective)
        with pytest.raises(PathEscape):
            PathContainment().resolve_read("notes.md", roots)

    def test_a_store_failure_merges_caller_supplied_details(self) -> None:
        from datetime import UTC, datetime

        from toolyard import (
            EgressClass,
            RiskClass,
            StoreFailure,
            ToolCallRecord,
            ToolResult,
            ToolStatus,
        )

        record = ToolCallRecord(
            invocation_id="inv",
            tool_name="echo",
            args_json=None,
            args_sha256="0" * 64,
            status=ToolStatus.OK,
            result_summary="",
            result_sha256="0" * 64,
            duration_ms=0,
            risk_class=RiskClass.READ_ONLY,
            egress=EgressClass.NONE,
            started_at=datetime(2026, 9, 3, tzinfo=UTC),
        )
        result = ToolResult(
            invocation_id="inv", status=ToolStatus.OK, content="", reason=None, duration_ms=0
        )
        failure = StoreFailure("x", result=result, record=record, details={"backend": "postgres"})
        assert failure.details["backend"] == "postgres"
        assert failure.details["tool_name"] == "echo"

    def test_a_path_args_declaration_that_is_not_a_mapping_raises(self) -> None:
        from fakes import PATH_SCHEMA, spec
        from toolyard import InvalidToolSpec

        with pytest.raises(InvalidToolSpec, match="path_args"):
            spec("tool", args_schema=PATH_SCHEMA, path_args=[("path", "read")])  # type: ignore[arg-type]

    def test_a_validator_that_fails_outright_reports_a_detail_rather_than_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``jsonschema`` raising on hostile input is a refusal, not a crash."""
        import jsonschema

        from toolyard.validation import ArgsValidator

        validator = ArgsValidator(
            {
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "additionalProperties": False,
            }
        )

        def explode(self: object, instance: object) -> object:
            raise RuntimeError("validator gave up")

        monkeypatch.setattr(jsonschema.Draft202012Validator, "iter_errors", explode)
        detail = validator.validate({"value": "x"})
        assert detail is not None
        assert "could not complete" in detail

    def test_an_unserializable_schema_fragment_still_renders_an_expectation(self) -> None:
        """The schema is the caller's, but a refusal must not break on a caller's odd fragment."""
        from toolyard.validation import _expectation

        assert "object" in _expectation(object())

    def test_an_additional_properties_error_that_cannot_be_named_says_so(self) -> None:
        from toolyard.validation import _unexpected_properties

        class Fake:
            instance = "not a mapping"
            schema = {"additionalProperties": False}

        assert _unexpected_properties(Fake()) == "(unnameable)"  # type: ignore[arg-type]

    def test_an_additional_properties_error_with_nothing_extra_says_so(self) -> None:
        from toolyard.validation import _unexpected_properties

        class Fake:
            instance = {"value": 1}
            schema = {"properties": {"value": {}}, "additionalProperties": False}

        assert _unexpected_properties(Fake()) == "(none identifiable)"  # type: ignore[arg-type]

    def test_many_extra_properties_are_capped_and_counted(self) -> None:
        from toolyard.validation import _unexpected_properties

        class Fake:
            instance = {f"extra{index}": 1 for index in range(20)}
            schema: dict[str, object] = {"properties": {}, "additionalProperties": False}

        rendered = _unexpected_properties(Fake())  # type: ignore[arg-type]
        assert "more)" in rendered
