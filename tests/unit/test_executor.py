"""The executor: the fixed order, every §13 row, and the promise that model input never raises."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import pytest
from baseaicore import ValidationError

from fakes import (
    PATH_SCHEMA,
    ArgumentMutatingTool,
    EchoTool,
    ExplodingSandbox,
    FixedOutputTool,
    FixedTierSandbox,
    RaisingTool,
    RecordingTool,
    ReturningTool,
    SleepingTool,
    SteppingMonotonic,
    UnrenderableError,
    spec,
)
from toolyard import (
    DEFAULT_MAX_CONTENT_BYTES,
    REFUSAL_ORDER,
    REFUSAL_REASONS,
    EgressClass,
    InMemoryToolCallStore,
    IsolationTier,
    PathAccess,
    PathContainment,
    Reason,
    RiskClass,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolRegistry,
    ToolStatus,
)
from toolyard._safe import TRUNCATION_LABEL_TEMPLATE

if TYPE_CHECKING:
    from toolyard import SandboxPaths, ToolResult

LADDER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}


def _ladder_spec() -> Any:
    """A tool that can fail every check at once: network, isolated, and path-taking."""
    return spec(
        "escalate",
        args_schema=LADDER_SCHEMA,
        risk_class=RiskClass.MUTATING,
        egress=EgressClass.NETWORK,
        path_args={"path": PathAccess.WRITE},
        requires_isolation=True,
    )


class TestRefusalOrder:
    """Spec §11.2's order, asserted as an order rather than as five separate checks."""

    def test_the_declared_order_is_the_spec_order(self) -> None:
        assert REFUSAL_ORDER == ("registry", "allowlist", "schema", "egress", "containment")

    def test_the_ladder_refuses_to_import_with_positions_that_are_not_a_sequence(self) -> None:
        """Changing a position is a one-number diff, and a wrong one stops the package importing."""
        from toolyard.executor import _Check, _check_registry, _ordered

        with pytest.raises(ValidationError, match="0..1"):
            _ordered((_Check(0, "a", _check_registry), _Check(2, "b", _check_registry)))
        with pytest.raises(ValidationError, match="exactly once"):
            _ordered((_Check(0, "a", _check_registry), _Check(0, "b", _check_registry)))

    def test_rearranging_the_declaration_cannot_rearrange_the_ladder(self) -> None:
        from toolyard.executor import _Check, _check_egress, _check_registry, _ordered

        shuffled = _ordered(
            (_Check(1, "second", _check_egress), _Check(0, "first", _check_registry))
        )
        assert [check.name for check in shuffled] == ["first", "second"]

    def test_a_call_failing_every_check_walks_down_the_ladder_one_rung_at_a_time(
        self, workspace: SandboxPaths
    ) -> None:
        """The whole point. Each rung is fixed and the previous refusal is removed one at a time.

        The same request fails registry, allowlist, intent, schema, egress, isolation and
        containment simultaneously. Each assertion is about the **order**, not about the check: a
        chain of ``if`` statements that someone reordered would still pass every individual
        refusal test and fail here.
        """
        request = ToolCallRequest(name="escalate", args={"path": "../../etc/passwd", "extra": 1})
        registry = ToolRegistry()
        store = InMemoryToolCallStore()

        def refuse(
            *,
            registered: bool,
            allowlisted: bool,
            approved: bool,
            valid_args: bool,
            egress: bool,
            tier: bool,
        ) -> ToolResult:
            if registered and registry.get("escalate") is None:
                registry.register(_ladder_spec(), EchoTool())
            executor = ToolExecutor(
                registry,
                FixedTierSandbox(IsolationTier.BWRAP if tier else IsolationTier.UNAVAILABLE),
                allowlist=frozenset({"escalate"}) if allowlisted else frozenset(),
                store=store,
                monotonic_ns=SteppingMonotonic(),
            )
            context = ToolContext(
                invocation_id="inv-ladder",
                workspace=workspace,
                approved_tools=frozenset({"escalate"}) if approved else frozenset(),
                max_egress=EgressClass.NETWORK if egress else EgressClass.NONE,
            )
            call = (
                ToolCallRequest(name="escalate", args={"path": "../../etc/passwd"})
                if valid_args
                else request
            )
            return executor.execute(call, context)

        rungs = {
            "registry": {
                "registered": False,
                "allowlisted": False,
                "approved": False,
                "valid_args": False,
                "egress": False,
                "tier": False,
            },
            "allowlist": {
                "registered": True,
                "allowlisted": False,
                "approved": False,
                "valid_args": False,
                "egress": False,
                "tier": False,
            },
            "intent": {
                "registered": True,
                "allowlisted": True,
                "approved": False,
                "valid_args": False,
                "egress": False,
                "tier": False,
            },
            "schema": {
                "registered": True,
                "allowlisted": True,
                "approved": True,
                "valid_args": False,
                "egress": False,
                "tier": False,
            },
            "egress": {
                "registered": True,
                "allowlisted": True,
                "approved": True,
                "valid_args": True,
                "egress": False,
                "tier": False,
            },
            "isolation": {
                "registered": True,
                "allowlisted": True,
                "approved": True,
                "valid_args": True,
                "egress": True,
                "tier": False,
            },
            "containment": {
                "registered": True,
                "allowlisted": True,
                "approved": True,
                "valid_args": True,
                "egress": True,
                "tier": True,
            },
        }
        expected = [
            Reason.UNKNOWN_TOOL,
            Reason.NOT_ALLOWLISTED,
            Reason.NOT_APPROVED,
            Reason.ARGS_INVALID,
            Reason.EGRESS_NOT_PERMITTED,
            Reason.ISOLATION_UNAVAILABLE,
            Reason.PATH_ESCAPE,
        ]
        observed = [refuse(**arguments).reason for arguments in rungs.values()]
        assert observed == [reason.value for reason in expected]
        assert len(store.records) == len(rungs), "exactly one record per call, refusals included"

    def test_the_trajectory_refusal_outranks_the_turn_refusal(
        self, workspace: SandboxPaths
    ) -> None:
        """Never re-approvable outranks re-approvable: a model must not be told to seek a grant
        that could never be given."""
        registry = ToolRegistry()
        registry.register(spec("echo"), EchoTool())
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset())
        context = ToolContext(invocation_id="inv", workspace=workspace, approved_tools=frozenset())
        result = executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert result.reason == Reason.NOT_ALLOWLISTED.value


class TestEverySpecThirteenRow:
    """One test per row of spec §13, each asserting a result rather than an exception."""

    def test_a_tool_not_in_the_registry(self, executor: ToolExecutor, context: ToolContext) -> None:
        result = executor.execute(ToolCallRequest(name="nope", args={}), context)
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.UNKNOWN_TOOL.value

    @pytest.mark.parametrize(
        "name", ["Echo", "echo ", " echo", "ech", "echoo", "e_cho", "", "echo\x00", "ECHO"]
    )
    def test_a_near_miss_name_is_unknown_rather_than_resolved_helpfully(
        self, executor: ToolExecutor, context: ToolContext, name: str
    ) -> None:
        result = executor.execute(ToolCallRequest(name=name, args={"value": "x"}), context)
        assert result.reason == Reason.UNKNOWN_TOOL.value

    def test_cleaning_a_name_for_the_record_never_cleans_it_for_the_lookup(
        self, executor: ToolExecutor, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """A sharp edge the property suite found, pinned so it stays closed.

        The record must say what was asked for, so a model-supplied name is cleaned of NUL before
        it is stored. The *lookup* must not be: ``"echo\x00"`` cleans to ``"echo"``, which is
        registered — so a cleaned lookup would resolve a name nobody registered and defeat the
        exact-match rule in the one direction that matters.
        """
        result = executor.execute(ToolCallRequest(name="echo\x00", args={"value": "x"}), context)
        assert result.reason == Reason.UNKNOWN_TOOL.value
        assert store.records[0].tool_name == "echo", "the record still says what was asked for"

    def test_a_name_that_could_never_be_registered_is_unknown_not_an_invalid_spec(
        self, executor: ToolExecutor, context: ToolContext
    ) -> None:
        """The raise/refuse boundary, from the model's side. The same string raises if a caller
        registers it and refuses if a model asks for it."""
        result = executor.execute(ToolCallRequest(name="../../etc/passwd", args={}), context)
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.UNKNOWN_TOOL.value

    def test_a_registered_tool_outside_the_allowlist(
        self, registry: ToolRegistry, context: ToolContext, workspace: SandboxPaths
    ) -> None:
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset())
        result = executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert result.reason == Reason.NOT_ALLOWLISTED.value

    def test_a_tool_outside_this_turns_intent(
        self, executor: ToolExecutor, workspace: SandboxPaths
    ) -> None:
        context = ToolContext(
            invocation_id="inv", workspace=workspace, approved_tools=frozenset({"other"})
        )
        result = executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert result.reason == Reason.NOT_APPROVED.value

    def test_an_absent_approved_set_leaves_the_trajectory_allowlist_standing_alone(
        self, executor: ToolExecutor, context: ToolContext
    ) -> None:
        result = executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert result.status is ToolStatus.OK

    def test_an_intent_can_only_narrow_never_widen(
        self, registry: ToolRegistry, workspace: SandboxPaths
    ) -> None:
        """The safety property, asserted directly: an approved set naming a tool the trajectory
        does not allow cannot make it callable."""
        registry.register(spec("secret"), EchoTool())
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"echo"}))
        context = ToolContext(
            invocation_id="inv",
            workspace=workspace,
            approved_tools=frozenset({"echo", "secret"}),
        )
        result = executor.execute(ToolCallRequest(name="secret", args={"value": "x"}), context)
        assert result.reason == Reason.NOT_ALLOWLISTED.value

    def test_arguments_failing_the_schema_carry_the_validators_paths(
        self, executor: ToolExecutor, context: ToolContext
    ) -> None:
        result = executor.execute(ToolCallRequest(name="echo", args={"value": 1}), context)
        assert result.reason == Reason.ARGS_INVALID.value
        assert result.reason_detail is not None
        assert "$.value" in result.reason_detail

    def test_an_egress_tool_where_egress_is_not_permitted(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("fetch", egress=EgressClass.NETWORK), EchoTool())
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"fetch"}))
        context = ToolContext(invocation_id="inv", workspace=workspace)
        result = executor.execute(ToolCallRequest(name="fetch", args={"value": "x"}), context)
        assert result.reason == Reason.EGRESS_NOT_PERMITTED.value

    def test_an_egress_tool_where_egress_is_permitted_runs(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("fetch", egress=EgressClass.NETWORK), EchoTool())
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"fetch"}))
        context = ToolContext(
            invocation_id="inv", workspace=workspace, max_egress=EgressClass.NETWORK
        )
        result = executor.execute(ToolCallRequest(name="fetch", args={"value": "x"}), context)
        assert result.status is ToolStatus.OK

    def test_a_path_escaping_containment(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(
            spec("reader", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.READ}), EchoTool()
        )
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"reader"}))
        context = ToolContext(invocation_id="inv", workspace=workspace)
        result = executor.execute(
            ToolCallRequest(name="reader", args={"path": "../../etc/passwd"}), context
        )
        assert result.reason == Reason.PATH_ESCAPE.value

    def test_no_isolation_tier_for_a_tool_that_needs_one(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("runner", requires_isolation=True), EchoTool())
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"runner"}))
        context = ToolContext(invocation_id="inv", workspace=workspace)
        result = executor.execute(ToolCallRequest(name="runner", args={"value": "x"}), context)
        assert result.reason == Reason.ISOLATION_UNAVAILABLE.value

    def test_a_tool_needing_isolation_runs_when_a_tier_exists(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(spec("runner", requires_isolation=True), EchoTool())
        executor = ToolExecutor(
            registry, FixedTierSandbox(IsolationTier.BWRAP), allowlist=frozenset({"runner"})
        )
        context = ToolContext(invocation_id="inv", workspace=workspace)
        result = executor.execute(ToolCallRequest(name="runner", args={"value": "x"}), context)
        assert result.status is ToolStatus.OK

    def test_a_handler_exception_names_the_class_and_shows_no_traceback(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(spec("boom"), RaisingTool(KeyError("the/secret/path")))
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"boom"}))
        context = ToolContext(invocation_id="inv", workspace=workspace)
        result = executor.execute(ToolCallRequest(name="boom", args={"value": "x"}), context)
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.HANDLER_ERROR.value
        assert "KeyError" in (result.reason_detail or "")
        for traceback_marker in ("Traceback", 'File "', "line ", ".py"):
            assert traceback_marker not in result.content

    def test_a_timeout_names_the_elapsed_time_and_the_limit(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("slow"), SleepingTool(seconds=0.02))
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"slow"}))
        context = ToolContext(invocation_id="inv", workspace=workspace, timeout_seconds=0.001)
        result = executor.execute(ToolCallRequest(name="slow", args={"value": "x"}), context)
        assert result.status is ToolStatus.TIMEOUT
        assert result.reason == Reason.TIMEOUT.value
        assert "0.001" in (result.reason_detail or "")
        assert "slept" not in result.content, "a timed-out result must not surface its output"

    def test_output_over_the_cap_is_truncated_and_labelled(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("big"), FixedOutputTool("x" * (DEFAULT_MAX_CONTENT_BYTES * 2)))
        store = InMemoryToolCallStore()
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"big"}), store=store
        )
        context = ToolContext(invocation_id="inv", workspace=workspace)
        result = executor.execute(ToolCallRequest(name="big", args={"value": "x"}), context)
        assert result.status is ToolStatus.OK
        assert len(result.content.encode("utf-8")) <= DEFAULT_MAX_CONTENT_BYTES
        assert "truncated by toolyard" in result.content
        assert TRUNCATION_LABEL_TEMPLATE.split("{")[0].strip() in result.content
        assert store.records[0].result_sha256 != "", "the full output's hash is recorded"


class TestNothingAModelInfluencesRaises:
    """The parts *after* the handler returns are on the same path and get the same promise."""

    def _run(self, handler: object, *, workspace: SandboxPaths, **kwargs: Any) -> ToolResult:
        registry = ToolRegistry()
        registry.register(spec("probe"), handler)  # type: ignore[arg-type]
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"probe"}), **kwargs
        )
        return executor.execute(
            ToolCallRequest(name="probe", args={"value": "x"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )

    @pytest.mark.parametrize("returned", [None, "text", 17, [1], {"a": 1}, object()])
    def test_a_handler_returning_the_wrong_type_is_a_failure_not_a_crash(
        self, workspace: SandboxPaths, returned: object
    ) -> None:
        result = self._run(ReturningTool(returned), workspace=workspace)
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.HANDLER_ERROR.value

    def test_a_handler_returning_non_utf8_shaped_text_is_cleaned_not_raised(
        self, workspace: SandboxPaths
    ) -> None:
        result = self._run(FixedOutputTool("before\ud800after\x00end"), workspace=workspace)
        assert result.status is ToolStatus.OK
        assert result.content == "beforeafterend"

    def test_a_handler_whose_exception_cannot_be_rendered_still_fails_cleanly(
        self, workspace: SandboxPaths
    ) -> None:
        result = self._run(RaisingTool(UnrenderableError()), workspace=workspace)
        assert result.status is ToolStatus.FAILED
        assert "UnrenderableError" in (result.reason_detail or "")

    @pytest.mark.parametrize(
        "error",
        [ValueError("x"), MemoryError(), RecursionError(), OSError(13, "denied"), Exception()],
    )
    def test_any_exception_class_becomes_a_failed_result(
        self, workspace: SandboxPaths, error: Exception
    ) -> None:
        result = self._run(RaisingTool(error), workspace=workspace)
        assert result.status is ToolStatus.FAILED

    def test_a_handler_mutating_its_arguments_cannot_change_the_record(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(spec("probe"), ArgumentMutatingTool())
        store = InMemoryToolCallStore()
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"probe"}), store=store
        )
        executor.execute(
            ToolCallRequest(name="probe", args={"value": "original"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert store.records[0].args_json == '{"value":"original"}'
        assert "injected" not in (store.records[0].args_json or "")

    def test_a_sandbox_that_explodes_produces_a_refusal_not_a_crash(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(
            spec("reader", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.READ}), EchoTool()
        )
        executor = ToolExecutor(registry, ExplodingSandbox(), allowlist=frozenset({"reader"}))
        result = executor.execute(
            ToolCallRequest(name="reader", args={"path": "notes.md"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.reason == Reason.PATH_ESCAPE.value

    def test_an_isolation_probe_that_explodes_is_read_as_no_tier(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(spec("runner", requires_isolation=True), EchoTool())
        executor = ToolExecutor(registry, ExplodingSandbox(), allowlist=frozenset({"runner"}))
        result = executor.execute(
            ToolCallRequest(name="runner", args={"value": "x"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.reason == Reason.ISOLATION_UNAVAILABLE.value

    def test_every_reason_produced_is_in_the_closed_set(
        self, executor: ToolExecutor, context: ToolContext
    ) -> None:
        for call in (
            ToolCallRequest(name="nope", args={}),
            ToolCallRequest(name="echo", args={"value": 1}),
            ToolCallRequest(name="echo", args={"value": "ok"}),
        ):
            result = executor.execute(call, context)
            assert result.reason is None or result.reason in REFUSAL_REASONS


class TestTheOneThingThatIsReRaised:
    """A ``BaseException`` that is not an ``Exception`` is recorded and then let through."""

    def test_a_keyboard_interrupt_is_recorded_and_re_raised(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("probe"), RaisingTool(KeyboardInterrupt()))
        store = InMemoryToolCallStore()
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"probe"}), store=store
        )
        with pytest.raises(KeyboardInterrupt):
            executor.execute(
                ToolCallRequest(name="probe", args={"value": "x"}),
                ToolContext(invocation_id="inv", workspace=workspace),
            )
        assert len(store.records) == 1, "the call is recorded before the interrupt is let through"
        assert store.records[0].status is ToolStatus.FAILED
        assert "KeyboardInterrupt" in (store.records[0].reason_detail or "")

    def test_a_system_exit_is_recorded_and_re_raised(self, workspace: SandboxPaths) -> None:
        registry = ToolRegistry()
        registry.register(spec("probe"), RaisingTool(SystemExit(2)))
        store = InMemoryToolCallStore()
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"probe"}), store=store
        )
        with pytest.raises(SystemExit):
            executor.execute(
                ToolCallRequest(name="probe", args={"value": "x"}),
                ToolContext(invocation_id="inv", workspace=workspace),
            )
        assert len(store.records) == 1


class TestContainmentSubstitution:
    """The handler receives the resolved path, so it never re-resolves a candidate."""

    def test_the_handler_is_handed_the_resolved_path(self, workspace: SandboxPaths) -> None:
        recorder = RecordingTool()
        registry = ToolRegistry()
        registry.register(
            spec("reader", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.READ}), recorder
        )
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"reader"}))
        executor.execute(
            ToolCallRequest(name="reader", args={"path": "sub/../notes.md"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert recorder.seen[0]["path"] == str(workspace.write_root / "notes.md")

    def test_a_write_argument_is_checked_against_the_write_root_alone(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(
            spec("writer", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.WRITE}),
            EchoTool(),
        )
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"writer"}))
        result = executor.execute(
            ToolCallRequest(name="writer", args={"path": str(workspace.read_roots[0] / "x")}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.reason == Reason.PATH_ESCAPE.value

    def test_an_absent_optional_path_argument_is_skipped(self, workspace: SandboxPaths) -> None:
        schema = {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        }
        recorder = RecordingTool()
        registry = ToolRegistry()
        registry.register(
            spec("reader", args_schema=schema, path_args={"path": PathAccess.READ}), recorder
        )
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"reader"}))
        result = executor.execute(
            ToolCallRequest(name="reader", args={}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.status is ToolStatus.OK


class TestRefusalTextIsPromptSurface:
    """ADR-0053's last consequence, asserted rather than intended."""

    def test_a_refusal_never_names_the_allowlists_members(
        self, registry: ToolRegistry, workspace: SandboxPaths
    ) -> None:
        registry.register(spec("secret_tool"), EchoTool())
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"echo", "secret_tool"})
        )
        context = ToolContext(
            invocation_id="inv", workspace=workspace, approved_tools=frozenset({"echo"})
        )
        result = executor.execute(ToolCallRequest(name="secret_tool", args={"value": "x"}), context)
        assert result.reason == Reason.NOT_APPROVED.value
        assert "echo" not in result.content.replace("secret_tool", "")

    def test_a_path_escape_names_the_roots_role_to_the_model_and_its_path_to_the_record(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(
            spec("reader", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.READ}), EchoTool()
        )
        store = InMemoryToolCallStore()
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"reader"}), store=store
        )
        result = executor.execute(
            ToolCallRequest(name="reader", args={"path": "/etc/passwd"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert "read_roots" in result.content
        assert str(workspace.write_root) not in result.content
        assert str(workspace.write_root) in store.records[0].result_summary


class TestConfigurationIsConstructorArgumentsOnly:
    """Spec §12: no environment, no files, and every cap checked where it is set."""

    def test_a_cap_below_the_floor_is_refused(self, registry: ToolRegistry) -> None:
        for field_name in ("max_content_bytes", "max_summary_bytes", "max_args_json_bytes"):
            caps: dict[str, Any] = {field_name: 10}
            with pytest.raises(ValidationError, match=field_name):
                ToolExecutor(registry, PathContainment(), allowlist=frozenset(), **caps)

    @pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), "5", True])
    def test_a_default_timeout_that_is_not_a_finite_positive_number_is_refused(
        self, registry: ToolRegistry, value: object
    ) -> None:
        with pytest.raises(ValidationError, match="default_timeout_seconds"):
            ToolExecutor(
                registry,
                PathContainment(),
                allowlist=frozenset(),
                default_timeout_seconds=value,  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize("allowlist", [["echo"], "echo", None, frozenset({1})])
    def test_an_allowlist_that_is_not_a_set_of_strings_is_refused(
        self, registry: ToolRegistry, allowlist: object
    ) -> None:
        with pytest.raises(ValidationError, match="allowlist"):
            ToolExecutor(registry, PathContainment(), allowlist=allowlist)  # type: ignore[arg-type]

    def test_the_context_timeout_overrides_the_executors_default(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(spec("slow"), SleepingTool(seconds=0.02))
        executor = ToolExecutor(
            registry,
            PathContainment(),
            allowlist=frozenset({"slow"}),
            default_timeout_seconds=0.001,
        )
        context = ToolContext(invocation_id="inv", workspace=workspace, timeout_seconds=10.0)
        assert (
            executor.execute(ToolCallRequest(name="slow", args={"value": "x"}), context).status
            is ToolStatus.OK
        )


class TestLogging:
    """Spec §17: nothing at INFO, and never an argument or a result body at any level."""

    def test_nothing_is_logged_at_info(
        self, executor: ToolExecutor, context: ToolContext, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="toolyard"):
            executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert caplog.records == []

    def test_debug_logs_names_and_statuses_and_never_arguments_or_content(
        self, workspace: SandboxPaths, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One ``logger.debug("args=%s", args)`` defeats the whole of ``redact_args``."""
        secret = "corn-horse-battery-staple"  # noqa: S105 — a marker to look for, not a credential
        registry = ToolRegistry()
        registry.register(spec("echo", redact_args=True), FixedOutputTool(secret + "-output"))
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"echo"}))
        with caplog.at_level(logging.DEBUG, logger="toolyard"):
            executor.execute(
                ToolCallRequest(name="echo", args={"value": secret}),
                ToolContext(invocation_id="inv", workspace=workspace),
            )
        assert caplog.records, "DEBUG should say something"
        rendered = "\n".join(
            [record.getMessage() for record in caplog.records]
            + [repr(record.args) for record in caplog.records]
        )
        assert secret not in rendered
        assert "echo" in rendered
