"""The vocabulary: what raises at construction, what never does, and the wire-definition golden."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from baseaicore import ValidationError, canonical_json, sha256_of

from fakes import EMPTY_SCHEMA, PATH_SCHEMA, spec
from toolyard import (
    REFUSAL_REASONS,
    TOOL_NAME_PATTERN,
    EgressClass,
    InMemoryToolCallStore,
    InvalidToolSpec,
    PathAccess,
    PathContainment,
    Reason,
    RiskClass,
    SandboxPaths,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolOutput,
    ToolRefusal,
    ToolRegistry,
    ToolSpec,
    ToolStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

GOLDEN = Path(__file__).resolve().parents[1] / "goldens" / "wire_definitions.json"


class TestOrderedCeilings:
    """``RiskClass`` and ``EgressClass`` are ceilings, so they compare rather than merely differ."""

    def test_a_read_only_ceiling_refuses_a_mutating_tool(self) -> None:
        assert RiskClass.READ_ONLY.permits(RiskClass.READ_ONLY)
        assert not RiskClass.READ_ONLY.permits(RiskClass.MUTATING)
        assert RiskClass.MUTATING.permits(RiskClass.READ_ONLY)

    def test_the_closed_egress_ceiling_refuses_a_network_tool(self) -> None:
        assert EgressClass.NONE.permits(EgressClass.NONE)
        assert not EgressClass.NONE.permits(EgressClass.NETWORK)
        assert EgressClass.NETWORK.permits(EgressClass.NETWORK)

    def test_the_ranks_are_a_total_order_over_every_member(self) -> None:
        assert sorted(RiskClass, key=lambda member: member.rank) == [
            RiskClass.READ_ONLY,
            RiskClass.MUTATING,
        ]
        assert sorted(EgressClass, key=lambda member: member.rank) == [
            EgressClass.NONE,
            EgressClass.NETWORK,
        ]


class TestToolSpecValidation:
    """A ``ToolSpec`` that exists is a valid one — validation is part of construction."""

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "A",
            "1abc",
            "a",
            "read file",
            "read-file",
            "read_file ",
            "READ_FILE",
            "a" * 65,
            "ünïcode",
        ],
    )
    def test_a_name_outside_the_pattern_raises(self, name: str) -> None:
        with pytest.raises(InvalidToolSpec) as caught:
            spec(name)
        assert caught.value.code == "TOOL_SPEC_INVALID"

    @pytest.mark.parametrize("name", ["ab", "read_file", "a1", "a" * 64])
    def test_a_name_inside_the_pattern_is_accepted(self, name: str) -> None:
        assert spec(name).name == name
        assert TOOL_NAME_PATTERN.fullmatch(name)

    def test_a_non_string_name_raises_rather_than_being_coerced(self) -> None:
        with pytest.raises(InvalidToolSpec):
            spec(name=None)  # type: ignore[arg-type]  # the caller-bug direction of the boundary

    def test_an_empty_description_raises(self) -> None:
        with pytest.raises(InvalidToolSpec, match="description"):
            ToolSpec(
                name="tool",
                description="   ",
                args_schema=dict(EMPTY_SCHEMA),
                result_schema=None,
                risk_class=RiskClass.READ_ONLY,
                egress=EgressClass.NONE,
            )

    def test_a_class_that_is_not_an_enum_member_raises(self) -> None:
        with pytest.raises(InvalidToolSpec, match="RiskClass"):
            ToolSpec(
                name="tool",
                description="d",
                args_schema=dict(EMPTY_SCHEMA),
                result_schema=None,
                risk_class="read_only",  # type: ignore[arg-type]  # a string is not the enum
                egress=EgressClass.NONE,
            )

    def test_the_schema_is_deep_copied_so_a_later_mutation_cannot_reach_it(self) -> None:
        inner: dict[str, Any] = {"type": "string"}
        schema: dict[str, Any] = {
            "type": "object",
            "properties": {"value": inner},
            "additionalProperties": False,
        }
        built = spec("tool", args_schema=schema)
        schema["additionalProperties"] = True
        inner["type"] = "integer"
        assert built.args_schema["additionalProperties"] is False
        assert built.args_schema["properties"]["value"]["type"] == "string"

    def test_a_result_schema_is_checked_but_need_not_be_closed(self) -> None:
        built = ToolSpec(
            name="tool",
            description="d",
            args_schema=dict(EMPTY_SCHEMA),
            result_schema={"type": "object", "properties": {"n": {"type": "integer"}}},
            risk_class=RiskClass.READ_ONLY,
            egress=EgressClass.NONE,
        )
        assert built.result_schema is not None

    def test_a_malformed_result_schema_raises(self) -> None:
        with pytest.raises(InvalidToolSpec, match="result_schema"):
            ToolSpec(
                name="tool",
                description="d",
                args_schema=dict(EMPTY_SCHEMA),
                result_schema={"type": 17},
                risk_class=RiskClass.READ_ONLY,
                egress=EgressClass.NONE,
            )


class TestPathArgumentDeclaration:
    """``path_args`` is the input the containment check would otherwise lack, so it is checked."""

    def test_a_declared_path_argument_must_be_a_string_property(self) -> None:
        with pytest.raises(InvalidToolSpec, match="path_args"):
            spec("tool", args_schema=PATH_SCHEMA, path_args={"missing": PathAccess.READ})

    def test_a_declared_path_argument_typed_as_something_else_is_refused(self) -> None:
        schema = {
            "type": "object",
            "properties": {"path": {"type": "integer"}},
            "additionalProperties": False,
        }
        with pytest.raises(InvalidToolSpec, match="path_args"):
            spec("tool", args_schema=schema, path_args={"path": PathAccess.READ})

    def test_a_path_args_declaration_that_is_not_a_mapping_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="path_args"):
            ToolSpec(
                name="tool",
                description="d",
                args_schema=dict(PATH_SCHEMA),
                result_schema=None,
                risk_class=RiskClass.READ_ONLY,
                egress=EgressClass.NONE,
                path_args=[("path", PathAccess.READ)],  # type: ignore[arg-type]
            )

    def test_a_path_access_value_of_the_wrong_type_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="PathAccess"):
            spec("tool", args_schema=PATH_SCHEMA, path_args={"path": "read"})  # type: ignore[dict-item]

    def test_a_valid_declaration_is_kept(self) -> None:
        built = spec("tool", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.WRITE})
        assert built.path_args == {"path": PathAccess.WRITE}


class TestWireDefinition:
    """Contract 7: provider-neutral, byte-stable, and holding none of the caller's policy."""

    def test_the_key_set_is_fixed_and_holds_no_policy(self) -> None:
        built = spec(
            "tool",
            risk_class=RiskClass.MUTATING,
            egress=EgressClass.NETWORK,
            redact_args=True,
            requires_isolation=True,
        )
        definition = built.wire_definition()
        assert set(definition) == {"name", "description", "parameters"}
        rendered = canonical_json(definition)
        for leaked in ("mutating", "network", "redact", "isolation", "path_args"):
            assert leaked not in rendered

    def test_the_definition_is_byte_stable_across_constructions(self) -> None:
        first = canonical_json(spec("tool").wire_definition())
        second = canonical_json(spec("tool").wire_definition())
        assert first == second

    def test_insertion_order_in_the_schema_cannot_reach_the_digest(self) -> None:
        forward = {
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
            "additionalProperties": False,
        }
        backward = {
            "additionalProperties": False,
            "properties": {"b": {"type": "string"}, "a": {"type": "string"}},
            "type": "object",
        }
        assert sha256_of(spec("tool", args_schema=forward).wire_definition()) == sha256_of(
            spec("tool", args_schema=backward).wire_definition()
        )

    @pytest.mark.contract
    def test_the_committed_golden_still_matches(self) -> None:
        specs = [
            spec("echo"),
            spec("read_notes", args_schema=PATH_SCHEMA, path_args={"path": PathAccess.READ}),
            spec("no_args", args_schema=EMPTY_SCHEMA),
        ]
        produced = {
            built.name: {
                "definition": built.wire_definition(),
                "sha256": sha256_of(built.wire_definition()),
            }
            for built in specs
        }
        expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
        assert produced == expected, (
            "A wire definition changed. These are hashed into PromptCadence's turn records, so a "
            "change here is a change to every recorded turn — regenerate the golden deliberately "
            "and note it in the changelog, never to make a test pass."
        )


class TestToolOutput:
    """The other untrusted half: what a handler produced."""

    def test_a_non_string_content_raises_inside_the_handler_frame(self) -> None:
        with pytest.raises(ValidationError, match="content"):
            ToolOutput(content=17)  # type: ignore[arg-type]  # caught by the executor as FAILED

    def test_structured_output_is_optional_and_separate_from_content(self) -> None:
        output = ToolOutput(content="text", structured={"n": 1})
        assert output.content == "text"
        assert output.structured == {"n": 1}


class TestToolContextIsTheTrustedHalf:
    """Every field is the application's, so every bad one raises at construction."""

    def test_a_blank_invocation_id_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="invocation_id"):
            ToolContext(invocation_id="  ", workspace=SandboxPaths(write_root=tmp_path))

    def test_a_workspace_of_the_wrong_type_raises(self) -> None:
        with pytest.raises(ValidationError, match="workspace"):
            ToolContext(invocation_id="inv", workspace=Path("/nonexistent"))  # type: ignore[arg-type]

    @pytest.mark.parametrize("value", [0, -1.0, float("inf"), float("nan"), "5", True])
    def test_a_timeout_that_is_not_a_finite_positive_number_raises(
        self, tmp_path: Path, value: object
    ) -> None:
        with pytest.raises(ValidationError, match="timeout_seconds"):
            ToolContext(
                invocation_id="inv",
                workspace=SandboxPaths(write_root=tmp_path),
                timeout_seconds=value,  # type: ignore[arg-type]
            )

    def test_none_is_the_only_way_to_ask_for_the_default_and_it_is_not_unlimited(
        self, tmp_path: Path
    ) -> None:
        context = ToolContext(
            invocation_id="inv", workspace=SandboxPaths(write_root=tmp_path), timeout_seconds=None
        )
        assert context.timeout_seconds is None

    def test_approved_tools_must_be_a_set_of_strings(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="approved_tools"):
            ToolContext(
                invocation_id="inv",
                workspace=SandboxPaths(write_root=tmp_path),
                approved_tools={1, 2},  # type: ignore[arg-type]
            )

    def test_a_mutable_approved_set_is_frozen_on_the_way_in(self, tmp_path: Path) -> None:
        mutable = {"echo"}
        context = ToolContext(
            invocation_id="inv",
            workspace=SandboxPaths(write_root=tmp_path),
            approved_tools=mutable,  # type: ignore[arg-type]
        )
        mutable.add("smuggled")
        assert context.approved_tools == frozenset({"echo"})

    def test_the_egress_ceiling_defaults_closed(self, tmp_path: Path) -> None:
        context = ToolContext(invocation_id="inv", workspace=SandboxPaths(write_root=tmp_path))
        assert context.max_egress is EgressClass.NONE

    def test_a_ceiling_of_the_wrong_type_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="max_egress"):
            ToolContext(
                invocation_id="inv",
                workspace=SandboxPaths(write_root=tmp_path),
                max_egress="network",  # type: ignore[arg-type]
            )

    def test_a_clock_that_is_not_callable_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="clock"):
            ToolContext(
                invocation_id="inv",
                workspace=SandboxPaths(write_root=tmp_path),
                clock=datetime(2026, 9, 3, tzinfo=UTC),  # type: ignore[arg-type]
            )


class TestToolCallRequestIsNeverValidated:
    """The untrusted half. A ``__post_init__`` here would raise on model input — the design
    ADR-0053 rejects."""

    @pytest.mark.parametrize(
        "name", ["", "A" * 10_000, None, 17, "../../etc/passwd", "echo\x00", "echo "]
    )
    def test_any_name_at_all_constructs(self, name: object) -> None:
        assert ToolCallRequest(name=name, args={}).name is name  # type: ignore[arg-type]

    @pytest.mark.parametrize("args", [None, "not a mapping", [1, 2, 3], {1: 2}, 17])
    def test_any_arguments_at_all_construct(self, args: object) -> None:
        assert ToolCallRequest(name="echo", args=args).args is args  # type: ignore[arg-type]

    def test_a_cyclic_argument_structure_constructs(self) -> None:
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        assert ToolCallRequest(name="echo", args=cyclic).args is cyclic


class TestClosedReasonSet:
    """PromptCadence maps a reason onto a deviation category, so the set is closed."""

    def test_every_status_and_reason_is_a_plain_string_value(self) -> None:
        assert {status.value for status in ToolStatus} == {"ok", "refused", "failed", "timeout"}
        assert all(isinstance(reason.value, str) and reason.value for reason in Reason)

    def test_the_reason_names_match_their_values(self) -> None:
        for reason in Reason:
            assert reason.name.lower() == reason.value


class TestToolRefusal:
    """A handler's own refusal — the type that makes spec §13's fetch rows expressible.

    Without it a handler could only succeed or raise, and a raise is ``handler_error``, which names
    an exception class and not a check. The validation below is why a handler cannot smuggle a
    vocabulary past the closed reason set.
    """

    def test_a_refusal_defaults_to_refused(self) -> None:
        """The common case is a rule of this package declining; ``FAILED`` is stated explicitly."""
        assert ToolRefusal(Reason.TOO_LARGE, "over the cap").status is ToolStatus.REFUSED

    @pytest.mark.parametrize("status", [ToolStatus.REFUSED, ToolStatus.FAILED, ToolStatus.TIMEOUT])
    def test_every_non_ok_status_is_allowed(self, status: ToolStatus) -> None:
        assert ToolRefusal(Reason.TIMEOUT, "elapsed", status=status).status is status

    def test_a_refusal_reporting_ok_is_refused(self) -> None:
        """The one shape that cannot be true."""
        with pytest.raises(ValidationError, match="status"):
            ToolRefusal(Reason.TOO_LARGE, "over", status=ToolStatus.OK)

    @pytest.mark.parametrize("reason", ["too_large", None, 17, Reason])
    def test_a_reason_outside_the_closed_set_is_refused(self, reason: object) -> None:
        """A handler can no more invent a reason than the executor can (spec §7's Reason note)."""
        with pytest.raises(ValidationError, match="reason"):
            ToolRefusal(reason, "detail")  # type: ignore[arg-type]

    @pytest.mark.parametrize("detail", ["", "   ", None, 17])
    def test_a_detail_that_says_nothing_is_refused(self, detail: object) -> None:
        """It is the sentence the model reads; one it cannot act on teaches it nothing."""
        with pytest.raises(ValidationError, match="detail"):
            ToolRefusal(Reason.TOO_LARGE, detail)  # type: ignore[arg-type]

    def test_a_record_detail_that_is_not_text_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="record_detail"):
            ToolRefusal(Reason.TOO_LARGE, "over", record_detail=17)  # type: ignore[arg-type]

    def test_a_record_detail_may_be_absent(self) -> None:
        assert ToolRefusal(Reason.TOO_LARGE, "over").record_detail is None

    def test_a_broken_refusal_raised_inside_a_handler_is_reported_as_a_handler_error(
        self, workspace: SandboxPaths, store: InMemoryToolCallStore
    ) -> None:
        """A handler bug is never a broken agent loop: the raise happens in the handler's frame."""

        class BrokenHandler:
            def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
                del args, context
                return ToolRefusal("not_a_reason", "x")  # type: ignore[arg-type,return-value]

        registry = ToolRegistry()
        registry.register(spec("broken"), BrokenHandler())
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"broken"}), store=store
        )
        result = executor.execute(
            ToolCallRequest(name="broken", args={"value": "x"}),
            ToolContext(invocation_id="inv-1", workspace=workspace),
        )
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.HANDLER_ERROR.value

    def test_every_reason_a_handler_may_produce_is_in_the_exported_set(self) -> None:
        """`REFUSAL_REASONS` is what a consumer exhausts; a handler cannot widen it."""
        assert {reason.value for reason in Reason} == set(REFUSAL_REASONS)
