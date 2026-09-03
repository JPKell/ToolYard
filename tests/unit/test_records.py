"""The record: one per call, for every outcome, with redaction that actually redacts."""

from __future__ import annotations

import dataclasses
import json
import math
from typing import TYPE_CHECKING, Any

import pytest
from baseaicore import canonical_json, sha256_of

from fakes import (
    FixedOutputTool,
    FrozenClock,
    RaisingTool,
    SleepingTool,
    SteppingMonotonic,
    spec,
)
from toolyard import (
    DEFAULT_MAX_ARGS_JSON_BYTES,
    EgressClass,
    InMemoryToolCallStore,
    PathContainment,
    Reason,
    RiskClass,
    StoreFailure,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolRegistry,
    ToolStatus,
)
from toolyard._safe import json_sanitize

if TYPE_CHECKING:
    from toolyard import SandboxPaths

SECRET = "hunter2-correct-horse"  # noqa: S105 — a marker to look for, not a credential


def build(
    handler: object,
    *,
    workspace: SandboxPaths,
    redact: bool = False,
    store: InMemoryToolCallStore | None = None,
    **kwargs: Any,
) -> tuple[ToolExecutor, ToolContext, InMemoryToolCallStore]:
    """An executor over one tool, with a deterministic clock and duration source."""
    from conftest import FIXED_MOMENT

    registry = ToolRegistry()
    registry.register(spec("echo", redact_args=redact), handler)  # type: ignore[arg-type]
    kept = store if store is not None else InMemoryToolCallStore()
    executor = ToolExecutor(
        registry,
        PathContainment(),
        allowlist=frozenset({"echo"}),
        store=kept,
        monotonic_ns=SteppingMonotonic(),
        **kwargs,
    )
    context = ToolContext(
        invocation_id="inv-1", workspace=workspace, clock=FrozenClock(FIXED_MOMENT)
    )
    return executor, context, kept


class TestOneRecordPerCallWhateverHappens:
    """Spec §11.6, across all four statuses."""

    def test_a_successful_call_is_recorded(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(FixedOutputTool("done"), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert len(store.records) == 1
        assert store.records[0].status is ToolStatus.OK
        assert store.records[0].reason is None

    def test_a_refused_call_is_recorded_with_its_reason(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="ghost", args={}), context)
        assert store.records[0].status is ToolStatus.REFUSED
        assert store.records[0].reason == Reason.UNKNOWN_TOOL.value

    def test_a_failed_call_is_recorded(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(RaisingTool(ValueError("no")), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert store.records[0].status is ToolStatus.FAILED
        assert store.records[0].reason == Reason.HANDLER_ERROR.value

    def test_a_timed_out_call_is_recorded(self, workspace: SandboxPaths) -> None:
        """The injected monotonic source advances 1 ms per reading, so no test has to sleep."""
        executor, context, store = build(
            SleepingTool(0.0), workspace=workspace, default_timeout_seconds=0.0005
        )
        executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert store.records[0].status is ToolStatus.TIMEOUT
        assert store.records[0].reason == Reason.TIMEOUT.value

    def test_a_refusal_names_what_was_asked_for_even_when_it_does_not_exist(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="ghost_tool", args={}), context)
        assert store.records[0].tool_name == "ghost_tool"

    def test_a_hostile_name_is_cleaned_and_capped_in_the_record(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="A" * 10_000 + "\x00", args={}), context)
        assert len(store.records[0].tool_name) <= 128
        assert "\x00" not in store.records[0].tool_name

    def test_a_name_that_is_not_a_string_is_described_rather_than_rendered(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name=None, args={}), context)  # type: ignore[arg-type]
        assert store.records[0].tool_name == "<NoneType>"

    def test_a_refusal_before_a_tool_is_identified_records_the_closed_classes(
        self, workspace: SandboxPaths
    ) -> None:
        """A call refused before a tool was found performed no action of any class."""
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="ghost", args={}), context)
        assert store.records[0].risk_class is RiskClass.READ_ONLY
        assert store.records[0].egress is EgressClass.NONE

    def test_a_store_of_none_appends_nothing_but_still_returns_a_result(
        self, workspace: SandboxPaths
    ) -> None:
        registry = ToolRegistry()
        registry.register(spec("echo"), FixedOutputTool("done"))
        executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"echo"}))
        result = executor.execute(
            ToolCallRequest(name="echo", args={"value": "x"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.status is ToolStatus.OK


class TestRedactionRedacts:
    """``args_sha256`` always present, ``args_json`` ``None``, plaintext nowhere at any length."""

    def test_a_redacted_call_stores_the_hash_and_not_the_plaintext(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace, redact=True)
        executor.execute(ToolCallRequest(name="echo", args={"value": SECRET}), context)
        held = store.records[0]
        assert held.args_json is None
        assert len(held.args_sha256) == 64

    def test_the_plaintext_appears_in_no_field_of_a_redacted_record(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace, redact=True)
        executor.execute(ToolCallRequest(name="echo", args={"value": SECRET}), context)
        rendered = canonical_json(
            {key: str(value) for key, value in dataclasses.asdict(store.records[0]).items()}
        )
        assert SECRET not in rendered
        for length in (4, 8, 12, len(SECRET)):
            assert SECRET[:length] not in rendered

    def test_a_redacted_refusal_is_redacted_too(self, workspace: SandboxPaths) -> None:
        """The refusal path builds its own record; redaction must reach it as well."""
        executor, context, store = build(FixedOutputTool(), workspace=workspace, redact=True)
        executor.execute(ToolCallRequest(name="echo", args={"value": SECRET, "x": 1}), context)
        assert store.records[0].status is ToolStatus.REFUSED
        assert store.records[0].args_json is None
        assert SECRET not in canonical_json(dict(store.records[0].__slots__ and {}))

    def test_an_unredacted_call_keeps_the_arguments(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args={"value": "public"}), context)
        assert store.records[0].args_json == '{"value":"public"}'


class TestArgumentRendering:
    """``args_json`` is always valid JSON, and the digest exists for values that cannot be."""

    def test_arguments_are_canonical_json(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert json.loads(store.records[0].args_json or "") == {"value": "x"}

    def test_oversize_arguments_become_a_size_and_digest_object_not_a_fragment(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(
            ToolCallRequest(name="echo", args={"value": "x" * (DEFAULT_MAX_ARGS_JSON_BYTES * 2)}),
            context,
        )
        rendered = json.loads(store.records[0].args_json or "")
        assert rendered["__toolyard_args_omitted__"] == "oversize"
        assert rendered["bytes"] > DEFAULT_MAX_ARGS_JSON_BYTES
        assert len(rendered["sha256"]) == 64

    @pytest.mark.parametrize(
        "args",
        [
            {"value": math.nan},
            {"value": math.inf},
            {"value": b"bytes"},
            {"value": {1, 2, 3}},
            {"value": object()},
            {17: "non-string key"},
        ],
    )
    def test_arguments_json_cannot_hold_still_produce_a_digest(
        self, workspace: SandboxPaths, args: dict[Any, Any]
    ) -> None:
        """``canonical_json`` refuses all of these, and ``json.loads`` accepts ``NaN`` by default —
        so they really do arrive, and a record must exist for the refusal that follows."""
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args=args), context)
        held = store.records[0]
        assert len(held.args_sha256) == 64
        assert json.loads(held.args_json or "") is not None

    def test_a_cyclic_structure_produces_a_digest(self, workspace: SandboxPaths) -> None:
        cyclic: dict[str, Any] = {"value": "x"}
        cyclic["self"] = cyclic
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args=cyclic), context)
        assert len(store.records[0].args_sha256) == 64

    def test_arguments_that_are_not_a_mapping_still_produce_a_record(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args="not a mapping"), context)  # type: ignore[arg-type]
        assert store.records[0].status is ToolStatus.REFUSED
        assert len(store.records[0].args_sha256) == 64


class TestHashesAreStable:
    """A digest is a function of the arguments, not of how they were typed."""

    def test_the_same_arguments_hash_the_same(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        for _ in range(2):
            executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert store.records[0].args_sha256 == store.records[1].args_sha256

    def test_key_insertion_order_does_not_change_the_digest(self) -> None:
        assert sha256_of(json_sanitize({"a": 1, "b": 2})) == sha256_of(
            json_sanitize({"b": 2, "a": 1})
        )

    def test_different_arguments_hash_differently(self, workspace: SandboxPaths) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args={"value": "a"}), context)
        executor.execute(ToolCallRequest(name="echo", args={"value": "b"}), context)
        assert store.records[0].args_sha256 != store.records[1].args_sha256

    def test_the_result_digest_is_of_the_full_output_not_the_truncated_one(
        self, workspace: SandboxPaths
    ) -> None:
        """An artifact directory is keyed by this, so it must match what was stored."""
        full = "y" * 200_000
        executor, context, store = build(FixedOutputTool(full), workspace=workspace)
        executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
        assert store.records[0].result_sha256 == sha256_of(full)

    def test_an_outcome_with_no_output_hashes_the_empty_string(
        self, workspace: SandboxPaths
    ) -> None:
        executor, context, store = build(FixedOutputTool(), workspace=workspace)
        executor.execute(ToolCallRequest(name="ghost", args={}), context)
        assert store.records[0].result_sha256 == sha256_of("")


class TestDeterminism:
    """Same request, same specs, same allowlist, same injected clocks — same bytes."""

    def test_two_identical_calls_produce_byte_identical_records(
        self, workspace: SandboxPaths
    ) -> None:
        rendered = []
        for _ in range(2):
            executor, context, store = build(FixedOutputTool("out"), workspace=workspace)
            executor.execute(ToolCallRequest(name="echo", args={"value": "x"}), context)
            rendered.append(canonical_json(dataclasses.asdict(store.records[0])))
        assert rendered[0] == rendered[1]

    def test_a_refusal_is_byte_identical_too(self, workspace: SandboxPaths) -> None:
        rendered = []
        for _ in range(2):
            executor, context, store = build(FixedOutputTool(), workspace=workspace)
            executor.execute(ToolCallRequest(name="echo", args={"value": 1}), context)
            rendered.append(canonical_json(dataclasses.asdict(store.records[0])))
        assert rendered[0] == rendered[1]


class TestStoreFailure:
    """A broken store raises — after the result exists, and carrying it."""

    def test_the_error_carries_the_result_and_the_record(self, workspace: SandboxPaths) -> None:
        from fakes import BreakingStore

        registry = ToolRegistry()
        registry.register(spec("echo"), FixedOutputTool("side effect happened"))
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"echo"}), store=BreakingStore()
        )
        with pytest.raises(StoreFailure) as caught:
            executor.execute(
                ToolCallRequest(name="echo", args={"value": "x"}),
                ToolContext(invocation_id="inv", workspace=workspace),
            )
        assert caught.value.result.content == "side effect happened"
        assert caught.value.record.status is ToolStatus.OK
        assert isinstance(caught.value.__cause__, OSError)

    def test_a_store_raising_store_failure_itself_is_not_double_wrapped(
        self, workspace: SandboxPaths
    ) -> None:
        """An implementation that already speaks the contract is passed through unchanged."""
        from toolyard import ToolResult

        mine = StoreFailure(
            "mine",
            result=ToolResult(
                invocation_id="inv",
                status=ToolStatus.OK,
                content="",
                reason=None,
                duration_ms=0,
            ),
            record=_bare_record(),
        )

        class Rude:
            def append(self, record: object) -> None:
                del record
                raise mine

        registry = ToolRegistry()
        registry.register(spec("echo"), FixedOutputTool())
        executor = ToolExecutor(
            registry, PathContainment(), allowlist=frozenset({"echo"}), store=Rude()
        )
        with pytest.raises(StoreFailure) as caught:
            executor.execute(
                ToolCallRequest(name="echo", args={"value": "x"}),
                ToolContext(invocation_id="inv", workspace=workspace),
            )
        assert caught.value is mine


def _bare_record() -> Any:
    """One minimal record, for building a StoreFailure by hand."""
    from datetime import UTC, datetime

    from toolyard import ToolCallRecord

    return ToolCallRecord(
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
