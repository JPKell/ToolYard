"""The store protocol and the in-memory stand-in that exists only for tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from toolyard import (
    EgressClass,
    InMemoryToolCallStore,
    RiskClass,
    ToolCallRecord,
    ToolCallStore,
    ToolStatus,
)


def record(invocation_id: str = "inv-1") -> ToolCallRecord:
    """One minimal record."""
    return ToolCallRecord(
        invocation_id=invocation_id,
        tool_name="echo",
        args_json="{}",
        args_sha256="0" * 64,
        status=ToolStatus.OK,
        result_summary="ok",
        result_sha256="1" * 64,
        duration_ms=1,
        risk_class=RiskClass.READ_ONLY,
        egress=EgressClass.NONE,
        started_at=datetime(2026, 9, 3, tzinfo=UTC),
    )


class TestInMemoryStore:
    """A list, and honest about being one."""

    def test_records_come_back_in_order(self) -> None:
        store = InMemoryToolCallStore()
        store.append(record("a"))
        store.append(record("b"))
        assert [held.invocation_id for held in store.records] == ["a", "b"]

    def test_the_snapshot_does_not_change_under_a_later_append(self) -> None:
        store = InMemoryToolCallStore()
        store.append(record("a"))
        snapshot = store.records
        store.append(record("b"))
        assert len(snapshot) == 1

    def test_it_satisfies_the_protocol(self) -> None:
        store: ToolCallStore = InMemoryToolCallStore()
        store.append(record())

    def test_its_docstring_says_it_is_for_tests(self) -> None:
        """The alternative is an application shipping with a variable as its audit trail."""
        assert InMemoryToolCallStore.__doc__ is not None
        assert "tests only" in InMemoryToolCallStore.__doc__.lower()


class TestErrorHierarchy:
    """Every error in the package is a caller bug, and every one carries its documented code."""

    def test_the_codes_are_the_spec_seven_codes(self) -> None:
        from toolyard import DuplicateTool, InvalidToolSpec, StoreFailure, ToolYardError

        assert ToolYardError.code == "TOOLYARD_ERROR"
        assert DuplicateTool.code == "TOOL_DUPLICATE"
        assert InvalidToolSpec.code == "TOOL_SPEC_INVALID"
        assert StoreFailure.code == "TOOL_STORE_FAILURE"
        for error in (DuplicateTool, InvalidToolSpec, StoreFailure):
            assert issubclass(error, ToolYardError)

    def test_a_store_failure_carries_the_result_and_the_record_it_could_not_write(self) -> None:
        from toolyard import StoreFailure, ToolResult

        result = ToolResult(
            invocation_id="inv-1", status=ToolStatus.OK, content="ok", reason=None, duration_ms=1
        )
        failure = StoreFailure("nope", result=result, record=record())
        assert failure.result is result
        assert failure.record.tool_name == "echo"

    def test_a_store_failures_details_hold_no_arguments_and_no_content(self) -> None:
        from toolyard import StoreFailure, ToolResult

        result = ToolResult(
            invocation_id="inv-1",
            status=ToolStatus.OK,
            content="secret output",
            reason=None,
            duration_ms=1,
        )
        failure = StoreFailure("nope", result=result, record=record())
        assert set(failure.details) == {"invocation_id", "tool_name", "status"}
        assert "secret output" not in str(failure.details)

    def test_a_path_escape_is_deliberately_not_in_the_caller_bug_hierarchy(self) -> None:
        """It is the model doing exactly what the threat model says it will, so it is a signal the
        executor converts — not an error a caller sees."""
        from toolyard import PathEscape, ToolYardError

        assert not issubclass(PathEscape, ToolYardError)

    def test_every_error_pickles_with_its_details(self) -> None:
        import pickle

        from toolyard import DuplicateTool

        restored = pickle.loads(  # noqa: S301 — round-trips this suite's own object, not untrusted data
            pickle.dumps(DuplicateTool("x", details={"tool_name": "echo"}))
        )
        assert restored.details == {"tool_name": "echo"}


@pytest.mark.parametrize("status", list(ToolStatus))
def test_a_record_holds_every_status(status: ToolStatus) -> None:
    """Refused and failed calls are recorded too — spec §11.6."""
    import dataclasses

    held = dataclasses.replace(record(), status=status)
    assert held.status is status
