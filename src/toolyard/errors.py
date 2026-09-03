"""Typed errors — raised for **caller bugs only**, never for anything a model influenced.

This module is the whole of ToolYard's raise surface, and its shortness is the point. ADR-0053
decision 4 splits the world in two:

* A **model** chose the tool name, the arguments, the output size and the runtime. Every failure
  reachable from those is a :class:`~toolyard.types.ToolResult` with a status and a machine-readable
  reason. None of them appears here, because an exception crossing an agent loop is a stop
  condition the model would then control.
* A **caller** wrote the registration, the spec and the store. Those failures are programming
  errors that a person should see at startup, loudly, where they can be fixed — so they raise.

The one place the line is subtle is :class:`StoreFailure`, which can fire *after* a side effect has
already happened. It carries the result and the record it could not write, so the application can
persist them by another route rather than losing an audited side effect; see its docstring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from baseaicore import SuiteError

if TYPE_CHECKING:
    from toolyard.types import ToolCallRecord, ToolResult

__all__ = [
    "DuplicateTool",
    "InvalidToolSpec",
    "StoreFailure",
    "ToolYardError",
]


class ToolYardError(SuiteError):
    """Base for every error this package raises.

    Every subclass is a **caller bug**. Nothing a model can influence reaches this hierarchy: see
    the module docstring and ADR-0053 decision 4.
    """

    code: ClassVar[str] = "TOOLYARD_ERROR"


class DuplicateTool(ToolYardError):
    """A second tool was registered under a name the registry already holds.

    Raised by :meth:`~toolyard.registry.ToolRegistry.register`. Registration happens once, at
    startup, in code (ADR-0053 decision 1), so a duplicate is a wiring mistake a person sees
    immediately — not a condition to resolve at runtime by picking one of the two.
    """

    code: ClassVar[str] = "TOOL_DUPLICATE"


class InvalidToolSpec(ToolYardError):
    """A :class:`~toolyard.types.ToolSpec` cannot be registered as written.

    Raised by :meth:`~toolyard.registry.ToolRegistry.register` for a malformed name, an argument
    schema that is not a valid draft 2020-12 schema, a schema that is not closed against extra
    properties, a schema using ``$ref``-family keywords, or a ``path_args`` declaration that does
    not match the schema. Each of those is a property the caller declared wrongly.

    It is emphatically **not** what a bad *model-supplied* name produces: a name the registry does
    not hold is ``unknown_tool``, a refusal. The distinction is the first place the raise/refuse
    boundary bites, and it runs in both directions — see :class:`~toolyard.types.ToolSpec`.
    """

    code: ClassVar[str] = "TOOL_SPEC_INVALID"


class StoreFailure(ToolYardError):
    """The :class:`~toolyard.store.ToolCallStore` refused or failed to append a record.

    This is a caller bug — a broken store — and it raises, which means it is the one exception that
    can leave :meth:`~toolyard.executor.ToolExecutor.execute` after a tool has already run. That is
    deliberate. "Every call is recorded" (spec §11.6) is a stronger promise than "execute never
    raises for a caller bug": returning the result while dropping the record would leave a
    trajectory holding a side effect that its audit trail does not contain, which is the exact
    failure this package exists to prevent.

    So the error carries what the caller needs to recover without re-running anything:

    Attributes:
        result: The fully-formed :class:`~toolyard.types.ToolResult` for the call, ready to hand
            back to the model.
        record: The :class:`~toolyard.types.ToolCallRecord` the store would not take, ready to
            persist by another route.

    ``details`` carries only the invocation id, the tool name and the status — never arguments and
    never content, because ``details`` travels into API error envelopes.
    """

    code: ClassVar[str] = "TOOL_STORE_FAILURE"

    def __init__(
        self,
        message: str,
        *,
        result: ToolResult,
        record: ToolCallRecord,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Build the error around the result and record that could not be persisted.

        Args:
            message: What failed and what the caller can do about it.
            result: The result the call produced, which the caller may still return to the model.
            record: The record the store rejected, which the caller may still persist elsewhere.
            details: Extra structured context. The invocation id, tool name and status are added
                here; a caller-supplied key of the same name wins, so pass none of them.
        """
        merged: dict[str, Any] = {
            "invocation_id": record.invocation_id,
            "tool_name": record.tool_name,
            "status": record.status.value,
        }
        if details is not None:
            merged.update(details)
        super().__init__(message, details=merged)
        self.result = result
        self.record = record
