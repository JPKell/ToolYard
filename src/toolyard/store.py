"""The record store: a protocol the application implements, and one in-memory stand-in for tests.

ToolYard owns no data (spec §10). It defines the shape of a record and the one method needed to
append one; the application owns the table, the retention and the migration. PromptCadence's own
schema is where these rows actually live.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from toolyard.types import ToolCallRecord

__all__ = ["InMemoryToolCallStore", "ToolCallStore"]


class ToolCallStore(Protocol):
    """Where records go. One method, because one method is all ToolYard needs.

    An implementation that raises makes the executor raise
    :class:`~toolyard.errors.StoreFailure` — after the call has already run. Read that error's
    docstring before writing a store: it carries the result and the record precisely so a broken
    store does not cost the application an audited side effect.
    """

    def append(self, record: ToolCallRecord) -> None:
        """Persist one record.

        Args:
            record: The record for one call, whatever its outcome.
        """
        ...


class InMemoryToolCallStore:
    """A list. **For tests only** — nothing here survives the process.

    Said plainly because the alternative is an application shipping with this as its store and
    discovering at the first restart that its tool-call audit trail was a variable. PromptCadence
    owns the real table (spec §10); this exists so the executor's tests can assert on records
    without a database.
    """

    __slots__ = ("_records",)

    def __init__(self) -> None:
        """Create an empty store."""
        self._records: list[ToolCallRecord] = []

    def append(self, record: ToolCallRecord) -> None:
        """Append one record to the list.

        Args:
            record: The record for one call.
        """
        self._records.append(record)

    @property
    def records(self) -> Sequence[ToolCallRecord]:
        """Return every record appended so far, in order.

        Returns:
            A tuple snapshot, so a caller iterating it cannot be surprised by a later append.
        """
        return tuple(self._records)
