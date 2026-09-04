"""The five built-in tools: the disciplined version of an operation the suite already regulates.

Each is a factory returning the ``(ToolSpec, ToolHandler)`` pair the registry takes, so
registration reads ``registry.register(*read_file_tool())`` and there is no implicit registration
anywhere — ADR-0053 decision 1 is that the registry is a reviewed list, and its shortness is a
feature.

None of them re-derives a control the package already owns. Path handling belongs to the executor,
which resolves every argument a spec declares in ``path_args`` and substitutes the resolved path
before the handler runs (spec §11.3), so **no handler here resolves a path**: a second resolution
would be a second containment, and the two would eventually disagree. Process launching belongs to
:mod:`toolyard.sandbox`, so ``run_command`` calls ``run_isolated`` and starts nothing itself —
``tests/unit/test_boundaries.py`` pins the package to exactly one ``Popen``. What is left in this
subpackage is each tool's own checks, and those are returned as
:class:`~toolyard.types.ToolRefusal` values rather than raised (ADR-0053 decision 4).
"""

from __future__ import annotations

from toolyard.tools.command import DEFAULT_COMMAND_ENV, MIN_PROCESS_COUNT, run_command_tool
from toolyard.tools.files import (
    DEFAULT_MAX_LIST_ENTRIES,
    DEFAULT_MAX_READ_BYTES,
    list_dir_tool,
    read_file_tool,
    write_file_tool,
)

__all__ = [
    "DEFAULT_COMMAND_ENV",
    "DEFAULT_MAX_LIST_ENTRIES",
    "DEFAULT_MAX_READ_BYTES",
    "MIN_PROCESS_COUNT",
    "list_dir_tool",
    "read_file_tool",
    "run_command_tool",
    "write_file_tool",
]
