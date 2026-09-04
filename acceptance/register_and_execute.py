#!/usr/bin/env python3
"""Spec §20 criterion 2: register a custom tool and execute it, on `toolyard` + `baseaicore` alone.

Run it in a throwaway virtualenv holding nothing but this package and its declared dependencies::

    python -m venv /tmp/toolyard-acceptance
    /tmp/toolyard-acceptance/bin/pip install .
    /tmp/toolyard-acceptance/bin/python acceptance/register_and_execute.py

It exits ``0`` when every claim below holds and non-zero with a message when one does not, so it is
a check rather than a demonstration — M10's exit condition is *"clean-venv acceptance scripts
pass"*, and a script that only printed things would pass while being wrong. Nothing here imports
pytest, this repository's test helpers, or any sibling package: the point is that an application
with `toolyard` installed and nothing else can do this.

It also stands as the quickstart. The shape is register → execute → record, and the one thing a new
caller gets wrong is in it twice: **a refusal is a result, not an exception.**
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from toolyard import (
    EgressClass,
    InMemoryToolCallStore,
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
    read_file_tool,
)

WORD_COUNT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "description": "The file to count words in."}
    },
    "required": ["path"],
    "additionalProperties": False,
}


class WordCount:
    """A custom tool an application might register: counts the words in a workspace file."""

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """Count the words, or say why not.

        ``args`` is a ``Mapping`` and not a ``dict``: the protocol says so, and a handler that
        narrowed it would not satisfy the protocol at all — mypy says so before the registry does.

        ``args["path"]`` is already **resolved** — the executor resolved it against the roots on
        this context and substituted the result, because the spec declares it in ``path_args``.
        A handler that resolved it again would be a second containment.

        Args:
            args: The validated arguments.
            context: The invocation. Unused here beyond documenting that it exists.

        Returns:
            The count, or a refusal when the file is not there.
        """
        del context
        target = Path(args["path"])
        if not target.is_file():
            return ToolRefusal(Reason.FILE_NOT_FOUND, "no such file", status=ToolStatus.FAILED)
        return ToolOutput(content=str(len(target.read_text(encoding="utf-8").split())))


def _check(claim: str, condition: bool) -> None:  # noqa: FBT001 — a check takes the answer
    """Print the claim and stop the script if it does not hold."""
    print(f"{'ok  ' if condition else 'FAIL'}  {claim}")
    if not condition:
        sys.exit(f"acceptance failed: {claim}")


def main() -> None:
    """Register two tools, execute four calls, and check the record afterwards."""
    with tempfile.TemporaryDirectory(prefix="toolyard-acceptance-") as temporary:
        workspace = Path(temporary) / "workspace"
        workspace.mkdir()
        (workspace / "notes.md").write_text("one two three four five\n", encoding="utf-8")

        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="word_count",
                description="Count the words in a file in the workspace.",
                args_schema=WORD_COUNT_SCHEMA,
                result_schema=None,
                risk_class=RiskClass.READ_ONLY,
                egress=EgressClass.NONE,
                path_args={"path": PathAccess.READ},
            ),
            WordCount(),
        )
        registry.register(*read_file_tool())

        store = InMemoryToolCallStore()
        executor = ToolExecutor(
            registry,
            PathContainment(),
            allowlist=frozenset({"word_count", "read_file"}),
            store=store,
        )
        context = ToolContext(
            invocation_id="acceptance-1", workspace=SandboxPaths(write_root=workspace)
        )

        counted = executor.execute(
            ToolCallRequest(name="word_count", args={"path": "notes.md"}), context
        )
        _check("a registered custom tool executes", counted.status is ToolStatus.OK)
        _check("and returns its own output", counted.content == "5")

        built_in = executor.execute(
            ToolCallRequest(name="read_file", args={"path": "notes.md"}), context
        )
        _check("a built-in tool executes beside it", built_in.status is ToolStatus.OK)

        escaped = executor.execute(
            ToolCallRequest(name="word_count", args={"path": "/etc/passwd"}), context
        )
        _check("a path escape is a result, not an exception", escaped.status is ToolStatus.REFUSED)
        _check("and it names the check that refused", escaped.reason == Reason.PATH_ESCAPE.value)
        _check(
            "and it does not name the workspace root to the model",
            str(workspace) not in escaped.content,
        )

        unknown = executor.execute(ToolCallRequest(name="rm_rf", args={"path": "/"}), context)
        _check("an unregistered tool is refused, not raised", unknown.status is ToolStatus.REFUSED)
        _check("and it says so", unknown.reason == Reason.UNKNOWN_TOOL.value)

        missing = executor.execute(
            ToolCallRequest(name="word_count", args={"path": "absent.md"}), context
        )
        _check(
            "a handler's own refusal keeps its reason",
            missing.status is ToolStatus.FAILED and missing.reason == Reason.FILE_NOT_FOUND.value,
        )

        _check("every call was recorded, refused ones included", len(store.records) == 5)
        _check(
            "and each record carries the reason its result did",
            [record.reason for record in store.records]
            == [
                None,
                None,
                Reason.PATH_ESCAPE.value,
                Reason.UNKNOWN_TOOL.value,
                Reason.FILE_NOT_FOUND.value,
            ],
        )

    print("\nAll acceptance checks passed.")


if __name__ == "__main__":
    main()
