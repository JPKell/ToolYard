"""The five built-ins' wire definitions, golden-locked.

A wire definition is what a model actually sees — the name, the description and the argument
schema — and spec §19 makes its stability a per-release golden test. It is asserted as a whole
document rather than by substring, because a substring assertion passes while the sentence around
it changes, and the sentence is the part a model reads. The digests are the same ones PromptCadence
hashes into its turn records (spec §11.7), so a change here is a change to every recorded turn.

Changing a description is a real change with a real cost, and it is meant to feel like one: a model
that was tuned against "there is no shell" and now reads something else will call the tool
differently. Regenerate this file deliberately, and say so in the changelog.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from baseaicore import sha256_of

from toolyard import (
    TieredSandbox,
    http_fetch_tool,
    list_dir_tool,
    read_file_tool,
    run_command_tool,
    write_file_tool,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from toolyard import ToolSpec

GOLDEN: Final[Path] = (
    Path(__file__).resolve().parents[1] / "goldens" / "builtin_wire_definitions.json"
)


def _no_resolution(_host: str) -> Sequence[str]:
    """A resolver for building the declaration; the definition does not depend on it."""
    return ()


def _built_in_specs() -> list[ToolSpec]:
    """Every shipped tool's declaration, built with its documented defaults."""
    return [
        read_file_tool()[0],
        write_file_tool()[0],
        list_dir_tool()[0],
        run_command_tool(TieredSandbox())[0],
        http_fetch_tool(("127.0.0.1",), resolve=_no_resolution)[0],
    ]


def _document() -> Mapping[str, Any]:
    """Render the goldens the way the file holds them."""
    return {
        built.name: {
            "definition": built.wire_definition(),
            "sha256": sha256_of(built.wire_definition()),
        }
        for built in _built_in_specs()
    }


@pytest.mark.contract
def test_the_committed_built_in_definitions_still_match() -> None:
    """The whole document, not a substring of it."""
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert _document() == expected, (
        "A built-in's wire definition changed. This is what the model reads and what "
        "PromptCadence hashes into its turn records, so regenerate the golden deliberately and "
        "note it in the changelog — never to make a test pass."
    )


def test_the_five_built_ins_are_the_five_the_spec_names() -> None:
    """A sixth tool is a spec §7 amendment, not an addition someone made on the way past."""
    assert sorted(_document()) == [
        "http_fetch",
        "list_dir",
        "read_file",
        "run_command",
        "write_file",
    ]


def test_a_wire_definition_carries_no_field_a_provider_would_have_to_interpret() -> None:
    """Provider-neutral (spec §11.7): a name, a description and a schema, and nothing else."""
    for entry in _document().values():
        assert set(entry["definition"]) == {"name", "description", "parameters"}


def test_no_definition_leaks_a_path_from_this_machine() -> None:
    """Descriptions are written once and read by every turn; a tmp path in one would be a bug."""
    rendered = json.dumps(_document())
    for machine_path in ("/tmp", "/home", str(Path.home())):  # noqa: S108 — the point is absence
        assert machine_path not in rendered
