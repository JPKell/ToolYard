"""Properties of ``execute()`` over generated hostile calls — Phase 1's acceptance criterion 1.

The criterion says "no exception escapes ``execute()`` under a fuzzing test that mutates names, args
and outputs". That is trivially satisfiable by a generator producing sensible names and well-typed
arguments, and worth nothing when it is. What makes it worth something is the corpus:
``tests/strategies.py``'s module docstring lists every family and why it is there.

Replaying a failure: hypothesis prints a ``@reproduce_failure(...)`` decorator with the failing
example encoded in it — paste it onto the test and run. ``pytest-randomly`` reorders the suite on
every run, and a failure that only reproduces under one seed is a real ordering bug, not a reason
to pin the seed.
"""

from __future__ import annotations

import dataclasses
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from baseaicore import canonical_json
from hypothesis import given, settings

from oracles import expected_reason
from strategies import SECRET_ARGUMENT, workspace_at, worlds
from toolyard import (
    DEFAULT_MAX_CONTENT_BYTES,
    REFUSAL_REASONS,
    PathAccess,
    ToolResult,
    ToolStatus,
)
from toolyard._safe import TRUNCATION_LABEL_TEMPLATE

if TYPE_CHECKING:
    from strategies import World

TRUNCATION_MARKER = TRUNCATION_LABEL_TEMPLATE.split("{")[0].strip()

WORKSPACE = workspace_at(Path(tempfile.mkdtemp(prefix="toolyard-property-")))
"""One real workspace for the module.

Built at import rather than through a fixture because ``@given``'s strategy is constructed when the
decorator runs, and a function-scoped fixture inside it would be redrawn per example — which
hypothesis rightly calls a health-check failure.
"""

CALLS = settings(max_examples=300, deadline=None)


def _run(world: World) -> ToolResult:
    """Execute a generated world. Nothing is caught here: that is the whole first property."""
    return world.executor.execute(world.request, world.context)


@CALLS
@given(world=worlds(WORKSPACE))
def test_execute_returns_a_result_for_every_generated_input(world: World) -> None:
    """Acceptance criterion 1, including the record-building and truncation paths.

    Would catch: a ``canonical_json`` refusal on ``NaN`` or ``bytes`` in the arguments; a
    ``UnicodeEncodeError`` hashing a handler's lone surrogate; a ``RecursionError`` inside the
    validator on a deeply nested argument; a ``TypeError`` from ``dict.get`` on an unhashable name;
    an ``OSError`` from resolving an impossible path; a truncation that splits a character.
    """
    result = _run(world)
    assert isinstance(result, ToolResult)
    assert result.invocation_id == world.context.invocation_id


@CALLS
@given(world=worlds(WORKSPACE))
def test_every_non_ok_result_carries_a_reason_from_the_closed_set(world: World) -> None:
    """PromptCadence maps a reason onto a deviation category, so an unrecognized one is a bug.

    Would catch: a reason built by formatting an exception class or a validator message into the
    field; a refusal that forgot its reason entirely; an ``OK`` result carrying one.
    """
    result = _run(world)
    assert isinstance(result.status, ToolStatus)
    if result.status is ToolStatus.OK:
        assert result.reason is None
    else:
        assert result.reason
        assert result.reason in REFUSAL_REASONS


@CALLS
@given(world=worlds(WORKSPACE))
def test_exactly_one_record_is_appended_per_call(world: World) -> None:
    """Spec §11.6, for every outcome.

    Would catch: a refusal path that returns before recording; a success path that records twice;
    a handler failure recorded by both the ``except`` branch and the ordinary one.
    """
    _run(world)
    assert len(world.store.records) == 1
    assert world.store.records[0].status is not None


@CALLS
@given(world=worlds(WORKSPACE))
def test_the_earliest_failing_check_is_the_one_reported(world: World) -> None:
    """Spec §11.2 as a property over combinations, not as five hand-written cases.

    The expectation comes from :mod:`oracles`, which restates the ladder from the spec's wording
    over labels the generator attached when it built the world — never from anything the package
    computed. Would catch: any reordering of the checks; a check that short-circuits another; a
    containment check that runs before the schema check and so resolves an unvalidated argument.
    """
    result = _run(world)
    expected = expected_reason(world)
    if expected is None:
        assert result.status is not ToolStatus.REFUSED, (
            f"every check passed, so this should have reached the handler: {result.reason}"
        )
    else:
        assert result.reason == expected
        assert result.status is ToolStatus.REFUSED
    assert world.store.records[0].reason == result.reason


@CALLS
@given(world=worlds(WORKSPACE))
def test_no_unvalidated_argument_ever_reaches_a_handler(world: World) -> None:
    """The development plan's ordering rule, stated as a property about the handler.

    Would catch: a handler invoked on the refusal path; validation moved after dispatch; a
    containment failure that logs and continues.
    """
    _run(world)
    if world.handler.seen:
        assert expected_reason(world) is None


@CALLS
@given(world=worlds(WORKSPACE))
def test_a_path_a_handler_received_is_resolved_and_inside_a_root(world: World) -> None:
    """Containment is resolution-then-check, and the handler operates on the resolved path.

    Would catch: the executor passing the candidate through unchanged (so the handler would have to
    re-resolve, reopening the window); a resolution that returns a relative path; a check that
    compares by string prefix, which would admit the ``work-decoy`` sibling the workspace holds.
    """
    _run(world)
    if not world.handler.seen or "path" not in world.spec.path_args:
        return
    seen = world.handler.seen[0]
    if "path" not in seen:
        return
    resolved = Path(seen["path"])
    assert resolved.is_absolute()
    roots = (
        (world.workspace.write_root,)
        if world.spec.path_args["path"] is PathAccess.WRITE
        else (world.workspace.write_root, *world.workspace.read_roots)
    )
    assert any(resolved == root.resolve() or root.resolve() in resolved.parents for root in roots)


@CALLS
@given(world=worlds(WORKSPACE))
def test_a_redacted_calls_plaintext_appears_in_no_field_at_any_length(world: World) -> None:
    """``redact_args`` means redacted, not "shortened".

    Would catch: a truncated ``args_json`` slipping past the redaction branch; a refusal path that
    builds its record without consulting the spec; the plaintext arriving through
    ``result_summary`` because a handler echoed it — which is why the generated
    ``mutates_args`` handler writes the same secret into the arguments it was handed.
    """
    _run(world)
    resolved_to_the_redacted_tool = (
        world.request.name == world.spec.name and world.name_is_registered and world.redacted
    )
    if not resolved_to_the_redacted_tool:
        return
    record = world.store.records[0]
    assert record.args_json is None
    rendered = canonical_json(
        {key: str(value) for key, value in dataclasses.asdict(record).items()}
    )
    for length in (6, 12, 24, len(SECRET_ARGUMENT)):
        assert SECRET_ARGUMENT[:length] not in rendered


@CALLS
@given(world=worlds(WORKSPACE))
def test_a_refusal_never_names_a_containment_root_or_the_allowlist(world: World) -> None:
    """ADR-0053's last consequence: refusal text is part of the prompt surface.

    Would catch exactly the thing a helpful error message reintroduces — "expected a path under
    /srv/trajectory-4172/work", or "callable tools are: read_file, write_file, run_command". Both
    are facts about the caller's deployment, handed to a reader whose input is assumed adversarial.
    """
    result = _run(world)
    if result.status is ToolStatus.OK:
        return
    for root in (world.workspace.write_root, *world.workspace.read_roots):
        assert str(root) not in result.content
        assert str(root) not in (result.reason_detail or "")
    # A refusal echoes the name the model itself supplied, which is its own string and may well
    # *contain* a registered name — "registered_tool " differs from "registered_tool" by a space.
    # The property is that the executor volunteers no name the model did not already have.
    echoed = world.store.records[0].tool_name
    volunteered = result.content.replace(echoed, "") if echoed else result.content
    for name in world.allowlist:
        assert name not in volunteered


@CALLS
@given(world=worlds(WORKSPACE))
def test_content_is_capped_and_labelled_when_truncated(world: World) -> None:
    """A model that assumes a result ended rather than stopped will answer from half a file.

    Would catch: a cap applied to characters rather than bytes; a label appended *after* the cap so
    the result overflows it; a truncation that splits a UTF-8 character; a label attached to output
    that was not truncated.
    """
    result = _run(world)
    encoded = result.content.encode("utf-8")
    assert len(encoded) <= DEFAULT_MAX_CONTENT_BYTES
    assert result.content == encoded.decode("utf-8")
    record = world.store.records[0]
    assert len(record.result_summary.encode("utf-8")) <= DEFAULT_MAX_CONTENT_BYTES
    if TRUNCATION_MARKER in result.content:
        assert result.status is ToolStatus.OK


@CALLS
@given(world=worlds(WORKSPACE))
def test_a_records_argument_digest_always_exists(world: World) -> None:
    """Even for arguments that cannot be serialized as they stand.

    Would catch: a digest computed with ``sha256_of`` directly, which refuses ``NaN``, ``bytes``,
    ``set`` and cycles — all of which the corpus sends, and the first of which ``json.loads``
    produces by default.
    """
    _run(world)
    digest = world.store.records[0].args_sha256
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)


@settings(max_examples=150, deadline=None)
@given(world=worlds(WORKSPACE))
def test_records_are_byte_identical_across_two_identically_configured_executors(
    world: World,
) -> None:
    """Determinism is a claim about the inputs, so it is proved with two executors, not two runs.

    Would catch: any figure derived from the wall clock rather than the injected one; iteration
    order of a set reaching a digest or a summary; a hash taken over a ``repr`` that embeds an
    object address.
    """
    first = _run(world)
    twin = world.twin()
    second = twin.executor.execute(twin.request, twin.context)
    assert canonical_json(dataclasses.asdict(first)) == canonical_json(dataclasses.asdict(second))
    assert canonical_json(dataclasses.asdict(world.store.records[0])) == canonical_json(
        dataclasses.asdict(twin.store.records[0])
    )
