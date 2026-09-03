"""Generators for hostile calls — designed before the properties, and labelled by construction.

Two rules shape every strategy here, both learned the expensive way in a sibling repository.

**Build valid shapes, do not filter invalid ones.** Heavy ``filter`` gives flaky
``filter_too_much`` health-check failures and shrinks to nothing useful. Every world below is
assembled from parts that are already what they need to be.

**A generator that labels its own answer beats an oracle that re-derives it.** A path candidate is
drawn together with whether it escapes; a tool name is drawn together with whether it is registered.
That is not laziness — an oracle that re-implements ``Path.resolve`` and containment would agree
with a *bug* in the implementation, because both would be reasoning the same way about the same
thing. The label comes from how the value was built.

What the corpus reaches, deliberately:

* **names** — empty, 10 000 characters, unicode, control characters, NUL, path separators, ``..``,
  differing from a registered name only by case or by a trailing space, matching the spec pattern
  but unregistered, registered but outside the allowlist, registered and allowlisted but outside
  the turn's intent, and values that are not strings at all;
* **arguments** — valid, wrongly typed, extra-propertied, missing a required property, ``null``
  where an object is required, nested past the depth cap, wider than the node cap, holding
  ``NaN``/``Infinity``, holding ``bytes``, holding a cycle, holding a value that is itself a valid
  JSON Schema document, and not being a mapping at all;
* **handlers** — returning oversize content, content that cannot encode as UTF-8, the wrong type,
  ``None``, an object whose ``__str__`` raises; raising arbitrary ``Exception`` classes; mutating
  the mapping they were handed; and running past their limit;
* **worlds** — every combination of registered / allowlisted / approved / egress ceiling / isolation
  tier, so the refusal ladder is exercised as an order rather than as five separate checks.

``BaseException`` handlers are deliberately **absent** from the generated corpus, because the
executor is documented to re-raise those after recording (see ``toolyard.executor``'s module
docstring). They are covered by named tests in ``tests/unit/test_executor.py`` instead, where the
assertion is that the exception *does* escape and the record exists anyway — a property saying
"nothing escapes" would have quietly contradicted that decision.
"""

from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from hypothesis import strategies as st

from fakes import FrozenClock, SteppingMonotonic
from toolyard import (
    EgressClass,
    InMemoryToolCallStore,
    IsolationTier,
    PathAccess,
    PathContainment,
    RiskClass,
    SandboxPaths,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
    ToolSpec,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

SIMPLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"value": {"type": "string"}},
    "required": ["value"],
    "additionalProperties": False,
}

PATH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}

WIDE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"value": {"type": "string"}, "count": {"type": "integer"}},
    "required": ["value"],
    "additionalProperties": False,
}

SCHEMAS: dict[str, dict[str, Any]] = {
    "simple": SIMPLE_SCHEMA,
    "pathy": PATH_SCHEMA,
    "wide": WIDE_SCHEMA,
}

REGISTERED = "registered_tool"
"""Registered, allowlisted and approved: the name that gets as far as the handler."""

ALLOWLISTED_ONLY = "allowlisted_only"
"""Registered and allowlisted, never approved: reaches ``not_approved``."""

REGISTERED_ONLY = "registered_only"
"""Registered and never allowlisted: reaches ``not_allowlisted``."""

REGISTERED_NAMES = (REGISTERED, ALLOWLISTED_ONLY, REGISTERED_ONLY)

FIXED_MOMENT = datetime(2026, 9, 3, 4, 5, 6, 250_000, tzinfo=UTC)
"""One instant for every generated world, so records are byte-comparable between twins."""

SECRET_ARGUMENT = "zq7vk-plaintext-that-must-never-be-recorded"  # noqa: S105 — a marker, not a credential
"""A distinctive value the redaction property looks for in every field at every prefix.

Deliberately not a word: an earlier marker began "argument", and the executor's own refusal
sentence contains "the path argument", so the six-character prefix matched honest text.
"""


class _RaisesOnStr:
    """An object whose ``__str__`` raises, because a handler may return one."""

    def __str__(self) -> str:
        """Raise, deliberately."""
        raise RuntimeError("unrenderable")


@dataclass
class GeneratedHandler:
    """A handler assembled from a drawn behaviour, with the behaviour kept for the assertions."""

    behaviour: str
    payload: Any = None
    seen: list[Mapping[str, Any]] = field(default_factory=list)

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
        """Do whatever the drawn behaviour says."""
        del context
        self.seen.append(dict(args) if isinstance(args, dict) else {})
        if self.behaviour == "ok":
            return ToolOutput(content="ok")
        if self.behaviour == "oversize":
            return ToolOutput(content="z" * 200_000)
        if self.behaviour == "unencodable":
            return ToolOutput(content="before\ud800after\x00tail")
        if self.behaviour == "wrong_type":
            # Deliberately returns something that is not a ToolOutput. The executor answers with
            # `handler_error`; a `cast` here rather than an ignore, because mypy is right.
            return cast("ToolOutput", self.payload)
        if self.behaviour == "mutates_args" and isinstance(args, dict):
            args["injected_by_handler"] = SECRET_ARGUMENT
            return ToolOutput(content="mutated")
        if self.behaviour == "raises":
            raise self.payload
        if self.behaviour == "slow":
            return ToolOutput(content="slow")
        return ToolOutput(content="ok")


@dataclass
class World:
    """One fully-assembled call: the executor, the request, the context, and the labels.

    The labels are what the properties assert against. They come from how the world was built, not
    from asking the implementation what it thinks.
    """

    executor: ToolExecutor
    request: ToolCallRequest
    context: ToolContext
    store: InMemoryToolCallStore
    handler: GeneratedHandler
    spec: ToolSpec
    workspace: SandboxPaths
    registry: ToolRegistry
    sandbox: Any
    allowlist: frozenset[str]
    step_ns: int
    name_is_registered: bool
    name_is_allowlisted: bool
    name_is_approved: bool
    args_are_valid: bool
    egress_permitted: bool
    tier_available: bool
    path_escapes: bool
    redacted: bool

    def twin(self) -> World:
        """Return the same call over a second, identically configured executor.

        Determinism is a claim about the *inputs*, so proving it needs two executors that were
        given the same ones — not the same executor run twice, whose monotonic source has moved.
        """
        store = InMemoryToolCallStore()
        return dataclasses.replace(
            self,
            store=store,
            executor=ToolExecutor(
                self.registry,
                self.sandbox,
                allowlist=self.allowlist,
                store=store,
                monotonic_ns=SteppingMonotonic(step_ns=self.step_ns),
            ),
        )


def _hostile_names() -> st.SearchStrategy[object]:
    """Names a hostile model would send, none of which can be in a registry."""
    return st.one_of(
        st.just(""),
        st.just(" "),
        st.just("A" * 10_000),
        st.just("Registered_Tool"),
        st.just(REGISTERED.upper()),
        st.just(REGISTERED + " "),
        st.just(" " + REGISTERED),
        st.just(REGISTERED + "\x00"),
        st.just(REGISTERED[:-1]),
        st.just(REGISTERED + "x"),
        st.just("../../etc/passwd"),
        st.just(".."),
        st.just("../" + REGISTERED),
        st.just("tool\nname"),
        st.just("tool\tname"),
        st.just("tóol_nàme"),
        st.just("🙂_tool"),
        st.just("unregistered_but_valid"),
        st.none(),
        st.integers(),
        st.lists(st.just("x"), max_size=2),
        st.text(max_size=40),
    )


def _valid_args(schema_name: str) -> st.SearchStrategy[dict[str, Any]]:
    """Arguments built to satisfy one of the three schemas, by construction."""
    if schema_name == "pathy":
        return st.fixed_dictionaries({"path": st.just("notes.md")})
    if schema_name == "wide":
        return st.one_of(
            st.fixed_dictionaries({"value": st.text(max_size=20)}),
            st.fixed_dictionaries({"value": st.text(max_size=20), "count": st.integers(-5, 5)}),
        )
    return st.fixed_dictionaries({"value": st.text(max_size=20)})


def _deep(levels: int) -> dict[str, Any]:
    """A structure nested past the validator's depth cap."""
    nested: Any = "leaf"
    for _ in range(levels):
        nested = {"n": nested}
    return {"value": nested}


def _cyclic() -> dict[str, Any]:
    """A structure that refers to itself."""
    cyclic: dict[str, Any] = {"value": "x"}
    cyclic["self"] = cyclic
    return cyclic


def _invalid_args() -> st.SearchStrategy[object]:
    """Arguments that no schema in the family accepts, in every shape that has bitten before."""
    return st.one_of(
        st.just({}),
        st.just({"value": 17}),
        st.just({"value": None}),
        st.just({"value": "x", "smuggled": "y"}),
        st.just({"value": {"nested": "object"}}),
        st.just({"value": math.nan}),
        st.just({"value": math.inf}),
        st.just({"value": -math.inf}),
        st.just({"value": b"raw bytes"}),
        st.just({"value": {1, 2, 3}}),
        st.just({"value": SIMPLE_SCHEMA}),
        st.just({"value": [SIMPLE_SCHEMA, PATH_SCHEMA]}),
        st.just({17: "non-string key"}),
        st.just({"value": list(range(30_000))}),
        st.builds(_deep, st.just(40)),
        st.builds(_cyclic),
        st.none(),
        st.just("not a mapping"),
        st.just([1, 2, 3]),
        st.integers(),
    )


def _path_candidates(workspace: SandboxPaths) -> st.SearchStrategy[tuple[str, bool]]:
    """``(candidate, escapes)`` pairs, labelled by how they were built, never re-derived."""
    inside = [
        "notes.md",
        "sub/notes.md",
        "sub/../notes.md",
        "./notes.md",
        str(workspace.write_root / "notes.md"),
        str(workspace.write_root),
    ]
    outside = [
        "../escape.md",
        "../../etc/passwd",
        "/etc/passwd",
        str(workspace.write_root.parent / "sibling.md"),
        str(workspace.write_root) + "-decoy/notes.md",
        "",
        "   ",
        "a" * 9_000,
        "notes\x00.md",
        "notes\ud800.md",
    ]
    return st.one_of(
        st.sampled_from([(candidate, False) for candidate in inside]),
        st.sampled_from([(candidate, True) for candidate in outside]),
    )


def _handlers() -> st.SearchStrategy[GeneratedHandler]:
    """Every way a handler can misbehave, short of the interpreter-level exceptions."""
    raising = st.sampled_from(
        [
            ValueError("boom"),
            KeyError("/absolute/secret/path"),
            RuntimeError("x" * 5_000),
            OSError(13, "permission denied"),
            MemoryError(),
            RecursionError(),
            Exception(),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
        ]
    )
    return st.one_of(
        st.builds(GeneratedHandler, st.just("ok")),
        st.builds(GeneratedHandler, st.just("oversize")),
        st.builds(GeneratedHandler, st.just("unencodable")),
        st.builds(
            GeneratedHandler,
            st.just("wrong_type"),
            st.sampled_from([None, "plain text", 17, [1, 2], {"a": 1}, _RaisesOnStr()]),
        ),
        st.builds(GeneratedHandler, st.just("mutates_args")),
        st.builds(GeneratedHandler, st.just("raises"), raising),
        st.builds(GeneratedHandler, st.just("slow")),
    )


@st.composite
def worlds(draw: st.DrawFn, workspace: SandboxPaths) -> World:
    """Assemble one fully-specified call, with every fact about it labelled.

    The combination axes — registered, allowlisted, approved, argument validity, egress ceiling,
    isolation tier, path escape, redaction — are drawn independently, so a single example can fail
    several checks at once. That is what makes the "earliest failure wins" property a property over
    combinations rather than a restatement of the hand-written ladder.
    """
    schema_name = draw(st.sampled_from(sorted(SCHEMAS)))
    requires_isolation = draw(st.booleans())
    egress = draw(st.sampled_from(list(EgressClass)))
    redacted = draw(st.booleans())
    path_args = {"path": draw(st.sampled_from(list(PathAccess)))} if schema_name == "pathy" else {}
    spec = ToolSpec(
        name=REGISTERED,
        description="A generated fake.",
        args_schema=dict(SCHEMAS[schema_name]),
        result_schema=None,
        risk_class=draw(st.sampled_from(list(RiskClass))),
        egress=egress,
        redact_args=redacted,
        path_args=path_args,
        requires_isolation=requires_isolation,
    )
    handler = draw(_handlers())

    registry = ToolRegistry()
    name_is_registered = draw(st.booleans())
    if name_is_registered:
        registry.register(spec, handler)
    for other in (ALLOWLISTED_ONLY, REGISTERED_ONLY):
        registry.register(
            ToolSpec(
                name=other,
                description="Another generated fake.",
                args_schema=dict(SIMPLE_SCHEMA),
                result_schema=None,
                risk_class=RiskClass.READ_ONLY,
                egress=EgressClass.NONE,
            ),
            GeneratedHandler("ok"),
        )

    allowlist = {ALLOWLISTED_ONLY} | ({REGISTERED} if draw(st.booleans()) else set())
    approved: frozenset[str] | None = draw(
        st.one_of(
            st.none(),
            st.sampled_from(
                [
                    frozenset(),
                    frozenset({REGISTERED}),
                    frozenset({ALLOWLISTED_ONLY}),
                    frozenset({REGISTERED, ALLOWLISTED_ONLY, REGISTERED_ONLY}),
                ]
            ),
        )
    )

    tier_available = draw(st.booleans())
    from fakes import TieredSandbox

    sandbox = TieredSandbox(IsolationTier.BWRAP) if tier_available else PathContainment()
    ceiling = draw(st.sampled_from(list(EgressClass)))
    step_ns = draw(st.sampled_from([1_000, 1_000_000, 5_000_000_000]))
    store = InMemoryToolCallStore()
    frozen_allowlist = frozenset(allowlist)
    executor = ToolExecutor(
        registry,
        sandbox,
        allowlist=frozen_allowlist,
        store=store,
        monotonic_ns=SteppingMonotonic(step_ns=step_ns),
    )
    context = ToolContext(
        invocation_id="inv-generated",
        workspace=workspace,
        approved_tools=approved,
        max_egress=ceiling,
        timeout_seconds=draw(st.sampled_from([None, 0.001, 1.0, 3600.0])),
        clock=FrozenClock(FIXED_MOMENT),
    )

    args_are_valid = draw(st.booleans())
    path_escapes = False
    if args_are_valid:
        args: Any = draw(_valid_args(schema_name))
        if schema_name == "pathy":
            candidate, path_escapes = draw(_path_candidates(workspace))
            args = {"path": candidate}
        if redacted and isinstance(args, dict) and "value" in args:
            args["value"] = SECRET_ARGUMENT
    else:
        args = draw(_invalid_args())
    path_escapes = bool(path_escapes and path_args)

    # The request name is drawn last, and the labels are then stated about *that* name. A request
    # for one of the two fixed extra tools is a different spec — simple schema, no path arguments,
    # no isolation, closed egress — so its labels are that spec's, not the drawn one's.
    request_name: object = draw(
        st.one_of(
            _hostile_names(),
            st.sampled_from([REGISTERED, ALLOWLISTED_ONLY, REGISTERED_ONLY]),
        )
    )
    labels: dict[str, bool]
    if request_name == REGISTERED:
        labels = {
            "name_is_registered": name_is_registered,
            "name_is_allowlisted": name_is_registered and REGISTERED in allowlist,
            "name_is_approved": approved is None or REGISTERED in approved,
            "args_are_valid": args_are_valid,
            "egress_permitted": ceiling.permits(egress),
            "tier_available": tier_available or not requires_isolation,
            "path_escapes": path_escapes,
        }
    elif request_name in (ALLOWLISTED_ONLY, REGISTERED_ONLY):
        labels = {
            "name_is_registered": True,
            "name_is_allowlisted": request_name in allowlist,
            "name_is_approved": approved is None or request_name in approved,
            "args_are_valid": _valid_for_simple_schema(args),
            "egress_permitted": True,
            "tier_available": True,
            "path_escapes": False,
        }
    else:
        labels = {
            "name_is_registered": False,
            "name_is_allowlisted": False,
            "name_is_approved": False,
            "args_are_valid": False,
            "egress_permitted": True,
            "tier_available": True,
            "path_escapes": False,
        }

    return World(
        executor=executor,
        request=ToolCallRequest(name=request_name, args=args),  # type: ignore[arg-type]
        context=context,
        store=store,
        handler=handler,
        spec=spec,
        workspace=workspace,
        registry=registry,
        sandbox=sandbox,
        allowlist=frozen_allowlist,
        step_ns=step_ns,
        redacted=redacted,
        **labels,
    )


def _valid_for_simple_schema(args: object) -> bool:
    """Independently decide whether ``args`` satisfies :data:`SIMPLE_SCHEMA`.

    Small enough to restate rather than delegate, which is the point: an oracle that asked
    :class:`~toolyard.validation.ArgsValidator` would move with a bug in it.
    """
    return isinstance(args, dict) and set(args) == {"value"} and isinstance(args["value"], str)


def workspace_at(root: Path) -> SandboxPaths:
    """Build a real two-root workspace under ``root``, with a prefix-colliding decoy beside it."""
    write_root = root / "work"
    read_root = root / "reference"
    decoy = root / "work-decoy"
    for directory in (write_root, read_root, decoy):
        directory.mkdir(exist_ok=True)
    (write_root / "sub").mkdir(exist_ok=True)
    return SandboxPaths(write_root=write_root, read_roots=(read_root,))
