"""The registry — a reviewed list, built in code at startup, that only ever grows at startup.

ADR-0053 decision 1 in one sentence: the application constructs handlers and calls
:meth:`ToolRegistry.register`, and there is no other way in. No loading from configuration, no
plugin directory, no entry-point discovery, no tool-server protocol — and, just as important, **no
code path that could grow one**. There is no ``unregister``, no ``replace``, no ``update`` and no
``from_config``. The ADR rejects dynamic loading on the merits and expects it to stay rejected; the
absence of a seam is what keeps that true when someone is in a hurry.

Registered is not callable. The registry is the outer bound; the trajectory allowlist and the
turn's approved set narrow it, and that narrowing happens in the executor, per invocation
(ADR-0053 decision 2, ADR-0056 §1).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from baseaicore import NotFoundError

from toolyard.errors import DuplicateTool, InvalidToolSpec
from toolyard.types import EgressClass, RegisteredTool, ToolSpec
from toolyard.validation import ArgsValidator

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from toolyard.types import RiskClass, ToolHandler

__all__ = ["ToolRegistry"]


class ToolRegistry:
    """The tools an application has registered. Lookup is by exact name, always.

    Exact means exact: no fuzzy match, no case folding, no aliasing, no trimming of a trailing
    space. A model asking for ``Read_File`` or ``read_file `` gets ``unknown_tool``, and that is
    the correct answer rather than a missed opportunity to be helpful — a near-miss resolved
    helpfully is a tool called by a name nobody registered, which is the beginning of a tool called
    by a name nobody reviewed.
    """

    __slots__ = ("_tools",)

    def __init__(self) -> None:
        """Create an empty registry. Registration happens at startup and only there."""
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, spec: ToolSpec, handler: ToolHandler) -> None:
        """Add one tool. Called at startup, in code, by the application.

        The spec was already validated when it was constructed — a :class:`~toolyard.types.ToolSpec`
        that exists is a valid one — so the only thing left to refuse here is a duplicate name. This
        is a deviation from spec §7's comment, which puts spec validation at registration; moving it
        to construction removes the possibility of a half-checked spec being passed around, and
        :class:`~toolyard.errors.InvalidToolSpec` is still what a caller sees for a bad
        declaration.

        Args:
            spec: The tool's validated declaration.
            handler: The object that does the work.

        Raises:
            DuplicateTool: If a tool of that name is already registered. A duplicate is a wiring
                mistake, visible at startup where a person can fix it — never a runtime condition
                to resolve by picking one of the two.
            InvalidToolSpec: If ``spec`` is not a :class:`~toolyard.types.ToolSpec`.
        """
        if not isinstance(spec, ToolSpec):
            raise InvalidToolSpec(
                f"register() takes a ToolSpec; got {type(spec).__name__}.",
                details={"kind": type(spec).__name__},
            )
        if spec.name in self._tools:
            raise DuplicateTool(
                f"A tool named {spec.name!r} is already registered. Tool names are unique across "
                "the registry, and registration happens once, at startup.",
                details={"tool_name": spec.name},
            )
        self._tools[spec.name] = RegisteredTool(
            spec=spec, handler=handler, args_validator=ArgsValidator(spec.args_schema)
        )

    def get(self, name: str) -> RegisteredTool | None:
        """Look a tool up by exact name.

        Args:
            name: The name to find. May be anything at all — this is called with a model-supplied
                value, so an unhashable or non-string argument is answered with ``None`` rather
                than a ``TypeError``.

        Returns:
            The registration, or ``None`` when there is no tool of exactly that name.
        """
        if not isinstance(name, str):
            return None
        return self._tools.get(name)

    def names(self) -> tuple[str, ...]:
        """Return every registered name, sorted.

        Returns:
            The names in code-point order. Sorted rather than insertion-ordered so that anything
            derived from this — a listing, a digest, a diff between two deployments — is a function
            of what is registered and not of the order someone happened to register it in.
        """
        return tuple(sorted(self._tools))

    def list_for_policy(
        self, *, max_risk: RiskClass | None = None, allow_egress: bool = True
    ) -> Sequence[ToolSpec]:
        """List the specs a policy admits, in a documented order.

        Args:
            max_risk: The most permissive risk class to include. ``None`` includes every class.
            allow_egress: When ``False``, tools declaring
                :attr:`~toolyard.types.EgressClass.NETWORK` are excluded.

        Returns:
            The matching specs, **sorted by name**. The order is part of the contract rather than
            an artefact of registration: a caller hashes this listing into a plan or shows it to a
            person, and either use is broken by an order that depends on startup sequencing.
        """
        selected = [
            registered.spec
            for registered in self._tools.values()
            if (max_risk is None or max_risk.permits(registered.spec.risk_class))
            and (allow_egress or registered.spec.egress is EgressClass.NONE)
        ]
        return tuple(sorted(selected, key=lambda spec: spec.name))

    def wire_definitions(self, names: Sequence[str]) -> Sequence[Mapping[str, Any]]:
        """Export wire definitions for the named tools, in a documented order.

        The order is **sorted by name, de-duplicated** — not the order of ``names``. That is a
        deliberate strengthening of spec §7, and it exists because callers pass sets: an
        ``ExecutionIntent``'s ``approved_tools`` is a ``frozenset``, whose iteration order varies
        between processes. Definitions are hashed into PromptCadence's turn records (spec §11.7), so
        an order that depends on the caller's container type would produce a digest that changes
        between runs of the same trajectory. Sorting makes the export a function of *which* tools
        were asked for and nothing else.

        Args:
            names: The tools to export. Duplicates are collapsed.

        Returns:
            One neutral definition per distinct name, sorted by name.

        Raises:
            NotFoundError: If a name is not registered. This is a caller bug — ``names`` comes from
                the application's own allowlist, which is a subset of the registry — so unlike a
                model's unknown name it raises rather than being skipped. Skipping would silently
                shorten the tool list a model is shown, which is a change to the prompt nobody
                asked for.
        """
        wanted = sorted({name for name in names})
        missing = [name for name in wanted if name not in self._tools]
        if missing:
            raise NotFoundError(
                f"wire_definitions() was asked for {missing[0]!r}, which is not registered. The "
                "names passed here come from the application's allowlist, which is a subset of the "
                "registry; a name outside it is a wiring mistake, not a model's mistake.",
                details={"missing": missing[:10], "missing_count": len(missing)},
            )
        return tuple(self._tools[name].spec.wire_definition() for name in wanted)
