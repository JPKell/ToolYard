"""The registry: registration in code, exact lookup, a documented order, and no plugin seam."""

from __future__ import annotations

import pytest
from baseaicore import NotFoundError, canonical_json

from fakes import EMPTY_SCHEMA, EchoTool, spec
from toolyard import DuplicateTool, EgressClass, InvalidToolSpec, RiskClass, ToolRegistry


@pytest.fixture
def filled() -> ToolRegistry:
    """A registry holding four tools spanning both risk classes and both egress classes."""
    registry = ToolRegistry()
    registry.register(spec("zebra"), EchoTool())
    registry.register(spec("alpha", risk_class=RiskClass.MUTATING), EchoTool())
    registry.register(spec("middle", egress=EgressClass.NETWORK), EchoTool())
    registry.register(
        spec("omega", risk_class=RiskClass.MUTATING, egress=EgressClass.NETWORK), EchoTool()
    )
    return registry


class TestRegistration:
    """Startup, in code, once."""

    def test_a_registered_tool_is_found(self) -> None:
        registry = ToolRegistry()
        handler = EchoTool()
        built = spec("echo")
        registry.register(built, handler)
        found = registry.get("echo")
        assert found is not None
        assert found.spec is built
        assert found.handler is handler
        assert found.args_validator.validate({"value": "x"}) is None

    def test_a_duplicate_name_raises_at_startup(self) -> None:
        registry = ToolRegistry()
        registry.register(spec("echo"), EchoTool())
        with pytest.raises(DuplicateTool) as caught:
            registry.register(spec("echo"), EchoTool())
        assert caught.value.code == "TOOL_DUPLICATE"

    def test_registering_something_that_is_not_a_spec_raises(self) -> None:
        registry = ToolRegistry()
        with pytest.raises(InvalidToolSpec):
            registry.register({"name": "echo"}, EchoTool())  # type: ignore[arg-type]

    def test_there_is_no_way_to_remove_or_replace_a_registration(self) -> None:
        """ADR-0053 rejects dynamic loading on the merits; the absence of a seam is what keeps it
        rejected when someone is in a hurry."""
        surface = {name for name in dir(ToolRegistry) if not name.startswith("_")}
        assert surface == {"get", "list_for_policy", "names", "register", "wire_definitions"}
        for forbidden in ("unregister", "remove", "replace", "update", "load", "discover", "clear"):
            assert not hasattr(ToolRegistry, forbidden)


class TestExactLookup:
    """A near-miss is ``unknown_tool``, not a suggestion."""

    @pytest.mark.parametrize(
        "name", ["Echo", "ECHO", "echo ", " echo", "ech", "echoo", "ec_ho", "", "écho"]
    )
    def test_a_near_miss_finds_nothing(self, name: str) -> None:
        registry = ToolRegistry()
        registry.register(spec("echo"), EchoTool())
        assert registry.get(name) is None

    @pytest.mark.parametrize("name", [None, 17, ["echo"], {"echo"}, object()])
    def test_a_lookup_with_a_non_string_answers_none_rather_than_raising(
        self, name: object
    ) -> None:
        """``get`` is called with a model-supplied value, and an unhashable one would otherwise be
        a ``TypeError`` from ``dict.get``."""
        registry = ToolRegistry()
        registry.register(spec("echo"), EchoTool())
        assert registry.get(name) is None  # type: ignore[arg-type]


class TestPolicyListing:
    """The order is part of the contract, because a caller hashes or renders the listing."""

    def test_everything_is_listed_by_name_not_by_registration_order(
        self, filled: ToolRegistry
    ) -> None:
        assert [built.name for built in filled.list_for_policy()] == [
            "alpha",
            "middle",
            "omega",
            "zebra",
        ]

    def test_a_read_only_ceiling_excludes_mutating_tools(self, filled: ToolRegistry) -> None:
        assert [built.name for built in filled.list_for_policy(max_risk=RiskClass.READ_ONLY)] == [
            "middle",
            "zebra",
        ]

    def test_forbidding_egress_excludes_network_tools(self, filled: ToolRegistry) -> None:
        assert [built.name for built in filled.list_for_policy(allow_egress=False)] == [
            "alpha",
            "zebra",
        ]

    def test_both_filters_compose(self, filled: ToolRegistry) -> None:
        assert [
            built.name
            for built in filled.list_for_policy(max_risk=RiskClass.READ_ONLY, allow_egress=False)
        ] == ["zebra"]

    def test_names_are_sorted(self, filled: ToolRegistry) -> None:
        assert filled.names() == ("alpha", "middle", "omega", "zebra")


class TestWireDefinitionsExport:
    """Byte-stable, which means the export order cannot come from the caller's container type."""

    def test_the_export_is_sorted_regardless_of_the_order_asked_for(
        self, filled: ToolRegistry
    ) -> None:
        forward = filled.wire_definitions(["zebra", "alpha", "middle"])
        backward = filled.wire_definitions(["middle", "alpha", "zebra"])
        assert [definition["name"] for definition in forward] == ["alpha", "middle", "zebra"]
        assert canonical_json(list(forward)) == canonical_json(list(backward))

    def test_a_frozenset_produces_the_same_bytes_every_time(self, filled: ToolRegistry) -> None:
        """An ``ExecutionIntent``'s ``approved_tools`` is a frozenset, whose iteration order varies
        between processes — and these definitions are hashed into turn records."""
        wanted = frozenset({"zebra", "alpha", "middle", "omega"})
        first = canonical_json(list(filled.wire_definitions(sorted(wanted))))
        second = canonical_json(list(filled.wire_definitions(list(wanted))))
        assert first == second

    def test_duplicates_are_collapsed(self, filled: ToolRegistry) -> None:
        assert len(filled.wire_definitions(["alpha", "alpha", "alpha"])) == 1

    def test_an_unregistered_name_raises_because_it_is_a_caller_bug(
        self, filled: ToolRegistry
    ) -> None:
        """Skipping would silently shorten the tool list a model is shown, which is a change to the
        prompt nobody asked for."""
        with pytest.raises(NotFoundError, match="ghost"):
            filled.wire_definitions(["alpha", "ghost"])

    def test_an_empty_request_is_an_empty_export(self, filled: ToolRegistry) -> None:
        assert filled.wire_definitions([]) == ()

    def test_a_definition_holds_only_the_neutral_shape(self, filled: ToolRegistry) -> None:
        registry = ToolRegistry()
        registry.register(spec("plain", args_schema=EMPTY_SCHEMA), EchoTool())
        (definition,) = registry.wire_definitions(["plain"])
        assert set(definition) == {"name", "description", "parameters"}
