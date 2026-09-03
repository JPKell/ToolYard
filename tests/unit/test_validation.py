"""Schema checking: the closedness requirement, the ``$ref`` refusal, and what a model is told."""

from __future__ import annotations

from typing import Any

import pytest

from toolyard import InvalidToolSpec
from toolyard.validation import (
    MAX_ARGS_DEPTH,
    MAX_ARGS_NODES,
    MAX_SCHEMA_DEPTH,
    ArgsValidator,
    check_args_schema,
    check_result_schema,
    string_property_names,
)

CLOSED: dict[str, Any] = {
    "type": "object",
    "properties": {"value": {"type": "string"}},
    "required": ["value"],
    "additionalProperties": False,
}


class TestClosednessIsRequired:
    """The plan's named failure mode: "schema validation accepting extra properties by default"."""

    def test_a_closed_root_is_accepted(self) -> None:
        check_args_schema(CLOSED)

    def test_an_open_root_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="additionalProperties"):
            check_args_schema({"type": "object", "properties": {"v": {"type": "string"}}})

    def test_additional_properties_true_is_refused_as_loudly_as_omitting_it(self) -> None:
        with pytest.raises(InvalidToolSpec, match="additionalProperties"):
            check_args_schema(
                {
                    "type": "object",
                    "properties": {"v": {"type": "string"}},
                    "additionalProperties": True,
                }
            )

    def test_a_nested_open_object_is_refused_too(self) -> None:
        """The nested case is where it actually gets forgotten, so it is where the check matters."""
        with pytest.raises(InvalidToolSpec, match=r"\$\.options"):
            check_args_schema(
                {
                    "type": "object",
                    "properties": {
                        "options": {"type": "object", "properties": {"deep": {"type": "string"}}}
                    },
                    "additionalProperties": False,
                }
            )

    def test_an_open_object_inside_an_array_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="additionalProperties"):
            check_args_schema(
                {
                    "type": "object",
                    "properties": {
                        "rows": {
                            "type": "array",
                            "items": {"type": "object", "properties": {"a": {"type": "string"}}},
                        }
                    },
                    "additionalProperties": False,
                }
            )

    def test_an_open_object_inside_a_combinator_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="additionalProperties"):
            check_args_schema(
                {
                    "type": "object",
                    "properties": {
                        "either": {
                            "anyOf": [
                                {"type": "string"},
                                {"type": "object", "properties": {"a": {"type": "string"}}},
                            ]
                        }
                    },
                    "additionalProperties": False,
                }
            )

    def test_unevaluated_properties_false_also_closes_a_schema(self) -> None:
        check_args_schema(
            {
                "type": "object",
                "properties": {"v": {"type": "string"}},
                "unevaluatedProperties": False,
            }
        )

    def test_an_object_with_no_declared_properties_needs_no_closing_keyword(self) -> None:
        """Nothing is declared, so nothing is being left open by omission."""
        check_args_schema({"type": "object", "additionalProperties": False})


class TestReferenceKeywordsAreRefused:
    """A ``$ref`` is a URI, and a validator handed an unresolved one tries to fetch it."""

    @pytest.mark.parametrize(
        "keyword",
        ["$ref", "$dynamicRef", "$id", "$anchor", "$dynamicAnchor", "$defs", "definitions"],
    )
    def test_each_reference_keyword_is_refused_at_the_root(self, keyword: str) -> None:
        schema = dict(CLOSED) | {keyword: "https://example.invalid/schema.json"}
        with pytest.raises(InvalidToolSpec, match="not permitted"):
            check_args_schema(schema)

    def test_a_nested_reference_is_refused_and_its_path_named(self) -> None:
        with pytest.raises(InvalidToolSpec, match=r"\$\.inner"):
            check_args_schema(
                {
                    "type": "object",
                    "properties": {"inner": {"$ref": "https://example.invalid/x.json"}},
                    "additionalProperties": False,
                }
            )

    def test_a_result_schema_is_held_to_the_same_reference_rule(self) -> None:
        with pytest.raises(InvalidToolSpec, match="not permitted"):
            check_result_schema({"$ref": "https://example.invalid/x.json"})


class TestSchemaShape:
    """Everything else a caller can get wrong about a declaration."""

    def test_a_non_mapping_schema_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="mapping"):
            check_args_schema("not a schema")  # type: ignore[arg-type]

    def test_a_non_object_root_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="type"):
            check_args_schema({"type": "array", "items": {"type": "string"}})

    def test_a_malformed_schema_is_refused_with_its_path(self) -> None:
        with pytest.raises(InvalidToolSpec, match="not a valid JSON Schema"):
            check_args_schema({"type": "object", "properties": {"v": {"type": 17}}})

    def test_an_over_deep_schema_is_refused(self) -> None:
        schema: dict[str, Any] = {"type": "object", "additionalProperties": False}
        node = schema
        for _ in range(MAX_SCHEMA_DEPTH + 2):
            child: dict[str, Any] = {"type": "object", "additionalProperties": False}
            node["properties"] = {"n": child}
            node = child
        with pytest.raises(InvalidToolSpec, match="deeper"):
            check_args_schema(schema)

    def test_a_non_mapping_result_schema_is_refused(self) -> None:
        with pytest.raises(InvalidToolSpec, match="mapping"):
            check_result_schema([1, 2])  # type: ignore[arg-type]

    def test_string_property_names_finds_only_pinned_strings(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "integer"},
                "c": {"type": ["string", "null"]},
                "d": {},
            },
            "additionalProperties": False,
        }
        assert string_property_names(schema) == frozenset({"a"})

    def test_string_property_names_tolerates_a_schema_without_properties(self) -> None:
        assert (
            string_property_names({"type": "object", "additionalProperties": False}) == frozenset()
        )


class TestArgsValidatorNeverRaises:
    """The model-facing half. Every answer is a string or ``None``; nothing propagates."""

    @pytest.fixture
    def validator(self) -> ArgsValidator:
        return ArgsValidator(CLOSED)

    def test_valid_arguments_return_none(self, validator: ArgsValidator) -> None:
        assert validator.validate({"value": "x"}) is None

    @pytest.mark.parametrize("args", [None, "text", [1], 17, (1, 2), set()])
    def test_arguments_that_are_not_an_object_are_named_as_such(
        self, validator: ArgsValidator, args: object
    ) -> None:
        detail = validator.validate(args)
        assert detail is not None
        assert "expected an object" in detail

    def test_a_wrong_type_names_the_path_and_the_expectation_but_not_the_value(
        self, validator: ArgsValidator
    ) -> None:
        detail = validator.validate({"value": 12345})
        assert detail is not None
        assert "$.value" in detail
        assert "12345" not in detail

    def test_an_extra_property_is_named_because_it_is_unfixable_otherwise(
        self, validator: ArgsValidator
    ) -> None:
        detail = validator.validate({"value": "x", "smuggled": "y"})
        assert detail is not None
        assert "smuggled" in detail

    def test_a_missing_required_property_names_the_keyword(self, validator: ArgsValidator) -> None:
        detail = validator.validate({})
        assert detail is not None
        assert "required" in detail

    def test_over_deep_arguments_are_refused_before_the_validator_sees_them(
        self, validator: ArgsValidator
    ) -> None:
        nested: Any = "leaf"
        for _ in range(MAX_ARGS_DEPTH + 5):
            nested = {"n": nested}
        detail = validator.validate({"value": nested})
        assert detail is not None
        assert "deeper" in detail

    def test_a_structure_that_would_blow_the_stack_is_a_detail_not_a_recursion_error(
        self, validator: ArgsValidator
    ) -> None:
        nested: Any = "leaf"
        for _ in range(5_000):
            nested = [nested]
        assert validator.validate({"value": nested}) is not None

    def test_enormous_arguments_are_refused_by_node_count(self, validator: ArgsValidator) -> None:
        detail = validator.validate({"value": list(range(MAX_ARGS_NODES + 10))})
        assert detail is not None
        assert "more than" in detail

    def test_a_cyclic_structure_is_refused_rather_than_looping(
        self, validator: ArgsValidator
    ) -> None:
        cyclic: dict[str, Any] = {}
        cyclic["self"] = cyclic
        assert validator.validate({"value": cyclic}) is not None

    def test_an_array_index_appears_in_the_path_as_a_bracketed_number(self) -> None:
        """A model needs to know *which element* of a list was wrong, not merely that one was."""
        validator = ArgsValidator(
            {
                "type": "object",
                "properties": {"rows": {"type": "array", "items": {"type": "string"}}},
                "additionalProperties": False,
            }
        )
        detail = validator.validate({"rows": ["ok", 17, "ok"]})
        assert detail is not None
        assert "$.rows[1]" in detail

    def test_the_detail_is_capped(self) -> None:
        wide = {
            "type": "object",
            "properties": {f"p{index}": {"type": "integer"} for index in range(50)},
            "additionalProperties": False,
        }
        detail = ArgsValidator(wide).validate({f"p{index}": "wrong" for index in range(50)})
        assert detail is not None
        assert len(detail) <= 400
        assert "more)" in detail
