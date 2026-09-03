"""Argument-schema checking — the only module that imports ``jsonschema``.

Two jobs, on opposite sides of the trust boundary:

* :func:`check_args_schema` runs once, when a :class:`~toolyard.types.ToolSpec` is constructed, over
  a schema the **caller** wrote. It raises :class:`~toolyard.errors.InvalidToolSpec`, because a
  malformed schema is a programming error a person should see at startup.
* :class:`ArgsValidator` runs on every call, over arguments a **model** wrote. It never raises; it
  returns a detail string naming what failed, or ``None``.

Three deliberate strictnesses, each closing something the development plan or the threat model
names:

1. **Closed schemas are required, recursively.** JSON Schema's default is that unknown properties
   are allowed, so a spec that forgot ``additionalProperties: false`` is a tool a model can pass
   extra arguments to — Phase 1's named likely failure mode. Documenting the requirement would
   leave it to be forgotten in exactly the repository whose inputs are adversarial, so it is
   enforced, at every object-typed subschema rather than only at the root, because a nested object
   is where it actually gets forgotten.
2. **The ``$ref`` family is refused outright.** A ``$ref`` is a URI, and a validator handed an
   unresolved one will try to *retrieve* it. That is an outbound fetch, from a tool declaration,
   in a package whose whole point is that egress is checked at one door. Refusing the keyword
   removes the door rather than guarding it. ``$id``, ``$anchor``, ``$dynamicRef``,
   ``$dynamicAnchor`` and ``$defs`` go with it: they exist to be reached by a reference.
3. **Format checking stays off.** ``jsonschema`` disables it by default and this module does not
   turn it on. A ``format: "hostname"`` or ``"uri"`` checker is another parser running on model
   input, and the checks that matter for a URL belong at the socket (ADR-0026 §3), not here.

The reported detail names **the validator's paths and the schema's expectation** — never the value
the model sent. A model needs to know *which* argument was wrong to stop retrying the same call, so
the path is essential; echoing its own value back adds nothing and puts model-chosen text into
records and logs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import jsonschema
from baseaicore import canonical_json

from toolyard._safe import clean_text
from toolyard.errors import InvalidToolSpec

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "MAX_ARGS_DEPTH",
    "MAX_ARGS_NODES",
    "MAX_SCHEMA_DEPTH",
    "ArgsValidator",
    "check_args_schema",
    "check_result_schema",
]

MAX_SCHEMA_DEPTH: Final[int] = 24
"""How deep a caller's schema may nest before it is refused as unreviewable."""

MAX_ARGS_DEPTH: Final[int] = 24
"""How deep a model's arguments may nest before the schema check refuses them unvalidated.

``jsonschema`` validates recursively, so a sufficiently nested argument structure exhausts the
interpreter's stack inside the validator — a refusal that arrives as a ``RecursionError`` rather
than as a result. Checking the depth first turns that into an ordinary ``args_invalid``.
"""

MAX_ARGS_NODES: Final[int] = 20_000
"""How many containers and leaves a model's arguments may hold before they are refused.

Validation is linear in the structure; an argument object with a million members is a denial of
service against the application, not a call anyone meant to make.
"""

_REFUSED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"$ref", "$dynamicRef", "$id", "$anchor", "$dynamicAnchor", "$defs", "definitions"}
)
_CLOSING_KEYWORDS: Final[tuple[str, str]] = ("additionalProperties", "unevaluatedProperties")
_MAX_REPORTED_ERRORS: Final[int] = 5
_MAX_DETAIL_CHARS: Final[int] = 400
_MAX_EXPECTATION_CHARS: Final[int] = 64
_MAX_PROPERTY_NAME_CHARS: Final[int] = 40
_MAX_REPORTED_PROPERTIES: Final[int] = 5


def check_args_schema(schema: Mapping[str, Any]) -> None:
    """Refuse an argument schema that cannot be relied on to bound a model's arguments.

    Args:
        schema: The candidate JSON Schema, as a mapping. JSON Schema documents are genuinely
            ``Mapping[str, Any]`` — the value at a key may be a string, a number, a list or another
            schema, and narrowing that would be a fiction. This is the one place in the package
            where ``Any`` at a public boundary is correct.

    Raises:
        InvalidToolSpec: If the schema is not a mapping; is not a valid draft 2020-12 schema; does
            not describe an object at its root; nests deeper than :data:`MAX_SCHEMA_DEPTH`; uses a
            ``$ref``-family keyword; or leaves any object-typed subschema with ``properties`` open
            to additional properties. Each is a property the caller declared wrongly, and each
            would otherwise show up as a tool a model can pass unreviewed arguments to.
    """
    if not isinstance(schema, dict):
        raise InvalidToolSpec(
            "args_schema must be a JSON Schema object (a mapping); got "
            f"{type(schema).__name__}. Tool arguments arrive as a JSON object, so the schema that "
            "bounds them describes an object.",
            details={"field": "args_schema", "kind": type(schema).__name__},
        )
    _refuse_reference_keywords(schema, path="$")
    _refuse_excessive_depth(schema, depth=0)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise InvalidToolSpec(
            f"args_schema is not a valid JSON Schema (draft 2020-12): {exc.message}. "
            "Fix the schema in the tool's registration.",
            details={"field": "args_schema", "schema_path": list(exc.absolute_path)},
        ) from exc
    if schema.get("type") != "object":
        raise InvalidToolSpec(
            'args_schema must declare `"type": "object"` at its root; got '
            f"{schema.get('type')!r}. A model supplies tool arguments as an object, and "
            "`additionalProperties` means nothing on a root that is not one.",
            details={"field": "args_schema", "type": repr(schema.get("type"))},
        )
    _refuse_open_objects(schema, path="$")


def check_result_schema(schema: Mapping[str, Any]) -> None:
    """Refuse a result schema that is not a valid draft 2020-12 schema.

    Result schemas are declared but not yet enforced beyond size caps (spec §21), so this checks
    only that the document is well formed and free of the ``$ref`` family. It does **not** require
    closedness: a tool's own output is not the attack surface a model's arguments are, and
    forbidding extra keys in a result would forbid a handler from ever adding a field.

    Args:
        schema: The candidate JSON Schema, as a mapping.

    Raises:
        InvalidToolSpec: If the schema is not a mapping, is not a valid draft 2020-12 schema,
            nests deeper than :data:`MAX_SCHEMA_DEPTH`, or uses a ``$ref``-family keyword.
    """
    if not isinstance(schema, dict):
        raise InvalidToolSpec(
            f"result_schema must be a JSON Schema object (a mapping) or None; got "
            f"{type(schema).__name__}.",
            details={"field": "result_schema", "kind": type(schema).__name__},
        )
    _refuse_reference_keywords(schema, path="$")
    _refuse_excessive_depth(schema, depth=0)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise InvalidToolSpec(
            f"result_schema is not a valid JSON Schema (draft 2020-12): {exc.message}.",
            details={"field": "result_schema", "schema_path": list(exc.absolute_path)},
        ) from exc


def string_property_names(schema: Mapping[str, Any]) -> frozenset[str]:
    """Return the root property names a schema types as ``string``.

    Used by :class:`~toolyard.types.ToolSpec` to check that every declared path argument is one the
    schema will actually deliver as a string, so a spec cannot declare containment over an argument
    the executor will receive as an integer.

    Args:
        schema: A schema already accepted by :func:`check_args_schema`.

    Returns:
        The names under ``properties`` whose subschema declares ``"type": "string"``. A property
        with a union type or no declared type is absent, deliberately: containment over an argument
        whose type is not pinned is containment over something that might not be a path.
    """
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return frozenset()
    return frozenset(
        name
        for name, subschema in properties.items()
        if isinstance(name, str)
        and isinstance(subschema, dict)
        and subschema.get("type") == "string"
    )


class ArgsValidator:
    """A compiled validator for one tool's argument schema. Never raises on model input.

    Compiled once per registration rather than per call, because spec §15 budgets 10 ms for the
    whole dispatch and building a validator is the expensive part.

    The instance is treated as immutable; it is built by
    :meth:`~toolyard.registry.ToolRegistry.register` and reached through
    :attr:`~toolyard.types.RegisteredTool.args_validator`.
    """

    __slots__ = ("_schema", "_validator")

    def __init__(self, schema: Mapping[str, Any]) -> None:
        """Compile a validator for an already-checked schema.

        Args:
            schema: A schema that has passed :func:`check_args_schema`. Passing an unchecked one is
                a caller bug; :class:`~toolyard.types.ToolSpec` checks at construction, so every
                schema reaching here through the ordinary path has been checked.
        """
        self._schema = schema
        self._validator = jsonschema.Draft202012Validator(schema)

    def validate(self, args: object) -> str | None:
        """Check a model's arguments, returning what failed rather than raising.

        Args:
            args: Whatever the model supplied. Any Python object at all — this is the untrusted
                half of a call and the annotation says so.

        Returns:
            ``None`` when the arguments are valid. Otherwise a capped, single-line detail naming
            the JSON paths that failed and what the schema expected there — never the value the
            model sent. The string is what reaches the model as its only clue, so it names paths;
            a model that cannot see which argument was wrong retries the same call forever.
        """
        if not isinstance(args, dict):
            return f"$: expected an object of arguments, received {type(args).__name__}"
        shape = _describe_shape(args)
        if shape is not None:
            return shape
        try:
            errors = sorted(
                self._validator.iter_errors(args),
                key=lambda error: (len(error.absolute_path), str(list(error.absolute_path))),
            )
        except Exception as exc:  # noqa: BLE001 — a validator failing on hostile input is a refusal
            return f"$: validation could not complete ({type(exc).__name__})"
        if not errors:
            return None
        rendered = [_render_error(error) for error in errors[:_MAX_REPORTED_ERRORS]]
        if len(errors) > _MAX_REPORTED_ERRORS:
            rendered.append(f"(+{len(errors) - _MAX_REPORTED_ERRORS} more)")
        return clean_text("; ".join(rendered))[:_MAX_DETAIL_CHARS]


def _render_error(error: jsonschema.ValidationError) -> str:
    """Render one validation error as ``path: keyword expectation``, without the model's value."""
    path = _json_path(error)
    keyword = str(error.validator)
    if keyword == "additionalProperties":
        return f"{path}: unexpected properties {_unexpected_properties(error)}"
    return f"{path}: {keyword} {_expectation(error.validator_value)}"


def _json_path(error: jsonschema.ValidationError) -> str:
    """Build a ``$.a.b[0]`` path from an error's absolute path, cleaning model-chosen keys."""
    parts = ["$"]
    for element in error.absolute_path:
        if isinstance(element, int):
            parts.append(f"[{element}]")
        else:
            parts.append("." + clean_text(str(element))[:_MAX_PROPERTY_NAME_CHARS])
    return "".join(parts)


def _expectation(value: object) -> str:
    """Render the unsatisfied schema fragment. From the caller's schema, not from the model."""
    try:
        rendered = canonical_json(value)
    except Exception:  # noqa: BLE001 — an unserializable schema fragment must not break a refusal
        rendered = repr(value)
    return rendered[:_MAX_EXPECTATION_CHARS]


def _unexpected_properties(error: jsonschema.ValidationError) -> str:
    """Name the extra properties a closed object rejected, capped and cleaned.

    This is the one place a model-chosen string is quoted back, and it is the one place it earns
    its keep: "you sent an argument this tool does not take" is unactionable without the name.
    """
    instance = error.instance
    schema = error.schema
    if not isinstance(instance, dict) or not isinstance(schema, dict):
        return "(unnameable)"
    declared = schema.get("properties")
    known = set(declared) if isinstance(declared, dict) else set()
    extra = sorted(
        clean_text(str(name))[:_MAX_PROPERTY_NAME_CHARS] for name in instance if name not in known
    )
    if not extra:
        return "(none identifiable)"
    shown = extra[:_MAX_REPORTED_PROPERTIES]
    suffix = f" (+{len(extra) - len(shown)} more)" if len(extra) > len(shown) else ""
    return ", ".join(shown) + suffix


def _describe_shape(args: dict[Any, Any]) -> str | None:
    """Refuse arguments too deep or too large to hand to the validator. Returns a detail or None."""
    nodes = 0
    stack: list[tuple[object, int]] = [(args, 0)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ARGS_NODES:
            return f"$: arguments hold more than {MAX_ARGS_NODES} values"
        if depth > MAX_ARGS_DEPTH:
            return f"$: arguments nest deeper than {MAX_ARGS_DEPTH} levels"
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list | tuple):
            stack.extend((item, depth + 1) for item in value)
    return None


def _refuse_reference_keywords(schema: Mapping[str, Any], *, path: str) -> None:
    """Walk a caller's schema refusing the ``$ref`` family wherever it appears."""
    for key, value in schema.items():
        if key in _REFUSED_KEYWORDS:
            raise InvalidToolSpec(
                f"Schema keyword {key!r} at {path} is not permitted. A reference is a URI, and a "
                "validator handed an unresolved one attempts to retrieve it — an outbound fetch "
                "from a tool declaration, in the package that exists to keep egress at one door. "
                "Inline the subschema instead.",
                details={"keyword": key, "schema_path": path},
            )
        for child, child_path in _subschemas(key, value, path):
            _refuse_reference_keywords(child, path=child_path)


def _refuse_excessive_depth(schema: Mapping[str, Any], *, depth: int) -> None:
    """Refuse a schema nested deeper than :data:`MAX_SCHEMA_DEPTH`."""
    if depth > MAX_SCHEMA_DEPTH:
        raise InvalidToolSpec(
            f"Schema nests deeper than {MAX_SCHEMA_DEPTH} levels. A tool's arguments are meant to "
            "be reviewable; a schema this deep is not.",
            details={"max_depth": MAX_SCHEMA_DEPTH},
        )
    for key, value in schema.items():
        for child, _ in _subschemas(key, value, ""):
            _refuse_excessive_depth(child, depth=depth + 1)


def _refuse_open_objects(schema: Mapping[str, Any], *, path: str) -> None:
    """Refuse any object-typed subschema with ``properties`` that admits additional properties."""
    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        closed = any(schema.get(keyword) is False for keyword in _CLOSING_KEYWORDS)
        if not closed:
            raise InvalidToolSpec(
                f'The object schema at {path} must set `"additionalProperties": false` (or '
                '`"unevaluatedProperties": false`). JSON Schema admits unknown properties by '
                "default, so an open schema is a tool a model can pass unreviewed arguments to — "
                "the failure mode ToolYard's development plan names for this phase.",
                details={"schema_path": path},
            )
    for key, value in schema.items():
        for child, child_path in _subschemas(key, value, path):
            _refuse_open_objects(child, path=child_path)


def _subschemas(key: str, value: object, path: str) -> list[tuple[Mapping[str, Any], str]]:
    """Yield the subschemas held under one schema keyword, with the path each sits at.

    Covers the applicator keywords a closed-schema check has to see: ``properties``,
    ``patternProperties``, ``$defs``-free nesting through ``items``/``prefixItems``/
    ``additionalProperties``/``contains``/``propertyNames``, and the boolean combinators.
    """
    if key in {"properties", "patternProperties", "dependentSchemas"} and isinstance(value, dict):
        return [
            (child, f"{path}.{name}") for name, child in value.items() if isinstance(child, dict)
        ]
    if key in {"allOf", "anyOf", "oneOf", "prefixItems"} and isinstance(value, list):
        return [
            (child, f"{path}[{index}]")
            for index, child in enumerate(value)
            if isinstance(child, dict)
        ]
    if key in {
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "unevaluatedItems",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
    } and isinstance(value, dict):
        return [(value, f"{path}.{key}")]
    return []
