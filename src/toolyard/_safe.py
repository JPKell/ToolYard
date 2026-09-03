"""Total functions over hostile values — nothing here raises, for any input.

Every function in this module is called on the path between a model and a record, which means it
is called on values the model chose. ADR-0053 decision 4 says nothing on that path may raise, so
nothing here does: each function has a defined answer for a value that is enormous, cyclic, of the
wrong type, un-encodable, or an object whose ``__repr__`` raises.

That is a stronger promise than "handles the obvious cases", and it is what the property suite
asserts directly. Three specific traps this module exists to close:

* :func:`baseaicore.canonical_json` **refuses** non-finite floats, ``bytes``, ``set``, cycles and
  naive datetimes — and ``json.loads`` accepts ``NaN`` and ``Infinity`` by default, so a model's
  arguments really can contain a float that cannot be hashed. :func:`json_sanitize` maps every
  such value to a tagged, JSON-safe stand-in so that a digest always exists.
* A ``str`` in Python may hold lone surrogates, which ``.encode("utf-8")`` refuses — so hashing a
  handler's output could raise on the handler's behalf. :func:`clean_text` removes them, and every
  digest and every cap in the package is taken over cleaned text.
* Truncating UTF-8 at a byte offset splits a character. :func:`truncate_text` cuts on a character
  boundary, leaves room for the label, and guarantees the labelled result still fits the cap.

Nothing here interprets a value: no argument is parsed, executed, or interpolated into a path, a
command or a URL (spec §14). Sanitizing means *replacing* a value with a description of its shape,
never rendering it.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Final

__all__ = [
    "TRUNCATION_LABEL_TEMPLATE",
    "clean_text",
    "json_sanitize",
    "truncate_text",
]

MAX_SANITIZE_DEPTH: Final[int] = 32
"""Structures deeper than this are replaced by a tag at the cut.

Deep enough for any real tool's arguments and shallow enough that the walk cannot exhaust the
stack; a model that sends something deeper is refused at the schema check anyway, but the digest
still has to exist for the record of that refusal.
"""

MAX_SANITIZE_NODES: Final[int] = 20_000
"""Total containers and leaves visited before the walk stops and tags the remainder.

An unbounded walk over a hostile structure is a denial of service against the *application*, in the
one package whose threat model says the input is adversarial.
"""

TRUNCATION_LABEL_TEMPLATE: Final[str] = "\n…[truncated by toolyard: {kept} of {total} bytes]"
"""The label appended to any truncated text, and part of the public contract.

A model reading a tool result has no other way to know the text stopped early rather than ended,
and a model that assumes it ended will answer from half a file. The byte figures are of the
*cleaned* text (:func:`clean_text`), which is what was measured.
"""

_SURROGATE_LOW: Final[int] = 0xD800
_SURROGATE_HIGH: Final[int] = 0xDFFF


def clean_text(value: str) -> str:
    """Return ``value`` with the characters that cannot survive a record or a prompt removed.

    Removes NUL (which truncates strings in C-backed stores and in many log pipelines) and lone
    surrogates (which ``str.encode("utf-8")`` refuses, so their presence would turn "hash the
    output" into "raise on the model's behalf"). Everything else is preserved, newlines and tabs
    included: a tool's output is text, and mangling it further would be a second lie about what the
    tool produced.

    Args:
        value: Any string, including one built from bytes decoded with ``surrogateescape``.

    Returns:
        A string that encodes to UTF-8 without raising and contains no NUL. ``value`` itself when
        it already satisfies both, so the common path allocates nothing.
    """
    if "\x00" not in value and value.isascii():
        return value
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        value = "".join(
            character
            for character in value
            if not _SURROGATE_LOW <= ord(character) <= _SURROGATE_HIGH
        )
    return value.replace("\x00", "")


def truncate_text(value: str, *, max_bytes: int) -> tuple[str, bool]:
    """Cap ``value`` at ``max_bytes`` UTF-8 bytes, labelling it when anything was cut.

    The guarantee is on the *returned* string: it is never larger than ``max_bytes``, label
    included. Truncation cuts on a character boundary, so the result is always decodable, and the
    label states the byte figures rather than merely saying "truncated" — a model deciding whether
    to ask for the rest of a file needs to know how much of it it has.

    Args:
        value: The text to cap. Cleaned by :func:`clean_text` first, so the figures in the label
            describe what the caller actually receives.
        max_bytes: The ceiling, in UTF-8 bytes. Must leave room for the label; callers that
            configure a cap validate that at construction, and a cap too small for the label
            here degrades to an unlabelled hard cut rather than raising.

    Returns:
        A ``(text, truncated)`` pair. ``truncated`` is ``True`` exactly when ``text`` differs from
        the cleaned input, which is exactly when the label is present.
    """
    cleaned = clean_text(value)
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= max_bytes:
        return cleaned, False
    label = TRUNCATION_LABEL_TEMPLATE.format(kept=0, total=len(encoded))
    budget = max_bytes - len(label.encode("utf-8")) - _LABEL_DIGITS_HEADROOM
    if budget <= 0:
        # The cap cannot hold a label. Hard-cut on a character boundary and say nothing, because
        # exceeding the cap the caller asked for would be worse than an unlabelled cut.
        return encoded[:max_bytes].decode("utf-8", errors="ignore"), True
    kept = encoded[:budget].decode("utf-8", errors="ignore")
    label = TRUNCATION_LABEL_TEMPLATE.format(kept=len(kept.encode("utf-8")), total=len(encoded))
    return kept + label, True


_LABEL_DIGITS_HEADROOM: Final[int] = 24
"""Slack for the two byte figures the label interpolates, so the labelled result still fits."""


def json_sanitize(value: object) -> Any:  # noqa: ANN401 — returns a JSON-shaped structure by design
    """Return a JSON-safe, hashable projection of ``value``, replacing what cannot be serialized.

    :func:`baseaicore.canonical_json` is the suite's one serialization convention and it refuses
    several things a model's arguments can contain. Rather than inventing a second convention, this
    walk replaces each refused value with a small tagged object describing its *shape* — never its
    content — so that ``canonical_json`` accepts the result and a digest always exists.

    The substitutions, each a single-key object so a reader can tell a substitution from real data:

    * non-finite ``float`` → ``{"__nonfinite__": "nan" | "inf" | "-inf"}``
    * ``bytes``/``bytearray`` → ``{"__bytes_sha256__": <hex>, "__len__": n}`` — the digest, never
      the bytes, because bytes in an argument are as likely to be a secret as anything else
    * ``set``/``frozenset`` → a sorted list of sanitized members (order is not meaning for a set,
      and a hash must not depend on iteration order)
    * a repeated reference that closes a cycle → ``{"__cycle__": true}``
    * anything else that is not ``str``/``int``/``bool``/``None``/mapping/sequence →
      ``{"__type__": <class name>}``
    * a value past :data:`MAX_SANITIZE_DEPTH` or :data:`MAX_SANITIZE_NODES` →
      ``{"__truncated__": "depth" | "nodes"}``

    Mapping keys are coerced to strings (``canonical_json`` requires string keys) with the same
    care: a key whose ``str()`` raises becomes ``"__unrenderable_key__"``. Strings are cleaned by
    :func:`clean_text`, so the result encodes to UTF-8.

    Args:
        value: Anything at all, including a structure a model supplied.

    Returns:
        A structure :func:`baseaicore.canonical_json` accepts. Never raises, for any input.
    """
    return _sanitize(value, depth=0, seen=frozenset(), budget=[MAX_SANITIZE_NODES])


def _sanitize(value: object, *, depth: int, seen: frozenset[int], budget: list[int]) -> Any:  # noqa: ANN401, PLR0911 — one branch per JSON-hostile shape
    """Walk one value; see :func:`json_sanitize` for the substitution table."""
    if budget[0] <= 0:
        return {"__truncated__": "nodes"}
    budget[0] -= 1
    if depth > MAX_SANITIZE_DEPTH:
        return {"__truncated__": "depth"}
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"__nonfinite__": "nan"}
        if math.isinf(value):
            return {"__nonfinite__": "inf" if value > 0 else "-inf"}
        return value
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, bytes | bytearray):
        raw = bytes(value)
        return {"__bytes_sha256__": hashlib.sha256(raw).hexdigest(), "__len__": len(raw)}
    identity = id(value)
    if identity in seen:
        return {"__cycle__": True}
    nested = seen | {identity}
    if isinstance(value, dict):
        return {
            _sanitize_key(key): _sanitize(item, depth=depth + 1, seen=nested, budget=budget)
            for key, item in value.items()
        }
    if isinstance(value, set | frozenset):
        members = [_sanitize(item, depth=depth + 1, seen=nested, budget=budget) for item in value]
        return sorted(members, key=_stable_sort_key)
    if isinstance(value, list | tuple):
        return [_sanitize(item, depth=depth + 1, seen=nested, budget=budget) for item in value]
    return {"__type__": _class_name(value)}


def _sanitize_key(key: object) -> str:
    """Coerce a mapping key to a clean string, whatever it is."""
    if isinstance(key, str):
        return clean_text(key)
    try:
        return clean_text(str(key))
    except Exception:  # noqa: BLE001 — a key whose __str__ raises is exactly what this catches
        return "__unrenderable_key__"


def _class_name(value: object) -> str:
    """Return a value's class name, without touching the value itself.

    ``type(value).__name__`` cannot run user code the way ``repr`` can, which is the point: an
    object whose ``__repr__`` raises (or blocks, or is enormous) is one of the generated cases.
    """
    try:
        return str(type(value).__name__)
    except Exception:  # noqa: BLE001 — a metaclass can make even this fail
        return "unknown"


def _stable_sort_key(value: Any) -> tuple[str, str]:  # noqa: ANN401 — sorts sanitized JSON values
    """Order mixed-type sanitized values deterministically, by type name then by rendering.

    No guard here, unlike everywhere else in this module, and the absence is deliberate: this is
    called only on values :func:`_sanitize` has already returned, so every one is a ``str``,
    ``int``, ``float``, ``bool``, ``None``, ``list`` or ``dict``. Their ``repr`` cannot run user
    code and cannot raise. A ``try`` here would be an untestable branch dressed as caution.
    """
    return (type(value).__name__, repr(value))
