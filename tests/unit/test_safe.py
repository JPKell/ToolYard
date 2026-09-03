"""The total functions: nothing in :mod:`toolyard._safe` raises, for any input at all.

Tested directly rather than only through ``execute()``, because "this never raises" is the claim
the whole package rests on and a claim tested only indirectly is a claim tested only where it
happened to be reached.
"""

from __future__ import annotations

import math
from typing import Any

import pytest
from baseaicore import canonical_json, sha256_of

from toolyard._safe import (
    MAX_SANITIZE_DEPTH,
    MAX_SANITIZE_NODES,
    TRUNCATION_LABEL_TEMPLATE,
    clean_text,
    json_sanitize,
    truncate_text,
)


class Unrenderable:
    """An object whose ``__str__`` and ``__repr__`` both raise."""

    def __str__(self) -> str:
        """Raise."""
        raise RuntimeError("no")

    def __repr__(self) -> str:
        """Raise."""
        raise RuntimeError("no")


class TestCleanText:
    """NUL and lone surrogates: the two things a string can hold that a record cannot."""

    def test_ordinary_text_is_returned_unchanged(self) -> None:
        assert clean_text("hello world") == "hello world"

    def test_unicode_is_preserved(self) -> None:
        assert clean_text("naïve 🙂 テスト") == "naïve 🙂 テスト"

    def test_nul_is_removed(self) -> None:
        assert clean_text("a\x00b") == "ab"

    def test_a_lone_surrogate_is_removed(self) -> None:
        assert clean_text("a\ud800b") == "ab"
        clean_text("a\ud800b").encode("utf-8")

    def test_newlines_and_tabs_survive(self) -> None:
        """A tool's output is text; mangling it further is a second lie about what it produced."""
        assert clean_text("a\n\tb") == "a\n\tb"

    def test_the_result_always_encodes(self) -> None:
        for value in ("\ud800", "\udfff\x00", "ok", "\ud800𐐀"):
            clean_text(value).encode("utf-8")


class TestTruncateText:
    """The cap is on the returned string, label included."""

    def test_text_within_the_cap_is_returned_unlabelled(self) -> None:
        assert truncate_text("short", max_bytes=1_000) == ("short", False)

    def test_text_over_the_cap_is_cut_and_labelled(self) -> None:
        text, truncated = truncate_text("x" * 5_000, max_bytes=500)
        assert truncated
        assert len(text.encode("utf-8")) <= 500
        assert TRUNCATION_LABEL_TEMPLATE.split("{")[0].strip() in text

    def test_the_label_states_both_byte_figures(self) -> None:
        text, _ = truncate_text("x" * 5_000, max_bytes=500)
        assert "of 5000 bytes" in text

    def test_a_multibyte_character_is_never_split(self) -> None:
        text, _ = truncate_text("🙂" * 1_000, max_bytes=300)
        text.encode("utf-8").decode("utf-8")
        assert len(text.encode("utf-8")) <= 300

    def test_a_cap_too_small_for_the_label_hard_cuts_rather_than_overflowing(self) -> None:
        """Exceeding the cap the caller asked for would be worse than an unlabelled cut."""
        text, truncated = truncate_text("🙂" * 100, max_bytes=8)
        assert truncated
        assert len(text.encode("utf-8")) <= 8

    def test_a_cap_of_zero_returns_nothing(self) -> None:
        assert truncate_text("anything", max_bytes=0) == ("", True)

    def test_the_input_is_cleaned_so_the_figures_describe_what_the_caller_gets(self) -> None:
        text, truncated = truncate_text("a\x00b", max_bytes=1_000)
        assert (text, truncated) == ("ab", False)


class TestJsonSanitize:
    """Every substitution, and the promise that the result always canonicalizes."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, None),
            (True, True),
            (17, 17),
            (1.5, 1.5),
            ("text", "text"),
            ([1, "a"], [1, "a"]),
            ((1, "a"), [1, "a"]),
            ({"k": 1}, {"k": 1}),
        ],
    )
    def test_json_shaped_values_pass_through(self, value: object, expected: object) -> None:
        assert json_sanitize(value) == expected

    @pytest.mark.parametrize(
        ("value", "tag"),
        [(math.nan, "nan"), (math.inf, "inf"), (-math.inf, "-inf")],
    )
    def test_non_finite_floats_become_a_tag(self, value: float, tag: str) -> None:
        assert json_sanitize(value) == {"__nonfinite__": tag}

    def test_bytes_become_a_digest_and_a_length_never_the_bytes(self) -> None:
        sanitized = json_sanitize(b"secret bytes")
        assert set(sanitized) == {"__bytes_sha256__", "__len__"}
        assert "secret" not in canonical_json(sanitized)

    def test_a_bytearray_is_treated_the_same(self) -> None:
        assert json_sanitize(bytearray(b"ab")) == json_sanitize(b"ab")

    def test_a_set_becomes_a_sorted_list_so_iteration_order_cannot_reach_a_hash(self) -> None:
        assert sha256_of(json_sanitize({3, 1, 2})) == sha256_of(json_sanitize({2, 3, 1}))

    def test_a_set_of_mixed_types_still_sorts_deterministically(self) -> None:
        mixed: set[Any] = {1, "a", 2.5, None, frozenset({7})}
        assert sha256_of(json_sanitize(mixed)) == sha256_of(json_sanitize(set(mixed)))

    def test_a_cycle_is_tagged_rather_than_followed(self) -> None:
        cyclic: dict[str, Any] = {"a": 1}
        cyclic["self"] = cyclic
        assert json_sanitize(cyclic) == {"a": 1, "self": {"__cycle__": True}}

    def test_a_list_cycle_is_tagged_too(self) -> None:
        looped: list[Any] = [1]
        looped.append(looped)
        assert json_sanitize(looped) == [1, {"__cycle__": True}]

    def test_an_arbitrary_object_becomes_its_class_name(self) -> None:
        assert json_sanitize(object()) == {"__type__": "object"}

    def test_an_object_whose_repr_raises_is_still_named_by_its_class(self) -> None:
        """``type(value).__name__`` cannot run user code the way ``repr`` can. That is the point."""
        assert json_sanitize(Unrenderable()) == {"__type__": "Unrenderable"}

    def test_a_key_whose_str_raises_is_replaced(self) -> None:
        assert json_sanitize({Unrenderable(): 1}) == {"__unrenderable_key__": 1}

    def test_a_non_string_key_is_rendered_as_a_string(self) -> None:
        assert json_sanitize({17: "v", None: "w"}) == {"17": "v", "None": "w"}

    def test_a_key_holding_a_nul_is_cleaned(self) -> None:
        assert json_sanitize({"a\x00b": 1}) == {"ab": 1}

    def test_depth_past_the_cap_is_tagged(self) -> None:
        nested: Any = "leaf"
        for _ in range(MAX_SANITIZE_DEPTH + 5):
            nested = {"n": nested}
        rendered = canonical_json(json_sanitize(nested))
        assert '"__truncated__":"depth"' in rendered

    def test_a_structure_wider_than_the_node_budget_is_tagged(self) -> None:
        rendered = canonical_json(json_sanitize(list(range(MAX_SANITIZE_NODES + 50))))
        assert '"__truncated__":"nodes"' in rendered

    @pytest.mark.parametrize(
        "value",
        [
            math.nan,
            b"bytes",
            {1, 2},
            object(),
            Unrenderable(),
            {"a": [math.inf, b"x", {frozenset({1})}]},
            [[[[[[[[[[math.nan]]]]]]]]]],
        ],
    )
    def test_the_result_always_canonicalizes(self, value: object) -> None:
        """The whole reason this module exists: ``canonical_json`` refuses every one of these."""
        canonical_json(json_sanitize(value))
        assert len(sha256_of(json_sanitize(value))) == 64

    def test_sanitizing_is_deterministic(self) -> None:
        value = {"a": [1, {2, 3}], "b": b"x", "c": math.nan}
        assert sha256_of(json_sanitize(value)) == sha256_of(json_sanitize(dict(value)))


class HostileMeta(type):
    """A metaclass whose ``__name__`` raises, so even ``type(x).__name__`` can fail."""

    @property
    def __name__(cls) -> str:  # type: ignore[override]  # deliberately breaks the class contract
        """Raise."""
        raise RuntimeError("even the class name is hostile")


class NamelessThing(metaclass=HostileMeta):
    """An instance of the metaclass above."""


def test_a_class_whose_name_raises_is_still_sanitized() -> None:
    """``type(value).__name__`` is the safe way to describe an object — but not the safe*st*.

    A metaclass can make even that raise, and this module promises totality without qualification.
    """
    assert json_sanitize(NamelessThing()) == {"__type__": "unknown"}


def test_sorting_a_sanitized_set_needs_no_guard_because_every_member_is_json() -> None:
    """The one place in the module with no ``try``, asserted so the reasoning stays visible."""
    sanitized = json_sanitize({b"a", 1, "z", None, math.nan})
    assert isinstance(sanitized, list)
    assert sanitized == sorted(sanitized, key=lambda item: (type(item).__name__, repr(item)))
