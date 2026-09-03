# Contributing to ToolYard

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## The gate

Everything below must pass before a pull request. It is identical to CI, and it is the whole gate —
there is nothing else to run.

```bash
ruff format --check .
ruff check --no-cache .
mypy src tests
lint-imports
pytest -m "not live and not performance"
```

`--no-cache` is not superstition. A stale `.ruff_cache` reports a file clean that CI then fails on;
that is exactly how a sibling repository in this suite shipped an import-order break with a green
local gate.

Coverage floor is **95 %** (shared packages carry the higher floor; applications use 85 %):

```bash
pytest --cov --cov-report=term-missing
```

The `performance` marker is excluded by default and run nightly:

```bash
pytest -m performance
```

## House method

**Docstring first.** Define the behaviour, write the Google-style docstring — including what the
function *refuses* — write the tests against it, then implement. This is the method, not a
preference.

* `from __future__ import annotations` at the top of every module.
* Units in every numeric name: `duration_ms`, `timeout_seconds`, `max_bytes`. A number without a
  unit in its name is a defect.
* Keyword-only for anything optional or boolean.
* `@dataclass(frozen=True, slots=True)` for value objects.
* Line length 100. `mypy --strict`, no bare `Any` at a public boundary, no `# type: ignore` without
  a trailing reason.

The one place `Any` is correct is a JSON Schema document, which is genuinely `Mapping[str, Any]` —
and the docstring there says why.

## The three things this package will not grow

Not style preferences; each is a decision with a record, and each has a test that fails if it is
reversed by accident.

1. **A refusal is a result, never an exception.** If a change makes something a model can influence
   raise — the name, the arguments, the output size, the encoding, the return type, the runtime —
   the change is wrong, whatever it fixes. Exceptions are for caller bugs: a duplicate registration,
   an invalid spec, a broken store. ADR-0053 decision 4 explains why, and the property suite
   asserts it over generated hostile input.
2. **No dynamic loading.** Not from configuration, not from entry points, not from a plugin
   directory, and not "just for tests". A test helper that loads a handler by import path is the
   first step back toward it. ADR-0053 rejects this on the merits and expects it to stay rejected;
   reopening it requires naming the consumer, the tools it cannot register in code, and how an
   unreviewed handler acquires a risk class and an egress class before a model can call it.
3. **The refusal order does not move.** registry → allowlist → schema → egress → containment. The
   positions are declared data and validated at import; changing one is a one-number diff, and a
   golden test plus a seven-rung ladder test will both fail. If an order change is genuinely right,
   it is an ADR and a spec amendment, not a patch.

`.importlinter` is likewise never weakened to make an import work. Two of its contracts are
*layered* and already carry the exemptions Phase 2 and Phase 3 will need — those phases add a
module, not a boundary rule.

## Tests

Property tests use `hypothesis` (a development dependency; the runtime budget is
`baseaicore` + `jsonschema`, and `httpx` from Phase 3).

**Replaying a failure.** Hypothesis prints a `@reproduce_failure(...)` decorator with the failing
example encoded in it. Paste it onto the test and run:

```python
from hypothesis import reproduce_failure


@reproduce_failure("6.100.0", b"AXicY2BkYGAAAAANAAI=")
@given(world=worlds(WORKSPACE))
def test_execute_returns_a_result_for_every_generated_input(world): ...
```

The `.hypothesis/` database also replays the last failure automatically on the next run in the same
checkout; it is gitignored, so CI does not have it and the decorator is what travels.

`pytest-randomly` reorders the suite on every run. A failure that only reproduces under one seed is
a **real ordering bug** — shared state leaking between tests — not a reason to pin the seed.

**Before adding a property, read `tests/strategies.py`'s module docstring.** It states the two rules
the corpus is built on: generate valid shapes rather than filtering invalid ones, and let a
generator label its own answer rather than writing an oracle that re-derives it. An oracle that
re-implements the thing it checks agrees with the bug.

**Validate a new property by breaking the code.** The suite was checked against ten deliberate
mutants — a reordered ladder, a digest taken without sanitization, redaction removed, the record
written only on success, the model handed an unresolved path, the containment root leaked into the
refusal — and all ten died. A property nothing can kill is a property that measures nothing.

## Commits

Conventional Commits. Update `CHANGELOG.md` under `## [Unreleased]` for any user-visible change —
and a new refusal reason is user-visible in the strongest sense, because PromptCadence maps reasons
onto deviation categories and a category nobody enumerated has no defined disposition.

## License

By contributing you agree that your contributions are licensed under Apache-2.0.
