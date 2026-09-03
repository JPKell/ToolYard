# Lockfiles

Exact, hash-verified pins for this repository's **own** CI and release pipeline, required by
Packaging and Release Standards §4 and Security Standards §11.

| File | Contents | Used by |
|---|---|---|
| `ci.lock` | Runtime dependencies plus the `dev` extra: the whole test, lint, type and boundary toolchain | Every blocking CI job |
| `release.in` / `release.lock` | The build and publish chain (`build`, `hatchling`, `twine`) | `release.yml`, and CI's `build` job |

## What these are not

They do **not** define what a consumer installs. `pip install toolyard` resolves the compatible
ranges in `pyproject.toml`; a library that shipped pinned runtime dependencies would be
un-coinstallable with the rest of the suite. These files exist so that a green build stays green:
without them every CI run re-resolves, and a new `ruff` or `mypy` release can change the result with
no commit to explain it — and `pip-audit` would be auditing today's resolution rather than what the
build actually used.

## The runtime dependencies, and the one that is deliberately absent

Gold standards §1.1 gives ToolYard a non-suite runtime budget of **two**: `jsonschema` and `httpx`.
Only the first is declared today.

`httpx` belongs to `http_fetch`, which is Phase 3 (row E2). Declaring it now would drag its
transitive tree — `httpcore`, `h11`, `anyio`, `certifi`, `idna`, `sniffio` — into this lock and into
`pip-audit`'s blast radius, so a CVE in a package no line of this repository imports could turn CI
red. It is declared in the same commit that first imports it. The `.importlinter` exemption that
will permit that import (`toolyard.tools.fetch -> httpx`) is **already written**, so E2 adds a
dependency and a module, and changes no boundary rule.

`hypothesis` is a development dependency and does not touch the runtime budget. ToolYard's central
claim — that nothing a model can influence raises — is a statement about *arbitrary* input, so it is
tested that way (spec §18). Nothing under `src/` imports it, and a test asserts the whole import
allowlist.

## Regenerating

Run after any change to `pyproject.toml`'s dependencies or `dev` extra, and commit the result:

```bash
pip install pip-tools
pip-compile --strip-extras --extra dev --generate-hashes \
    --output-file requirements/ci.lock pyproject.toml
pip-compile --strip-extras --generate-hashes \
    --output-file requirements/release.lock requirements/release.in
```

`uv pip compile` is the sanctioned alternative (Security Standards §11).

Both files were generated with **pip-tools 7.6.1**, which reconstructs `--no-index` into the header
comment where earlier versions did not. That flag is part of the recorded command, not part of the
resolution: the locks were resolved against PyPI, and re-running the commands above reproduces
them — passing `--no-index` yourself does not, it fails to resolve. `release.lock` is byte-identical
to CutCtx's, LoadLedger's, WeightsDB's, MirrorWall's and ModelRack's below the header, which is the
check that the chain really is reproducible rather than merely pinned.

## Interpreter

Resolved on Python 3.13. Every pin's `requires-python` admits 3.12, and no pin is
CPython-ABI-specific, so the same lock installs on both supported versions; the 3.14 early-warning
job deliberately resolves from ranges instead, because pinning a version that has no 3.14 wheels
would defeat the purpose of an early warning.

## Coverage measures the installed package, not the checkout

CI installs the built distribution (`pip install . --no-deps`), not an editable checkout, so
`[tool.coverage.run] source` in `pyproject.toml` names the **importable package** rather than
`src/toolyard`. A path-based source reports 0 % against a non-editable install — the tests all pass,
nothing is measured, and the coverage gate fails with a number that looks like a catastrophe instead
of a configuration error.
