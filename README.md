# ToolYard

Disciplined execution of model-directed tool calls, for the Local AI Suite. ToolYard is the one
place in the suite that runs a real, side-effecting operation on a model's behalf — so it is the one
place the discipline lives: schema validation, allowlisting, path containment, tiered subprocess
isolation, egress-checked fetching, structured refusals, and a persisted record of every call.

**Status: Phase 1, unreleased.** The vocabulary, the registry, the executor's fixed refusal order,
path containment and the record are built and gated. The isolation ladder is Phase 2; the five
built-in tools (`read_file`, `write_file`, `list_dir`, `run_command`, `http_fetch`) are Phase 3,
which is when `toolyard 0.1.0` is published. Nothing here is on PyPI yet, and the only tools in this
repository today are harmless fakes under `tests/`.

* Import name and distribution name: `toolyard`
* Runtime dependencies: `baseaicore`, `jsonschema` — and `httpx` from Phase 3
* Python: 3.12+
* Specification: [`docs/packages/toolyard/spec.md`](docs/packages/toolyard/spec.md) ·
  plan: [`docs/packages/toolyard/development-plan.md`](docs/packages/toolyard/development-plan.md)

## The one thing to understand: a refusal is a result

Not an exception. A tool that does not exist, a name outside the allowlist, arguments that fail the
schema, a path that escapes its root, a handler that raises, a call that runs long — every one of
them comes back as a `ToolResult` with a status and a machine-readable reason.

That is not politeness, it is control flow. The **model** chooses the tool name and every argument,
so if bad input raised, the model would choose when the exception fires — and an exception crossing
an agent loop ends the turn, often the trajectory. Exceptions here are reserved for **caller** bugs:
a duplicate registration, an invalid spec, a broken store.

```python
result = executor.execute(
    ToolCallRequest(name="rm_rf", args={}),
    ToolContext(invocation_id="inv-7", workspace=SandboxPaths(write_root=root)),
)
result.status  # ToolStatus.REFUSED
result.reason  # 'unknown_tool'  — from a closed set; PromptCadence maps it to a deviation
result.content  # "Tool 'rm_rf' — unknown_tool: no tool of that name is registered"
```

## The shape: register → execute → record

```python
from pathlib import Path

from toolyard import (
    EgressClass,
    InMemoryToolCallStore,
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


class ReadNotes:
    def execute(self, args, context):
        # `args["path"]` has already been resolved and contained. Never re-resolve it.
        return ToolOutput(content=Path(args["path"]).read_text(encoding="utf-8"))


spec = ToolSpec(
    name="read_notes",
    description="Read one note from the workspace.",
    args_schema={
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
        "additionalProperties": False,  # required, not merely recommended — see below
    },
    result_schema=None,
    risk_class=RiskClass.READ_ONLY,
    egress=EgressClass.NONE,
    path_args={"path": PathAccess.READ},  # what makes the containment check have an input
)

registry = ToolRegistry()
registry.register(spec, ReadNotes())

store = InMemoryToolCallStore()  # tests only; your application owns the real table
executor = ToolExecutor(
    registry, PathContainment(), allowlist=frozenset({"read_notes"}), store=store
)

result = executor.execute(
    ToolCallRequest(name="read_notes", args={"path": "today.md"}),
    ToolContext(invocation_id="inv-1", workspace=SandboxPaths(write_root=Path("/srv/work"))),
)
store.records[0].status, store.records[0].reason  # every call is recorded, refusals included
```

Registration is **code, at startup, or it does not happen**. There is no loading of tool code from
configuration, from a plugin directory, from an entry point, or from anything a model emitted — and
no `unregister`, so there is no code path that could grow one.

## The fixed refusal order

```text
registry  →  allowlist  →  schema  →  egress  →  containment
```

Always that order, and the reason names the **first** check that failed, so a refusal is diagnosable
from the record alone without re-running anything. The order is a declared sequence the executor
walks — not a chain of `if` statements — and the package refuses to import if the declared positions
are not a complete sequence. A request that fails every check is walked down all seven rungs in
`tests/unit/test_executor.py::TestRefusalOrder`.

| Reason | Check | Means |
|---|---|---|
| `unknown_tool` | registry | No tool of exactly that name. Lookup is exact: no fuzzy match, no case folding, no aliasing |
| `not_allowlisted` | allowlist | Outside the trajectory allowlist. **Never re-approvable** — the allowlist is the caller's |
| `not_in_intent` | allowlist | Inside the trajectory allowlist, outside this turn's approved set. The application's drift to resolve |
| `args_invalid` | schema | With the validator's JSON paths, so a model can see *which* argument was wrong |
| `egress_not_permitted` | egress | The tool reaches the network; this invocation's ceiling does not allow it |
| `isolation_unavailable` | containment | The tool needs a subprocess and this host has no tier. ADR-0018's floor, never an unisolated run |
| `path_escape` | containment | A declared path argument resolved outside its root |
| `timeout` | — | Elapsed against the limit. `TIMEOUT`, and the output is discarded |
| `handler_error` | — | The handler raised or broke its contract. Class name and capped message; **no traceback** |

## What it guarantees

| | |
|---|---|
| **Model input never raises** | Name, arguments, output size, output encoding, return type, runtime — all resolve to a result. Asserted over generated hostile input, not just examples |
| **The refusal order is fixed** | And structural: positions are declared data, validated at import, pinned by a golden |
| **Every call is recorded** | `OK`, `REFUSED`, `FAILED`, `TIMEOUT` alike — exactly one record per call |
| **`redact_args` means redacted** | `args_sha256` always present, `args_json` `None`; the plaintext reaches no field, at no length |
| **Argument schemas must be closed** | `additionalProperties: false` at *every* object subschema, checked at construction — an open schema is a tool a model can pass unreviewed arguments to |
| **`$ref` is refused in a tool schema** | A reference is a URI, and a validator handed an unresolved one tries to *fetch* it |
| **Containment is resolution-then-check** | Fully resolved — symlinks, `..`, relative parts — *then* compared by path ancestry, so `/data` and `/database` are two roots |
| **Refusal text is prompt surface** | A reason names the failed check; never the allowlist's members and never a containment root's path |
| **Wire definitions are byte-stable** | Fixed key set, deep-copied schema, sorted export order — because PromptCadence hashes them into turn records |
| **No `shell=True`, anywhere** | A grep test over `src/` says so, and it was written in Phase 1 so Phase 2 finds it already failing |

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

The full gate, identical to CI:

```bash
ruff format --check . && ruff check --no-cache . && mypy src tests && lint-imports \
  && pytest -m "not live and not performance"
```

`--no-cache` on the lint step is not superstition: a stale `.ruff_cache` reports a clean file that
CI then fails, which is exactly how a sibling repository shipped an import-order break.

Property tests use `hypothesis` (a development dependency; the runtime budget is unaffected). A
failing example prints a `@reproduce_failure` decorator you can paste onto the test to replay it —
see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

This is the package in the suite with something real to say about it: read
[`SECURITY.md`](SECURITY.md). Tool arguments are attacker-controlled and tool results are
attacker-influencing — that is the stated threat model, not a worst case.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
