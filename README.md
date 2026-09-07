# ToolYard

Disciplined execution of model-directed tool calls, for the Local AI Suite. ToolYard is the one
place in the suite that runs a real, side-effecting operation on a model's behalf — so it is the one
place the discipline lives: schema validation, allowlisting, path containment, tiered subprocess
isolation, egress-checked fetching, structured refusals, and a persisted record of every call.

**Status: Phase 3 complete, `0.1.1` — on PyPI.** The vocabulary, the registry, the executor's fixed
refusal order, path containment, the record, the isolation ladder — container → bwrap → refuse —
and the five built-in tools (`read_file`, `write_file`, `list_dir`, `run_command`, `http_fetch`)
are built and gated.

* Import name and distribution name: `toolyard`
* Runtime dependencies: `baseaicore`, `jsonschema`, `httpx` — and that is the whole budget
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
| `not_approved` | allowlist | Inside the trajectory allowlist, outside this invocation's approved set. The application's drift to resolve |
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
| **Containment is resolution-then-check** | Fully resolved — symlinks, `..`, relative parts — *then* compared by path ancestry, so `/data` and `/database` are two roots; `SandboxPaths` refuses relative or overlapping roots at construction |
| **Refusal text is prompt surface** | A reason names the failed check; never the allowlist's members and never a containment root's path |
| **Wire definitions are byte-stable** | Fixed key set, deep-copied schema, sorted export order — because PromptCadence hashes them into turn records |
| **No `shell=True`, anywhere** | An AST test over `src/` says so, and a second one pins the package to exactly one process-launch site |
| **Isolation never degrades silently** | Container → bwrap → refuse, each rung proven by running its real argv around `/bin/true`. No tier means `isolation_unavailable`, never an unisolated run — and a rung that fails after it was decided raises rather than degrading |
| **The child environment is an allowlist** | `env=None` is the empty mapping, never `os.environ`; the sandbox binary itself is launched with `PATH` alone |
| **A limit is enforced or reported** | CPU time, memory, file size and process count, applied inside the sandbox; whatever a rung cannot apply is named in `limits_unenforced` (ADR-0016) |
| **One fetch discipline, proven shared** | The ADR-0026 §3 checks are made at the socket, and `tests/fixtures/fetch/adr0026_vectors.json` is byte-identical to LoadCoach's copy, drives both implementations, and has its sha256 asserted in both repositories |
| **`http_fetch` carries no credential** | No `Authorization` header, no environment or file read, no argument through which a secret could arrive |
| **A handler refuses by returning** | `ToolRefusal` carries a `Reason` from the same closed set the executor uses, so a fetch violation reports the specific check rather than an exception's class name |

## The five built-in tools

| Tool | Class | What it refuses |
|---|---|---|
| `read_file` | `READ_ONLY` | A path outside the readable roots; a file over the cap (refused whole, never returned in part); bytes that are not UTF-8 |
| `write_file` | `MUTATING` | A path outside the write root; a parent directory that is a symbolic link; a final component that is one |
| `list_dir` | `READ_ONLY` | A path outside the readable roots; anything that is not a directory. Sorted, capped, and it says how many it omitted |
| `run_command` | `MUTATING` | Everything, on a host with no isolation tier. Argv only — no shell, no network, no `os.environ` |
| `http_fetch` | `READ_ONLY`, `NETWORK` | Every ADR-0026 §3 rule, re-checked on every redirect hop; a response that is not text; a body over the cap, stopped mid-stream |

Each returns the `(spec, handler)` pair the registry takes:

```python
registry.register(*read_file_tool())
registry.register(*run_command_tool(sandbox))  # the executor's own sandbox instance
registry.register(*http_fetch_tool(["docs.example"], resolve=my_resolver))
```

`http_fetch`'s `resolve` is required and has no default. The link-local rule compares addresses
*after* resolution, and `.importlinter` forbids `socket` in every module of this package — so
ToolYard opens no resolver socket of its own, and the application supplies one:

```python
import socket


def my_resolver(host: str) -> list[str]:
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except OSError:
        return []
```

A resolver that answers nothing for every host makes the link-local check vacuous, which is exactly
why this argument has no default rather than a convenient one.

## Acceptance

`acceptance/register_and_execute.py` is spec §20 criterion 2 as a runnable check: it registers a
custom tool and executes it with only `toolyard` and its declared dependencies installed. It exits
non-zero when a claim fails, so it is a check rather than a demonstration.

```bash
python -m venv /tmp/toolyard-acceptance
/tmp/toolyard-acceptance/bin/pip install .
/tmp/toolyard-acceptance/bin/python acceptance/register_and_execute.py
```

## Isolation: container → bwrap → refuse

`TieredSandbox` is the Phase-2 implementation of the `Sandbox` port. It composes `PathContainment`
for the path half and adds the ADR-0018 ladder for commands:

```python
from pathlib import Path

from toolyard import ResourceLimits, SandboxPaths, TieredSandbox

sandbox = TieredSandbox(limits=ResourceLimits(cpu_seconds=30, memory_bytes=512 << 20))
report = sandbox.report()  # probes once, caches; show this in your `doctor` command
report.tier  # IsolationTier.CONTAINER | BWRAP | UNAVAILABLE
report.reason  # every rung visited, in order, and why each was skipped or taken
report.limits_unenforced  # () here; the names of any limit this rung could not apply

outcome = sandbox.run_isolated(
    ["python3", "-c", "print('hello')"],
    paths=SandboxPaths(write_root=Path("/srv/work")),
    timeout_seconds=10.0,
    env={"PATH": "/usr/bin:/bin"},  # the allowlist; None means *nothing*, never os.environ
)
outcome.exit_code, outcome.stdout, outcome.tier, outcome.timed_out, outcome.output_truncated
outcome.limits_unenforced
```

* **The probe executes a canary.** Each rung is proven by running the exact argv `run_isolated`
  would build — same flags, same limits, a temporary workspace bound the same way — around
  `/bin/true`. A `bwrap` that cannot create namespaces, a container daemon that is down, or an image
  that was never pulled each fail their canary and are reported with the reason. The container rung
  uses `--pull=never`, so a probe never reaches the network.
* **Forcing a lower rung** is done by shaping the probe's view, never by mutating the host:
  `TieredSandbox(which=lambda name: None if name in ("podman", "docker") else shutil.which(name))`
  makes bwrap the top of the ladder. There is no way to force a rung *above* what the probe found,
  and no rung below refusal.
* **What a command sees.** The write root read-write and the read roots read-only, bound in place
  and nothing else from the host beyond the minimal runtime (`/usr`, `/bin`, `/sbin`, `/lib`,
  `/lib64` and six named `/etc` entries); a private `/tmp`, `/proc` and `/dev`; **no network** —
  `run_isolated`'s `network` flag is refused in v1, because no shipped tool runs a subprocess with
  network and a door with no consumer stays shut; the environment the caller named and nothing
  else.
* **The workspace is validated where it is built.** `SandboxPaths` refuses a relative root (it
  would resolve against the process working directory) and roots that are equal to or contain one
  another (the two containment halves would disagree about them), at construction.
* **Timeouts kill the tree**, output bombs are capped and killed with the truncation label on the
  text, and a `run_command`-style tool must declare `requires_isolation` — the executor refuses it
  before any handler runs on a host with no tier, and ToolYard cannot detect a handler that reaches
  for a subprocess without declaring it.
* **Linux only.** macOS and Windows have no tier and are not probed (spec §16); every other tool
  works there.

The marked suite, `pytest -m isolation`, runs both rungs for real and skips loudly where one is not
available. It needs `python3` on the host for the bwrap rung and the image (`python:3.12-slim` by
default) pulled locally for the container rung.

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
