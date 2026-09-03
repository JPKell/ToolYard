# ToolYard — Development Plan

**Sequence position:** PromptCadence arc, stream P ([roadmap §4](../../roadmap/promptcadence-roadmap.md)).
Depends on `baseaicore>=0.4.1`. Independent of the other new packages; may run in parallel with
CutCtx.
**Target:** `toolyard 0.1.0` at the end of Phase 3; `0.2.0` (hardened, macOS/Windows refusal
behaviour verified) before PromptCadence 1.0.

The ordering is security-first: the refusal machinery and containment exist and are tested
**before** any handler that could do harm, so at no commit in this repository's history does an
unvalidated model argument reach a side effect.

---

## Phase 1 — Specs, registry, executor discipline, refusal paths

**Goal:** the full validate → authorize → record pipeline works with a harmless fake tool; every
refusal path produces a structured result.

**Prerequisites:** the D-9 ADR accepted ([roadmap §2](../../roadmap/promptcadence-roadmap.md)).

**Work**
* Repository skeleton (standard toolchain).
* `types.py`: `ToolSpec`, `ToolContext`, `ToolCallRequest`, `ToolResult`, `ToolCallRecord`,
  `RiskClass`, `EgressClass`, `ToolStatus`; `wire_definition()` with a committed golden.
* `registry.py`: registration (duplicate raises), exact-name lookup, policy filtering, wire
  export.
* `executor.py`: the fixed refusal order — registry → allowlist → schema (`jsonschema`,
  draft 2020-12) → egress → containment — each failure a `REFUSED` result naming the check;
  handler exceptions → `FAILED`; timeouts → `TIMEOUT`; size caps with labelled truncation;
  records appended for every call, `redact_args` honoured.
* `store.py`: `ToolCallStore` protocol + an in-memory implementation for tests.
* `errors.py` (caller bugs only).

**Files/subsystems**
```text
src/toolyard/{__init__,__about__,types,registry,executor,store,errors}.py
tests/unit/{test_types,test_registry,test_executor,test_records}.py
```

**Tests**
* Every spec §13 refusal row via `execute()`, asserting result-not-exception and the recorded
  reason string.
* Refusal order: a call failing several checks reports the **first**, deterministically.
* Records for OK, REFUSED, FAILED, TIMEOUT; redaction stores hash only; hashes stable.
* Wire-definition golden byte-stable.

**Acceptance criteria**
1. No exception escapes `execute()` under a fuzzing test that mutates names, args and outputs.
2. `mypy --strict` clean; coverage ≥ 95 %.

**Known risks:** the refusal taxonomy proving too coarse for PromptCadence's deviation handling.
Mitigated by machine-readable `reason` strings being part of the public contract from day one.
**Likely failure modes:** an executor path that raises on a malformed record write; schema
validation accepting extra properties by default.
**Gold standards:** model input never raises; every call recorded.
**Deferred:** containment, isolation, built-ins.

---

## Phase 2 — Sandbox: containment and tiered isolation

**Goal:** path containment and the container → bwrap → refuse ladder, proven hostile-input-first.

**Prerequisites:** Phase 1.

**Work**
* `sandbox.py`: `SandboxPaths`, resolution-then-check for read and write separately; the
  isolation-tier probe; `run_isolated` with argv-only execution, env allowlist, resource limits
  (`resource` where supported, recorded where not), process-tree kill on timeout.
* Reuse the ADR-0018 tier order and detection approach FreeWeight proved (container runtime, then
  bwrap, then refuse) — the *pattern* is reused; the code is this package's own, because
  FreeWeight is an application and applications are never imported.

**Files/subsystems**
```text
src/toolyard/sandbox.py
tests/unit/test_containment.py
tests/integration/test_isolation.py            # marked: needs bwrap or a container runtime
```

**Tests**
* Containment: symlink escape, `..`, absolute paths, prefix-collision roots (`/data` vs
  `/database`), write into a read root — all refused with root and target named.
* Tier probe on a host with neither tier ⇒ `UNAVAILABLE`; `run_isolated` then refuses.
* Marked, on the reference machine: bwrap denies network, denies reads outside roots, denies
  writes outside `write_root`; timeout kills children; limits enforced.
* Grep test: no `shell=True` anywhere in `src/`.

**Acceptance criteria**
1. The containment suite passes with zero live-sandbox dependencies; the marked suite passes on
   the reference machine.
2. A deliberately malicious scripted tool (symlink race, output bomb, fork attempt) is contained
   or refused, never propagated.

**Known risks:** bwrap availability and flags varying across distributions. Mitigated by the
probe executing a canary command rather than trusting version strings.
**Likely failure modes:** TOCTOU between resolution and use (resolve inside the check, operate on
the resolved path, never the candidate); orphaned grandchildren on timeout.
**Gold standards:** refusal is the floor — no unisolated execution exists in any code path.
**Deferred:** macOS/Windows tiers.

---

## Phase 3 — Built-in tools — publish 0.1.0

**Goal:** the five shipped tools, each the disciplined version of an operation the suite already
regulates elsewhere.

**Prerequisites:** Phase 2. `http_fetch` also wants the ADR-0026 §3 shared test vectors
(coordinate with LoadCoach's existing fetch tests so both pass the same cases).

**Work**
* `tools/files.py`: `read_file`, `write_file`, `list_dir` under containment, size caps.
* `tools/command.py`: `run_command` (argv, isolated, no network).
* `tools/fetch.py`: `http_fetch` with the full ADR-0026 §3 discipline via `httpx`.
* README, quickstart (register-and-execute standalone example), security notes; publish
  `toolyard 0.1.0`.

**Files/subsystems**
```text
src/toolyard/tools/{__init__,files,command,fetch}.py
tests/unit/{test_files_tools,test_command_tool,test_fetch_tool}.py
tests/fixtures/fetch/*                          # recorded transports for every §3 case
```

**Tests**
* Files: caps, containment reuse, unicode and binary handling, missing-file → `FAILED` with a
  clean reason.
* Command: argv only; env allowlist; exit codes and streams captured; refusal without a tier.
* Fetch: the shared ADR-0026 vector set — scheme, allowlist, literal IP after resolution,
  redirect re-check per hop, size cap mid-stream — against recorded transports, no network.

**Acceptance criteria**
1. Spec §20 criteria 2–4 met; `toolyard 0.1.0` published and installable standalone.
2. The fetch vectors are byte-shared with LoadCoach's (one fixture set, two repositories, both
   green).

**Known risks:** built-ins accreting convenience flags that widen the attack surface. Mitigated
by the non-goals list and review against it.
**Likely failure modes:** a fetch redirect check applied to the first hop only; `write_file`
creating parents outside the root via a symlinked intermediate directory.
**Gold standards:** one fetch discipline suite-wide; typed refusals; ≥ 95 % coverage.
**Deferred:** result-schema enforcement; IdeaPress research adoption; platform tiers; rate
limits (0.2.0 hardening lands during PromptCadence P9 with the app's security pass).
