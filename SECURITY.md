# Security Policy

ToolYard is part of the Local AI Suite. It is the component with the most to say here, because it
is the one place in the suite that executes a real, side-effecting operation on a model's behalf —
and therefore the one place the associated risk concentrates.

## Threat model

Stated plainly, because it is the design input rather than a worst case
([spec §14](docs/packages/toolyard/spec.md), [ADR-0053](docs/packages/toolyard/spec.md)):

* **Tool arguments are attacker-controlled.** A model chooses the tool name and every argument, and
  a model may be under the influence of content it read earlier — prompt injection through a tool
  result is the *expected* attack, not a hypothetical.
* **Tool results are attacker-influencing.** What a tool returns goes back into a prompt.
* ToolYard's job is that neither can reach the filesystem outside containment, the network outside
  the allowlist, or a shell.

## The controls, and where each lives

| Control | Where | Asserted by |
|---|---|---|
| Registration is code, at startup, or it does not happen | `registry.py` | No `unregister`, no loader, no entry-point read; a test asserts the whole public surface and greps for `importlib` |
| Exact-name lookup only | `registry.py` | A near-miss is `unknown_tool`; cleaning a name for the *record* never cleans it for the *lookup* |
| Fixed refusal order, first failure reported | `executor.py` | Declared positions validated at import; a request failing every check walked down all seven rungs |
| Model input never raises | `executor.py`, `_safe.py` | Property tests over generated hostile names, arguments and handler behaviour |
| Argument schemas are closed | `validation.py` | `additionalProperties: false` required at *every* object subschema, checked when a `ToolSpec` is constructed |
| `$ref` refused in a tool schema | `validation.py` | A reference is a URI and an unresolved one is *fetched* — refusing the keyword removes the door rather than guarding it |
| Containment is resolution-then-check | `containment.py` | Symlink escape, `..`, absolute paths, prefix-collision roots (`/data` vs `/database`), write-into-read-root |
| Isolation never degrades silently | `containment.py`, `executor.py` | No tier ⇒ `isolation_unavailable`. There is no host-execution tier and no flag that creates one |
| No `shell=True`, anywhere | — | An AST test over `src/`, written in Phase 1, before the phase that adds `subprocess` |
| Refusal text is prompt surface | `executor.py` | A refusal names the failed check, never a containment root's path and never the allowlist's members — asserted as a property |
| Every call is recorded | `executor.py` | Exactly one record per call, whatever the outcome; `redact_args` stores the digest and never the plaintext, at any length |
| Nothing is logged that redaction hides | `executor.py` | DEBUG carries names and statuses only; a test drives a redacted call and asserts the plaintext appears in no log record |

## What is not built yet

This repository is at **Phase 1**. The tiered isolation ladder (container → bwrap → refuse) and the
five built-in tools — including `http_fetch` and its ADR-0026 §3 checks — are Phase 2 and Phase 3.
Until they land there is no code here that spawns a process or opens a socket, and the boundary
rules in `.importlinter` say so: only the (future) `toolyard.sandbox` may import `subprocess`, only
the (future) `toolyard.tools.fetch` may hold an HTTP client.

That ordering is deliberate and is recorded as a security ordering, not a preference: the refusal
machinery and containment exist and are tested **before** any handler that could do harm, so at no
commit in this repository's history does an unvalidated model argument reach a side effect.

## Handling of arguments and results

* No argument is interpolated into a path, a command or a URL. Path arguments are declared on the
  spec, resolved by the sandbox before the handler runs, and handed to the handler **already
  resolved** — a handler that re-resolves a candidate reopens the window containment just closed.
* No result is parsed, executed, or trusted to be well-formed text. Output is cleaned of NUL and
  lone surrogates, hashed in full, and capped with a label.
* No reason string is built by formatting an argument in without a cap. A handler's exception
  reaches the model as a filtered class name and a capped message — never a traceback, which would
  name the application's paths and internals to a reader whose input is assumed adversarial.
* `SuiteError.details` carries the invocation id, the tool name and the status. Never arguments,
  never content: `details` travels into API error envelopes.
* No prompt text appears anywhere in this package. A prompt is named by `prompt_id` (ADR-0012), and
  a test refuses long string literals in `src/`.

## Reporting a vulnerability

Please do not open a public issue for a suspected security vulnerability.

Report it privately to the maintainer with:

* A description of the issue and its potential impact.
* Steps to reproduce: the `ToolSpec` (schema included), the allowlist, the `ToolContext`'s roots and
  ceilings, and the call that was made. This package's whole configuration surface is its
  constructor arguments (spec §12) — it reads no environment and no files — so that is enough to
  reproduce anything it does. Please redact argument *values*; their shapes and types are what
  matter.
* The installed package version (`pip show toolyard`). This package ships no CLI.

You should expect an acknowledgement within a reasonable time and, once a fix is available, credit
in the release notes unless you ask otherwise.

## Scope

In scope: this repository's own code and its documented configuration surface. A report that a
refusal can be turned into an exception, that a check can be reordered, that a path can be resolved
outside its roots, or that a refusal string leaks a root or the allowlist is **in scope and
welcome** — those are the properties this package exists to hold.

Vulnerabilities in the operating system or in a third-party dependency should be reported to that
project directly; `pip-audit` runs in this repository's CI over the locked sets rather than over the
job's own environment.

Out of scope: a tool *handler's* behaviour. ToolYard validates, authorizes, contains and records;
what a registered handler does inside those bounds is that handler's own security surface, and
handlers are registered by an application in code that someone reviewed.
