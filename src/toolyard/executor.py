"""The executor — five checks in one fixed order, and a result for everything a model can cause.

This module is the package. Everything else is vocabulary it walks over.

**The order is data, not control flow.** Spec §11.2 fixes registry → allowlist → schema → egress →
containment, and the reason for the fixed order is that a refusal has to be diagnosable from the
record alone: "the arguments were invalid" said about a tool that was never registered is a lie
about which fence the call hit. Writing that as a chain of ``if`` statements would make the order an
accident of source layout — reorderable in a later patch with no test failing, because almost every
real call fails exactly one check. So the checks are a declared sequence of named
:class:`_Check` records, each carrying its own position, and :func:`_ordered` refuses at import time
to build a ladder whose positions are not exactly ``0..n-1``. Rearranging the tuple literal changes
nothing (it is sorted); changing a position is a one-number diff that
``tests/unit/test_executor.py::TestRefusalOrder`` pins as a golden. The same test walks a request
that fails **every** check down the ladder one rung at a time, so the order is asserted rather than
assumed.

**Nothing a model influences raises.** ADR-0053 decision 4, taken literally and further than the
obvious cases: the name, the arguments, the handler's exception, the handler's *return type*, the
size of its output, the encodability of its text, the time it took, and the shape of the structure
that gets hashed into the record. Every one of those resolves to a
:class:`~toolyard.types.ToolResult`.
:mod:`toolyard._safe` exists because several of them would otherwise raise inside
:func:`baseaicore.canonical_json` on the model's behalf.

**The two deliberate exceptions, both to caller bugs, both documented at their raise site.**

* :class:`~toolyard.errors.StoreFailure`, when the application's store will not take a record. It
  carries the result and the record, because losing the audit trail of a side effect that already
  happened is worse than raising.
* A ``BaseException`` that is not an ``Exception`` — ``KeyboardInterrupt``, ``SystemExit``,
  ``GeneratorExit``. The call is recorded as ``FAILED`` first, and then it is **re-raised**. Model
  input cannot produce one: those are delivered by a signal or by the interpreter, not by a name, an
  argument, an output size or a runtime. Swallowing them would make an agent loop uninterruptible by
  the person running it, which trades a stop condition the model controls (the thing ADR-0053
  forbids) for one *nobody* controls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from baseaicore import ValidationError, canonical_json, monotonic_ns, sha256_of

from toolyard._safe import clean_text, json_sanitize, truncate_text
from toolyard.containment import PathAccess, PathEscape, require_timeout_seconds
from toolyard.errors import StoreFailure
from toolyard.types import (
    MAX_RECORDED_NAME_CHARS,
    EgressClass,
    Reason,
    RiskClass,
    ToolCallRecord,
    ToolOutput,
    ToolRefusal,
    ToolResult,
    ToolStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from toolyard.containment import Sandbox
    from toolyard.registry import ToolRegistry
    from toolyard.store import ToolCallStore
    from toolyard.types import RegisteredTool, ToolCallRequest, ToolContext

__all__ = [
    "DEFAULT_MAX_ARGS_JSON_BYTES",
    "DEFAULT_MAX_CONTENT_BYTES",
    "DEFAULT_MAX_SUMMARY_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "REFUSAL_ORDER",
    "ToolExecutor",
]

_LOGGER: Final[logging.Logger] = logging.getLogger("toolyard.executor")

DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
"""The limit applied when :attr:`~toolyard.types.ToolContext.timeout_seconds` is ``None``.

``None`` means *this*, never "no timeout" (spec §11.8). There is no way to express an unlimited
call — not a sentinel, not a zero, not a negative — because the value of a mandatory timeout is
entirely in there being no way around it.
"""

DEFAULT_MAX_CONTENT_BYTES: Final[int] = 65_536
"""How much of a tool's output the model sees, in UTF-8 bytes, before truncation and labelling."""

DEFAULT_MAX_SUMMARY_BYTES: Final[int] = 4_096
"""How much of that account reaches the record. Smaller: the record is a row, not an artifact."""

DEFAULT_MAX_ARGS_JSON_BYTES: Final[int] = 16_384
"""How large ``args_json`` may be before the record stores a size-and-digest object instead."""

MIN_CONTENT_BYTES: Final[int] = 256
"""The floor for any configured cap, so a truncation label always fits inside one."""

_MAX_HANDLER_MESSAGE_CHARS: Final[int] = 200
_MAX_CANDIDATE_REPORT_CHARS: Final[int] = 200
_EXCEPTION_NAME_ALPHABET: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_."
)


@dataclass(frozen=True, slots=True)
class _Refusal:
    """One check saying no: the closed reason, what the model is told, what the record adds."""

    reason: Reason
    detail: str
    record_detail: str | None = None
    status: ToolStatus = ToolStatus.REFUSED


@dataclass(slots=True)
class _Pass:
    """The mutable state one call threads through the ladder.

    Mutable because the checks are sequential by nature: check 1 finds the registration that check 3
    validates against, and check 5 produces the resolved arguments the handler receives. What is
    *not* mutable is the order they run in.
    """

    request: ToolCallRequest
    context: ToolContext
    sandbox: Sandbox
    allowlist: frozenset[str]
    registered: RegisteredTool | None = None
    handler_args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _Check:
    """One rung of the ladder, carrying the position that decides when it runs."""

    position: int
    name: str
    run: Callable[[_Pass], _Refusal | None]


def _check_registry(state: _Pass) -> _Refusal | None:
    """Check 1 — the name is one the application registered, spelled exactly."""
    registered = state.registered
    if registered is None:
        return _Refusal(Reason.UNKNOWN_TOOL, "no tool of that name is registered")
    return None


def _check_allowlist(state: _Pass) -> _Refusal | None:
    """Check 2 — the tool is callable in this trajectory, and approved for this invocation.

    Two refusals, in that order, because they mean different things to the application. Outside the
    *trajectory allowlist* is ``not_allowlisted`` and is never re-approvable: the allowlist is the
    caller's, not the model's. Outside this *invocation's* approved set is ``not_approved``, which
    is a drift the application may resolve by approving a superseding set and retrying. Reporting
    the trajectory refusal first matters: telling a model its call merely needs approval, when no
    approval could ever grant it, invites a re-approval that can only fail.

    The distinction is ToolYard's and holds for any consumer; a consumer maps each reason onto its
    own category — PromptCadence onto the ``undeclared_tool`` row of lifecycle §5, resolving the
    second by minting a superseding intent revision (ADR-0056 §3).
    """
    name = state.request.name
    if name not in state.allowlist:
        return _Refusal(Reason.NOT_ALLOWLISTED, "the tool is not callable in this trajectory")
    approved = state.context.approved_tools
    if approved is not None and name not in approved:
        return _Refusal(Reason.NOT_APPROVED, "the tool is not approved for this invocation")
    return None


def _check_schema(state: _Pass) -> _Refusal | None:
    """Check 3 — the arguments satisfy the tool's closed schema."""
    assert state.registered is not None  # noqa: S101 — check 1 guarantees it; mypy needs the fact
    detail = state.registered.args_validator.validate(state.request.args)
    if detail is not None:
        return _Refusal(Reason.ARGS_INVALID, detail)
    return None


def _check_egress(state: _Pass) -> _Refusal | None:
    """Check 4 — the tool's egress class is within this invocation's ceiling.

    The ceiling is :attr:`~toolyard.types.ToolContext.max_egress`, per invocation, defaulting to
    :attr:`~toolyard.types.EgressClass.NONE`. Spec §13 has this refusal and spec §7 gave the
    executor nothing to decide it from; this is that input. Per-invocation rather than
    per-executor because in the real consumer a trajectory's tier and classification decide whether
    network is allowed at all, and those are turn-scoped facts.
    """
    assert state.registered is not None  # noqa: S101 — check 1 guarantees it; mypy needs the fact
    required = state.registered.spec.egress
    if not state.context.max_egress.permits(required):
        return _Refusal(
            Reason.EGRESS_NOT_PERMITTED,
            "the tool reaches the network and this invocation does not permit egress",
        )
    return None


def _check_containment(state: _Pass) -> _Refusal | None:
    """Check 5 — a tier exists if one is needed, and every declared path lands inside its root.

    The two halves run in that order, and the sub-order is a decision rather than an accident: a
    tool that cannot run *at all* on this host is refused before its arguments are resolved, so a
    model is told the unfixable fact first instead of correcting a path and then hitting a wall it
    could never have crossed.

    Resolution happens here, before the handler exists to be called, and the resolved path is
    substituted into the arguments the handler receives. That is the resolution-then-check rule of
    spec §11.3 and the reason a handler must never re-resolve a candidate.
    """
    assert state.registered is not None  # noqa: S101 — check 1 guarantees it; mypy needs the fact
    spec = state.registered.spec
    if spec.requires_isolation:
        try:
            tier = state.sandbox.isolation_tier()
        except Exception:  # noqa: BLE001 — a probe that fails is a host with no tier, not a crash
            tier = None
        if tier is None or tier.value == "unavailable":
            return _Refusal(
                Reason.ISOLATION_UNAVAILABLE,
                "the tool requires process isolation and this host offers no tier",
            )
    args = state.request.args
    resolved: dict[str, Any] = dict(args) if isinstance(args, dict) else {}
    for argument, access in spec.path_args.items():
        if argument not in resolved:
            continue
        candidate = resolved[argument]
        try:
            if access is PathAccess.WRITE:
                target = state.sandbox.resolve_write(candidate, state.context.workspace)
            else:
                target = state.sandbox.resolve_read(candidate, state.context.workspace)
        except PathEscape as escape:
            shown = clean_text(str(escape.candidate))[:_MAX_CANDIDATE_REPORT_CHARS]
            return _Refusal(
                Reason.PATH_ESCAPE,
                f"the path argument {argument!r} ({shown!r}) resolves outside the "
                f"invocation's {escape.root_role}",
                record_detail=None if escape.root is None else f"root={escape.root}",
            )
        except Exception:  # noqa: BLE001 — the candidate is the model's; every failure is a refusal
            return _Refusal(
                Reason.PATH_ESCAPE,
                f"the path argument {argument!r} could not be resolved",
            )
        resolved[argument] = str(target)
    state.handler_args = resolved
    return None


def _ordered(checks: tuple[_Check, ...]) -> tuple[_Check, ...]:
    """Sort the ladder by declared position and refuse a ladder that is not a complete sequence.

    Args:
        checks: The declared checks, in any source order.

    Returns:
        The checks sorted by ``position``.

    Raises:
        ValidationError: At import time, if the positions are not exactly ``0..n-1``. That makes
            the order impossible to change by accident: adding a check without deciding where it
            goes, or duplicating a position, stops the package from importing rather than quietly
            producing a ladder with two rungs at the same height.
    """
    positions = sorted(check.position for check in checks)
    if positions != list(range(len(checks))):
        raise ValidationError(
            f"The refusal ladder must declare positions 0..{len(checks) - 1} exactly once each; "
            f"got {positions}. The order is spec §11.2's and is not a matter of source layout.",
            details={"positions": positions},
        )
    return tuple(sorted(checks, key=lambda check: check.position))


_CHECKS: Final[tuple[_Check, ...]] = _ordered(
    (
        _Check(0, "registry", _check_registry),
        _Check(1, "allowlist", _check_allowlist),
        _Check(2, "schema", _check_schema),
        _Check(3, "egress", _check_egress),
        _Check(4, "containment", _check_containment),
    )
)

REFUSAL_ORDER: Final[tuple[str, ...]] = tuple(check.name for check in _CHECKS)
"""The names of the checks, in the order they run. Spec §11.2, exported so a test can pin it."""


class ToolExecutor:
    """Runs one tool call: validate, authorize, execute, record. Returns; does not raise.

    The whole surface is one method. Deciding *to* call is the application's loop (spec §3): this
    object has no memory of previous calls, no retry policy and no opinion about what a refusal
    means for a trajectory.

    Configuration is constructor arguments only — no environment, no files (spec §12) — and every
    cap is validated here rather than at first use, so a misconfigured executor fails at startup
    and not on the one call that happened to overflow.
    """

    __slots__ = (
        "_allowlist",
        "_default_timeout_seconds",
        "_max_args_json_bytes",
        "_max_content_bytes",
        "_max_summary_bytes",
        "_monotonic_ns",
        "_registry",
        "_sandbox",
        "_store",
    )

    def __init__(
        self,
        registry: ToolRegistry,
        sandbox: Sandbox,
        *,
        allowlist: frozenset[str],
        store: ToolCallStore | None = None,
        default_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
        max_summary_bytes: int = DEFAULT_MAX_SUMMARY_BYTES,
        max_args_json_bytes: int = DEFAULT_MAX_ARGS_JSON_BYTES,
        monotonic_ns: Callable[[], int] = monotonic_ns,
    ) -> None:
        """Build an executor over a registry, a sandbox and a trajectory allowlist.

        Args:
            registry: The tools the application registered at startup.
            sandbox: The containment port. There is no ``None`` option: an executor without one
                would have a fifth check that does nothing, and the fixed order would be a claim
                rather than a fact.
            allowlist: The **trajectory** allowlist — the set callable at all for the work this
                executor serves. It can only be narrowed per invocation, by
                :attr:`~toolyard.types.ToolContext.approved_tools`; nothing widens it. That
                direction is the whole safety property, so it is structural: the effective set is an
                intersection, and an intersection has no widening case to get wrong.
            store: Where records go. ``None`` appends nothing and is meant for a standalone script
                or a test — PromptCadence always supplies one, because "every call is recorded" is
                spec §11.6. The record is built either way, so the code path a test exercises is
                the code path production runs.
            default_timeout_seconds: Applied when a context passes ``None``.
            max_content_bytes: Cap on what the model sees.
            max_summary_bytes: Cap on what the record holds.
            max_args_json_bytes: Cap above which ``args_json`` becomes a size-and-digest object.
            monotonic_ns: The duration source, injected. Separate from
                :attr:`~toolyard.types.ToolContext.clock` because a wall clock cannot measure a
                duration — it steps backwards during an NTP correction — and because a test cannot
                make :func:`time.perf_counter_ns` deterministic. The name and the default follow
                ``modelrack.cache``'s precedent rather than inventing a second convention.

        Raises:
            ValidationError: If a cap is below :data:`MIN_CONTENT_BYTES`, the default timeout is not
                a finite positive number, or the allowlist is not a set of strings. Caller bugs, all
                of them, surfaced at startup.
        """
        if not isinstance(allowlist, frozenset | set) or not all(
            isinstance(name, str) for name in allowlist
        ):
            raise ValidationError(
                "allowlist must be a set of tool-name strings; it is the trajectory's, and it is "
                "the only thing that decides what is callable at all.",
                details={"field": "allowlist"},
            )
        require_timeout_seconds("default_timeout_seconds", default_timeout_seconds)
        for name, value in (
            ("max_content_bytes", max_content_bytes),
            ("max_summary_bytes", max_summary_bytes),
            ("max_args_json_bytes", max_args_json_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < MIN_CONTENT_BYTES:
                raise ValidationError(
                    f"{name} must be an int of at least {MIN_CONTENT_BYTES}; got {value!r}. A cap "
                    "smaller than a truncation label cannot label its own truncation.",
                    details={"field": name, "minimum": MIN_CONTENT_BYTES},
                )
        self._registry = registry
        self._sandbox = sandbox
        self._allowlist = frozenset(allowlist)
        self._store = store
        self._default_timeout_seconds = float(default_timeout_seconds)
        self._max_content_bytes = max_content_bytes
        self._max_summary_bytes = max_summary_bytes
        self._max_args_json_bytes = max_args_json_bytes
        self._monotonic_ns = monotonic_ns

    def execute(self, call: ToolCallRequest, context: ToolContext) -> ToolResult:
        """Run one tool call and record it, whatever happens.

        The ladder runs first and the **first** failing check decides the refusal (spec §11.2). If
        every check passes, the handler runs with validated arguments in which any declared path
        argument has already been replaced by its resolved path. Then the output is cleaned, hashed
        in full, capped for the model and capped again for the record, and one record is appended —
        exactly one, for every outcome including a refusal.

        Args:
            call: What the model asked for. Untrusted in both fields; see
                :class:`~toolyard.types.ToolCallRequest`.
            context: The invocation's trusted half — identity, roots, ceilings, clock.

        Returns:
            A :class:`~toolyard.types.ToolResult` with a status, a reason drawn from the closed set
            :class:`~toolyard.types.Reason` when the status is not ``OK``, and content the model can
            read. Never ``None``, and never an exception for anything the model chose.

        Raises:
            StoreFailure: If the store will not take the record. The result and the record travel on
                the exception, because a side effect may already have happened and losing its audit
                trail is the worse failure. See :class:`~toolyard.errors.StoreFailure`.
            BaseException: Re-raised, after the call is recorded, when a handler raises something
                that is not an ``Exception`` — ``KeyboardInterrupt``, ``SystemExit``. Model input
                cannot produce one, and swallowing it would make the loop uninterruptible by the
                person running it. Every ``Exception`` becomes a ``FAILED`` result instead.
        """
        started_at = context.clock()
        start_ns = self._monotonic_ns()
        state = _Pass(
            request=call,
            context=context,
            sandbox=self._sandbox,
            allowlist=self._allowlist,
            registered=self._registry.get(call.name),
        )
        for check in _CHECKS:
            refusal = check.run(state)
            if refusal is not None:
                return self._finish(state, refusal, None, started_at, start_ns)
        return self._run_handler(state, started_at, start_ns)

    def _run_handler(self, state: _Pass, started_at: datetime, start_ns: int) -> ToolResult:
        """Call the handler and turn whatever comes back — or out — into a result."""
        registered = state.registered
        assert registered is not None  # noqa: S101 — the ladder guarantees it; mypy needs the fact
        limit_seconds = (
            self._default_timeout_seconds
            if state.context.timeout_seconds is None
            else state.context.timeout_seconds
        )
        try:
            output = registered.handler.execute(state.handler_args, state.context)
        except Exception as exc:  # noqa: BLE001 — ADR-0053 decision 4: a handler failure is a result
            return self._finish(
                state,
                _Refusal(
                    Reason.HANDLER_ERROR,
                    f"{_exception_name(exc)}: {_exception_message(exc)}",
                    status=ToolStatus.FAILED,
                ),
                None,
                started_at,
                start_ns,
            )
        except BaseException as exc:
            # Not an Exception: KeyboardInterrupt, SystemExit, GeneratorExit. Record the call, then
            # let it through — see the module docstring for why this one thing is not swallowed.
            self._finish(
                state,
                _Refusal(
                    Reason.HANDLER_ERROR,
                    f"{_exception_name(exc)}: interpreter-level interruption, re-raised",
                    status=ToolStatus.FAILED,
                ),
                None,
                started_at,
                start_ns,
            )
            raise
        elapsed_ms = self._elapsed_ms(start_ns)
        elapsed_seconds = elapsed_ms / 1_000
        if elapsed_seconds > limit_seconds:
            # Reported, not enforced, and the docstring of `timeout_seconds` says which. An
            # in-process handler cannot be interrupted; a handler that must be *stopped* runs under
            # Sandbox.run_isolated, where the process-tree kill lives (Phase 2). ADR-0016's posture:
            # an unenforceable limit is reported rather than assumed. The output is discarded, so a
            # result the executor has declared timed out never reaches the model as if it had not.
            return self._finish(
                state,
                _Refusal(
                    Reason.TIMEOUT,
                    f"elapsed {elapsed_seconds:.3f} s exceeds the {limit_seconds:.3f} s limit",
                    status=ToolStatus.TIMEOUT,
                ),
                None,
                started_at,
                start_ns,
                elapsed_ms,
            )
        if isinstance(output, ToolRefusal):
            # The handler's own check said no. It is carried through unchanged rather than
            # re-decided here: the executor cannot re-run an ADR-0026 §3 check it did not make, and
            # a reason it did not recognize is impossible, because `Reason` is closed and
            # `ToolRefusal` validates against it at construction.
            return self._finish(
                state,
                _Refusal(
                    output.reason,
                    output.detail,
                    record_detail=output.record_detail,
                    status=output.status,
                ),
                None,
                started_at,
                start_ns,
                elapsed_ms,
            )
        if not isinstance(output, ToolOutput) or not isinstance(output.content, str):
            return self._finish(
                state,
                _Refusal(
                    Reason.HANDLER_ERROR,
                    f"the handler returned {type(output).__name__}, not a ToolOutput",
                    status=ToolStatus.FAILED,
                ),
                None,
                started_at,
                start_ns,
                elapsed_ms,
            )
        return self._finish(state, None, output.content, started_at, start_ns, elapsed_ms)

    def _finish(
        self,
        state: _Pass,
        refusal: _Refusal | None,
        content: str | None,
        started_at: datetime,
        start_ns: int,
        elapsed_ms: float | None = None,
    ) -> ToolResult:
        """Build the result and the record, append the record, and return the result.

        Nothing in here may raise for anything the model chose, which is why every value that
        reaches a digest or a cap has gone through :mod:`toolyard._safe` first.

        ``elapsed_ms`` is passed in by the timeout path so that the reported duration is the same
        measurement the timeout decision was made on. A second reading would be a millisecond later
        and the sentence "elapsed 1.502 s exceeds the 1.000 s limit" would sit beside a
        ``duration_ms`` of 1503 — a discrepancy small enough to be dismissed and large enough to
        make somebody doubt the record.
        """
        duration_ms = int(round(self._elapsed_ms(start_ns) if elapsed_ms is None else elapsed_ms))
        spec = None if state.registered is None else state.registered.spec
        tool_name = clean_text(_as_text(state.request.name))[:MAX_RECORDED_NAME_CHARS]
        full_output = clean_text(content) if content is not None else ""
        if refusal is None:
            model_text, _ = truncate_text(full_output, max_bytes=self._max_content_bytes)
            record_text, _ = truncate_text(full_output, max_bytes=self._max_summary_bytes)
            status = ToolStatus.OK
            reason: str | None = None
            reason_detail: str | None = None
        else:
            sentence = _sentence(tool_name, refusal)
            model_text, _ = truncate_text(sentence, max_bytes=self._max_content_bytes)
            record_sentence = (
                sentence
                if refusal.record_detail is None
                else f"{sentence} [{refusal.record_detail}]"
            )
            record_text, _ = truncate_text(record_sentence, max_bytes=self._max_summary_bytes)
            status = refusal.status
            reason = refusal.reason.value
            reason_detail = refusal.detail
        result = ToolResult(
            invocation_id=state.context.invocation_id,
            status=status,
            content=model_text,
            reason=reason,
            duration_ms=duration_ms,
            reason_detail=reason_detail,
        )
        record = ToolCallRecord(
            invocation_id=state.context.invocation_id,
            tool_name=tool_name,
            args_json=self._args_json(
                state.request.args, redact=spec is not None and spec.redact_args
            ),
            args_sha256=_args_digest(state.request.args),
            status=status,
            result_summary=record_text,
            result_sha256=sha256_of(full_output),
            duration_ms=duration_ms,
            risk_class=RiskClass.READ_ONLY if spec is None else spec.risk_class,
            egress=EgressClass.NONE if spec is None else spec.egress,
            started_at=started_at,
            reason=reason,
            reason_detail=reason_detail,
        )
        _LOGGER.debug("tool call %s finished with status %s", tool_name, status.value)
        self._append(record, result)
        return result

    def _append(self, record: ToolCallRecord, result: ToolResult) -> None:
        """Append the record, converting any store failure into :class:`StoreFailure`."""
        if self._store is None:
            return
        try:
            self._store.append(record)
        except StoreFailure:
            raise
        except Exception as exc:  # noqa: BLE001 — a store's own error type must not cross this API
            raise StoreFailure(
                f"The tool-call store refused the record for {record.tool_name!r} "
                f"({type(exc).__name__}). The call itself completed: its result and its record are "
                "on this error, so persist them by another route rather than re-running a tool "
                "whose side effect has already happened.",
                result=result,
                record=record,
            ) from exc

    def _args_json(self, args: Mapping[str, Any], *, redact: bool) -> str | None:
        """Render the arguments for the record, or ``None`` when the spec redacts them.

        The plaintext never reaches the record when ``redact`` is set — not truncated, not
        summarized, not in a fallback. When it is not set, the rendering is always **valid JSON**:
        an oversize argument set becomes a small object naming its size and digest rather than a
        fragment cut mid-string, so an application can always parse this field.
        """
        if redact:
            return None
        rendered = canonical_json(json_sanitize(args))
        encoded = rendered.encode("utf-8")
        if len(encoded) <= self._max_args_json_bytes:
            return rendered
        return canonical_json(
            {
                "__toolyard_args_omitted__": "oversize",
                "bytes": len(encoded),
                "sha256": sha256_of(json_sanitize(args)),
            }
        )

    def _elapsed_ms(self, start_ns: int) -> float:
        """Return milliseconds since ``start_ns``, tolerating a monotonic source that misbehaves."""
        end_ns = self._monotonic_ns()
        if not isinstance(end_ns, int) or end_ns < start_ns:
            return 0.0
        return (end_ns - start_ns) / 1_000_000


def _sentence(tool_name: str, refusal: _Refusal) -> str:
    """Build the model-facing sentence for a non-``OK`` outcome.

    It names the tool, the failed check and the detail — and never the allowlist's members or a
    containment root's path, because refusal text is part of the prompt surface (ADR-0053's last
    consequence). The root that was violated goes to the record instead, via
    :attr:`_Refusal.record_detail`: the operator may see it, the model may not.
    """
    return f"Tool {tool_name!r} — {refusal.reason.value}: {refusal.detail}"


def _as_text(value: object) -> str:
    """Render a model-supplied name as text without letting it run code."""
    if isinstance(value, str):
        return value
    return f"<{type(value).__name__}>"


def _exception_name(exc: BaseException) -> str:
    """Return a handler exception's class name, filtered to a class name's alphabet.

    The class name reaches the model, and a handler may define a class named anything at all, so it
    is filtered rather than trusted. No traceback goes with it (spec §13): a traceback names the
    application's paths and internals, to a reader whose arguments were assumed adversarial.
    """
    raw = type(exc).__name__
    filtered = "".join(character for character in raw if character in _EXCEPTION_NAME_ALPHABET)
    return filtered[:64] or "Exception"


def _exception_message(exc: BaseException) -> str:
    """Return a handler exception's message, cleaned and capped. Never a traceback."""
    try:
        message = str(exc)
    except Exception:  # noqa: BLE001 — an exception whose __str__ raises is one of the fuzz cases
        return "(unrenderable)"
    return clean_text(message)[:_MAX_HANDLER_MESSAGE_CHARS]


def _args_digest(args: object) -> str:
    """Digest a model's arguments, for any value at all.

    :func:`baseaicore.sha256_of` refuses non-finite floats, ``bytes``, ``set``, cycles and naive
    datetimes — and ``json.loads`` accepts ``NaN`` by default, so those really do arrive. Sanitizing
    first means the digest always exists and is still a function of the arguments' *shape and
    content*, rather than a constant sentinel that would make two different bad calls
    indistinguishable in the record.
    """
    return sha256_of(json_sanitize(args))
