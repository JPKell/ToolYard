"""The vocabulary: what a tool is, what a call is, what came back, and what was recorded.

Read the trust boundary off the types. Two of them hold what a **model** chose and are validated by
nobody at construction, because validating them would raise on model input:
:class:`ToolCallRequest` (the name and the arguments) and :class:`ToolOutput` (what a handler
produced). Everything else is the **application's**, is checked at construction, and raises when it
is wrong. :class:`ToolContext` in particular is the trusted half of an invocation — the identity,
the roots, the ceilings — and no field on it is ever model-supplied.

Where this file adds a name spec §7 uses only as an annotation, the docstring says why the shape is
what it is. Five such names: :class:`ToolOutput`, :class:`ToolCallRequest`, :class:`RegisteredTool`,
and — from :mod:`toolyard.containment` — ``IsolationTier`` and ``SubprocessResult``.
"""

from __future__ import annotations

import re
from dataclasses import KW_ONLY, dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

from baseaicore import ValidationError, utc_now

from toolyard._safe import clean_text
from toolyard.containment import PathAccess, SandboxPaths
from toolyard.errors import InvalidToolSpec
from toolyard.validation import check_args_schema, check_result_schema, string_property_names

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from baseaicore import Clock

    from toolyard.validation import ArgsValidator

__all__ = [
    "MAX_RECORDED_NAME_CHARS",
    "REFUSAL_REASONS",
    "TOOL_NAME_PATTERN",
    "EgressClass",
    "Reason",
    "RegisteredTool",
    "RiskClass",
    "ToolCallRecord",
    "ToolCallRequest",
    "ToolContext",
    "ToolHandler",
    "ToolOutput",
    "ToolRefusal",
    "ToolResult",
    "ToolSpec",
    "ToolStatus",
]

TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
"""Spec §7's tool-name pattern, and the sharpest edge of the raise/refuse boundary.

A **caller** registering a name that does not match has written an invalid spec, and that raises
:class:`~toolyard.errors.InvalidToolSpec` at startup where a person sees it. A **model** asking for
a name that does not match gets ``unknown_tool``, a refusal, because a name that cannot be
registered cannot be in the registry. Same pattern, opposite outcomes, and confusing them in either
direction is a defect: raising on the model's name hands it a stop condition, and refusing the
caller's hides a wiring mistake until a model happens to ask for that tool.
"""

MAX_RECORDED_NAME_CHARS: Final[int] = 128
"""How much of a model-supplied tool name reaches a record.

A record must say what was asked for, including when what was asked for is nonsense — otherwise the
refusal is undiagnosable. But the name is model-chosen text landing in the application's table, so
it is cleaned and capped first: an unbounded name is a write amplification attack on the audit log.
"""


class RiskClass(StrEnum):
    """What a tool can do to the world, as an ordered ceiling.

    Ordered because :meth:`~toolyard.registry.ToolRegistry.list_for_policy` filters by a *maximum*:
    a policy that permits read-only work must not be handed a mutating tool, and expressing that as
    a rank rather than a set means a third class inserted later needs no call site changed.
    """

    READ_ONLY = "read_only"
    """Observes. Reads a file, lists a directory, fetches a URL."""

    MUTATING = "mutating"
    """Changes something. Writes a file, runs a command."""

    @property
    def rank(self) -> int:
        """Return the ordering position; higher is more permissive."""
        return _RISK_RANK[self]

    def permits(self, required: RiskClass) -> bool:
        """Report whether this ceiling admits a tool of class ``required``.

        Args:
            required: The class the tool declares.

        Returns:
            ``True`` when ``required`` is no more permissive than this ceiling.
        """
        return required.rank <= self.rank


class EgressClass(StrEnum):
    """Whether a tool reaches the network, as an ordered ceiling defaulting closed.

    The ceiling lives on :class:`ToolContext` and defaults to :attr:`NONE`, so a caller who has not
    thought about egress gets the answer that cannot leak. That is the same posture ADR-0046 fixes
    for data classification and ADR-0026 §3 fixes for host allowlists: the closed default is what
    stands in for the decision nobody made.
    """

    NONE = "none"
    """Touches no socket."""

    NETWORK = "network"
    """Opens an outbound connection, under the ADR-0026 §3 checks at the socket."""

    @property
    def rank(self) -> int:
        """Return the ordering position; higher is more permissive."""
        return _EGRESS_RANK[self]

    def permits(self, required: EgressClass) -> bool:
        """Report whether this ceiling admits a tool of class ``required``.

        Args:
            required: The class the tool declares.

        Returns:
            ``True`` when ``required`` is no more permissive than this ceiling.
        """
        return required.rank <= self.rank


_RISK_RANK: Final[dict[RiskClass, int]] = {RiskClass.READ_ONLY: 0, RiskClass.MUTATING: 1}
_EGRESS_RANK: Final[dict[EgressClass, int]] = {EgressClass.NONE: 0, EgressClass.NETWORK: 1}


class ToolStatus(StrEnum):
    """How a call ended. Four outcomes, and only the first means the handler's output is real."""

    OK = "ok"
    """The handler ran and produced output, possibly truncated and labelled as such."""

    REFUSED = "refused"
    """A check said no. Nothing ran. The reason names the first check that failed."""

    FAILED = "failed"
    """The handler ran and raised, or broke its own contract. No traceback reaches the model."""

    TIMEOUT = "timeout"
    """The handler exceeded its limit. Its output is discarded rather than shown."""


class Reason(StrEnum):
    """The closed set of machine-readable reasons a non-``OK`` result can carry.

    Closed on purpose. A consumer maps a reason onto its own deviation category — PromptCadence
    onto the ``undeclared_tool`` row of
    ([lifecycle §5](https://github.com/JPKell/OpenWeight-Gym/blob/main/apps/promptcadence/lifecycle.md#5-deviation-handling))
    — and a category nobody enumerated has no defined disposition, so an unrecognized reason string
    is a bug in this package and a property test asserts none is ever produced. Adding a reason is
    a **minor** version change (spec §19) and a change consumers must be told about; it is not a
    thing to do casually in a handler.

    Human detail belongs in :attr:`ToolResult.reason_detail` and in the content the model reads,
    never in this field.
    """

    UNKNOWN_TOOL = "unknown_tool"
    """No tool of that name is registered. Also what an unregistrable name produces."""

    NOT_ALLOWLISTED = "not_allowlisted"
    """Outside the trajectory allowlist. Never re-approvable: the allowlist is the caller's."""

    NOT_APPROVED = "not_approved"
    """Inside the trajectory allowlist, outside this invocation's approved set. The app's drift."""

    ARGS_INVALID = "args_invalid"
    """The arguments failed the schema. The detail names the paths."""

    EGRESS_NOT_PERMITTED = "egress_not_permitted"
    """The tool reaches the network and this invocation's egress ceiling does not allow it."""

    PATH_ESCAPE = "path_escape"
    """A declared path argument resolved outside its root."""

    ISOLATION_UNAVAILABLE = "isolation_unavailable"
    """The tool requires process isolation and this host has no tier. ADR-0018's floor."""

    TIMEOUT = "timeout"
    """The handler exceeded its limit."""

    HANDLER_ERROR = "handler_error"
    """The handler raised, or returned neither a :class:`ToolOutput` nor a :class:`ToolRefusal`."""

    # -- the built-ins' own checks (spec §13) ----------------------------------------------------
    # Everything above is the executor's and is decided before a handler runs. Everything below is
    # produced by a shipped tool returning a `ToolRefusal`. The split between REFUSED and FAILED is
    # spec §13's: REFUSED is this package declining under a rule of its own, and the identical call
    # will be declined again; FAILED is the work attempted and the world answering badly, where a
    # different argument or a later attempt may succeed.

    MALFORMED_URL = "malformed_url"
    """REFUSED. The fetch URL does not parse. ADR-0026 §3, before a name is resolved."""

    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    """REFUSED. Not ``http`` or ``https``. ``file://`` in particular is a local read in a URL's
    clothing."""

    NO_HOST = "no_host"
    """REFUSED. The URL parses and names no host, so an allowlist has nothing to check."""

    HOST_NOT_ALLOWED = "host_not_allowed"
    """REFUSED. Outside the tool's host allowlist. The allowlist's members are never named back."""

    LINK_LOCAL_ADDRESS = "link_local_address"
    """REFUSED. The host is, or resolves to, a link-local address. The metadata range, refused
    unconditionally — the allowlist is not a second opinion on this one."""

    CROSS_HOST_REDIRECT = "cross_host_redirect"
    """REFUSED. A redirect changed host. Never followed, whatever the count."""

    TOO_MANY_REDIRECTS = "too_many_redirects"
    """REFUSED. Past the hop cap."""

    CONTENT_TYPE_NOT_ALLOWED = "content_type_not_allowed"
    """REFUSED. Checked before any of the body is returned, so it is a fact about the response and
    not about what parsing it happened to do."""

    TOO_LARGE = "too_large"
    """REFUSED. A cap this package chose said no: a declared ``Content-Length``, a body that
    outgrew the cap mid-stream, or a file larger than ``read_file``'s cap. Not a truncation — the
    executor's labelled truncation is about what the *model* sees, while this is about what the
    process would have to load, and a handler that returned a prefix would make the record's
    ``result_sha256`` a digest of the prefix."""

    TRANSPORT_ERROR = "transport_error"
    """FAILED. Connect, TLS, read or timeout. The origin was never heard from; retrying is
    meaningful."""

    HTTP_STATUS = "http_status"
    """FAILED. The origin answered, with 4xx or 5xx. The detail carries the code."""

    FILE_NOT_FOUND = "file_not_found"
    """FAILED. Nothing at the resolved path. The path was contained; it just names nothing."""

    NOT_A_REGULAR_FILE = "not_a_regular_file"
    """FAILED. Something is there and it is not what this tool handles — a directory where a file
    was wanted, a file where a directory was, a device, a socket, a fifo."""

    PERMISSION_DENIED = "permission_denied"
    """FAILED. The operating system refused the open. Inside containment, so this is the host's
    answer and not a containment decision — a containment decision is ``path_escape``."""

    NOT_UTF8 = "not_utf8"
    """FAILED. The bytes are not decodable text. Returned rather than decoded with replacement,
    because a model handed mojibake cannot tell it read a broken file."""


REFUSAL_REASONS: Final[frozenset[str]] = frozenset(reason.value for reason in Reason)
"""Every reason string this package can produce, for a consumer to exhaust in a match."""


_REFUSAL_STATUSES: Final[frozenset[ToolStatus]] = frozenset(
    {ToolStatus.REFUSED, ToolStatus.FAILED, ToolStatus.TIMEOUT}
)
"""Every status a :class:`ToolRefusal` may carry — that is, every status but ``OK``."""


@dataclass(frozen=True, slots=True)
class ToolOutput:
    """What a :class:`ToolHandler` returns. Uncapped, unhashed, and not yet the model's to see.

    Spec §7 names this type and does not define it, and the shape follows from two facts elsewhere
    in the spec: :attr:`ToolResult.content` is size-capped, and :attr:`ToolCallRecord.result_sha256`
    is a digest of the whole thing. So a handler returns its output **in full** and the executor —
    never the handler — does the capping and the hashing. A handler that capped its own output would
    make the recorded digest a digest of the cap, and the application's artifact would no longer
    match the record that points at it.

    Attributes:
        content: The text a model would see, in full. Cleaned (NUL and lone surrogates removed) by
            the executor before it is hashed or capped, so a handler need not produce
            well-formed text — spec §14 says its output is untrusted too.
        structured: Optional machine-readable output for the application, checked against
            ``result_schema`` when result-schema enforcement lands (spec §21). It does **not** reach
            the model: the model reads ``content``, and a second channel it could not see would be
            a fact the trajectory record holds and the transcript does not.
    """

    content: str
    structured: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        """Refuse a non-string ``content``.

        Raises:
            ValidationError: If ``content`` is not a ``str``. Raised inside the handler's own call
                frame, which means the executor catches it as any other handler failure and reports
                ``handler_error`` — a broken handler is never a broken agent loop.
        """
        if not isinstance(self.content, str):
            raise ValidationError(
                f"ToolOutput.content must be a str; got {type(self.content).__name__}. Serialize "
                "structured output into text for the model and pass the structure as `structured`.",
                details={"field": "content", "kind": type(self.content).__name__},
            )


@dataclass(frozen=True, slots=True)
class ToolRefusal:
    """What a handler returns instead of output when one of *its own* checks says no.

    ADR-0053 decision 4 — a refusal is a result, not an exception — applied one layer in. The
    executor's five checks run before a handler and produce their refusals directly; a handler has
    checks of its own that no executor could make for it (``http_fetch``'s ADR-0026 §3 ladder is
    the whole of spec §11.5), and without this type the only thing it could do with a failed one is
    raise. A raise is ``FAILED`` / ``handler_error``, which names an exception class and not a
    check, so spec §13's "the specific ADR-0026 check" would be unexpressible and every fetch
    refusal would arrive at a consumer as the same undifferentiated failure.

    The reason is a :class:`Reason`, so a handler can no more invent a vocabulary than the executor
    can: the set stays closed, and the property test that asserts no unrecognized reason is ever
    produced covers handlers too.

    Attributes:
        reason: The check that said no.
        detail: What the **model** is told. It names the failed check and the model's own argument,
            and never a containment root, an allowlist's members or a resolved address — refusal
            text is part of the prompt surface (ADR-0053's last consequence).
        status: ``REFUSED``, ``FAILED`` or ``TIMEOUT``. Spec §13 assigns one per row and the choice
            is what tells a consumer whether retrying is meaningful; ``OK`` is refused here,
            because a refusal that reports success is the one shape that cannot be true.
        record_detail: What only the record and the operator see — the resolved path, the address a
            host resolved to. Appended to the recorded summary, never to the model's content.
    """

    reason: Reason
    detail: str
    status: ToolStatus = ToolStatus.REFUSED
    record_detail: str | None = None

    def __post_init__(self) -> None:
        """Refuse a refusal that is not one.

        Raises:
            ValidationError: If ``reason`` is not a :class:`Reason`, ``detail`` is not a non-empty
                string, ``status`` is not one of ``REFUSED``/``FAILED``/``TIMEOUT``, or
                ``record_detail`` is neither ``None`` nor a string. Raised inside the handler's own
                call frame, so the executor reports it as ``handler_error`` like any other broken
                handler — a handler bug is never a broken agent loop.
        """
        if not isinstance(self.reason, Reason):
            raise ValidationError(
                f"ToolRefusal.reason must be a Reason; got {type(self.reason).__name__}. The set "
                "is closed on purpose: a consumer maps each reason onto a disposition, and one "
                "nobody enumerated has none.",
                details={"field": "reason"},
            )
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ValidationError(
                "ToolRefusal.detail must be a non-empty string: it is the sentence the model "
                "reads, and a refusal it cannot act on teaches it nothing.",
                details={"field": "detail"},
            )
        if self.status not in _REFUSAL_STATUSES:
            raise ValidationError(
                f"ToolRefusal.status must be one of "
                f"{', '.join(sorted(s.value for s in _REFUSAL_STATUSES))}; got {self.status!r}. A "
                "refusal reporting OK is the one shape that cannot be true.",
                details={"field": "status"},
            )
        if self.record_detail is not None and not isinstance(self.record_detail, str):
            raise ValidationError(
                "ToolRefusal.record_detail must be a string or None.",
                details={"field": "record_detail"},
            )


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool's declaration — and a validated one, because it is checked at construction.

    Validation lives in ``__post_init__`` rather than in
    :meth:`~toolyard.registry.ToolRegistry.register` so that a ``ToolSpec`` which exists is a
    ``ToolSpec`` that can be relied on. There is no half-checked spec to pass around, no factory to
    forget and no registration path that skips the check. The registry then has exactly one job left
    (refusing a duplicate name), which is the CutCtx precedent applied to a smaller object.

    Attributes:
        name: Matches :data:`TOOL_NAME_PATTERN`. See that constant for why a bad name here raises
            while a bad name from a model refuses.
        description: What the tool does, for the model. Non-empty: a tool a model cannot tell apart
            from another tool is a tool it will call wrongly.
        args_schema: A JSON Schema (draft 2020-12) for the arguments, which must describe an object
            and must be **closed** at every object-typed subschema. ``Mapping[str, Any]`` is the
            honest annotation for a JSON Schema document and the one place ``Any`` at a public
            boundary is correct. See :func:`~toolyard.validation.check_args_schema` for the three
            strictnesses and why each exists.
        result_schema: An optional schema for the handler's structured output. Declared, not yet
            enforced (spec §21).
        risk_class: What the tool can do to the world.
        egress: Whether it reaches the network.
        redact_args: When true, the record stores ``args_sha256`` only and ``args_json`` is
            ``None``. The plaintext never reaches the record, not even truncated.
        path_args: The argument names that are paths, and which root each is checked against.
            **This is the input spec §11.2's containment check otherwise lacks.** The executor
            resolves each declared argument through the sandbox *before* the handler runs and
            substitutes the resolved path into the arguments the handler receives, so a handler
            operates on a resolved path and never re-resolves a candidate — which is the
            resolution-then-check rule and the TOCTOU mitigation in one move. Top-level string
            arguments only: an argument nested where the executor cannot see it is an argument the
            executor cannot contain, and that is a refusal to express it rather than an oversight.
        requires_isolation: When true, the tool runs a subprocess and the executor refuses it with
            ``isolation_unavailable`` unless the sandbox reports a tier. ADR-0018's ladder ends in
            refusal, and this is the flag that makes the ladder's floor reachable from
            :meth:`~toolyard.executor.ToolExecutor.execute` before any code exists that could run a
            command.
    """

    name: str
    description: str
    args_schema: Mapping[str, Any]
    result_schema: Mapping[str, Any] | None
    risk_class: RiskClass
    egress: EgressClass
    _: KW_ONLY
    redact_args: bool = False
    path_args: Mapping[str, PathAccess] = field(default_factory=dict)
    requires_isolation: bool = False

    def __post_init__(self) -> None:
        """Check every declared property and freeze the schemas against later mutation.

        The schemas are deep-copied, so a caller that keeps a reference and mutates it after
        registration cannot change what the compiled validator is validating against — an argument
        schema is a security control, and a security control that can be edited from outside is
        not one.

        Raises:
            InvalidToolSpec: If the name does not match :data:`TOOL_NAME_PATTERN`; the description
                is empty; either schema is malformed, open, over-deep or uses a ``$ref``-family
                keyword; or a ``path_args`` entry names something the schema does not deliver as a
                string property.
        """
        if not isinstance(self.name, str) or not TOOL_NAME_PATTERN.fullmatch(self.name):
            raise InvalidToolSpec(
                f"Tool name {self.name!r} does not match {TOOL_NAME_PATTERN.pattern}. Names are "
                "lowercase, start with a letter, and hold letters, digits and underscores. A model "
                "asking for such a name is refused with `unknown_tool`; a caller registering one "
                "is a wiring mistake, which is why this raises.",
                details={"field": "name", "pattern": TOOL_NAME_PATTERN.pattern},
            )
        if not isinstance(self.description, str) or not self.description.strip():
            raise InvalidToolSpec(
                f"Tool {self.name!r} needs a non-empty description: it is what the model reads to "
                "decide whether this is the tool it wants.",
                details={"field": "description", "tool_name": self.name},
            )
        if not isinstance(self.risk_class, RiskClass) or not isinstance(self.egress, EgressClass):
            raise InvalidToolSpec(
                f"Tool {self.name!r} must declare a RiskClass and an EgressClass; got "
                f"{type(self.risk_class).__name__} and {type(self.egress).__name__}.",
                details={"tool_name": self.name},
            )
        check_args_schema(self.args_schema)
        if self.result_schema is not None:
            check_result_schema(self.result_schema)
        object.__setattr__(self, "args_schema", _deep_freeze(self.args_schema))
        if self.result_schema is not None:
            object.__setattr__(self, "result_schema", _deep_freeze(self.result_schema))
        object.__setattr__(self, "path_args", self._checked_path_args())

    def _checked_path_args(self) -> dict[str, PathAccess]:
        """Validate the path-argument declaration against the schema and return a private copy."""
        declared = self.path_args
        if not isinstance(declared, dict):
            raise InvalidToolSpec(
                f"Tool {self.name!r}: path_args must be a mapping of argument name to PathAccess.",
                details={"field": "path_args", "tool_name": self.name},
            )
        strings = string_property_names(self.args_schema)
        checked: dict[str, PathAccess] = {}
        for argument, access in declared.items():
            if not isinstance(access, PathAccess):
                raise InvalidToolSpec(
                    f"Tool {self.name!r}: path_args[{argument!r}] must be a PathAccess; got "
                    f"{type(access).__name__}.",
                    details={"field": "path_args", "argument": str(argument)},
                )
            if argument not in strings:
                raise InvalidToolSpec(
                    f"Tool {self.name!r}: path_args names {argument!r}, which args_schema does not "
                    'declare as a top-level `"type": "string"` property. Containment over an '
                    "argument whose type is not pinned is containment over something that might "
                    "not be a path.",
                    details={"field": "path_args", "argument": str(argument)},
                )
            checked[argument] = access
        return checked

    def wire_definition(self) -> Mapping[str, Any]:
        """Export the provider-neutral definition a caller adapts for its model API.

        Byte-stable for a given spec, because PromptCadence hashes these into turn records
        (spec §11.7). Stability comes from three choices, all of which are part of the contract:
        the key set is fixed at exactly ``name``, ``description`` and ``parameters``; the schema is
        the deep copy taken at construction, so a caller's later edit cannot change it; and callers
        serialize with :func:`baseaicore.canonical_json`, which sorts keys — so insertion order,
        the classic source of a hash that drifts between runs, cannot reach the digest.

        Deliberately absent: ``risk_class``, ``egress``, ``redact_args``, ``path_args`` and
        ``requires_isolation``. Those are the *caller's* policy inputs, not the model's business,
        and putting them on the wire would invite a model to reason about its own containment.

        Returns:
            A mapping with ``name``, ``description`` and ``parameters`` (the argument schema).
        """
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.args_schema,
        }


@dataclass(frozen=True, slots=True)
class ToolContext:
    """The trusted half of an invocation: identity, roots and ceilings, all from the application.

    Nothing here is model-supplied, and that is the design rather than a coincidence.
    ``invocation_id`` in particular lives here and **not** on :class:`ToolCallRequest`: a model that
    could choose the id could collide two records or point a result at another turn's call, and the
    record is the thing the application reasons about afterwards.

    Attributes:
        invocation_id: The application's identifier for this call. Echoed onto the result and the
            record.
        workspace: The read and write roots this invocation may touch.
        timeout_seconds: The handler's limit. ``None`` means the executor's configured default,
            **never** "no timeout" (spec §11.8) — there is no way to express an unlimited call, and
            that is deliberate.
        approved_tools: The subset approved for this invocation. It can only **narrow**: the
            effective allowlist is the intersection of this and the executor's trajectory
            allowlist, so a value that arrived from anywhere untrustworthy still cannot widen what
            is callable. ``None`` means "the trajectory allowlist stands alone", for a caller with
            no per-invocation narrowing. A consumer that mints one per turn supplies it from there
            — PromptCadence from its ``ExecutionIntent`` (ADR-0056 §1) — but this field is a set of
            names and knows nothing about where they came from.
        max_egress: The egress ceiling for this invocation, defaulting to
            :attr:`EgressClass.NONE`. A caller who has not decided gets the answer that cannot leak.
        clock: The wall clock, injected, used only for ``started_at``. Durations do **not** come
            from it — a wall clock steps backwards during an NTP correction, and the executor takes
            a separate injected monotonic source for ``duration_ms``.
    """

    invocation_id: str
    workspace: SandboxPaths
    _: KW_ONLY
    timeout_seconds: float | None = None
    approved_tools: frozenset[str] | None = None
    max_egress: EgressClass = EgressClass.NONE
    clock: Clock = utc_now

    def __post_init__(self) -> None:
        """Check the trusted half at construction, so the executor never has to mid-call.

        Every field here comes from the application, so every one of these is a caller bug and
        raises — which is the opposite of :class:`ToolCallRequest`, whose fields come from a model
        and are therefore never checked at construction. Putting the check here rather than inside
        :meth:`~toolyard.executor.ToolExecutor.execute` means a misconfigured context fails where
        it was built, not on the one call that happened to reach the field.

        Raises:
            ValidationError: If ``invocation_id`` is not a non-empty string, ``workspace`` is not a
                :class:`~toolyard.containment.SandboxPaths`, ``timeout_seconds`` is present but not
                a finite positive number, ``approved_tools`` is present but is not a set of
                strings, ``max_egress`` is not an :class:`EgressClass`, or ``clock`` is not
                callable.
        """
        if not isinstance(self.invocation_id, str) or not self.invocation_id.strip():
            raise ValidationError(
                "ToolContext.invocation_id must be a non-empty string. It is the application's "
                "identifier for the call and it is echoed onto the result and the record; a model "
                "never supplies it.",
                details={"field": "invocation_id"},
            )
        if not isinstance(self.workspace, SandboxPaths):
            raise ValidationError(
                "ToolContext.workspace must be a SandboxPaths naming this invocation's roots; got "
                f"{type(self.workspace).__name__}.",
                details={"field": "workspace"},
            )
        if self.timeout_seconds is not None:
            value = self.timeout_seconds
            finite = isinstance(value, int | float) and not isinstance(value, bool)
            if not finite or not value > 0 or value in (float("inf"), float("-inf")):
                raise ValidationError(
                    f"ToolContext.timeout_seconds must be a finite positive number of seconds or "
                    f"None; got {value!r}. None means the executor's default, never "
                    '"no timeout" (spec §11.8).',
                    details={"field": "timeout_seconds"},
                )
        if self.approved_tools is not None and (
            not isinstance(self.approved_tools, frozenset | set)
            or not all(isinstance(name, str) for name in self.approved_tools)
        ):
            raise ValidationError(
                "ToolContext.approved_tools must be a set of tool-name strings or None. It can "
                "only narrow the executor's trajectory allowlist; None means the allowlist stands "
                "alone.",
                details={"field": "approved_tools"},
            )
        if not isinstance(self.max_egress, EgressClass):
            raise ValidationError(
                f"ToolContext.max_egress must be an EgressClass; got "
                f"{type(self.max_egress).__name__}. It defaults to EgressClass.NONE, closed.",
                details={"field": "max_egress"},
            )
        if not callable(self.clock):
            raise ValidationError(
                "ToolContext.clock must be callable and return a timezone-aware datetime.",
                details={"field": "clock"},
            )
        if isinstance(self.approved_tools, set):
            object.__setattr__(self, "approved_tools", frozenset(self.approved_tools))


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    """The untrusted half of an invocation: what the model asked for, exactly as it asked.

    **Nothing here is validated at construction, and that is the point.** A model chose both
    fields; a ``__post_init__`` that refused a bad name or bad arguments would raise on model input,
    which is the design ADR-0053 rejects — the model would then choose when the exception fires. Any
    Python value at all can sit in either field, and every one of them has a defined outcome at
    :meth:`~toolyard.executor.ToolExecutor.execute`.

    Attributes:
        name: The tool name the model asked for. Annotated ``str`` because that is what a
            well-behaved caller passes; the executor assumes nothing and handles anything.
        args: The arguments the model supplied. May be enormous, cyclic, wrongly typed, or hold
            values that are not JSON at all. The executor sanitizes before hashing and refuses
            before validating.
    """

    name: str
    args: Mapping[str, Any]


class ToolHandler(Protocol):
    """What the application registers: a Python object that does the work.

    Registered in code, at startup, or it does not happen (ADR-0053 decision 1). There is no loading
    from configuration, from an entry point, from a plugin directory, or from anything a model
    emitted — and no test helper that loads one by import path, which is the first step back toward
    it.
    """

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """Do the work and return its output in full, or return why it will not.

        Args:
            args: The validated arguments, with any declared path argument already replaced by its
                **resolved** path. Do not re-resolve it; resolving a second time reopens the window
                containment just closed.
            context: The invocation's trusted half.

        Returns:
            A :class:`ToolOutput` holding the whole output — the executor caps and hashes it — or a
            :class:`ToolRefusal` naming the handler's own check that said no. A handler that
            *raises* is reported as ``handler_error``, which names an exception class and not a
            check, so anything the handler decided deliberately belongs in a ``ToolRefusal``.
        """
        ...


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """One registration: the declaration, the callable, and the validator compiled for it.

    Spec §7 names this type and does not define it. It exposes the handler because
    :meth:`~toolyard.registry.ToolRegistry.get` returns it and the registry is the *application's*
    object, built from handlers the application already holds — hiding it would be theatre. What
    matters is the other direction: there is no way to *add* one after startup, and no unregister.

    The validator is carried here rather than rebuilt per call because spec §15 budgets 10 ms for a
    whole dispatch, and it keeps :mod:`toolyard.executor` free of ``jsonschema`` entirely.

    Attributes:
        spec: The tool's declaration.
        handler: The callable that does the work.
        args_validator: The validator compiled from ``spec.args_schema`` at registration.
    """

    spec: ToolSpec
    handler: ToolHandler
    args_validator: ArgsValidator


@dataclass(frozen=True, slots=True)
class ToolResult:
    """What the caller gets back, and what the model is shown. Never an exception.

    Attributes:
        invocation_id: The application's id for the call, from :attr:`ToolContext.invocation_id`.
        status: One of :class:`ToolStatus`.
        content: What the model sees. Capped and, when capped, labelled — the label is part of the
            contract, because a model that assumes a result ended rather than stopped will answer
            from half a file. For a refusal this is a sentence naming the failed check; it never
            names a containment root's path or the allowlist's members, since refusal text is part
            of the prompt surface (ADR-0053's last consequence).
        reason: ``None`` for ``OK``; otherwise a member of :class:`Reason`, which is a closed set.
        duration_ms: Wall time from a monotonic source, rounded to a whole millisecond.
        reason_detail: The diagnosable half of a non-``OK`` result — the validator's paths, the
            candidate that escaped, the exception's class name, the elapsed time against the limit.
            Spec §13 asks three of its rows to carry detail that a closed reason set cannot hold,
            so the detail has its own field rather than being packed into ``reason`` (which
            PromptCadence matches exactly) or left only in prose.
    """

    invocation_id: str
    status: ToolStatus
    content: str
    reason: str | None
    duration_ms: int
    _: KW_ONLY
    reason_detail: str | None = None


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """What the store persists — one row per call, refused and failed calls included.

    The record is the observability surface (spec §17) and the thing PromptCadence reads to build a
    deviation. It is written for **every** outcome, which is what makes "a refusal is diagnosable
    from the record alone" (spec §11.2) true rather than aspirational.

    Attributes:
        invocation_id: The application's id for the call.
        tool_name: What the model asked for — cleaned and capped at
            :data:`MAX_RECORDED_NAME_CHARS`, and present even when no such tool exists, because a
            refusal that does not say what was asked for cannot be diagnosed.
        args_json: The canonical JSON of the sanitized arguments, or ``None`` when
            ``redact_args``. Always **valid JSON**: when the arguments are larger than the record's
            cap it becomes a small object naming the size and digest rather than a truncated
            fragment, so an application can always parse this field.
        args_sha256: Always present, including when redacted and including when the arguments could
            not be serialized as they stood. See
            :func:`~toolyard._safe.json_sanitize` for what is substituted and why.
        status: How the call ended.
        result_summary: The operator-facing account, capped. Identical to
            :attr:`ToolResult.content` except for a ``path_escape``, where the record names the root
            that was violated and the model-facing content names only its role.
        result_sha256: The digest of the handler's **full**, cleaned output — the value an
            application's artifact directory is keyed by when the output was too large to inline.
            The digest of the empty string when there was no output.
        duration_ms: Wall time from a monotonic source.
        risk_class: The registered tool's class, or ``READ_ONLY`` when no tool was found — a call
            that was refused before a tool was identified performed no action of any class.
        egress: The registered tool's class, or ``NONE`` on the same reasoning.
        started_at: From the injected wall clock, timezone-aware.
        reason: The machine-readable reason, mirrored from the result. Spec §11.2's promise that a
            refusal is diagnosable *from the record alone* needs the reason to be in the record.
        reason_detail: The detail, mirrored from the result.
    """

    invocation_id: str
    tool_name: str
    args_json: str | None
    args_sha256: str
    status: ToolStatus
    result_summary: str
    result_sha256: str
    duration_ms: int
    risk_class: RiskClass
    egress: EgressClass
    started_at: datetime
    _: KW_ONLY
    reason: str | None = None
    reason_detail: str | None = None


def _deep_freeze(value: Any) -> Any:  # noqa: ANN401 — copies a JSON Schema document
    """Return a private deep copy of a JSON-shaped structure.

    ``jsonschema`` consumes real ``dict`` and ``list`` objects, so this copies rather than wrapping
    in read-only views: the goal is that a caller's later mutation cannot reach the registered spec,
    not that the copy itself be un-writable from inside this package.
    """
    if isinstance(value, dict):
        return {clean_text(str(key)): _deep_freeze(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_deep_freeze(item) for item in value]
    return value
