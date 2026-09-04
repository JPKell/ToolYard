"""``http_fetch`` — ADR-0026 §3's outbound discipline, performed at the socket.

The checks are here rather than in a caller because a caller who forgets one has an SSRF, and the
redirect hop is the one everybody forgets. Spec §11.5 names them: scheme, host allowlist, literal-IP
comparison after resolution, re-checked on **every** hop, and a size cap enforced during streaming.
The same checks LoadCoach's evidence import makes — proven so rather than asserted, by
``tests/fixtures/fetch/adr0026_vectors.json``, which is byte-identical in both repositories and
drives both implementations.

Three things are this package's and not LoadCoach's:

* **No credentials, ever.** There is no ``Authorization`` header, no environment read, no file read,
  and no argument through which a secret could arrive (spec §14). A fetch that needs a credential is
  a fetch this tool does not perform.
* **Name resolution is injected and required.** ``.importlinter`` forbids ``socket`` in every module
  of this package, forever, so ToolYard opens no resolver socket of its own. The argument has no
  default because every default available here is either that boundary violation or a resolver that
  answers nothing — and a resolver that answers nothing makes the link-local rule vacuous without
  saying so.
* **The content-type allowlist is closed and small**, and it is checked before any of the body is
  returned. LoadCoach admits JSON because it parses JSON; an agent tool reads text, so the default
  set is text and the structured text formats, and nothing else.

**The residual, stated rather than implied away.** The check resolves a name and then connects, and
those are two operations. A name whose answer changes between them — DNS rebinding against a host
the caller allowlisted — is not addressed by this design; closing it needs the connection pinned to
the address that was checked, and httpx exposes no seam for that. The host allowlist is what stands
in its place. Nothing in this module's docstrings claims an address pinning it does not implement.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any, Final

import httpx
from baseaicore import ValidationError

from toolyard.types import (
    EgressClass,
    Reason,
    RiskClass,
    ToolOutput,
    ToolRefusal,
    ToolSpec,
    ToolStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from toolyard.types import ToolContext, ToolHandler

__all__ = [
    "DEFAULT_ALLOWED_MEDIA_TYPES",
    "DEFAULT_CONNECT_TIMEOUT_SECONDS",
    "DEFAULT_MAX_FETCH_BYTES",
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_READ_TIMEOUT_SECONDS",
    "LOOPBACK_HOSTS",
    "Resolver",
    "http_fetch_tool",
]

type Resolver = Callable[[str], Sequence[str]]
"""Maps a hostname to the addresses it names.

Injected, and required, for two reasons that point the same way: this package may not open a socket
(``.importlinter``, forever), and the link-local rule is only testable without a DNS server that
answers with a link-local address if the resolution is a seam. The application's implementation is
one line — ``lambda host: [info[4][0] for info in socket.getaddrinfo(host, None)]`` — and writing it
is a deliberate act, which is the point.
"""

DEFAULT_MAX_FETCH_BYTES: Final[int] = 8_388_608
"""Spec §7's cap: what this tool will pull from a stranger before it knows what the body is.
Enforced against a declared ``Content-Length`` *and* during streaming, because a declaration is the
origin's claim and the stream is the fact."""

DEFAULT_MAX_REDIRECTS: Final[int] = 3
"""ADR-0026 §3's cap. A redirect that changes host is refused whatever the count."""

DEFAULT_CONNECT_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_READ_TIMEOUT_SECONDS: Final[float] = 30.0
"""ADR-0026 §3 requires both and names neither. The same figures LoadCoach chose, so that a reader
comparing the two implementations is not comparing two sets of numbers as well."""

DEFAULT_ALLOWED_MEDIA_TYPES: Final[tuple[str, ...]] = (
    "text/plain",
    "text/markdown",
    "text/html",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
)
"""What a fetch may return, closed and checked before the body is.

An agent tool reads text, so the set is text and the structured text formats. A media type ending
``+json`` is admitted too — RFC 6839's structured suffix, and the one rule LoadCoach also applies,
so a shared vector asserting it holds in both. Everything else, images and archives and octet
streams included, is refused: this tool returns a string, and a model handed a decoded PNG has been
handed noise it will treat as text.
"""

LOOPBACK_HOSTS: Final[tuple[str, ...]] = ("127.0.0.1", "localhost", "::1")
"""What an empty allowlist means (spec §11.5): loopback only, never everything. An allowlist that
defaulted open would be an allowlist in name."""

MIN_FETCH_BYTES: Final[int] = 1_024
"""Floor for a configured cap. Below this no useful document fits."""

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
"""ADR-0026 §3: nothing else. ``file://`` in particular is a local read in a URL's clothing."""

_URL_SCHEMA: Final[Mapping[str, Any]] = {
    "type": "object",
    "properties": {
        "url": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2048,
            "description": "An http or https URL whose host is on this tool's allowlist.",
        }
    },
    "required": ["url"],
    "additionalProperties": False,
}


class _FetchPolicy:
    """One fetch's rules, resolved from the factory's arguments and never from a model's."""

    __slots__ = (
        "allowed_hosts",
        "allowed_media_types",
        "connect_timeout_seconds",
        "max_bytes",
        "max_redirects",
        "read_timeout_seconds",
    )

    def __init__(
        self,
        *,
        allowed_hosts: tuple[str, ...],
        max_bytes: int,
        max_redirects: int,
        allowed_media_types: tuple[str, ...],
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
    ) -> None:
        """Hold the validated policy. Every value is the caller's."""
        self.allowed_hosts = allowed_hosts
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.allowed_media_types = allowed_media_types
        self.connect_timeout_seconds = connect_timeout_seconds
        self.read_timeout_seconds = read_timeout_seconds


def _refuse(reason: Reason, detail: str, *, record_detail: str | None = None) -> ToolRefusal:
    """Build a ``REFUSED`` result for a rule of this package that said no."""
    return ToolRefusal(reason, detail, record_detail=record_detail)


def _addresses_of(
    host: str, *, resolve: Resolver
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return every address a host names, whether it is a literal or a name to be resolved.

    A literal is not passed to the resolver: it already *is* the answer, and handing it to an
    application-supplied callable would let a resolver that answers ``[]`` erase a link-local
    literal — the one case that must never depend on anything injectable.

    Args:
        host: The URL's host, brackets stripped for an IPv6 literal.
        resolve: The injected resolver.

    Returns:
        The addresses. An entry the resolver returns that is not an address is skipped rather than
        raising: the resolver is the application's code and this is a check, not a validator of it.
    """
    try:
        return [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        pass
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for candidate in resolve(host):
        try:
            addresses.append(ipaddress.ip_address(str(candidate).split("%")[0]))
        except ValueError:
            continue
    return addresses


def _check_url(url: str, policy: _FetchPolicy, *, resolve: Resolver) -> httpx.URL | ToolRefusal:
    """Apply ADR-0026 §3's URL rules to one URL, or say which one it failed.

    The order is deliberate and it is the order LoadCoach uses: parse, then scheme, then host, then
    addresses. A ``file://`` URL fails on its scheme without a name ever being resolved, and a host
    outside the allowlist fails without a connection ever being opened — so a refusal costs the
    attacker no information about what is reachable.

    Args:
        url: The URL to check. On the first hop this is the model's argument; on later hops it is
            the ``Location`` the origin sent, which is no more trusted than the first.
        policy: The fetch rules.
        resolve: The injected resolver.

    Returns:
        The parsed URL when every rule passes, or the :class:`ToolRefusal` for the first that did
        not.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError):
        return _refuse(Reason.MALFORMED_URL, f"{_shorten(url)!r} is not a URL that can be fetched")

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return _refuse(
            Reason.SCHEME_NOT_ALLOWED,
            f"only http and https may be fetched; {scheme or '(none)'!r} may not",
        )
    host = parsed.host
    if not host:
        return _refuse(Reason.NO_HOST, f"{_shorten(url)!r} names no host")
    if host.lower() not in {allowed.lower() for allowed in policy.allowed_hosts}:
        return _refuse(
            Reason.HOST_NOT_ALLOWED,
            f"{host!r} is not a host this tool may fetch from",
            record_detail=f"allowed_hosts={list(policy.allowed_hosts)}",
        )
    for address in _addresses_of(host, resolve=resolve):
        if address.is_link_local:
            return _refuse(
                Reason.LINK_LOCAL_ADDRESS,
                f"{host!r} is, or resolves to, a link-local address; that range is refused "
                "unconditionally and being on the allowlist does not change it",
                record_detail=f"address={address}",
            )
    return parsed


def _shorten(value: object) -> str:
    """Cap a model-supplied string before it is quoted back into a refusal sentence."""
    text = value if isinstance(value, str) else f"<{type(value).__name__}>"
    return text if len(text) <= _MAX_URL_REPORT_CHARS else f"{text[:_MAX_URL_REPORT_CHARS]}…"


_MAX_URL_REPORT_CHARS: Final[int] = 200
"""How much of a URL a refusal sentence repeats. The model wrote it; it does not need all of it
back, and a refusal is not a place to echo two kilobytes into a prompt."""


def _check_media_type(response: httpx.Response, policy: _FetchPolicy) -> ToolRefusal | str:
    """Verify ``Content-Type`` before any of the body is returned.

    Args:
        response: The response, headers read and body not.
        policy: The fetch rules, for the allowlist.

    Returns:
        The media type when it is admitted, or the refusal.
    """
    raw = str(response.headers.get("content-type", ""))
    media_type = raw.split(";")[0].strip().lower()
    if media_type in policy.allowed_media_types or media_type.endswith("+json"):
        return media_type
    return _refuse(
        Reason.CONTENT_TYPE_NOT_ALLOWED,
        f"the response declared Content-Type {_shorten(raw) or '(none)'!r}, which this tool does "
        "not return; it returns text",
        record_detail=f"allowed_media_types={list(policy.allowed_media_types)}",
    )


class _HttpFetch:
    """``http_fetch``'s handler: one client, one policy, one injected resolver."""

    __slots__ = ("_client", "_policy", "_resolve")

    def __init__(
        self, policy: _FetchPolicy, *, resolve: Resolver, transport: httpx.BaseTransport | None
    ) -> None:
        """Build the handler and its client.

        ``follow_redirects=False`` is load-bearing rather than a preference: httpx following a
        redirect itself would put the hop beyond every check in this module, which is precisely the
        omission ADR-0026 §3 exists to prevent.
        """
        self._policy = policy
        self._resolve = resolve
        self._client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(
                policy.read_timeout_seconds, connect=policy.connect_timeout_seconds
            ),
            follow_redirects=False,
        )

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """Fetch one URL under every ADR-0026 §3 rule, and return its text or why not.

        Args:
            args: ``url``. The model's, and checked before a socket is opened.
            context: The invocation. Unused: this tool touches no path and holds no credential, so
                there is nothing on the context it may read.

        Returns:
            The body as text, or the refusal naming the check that stopped it. A transport failure
            is ``FAILED`` / ``transport_error`` and a 4xx/5xx is ``FAILED`` / ``http_status``,
            because in both the origin — not this package — is what did not cooperate, and
            retrying may be meaningful. Every rule this package applied is ``REFUSED``, where
            retrying the identical call cannot be.
        """
        del context
        checked = _check_url(str(args["url"]), self._policy, resolve=self._resolve)
        if isinstance(checked, ToolRefusal):
            return checked
        target = checked
        origin_host = target.host
        redirects = 0
        while True:
            response_or_refusal = self._send(target)
            if isinstance(response_or_refusal, ToolRefusal):
                return response_or_refusal
            response = response_or_refusal
            if not response.is_redirect:
                return self._read(response, target)
            response.close()
            redirects += 1
            hop = self._next_hop(response, target, origin_host, redirects)
            if isinstance(hop, ToolRefusal):
                return hop
            target = hop

    def _send(self, target: httpx.URL) -> httpx.Response | ToolRefusal:
        """Open a streaming request, turning a transport failure into a result."""
        request = self._client.build_request("GET", target)
        try:
            return self._client.send(request, stream=True)
        except httpx.HTTPError as exc:
            return ToolRefusal(
                Reason.TRANSPORT_ERROR,
                f"{target.host!r} could not be reached ({type(exc).__name__})",
                status=ToolStatus.FAILED,
                record_detail=f"url={target}: {exc}",
            )

    def _next_hop(
        self, response: httpx.Response, target: httpx.URL, origin_host: str, redirects: int
    ) -> httpx.URL | ToolRefusal:
        """Decide where a redirect may go, applying every first-hop rule again.

        The cap is checked first, then the host change, then the whole of :func:`_check_url` on the
        new URL — scheme, allowlist and link-local addresses included. A check applied to the first
        hop only is this phase's named failure mode, and a redirect to ``http://169.254.169.254/``
        from an allowlisted origin is exactly the shape it takes.

        ``join`` is not guarded, and that is deliberate rather than an omission: httpx parses the
        ``Location`` header while it builds the response, so a header that is not a URL never
        reaches here — it arrives as a transport error from :meth:`_send` instead, which is a
        result like any other. A guard here would be a branch no input could take.
        ``test_a_malformed_location_header_arrives_as_a_transport_failure`` pins that, so if httpx
        ever stops pre-parsing, a test says so rather than a model receiving an exception.
        """
        if redirects > self._policy.max_redirects:
            return _refuse(
                Reason.TOO_MANY_REDIRECTS,
                f"the fetch was redirected more than {self._policy.max_redirects} times",
                record_detail=f"url={target}",
            )
        nxt = target.join(str(response.headers.get("location", "")))
        if nxt.host != origin_host:
            return _refuse(
                Reason.CROSS_HOST_REDIRECT,
                f"{target.host!r} redirected to a different host; redirects are not followed "
                "across a host change",
                record_detail=f"redirect_host={nxt.host!r}, origin_host={origin_host!r}",
            )
        recheck = _check_url(str(nxt), self._policy, resolve=self._resolve)
        if isinstance(recheck, ToolRefusal):
            return recheck
        return recheck

    def _read(self, response: httpx.Response, target: httpx.URL) -> ToolOutput | ToolRefusal:
        """Verify the head, then stream the body under the cap, then decode it.

        The declared ``Content-Length`` is checked before a byte is streamed and the running total
        is checked as the bytes arrive, because the declaration is the origin's claim and the stream
        is the fact — an origin that lies about its length is the case the second check exists for.
        The transfer *stops* at the cap rather than being read to the end and measured.
        """
        try:
            if response.status_code >= _HTTP_ERROR_FLOOR:
                return ToolRefusal(
                    Reason.HTTP_STATUS,
                    f"{target.host!r} answered {response.status_code}",
                    status=ToolStatus.FAILED,
                    record_detail=f"url={target}",
                )
            media_type = _check_media_type(response, self._policy)
            if isinstance(media_type, ToolRefusal):
                return media_type
            declared = response.headers.get("content-length")
            over_declared = (
                declared is not None
                and declared.isdigit()
                and int(declared) > self._policy.max_bytes
            )
            if over_declared and declared is not None:
                return _refuse(
                    Reason.TOO_LARGE,
                    f"the response declared {int(declared)} bytes and the limit is "
                    f"{self._policy.max_bytes}",
                    record_detail=f"url={target}",
                )
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > self._policy.max_bytes:
                    return _refuse(
                        Reason.TOO_LARGE,
                        f"the response sent more than the {self._policy.max_bytes}-byte limit; "
                        "the transfer was stopped rather than read to the end",
                        record_detail=f"url={target}",
                    )
                chunks.append(chunk)
        except httpx.HTTPError as exc:
            return ToolRefusal(
                Reason.TRANSPORT_ERROR,
                f"{target.host!r} stopped responding part way through ({type(exc).__name__})",
                status=ToolStatus.FAILED,
                record_detail=f"url={target}: {exc}",
            )
        finally:
            response.close()
        raw = b"".join(chunks)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return ToolRefusal(
                Reason.NOT_UTF8,
                f"{target.host!r} returned {len(raw)} bytes that are not valid UTF-8 text",
                status=ToolStatus.FAILED,
                record_detail=f"url={target}, content_type={media_type}",
            )
        return ToolOutput(
            content=text,
            structured={"url": str(target), "content_type": media_type, "bytes": len(raw)},
        )


_HTTP_ERROR_FLOOR: Final[int] = 400
"""HTTP's own boundary between an answer and an error."""


def http_fetch_tool(
    allowed_hosts: Sequence[str],
    *,
    resolve: Resolver,
    max_bytes: int = DEFAULT_MAX_FETCH_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allowed_media_types: Sequence[str] = DEFAULT_ALLOWED_MEDIA_TYPES,
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
    read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
    transport: httpx.BaseTransport | None = None,
) -> tuple[ToolSpec, ToolHandler]:
    """Build ``http_fetch``: one GET, under ADR-0026 §3, returning text.

    Args:
        allowed_hosts: The hosts this tool may fetch from. **Empty means loopback only**
            (:data:`LOOPBACK_HOSTS`), never everything: an allowlist that defaulted open would be
            an allowlist in name. Compared case-insensitively against the URL's host, and the
            members are never named back to a model.
        resolve: Hostname resolution. Required, with no default — see :data:`Resolver`.
        max_bytes: The transfer cap, applied to a declared ``Content-Length`` and during streaming.
        max_redirects: How many same-host hops to follow. Each hop is re-checked in full.
        allowed_media_types: What may be returned, checked before the body is.
        connect_timeout_seconds: Connect timeout.
        read_timeout_seconds: Read timeout.
        transport: httpx's injection seam. ``None`` is the real one; the ADR-0026 §3 vector set
            drives the whole tool through a recorded transport, so the suite opens no socket.

    Returns:
        The ``(spec, handler)`` pair for ``registry.register(*http_fetch_tool(hosts, resolve=r))``.

    Raises:
        ValidationError: If ``resolve`` is not callable, a host is not a non-empty string, a cap or
            a timeout is out of range, or the media-type list is empty. Every one of these is the
            caller's input, so a mistake in it raises at startup rather than refusing on the one
            call that mattered.
    """
    if not callable(resolve):
        raise ValidationError(
            "http_fetch_tool's resolve must be callable: the link-local rule compares addresses "
            "after resolution, and this package opens no socket of its own. Supply the "
            "application's resolver.",
            details={"field": "resolve"},
        )
    hosts = tuple(LOOPBACK_HOSTS) if not allowed_hosts else tuple(allowed_hosts)
    if not all(isinstance(host, str) and host.strip() for host in hosts):
        raise ValidationError(
            "http_fetch_tool's allowed_hosts must be non-empty strings.",
            details={"field": "allowed_hosts"},
        )
    media_types = tuple(str(item).lower() for item in allowed_media_types)
    if not media_types:
        raise ValidationError(
            "http_fetch_tool's allowed_media_types must name at least one type: an empty "
            "allowlist admits nothing, which is a tool that cannot succeed rather than a tool that "
            "is closed.",
            details={"field": "allowed_media_types"},
        )
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < MIN_FETCH_BYTES:
        raise ValidationError(
            f"http_fetch_tool's max_bytes must be an int of at least {MIN_FETCH_BYTES}; got "
            f"{max_bytes!r}.",
            details={"field": "max_bytes", "minimum": MIN_FETCH_BYTES},
        )
    if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or max_redirects < 0:
        raise ValidationError(
            f"http_fetch_tool's max_redirects must be an int of at least 0; got {max_redirects!r}. "
            "Zero means no redirect is followed, which is a policy; a negative number is not.",
            details={"field": "max_redirects"},
        )
    for name, seconds in (
        ("connect_timeout_seconds", connect_timeout_seconds),
        ("read_timeout_seconds", read_timeout_seconds),
    ):
        if isinstance(seconds, bool) or not isinstance(seconds, int | float) or seconds <= 0:
            raise ValidationError(
                f"http_fetch_tool's {name} must be a positive number; got {seconds!r}. ADR-0026 §3 "
                "requires both timeouts, and 'no timeout' is not one of the values it permits.",
                details={"field": name},
            )
    policy = _FetchPolicy(
        allowed_hosts=hosts,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
        allowed_media_types=media_types,
        connect_timeout_seconds=float(connect_timeout_seconds),
        read_timeout_seconds=float(read_timeout_seconds),
    )
    spec = ToolSpec(
        name="http_fetch",
        description=(
            "Fetch one http or https URL and return its body as text. Only a short list of hosts "
            "may be fetched from, and a URL naming any other host is refused; so is any scheme "
            "other than http and https, any address in the link-local range, and any redirect "
            "that changes host. The response must be text — HTML, Markdown, plain text, CSV, JSON "
            "or XML — and there is a size limit, above which the transfer is stopped rather than "
            "truncated. No credentials are sent and none can be supplied."
        ),
        args_schema=_URL_SCHEMA,
        result_schema=None,
        risk_class=RiskClass.READ_ONLY,
        egress=EgressClass.NETWORK,
    )
    return spec, _HttpFetch(policy, resolve=resolve, transport=transport)
