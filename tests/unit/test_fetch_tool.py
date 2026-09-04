"""``http_fetch``, driven by the ADR-0026 §3 vector set that LoadCoach's fetch also runs.

The vectors live in ``tests/fixtures/fetch/adr0026_vectors.json``, and that file is
**byte-identical** here and in LoadCoach — dev-plan AC2 and spec §20 criterion 4: one fixture
set, two repositories, both green. :data:`VECTORS_SHA256` is asserted here and the same digest is
asserted there, so a drift is a failing test in both rather than a discovery made later by someone
comparing behaviour in production.

Nothing here opens a socket. Every response is scripted through ``httpx.MockTransport`` and every
name resolution through the injected resolver, which is the whole reason both are injectable:
the link-local rule cannot otherwise be tested without a DNS server that answers with a link-local
address, and no test suite should need one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import httpx
import pytest
from baseaicore import ValidationError

from toolyard import (
    DEFAULT_ALLOWED_MEDIA_TYPES,
    EgressClass,
    PathContainment,
    Reason,
    RiskClass,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolOutput,
    ToolRefusal,
    ToolRegistry,
    ToolSpec,
    ToolStatus,
    http_fetch_tool,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from toolyard import InMemoryToolCallStore, SandboxPaths

VECTORS_PATH: Final[Path] = (
    Path(__file__).parent.parent / "fixtures" / "fetch" / "adr0026_vectors.json"
)

VECTORS_SHA256: Final[str] = "ae7d6689ded17443ff6a944d567d343b1981acfb3e17d4ae87ed43bad0e91fcc"
"""The digest of the shared vector file, asserted in **both** repositories.

Update it only when the file is deliberately changed — and when it is, the change lands in this
repository first, is copied into LoadCoach byte-for-byte, is proven with ``cmp``, and both digests
move in the same session. That is what makes "one fixture set" a fact rather than an intention.
"""


_DOCUMENT: Final[Mapping[str, Any]] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
VECTORS: Final[Sequence[Mapping[str, Any]]] = _DOCUMENT["vectors"]


def _resolver(mapping: Mapping[str, Sequence[str]]) -> Callable[[str], Sequence[str]]:
    """Build the resolver a vector describes; a host it does not name resolves to nothing."""

    def resolve(host: str) -> Sequence[str]:
        return mapping.get(host, ())

    return resolve


def _transport(
    vector: Mapping[str, Any], *, cap: int, seen: list[httpx.Request]
) -> httpx.MockTransport:
    """Script the vector's responses, in order, recording every request that was made.

    ``body_bytes_over_cap`` and ``declared_length_over_cap`` are resolved against ``cap`` here,
    which is the whole reason they are written relative to it: this repository's default cap is
    8 MiB and LoadCoach's is 128 MiB, and a vector naming either number would be a vector only one
    of them could run.
    """
    scripted = list(vector["responses"])

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        step = scripted[len(seen) - 1] if len(seen) <= len(scripted) else scripted[-1]
        if step.get("raise") == "connect_error":
            raise httpx.ConnectError("connection refused", request=request)
        headers = dict(step.get("headers", {}))
        if "body_bytes_over_cap" in step:
            body = b"a" * (cap + int(step["body_bytes_over_cap"]))
        else:
            body = str(step.get("body", "")).encode("utf-8")
        if "declared_length_over_cap" in step:
            headers["content-length"] = str(cap + int(step["declared_length_over_cap"]))
        if step.get("streamed"):
            # An iterator makes httpx send the body chunked, with no Content-Length — the only
            # shape in which the during-streaming check is the one that fires.
            size = int(step.get("chunk_bytes", 1024))
            content: Any = iter([body[at : at + size] for at in range(0, len(body), size)])
            return httpx.Response(int(step["status"]), content=content, headers=headers)
        return httpx.Response(int(step["status"]), content=body, headers=headers)

    return httpx.MockTransport(handler)


class TestTheSharedVectorFile:
    """The fixture is an artefact two repositories depend on, so its identity is asserted."""

    def test_the_vector_file_has_not_drifted(self) -> None:
        """A change here without the matching change in LoadCoach is a divergence, not an edit."""
        digest = hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()
        assert digest == VECTORS_SHA256, (
            "tests/fixtures/fetch/adr0026_vectors.json changed. Copy it into LoadCoach's "
            "tests/fixtures/fetch/, prove the copy with `cmp`, and update VECTORS_SHA256 in both "
            "repositories in the same change."
        )

    def test_every_vector_is_named_once_and_states_its_rule(self) -> None:
        names = [vector["name"] for vector in VECTORS]
        assert len(set(names)) == len(names)
        assert all(vector["why"].strip() for vector in VECTORS)

    def test_no_vector_states_the_cap_as_a_number(self) -> None:
        """The caps differ between the two repositories, so a shared vector may not name one."""
        for vector in VECTORS:
            for response in vector["responses"]:
                assert "body_bytes" not in response
                assert "content-length" not in {key.lower() for key in response.get("headers", {})}


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: str(vector["name"]))
class TestAdr0026Vectors:
    """Every §3 rule, against a recorded transport, with no socket opened."""

    def test_the_vector_produces_the_outcome_it_names(
        self, vector: Mapping[str, Any], context: ToolContext
    ) -> None:
        seen: list[httpx.Request] = []
        overrides: dict[str, Any] = {}
        if vector["max_bytes"] is not None:
            overrides["max_bytes"] = int(vector["max_bytes"])
        if vector["max_redirects"] is not None:
            overrides["max_redirects"] = int(vector["max_redirects"])
        cap = overrides.get("max_bytes", 8_388_608)
        _spec, handler = http_fetch_tool(
            vector["allowed_hosts"],
            resolve=_resolver(vector["resolves"]),
            transport=_transport(vector, cap=cap, seen=seen),
            **overrides,
        )
        outcome = handler.execute({"url": vector["url"]}, context)
        expected = vector["expect"]
        if expected["outcome"] == "ok":
            assert isinstance(outcome, ToolOutput), outcome
            assert outcome.structured is not None
            assert outcome.structured["content_type"] == expected["content_type"]
        else:
            assert isinstance(outcome, ToolRefusal), outcome
            assert outcome.reason.value == expected["reason"]
            assert outcome.status is (
                ToolStatus.REFUSED if expected["outcome"] == "refused" else ToolStatus.FAILED
            )
        assert len(seen) == vector["requests_expected"], (
            f"{vector['name']}: made {len(seen)} requests, expected "
            f"{vector['requests_expected']} — a check that must happen before a socket is opened "
            "shows here as zero."
        )


def _tool_spec() -> ToolSpec:
    """The declaration, built with a resolver that answers nothing."""
    return http_fetch_tool(("127.0.0.1",), resolve=lambda _host: ())[0]


def _fetch_executor(
    store: InMemoryToolCallStore, *, transport: httpx.MockTransport | None = None
) -> ToolExecutor:
    """An executor holding ``http_fetch`` over a scripted transport."""
    registry = ToolRegistry()
    registry.register(
        *http_fetch_tool(("127.0.0.1",), resolve=lambda _host: ("127.0.0.1",), transport=transport)
    )
    return ToolExecutor(
        registry, PathContainment(), allowlist=frozenset({"http_fetch"}), store=store
    )


def _open_context(workspace: SandboxPaths) -> ToolContext:
    """An invocation whose egress ceiling admits the network."""
    return ToolContext(invocation_id="inv-1", workspace=workspace, max_egress=EgressClass.NETWORK)


class TestTheDeclarationItself:
    """What the model is shown, and what the executor is told to enforce."""

    def _tool(self) -> ToolSpec:
        return _tool_spec()

    def test_it_declares_network_egress_so_the_ceiling_can_refuse_it(self) -> None:
        """`max_egress` defaults closed, so an invocation that has not thought about the network
        cannot reach it (spec §11, C2 §4b)."""
        assert self._tool().egress is EgressClass.NETWORK

    def test_it_is_read_only(self) -> None:
        assert self._tool().risk_class is RiskClass.READ_ONLY

    def test_it_requires_no_isolation_and_declares_no_path(self) -> None:
        spec = self._tool()
        assert spec.requires_isolation is False
        assert spec.path_args == {}

    def test_the_description_says_no_credentials_can_be_supplied(self) -> None:
        """Spec §14: there is no credential surface, and the model should not try to find one."""
        assert "no credentials" in self._tool().description.lower()

    def test_the_argument_schema_admits_a_url_and_nothing_else(self) -> None:
        """A header, a method or a body would each be a door this tool does not have."""
        schema = self._tool().args_schema
        assert set(schema["properties"]) == {"url"}
        assert schema["additionalProperties"] is False


class TestTheCallerOwnedInputsRaise:
    """Everything a model does not choose is validated at construction (spec §12)."""

    def test_a_missing_resolver_is_a_type_error_rather_than_a_silent_default(self) -> None:
        """There is no default. Every default available here is either a boundary violation or a
        resolver that answers nothing, and the second makes the link-local check vacuous."""
        with pytest.raises(TypeError):
            http_fetch_tool(("127.0.0.1",))  # type: ignore[call-arg]

    def test_a_resolver_that_is_not_callable_raises(self) -> None:
        with pytest.raises(ValidationError, match="resolve"):
            http_fetch_tool(("127.0.0.1",), resolve="socket")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("http://127.0.0.1/x", None),
            ("http://localhost/x", None),
            ("http://elsewhere.example/x", Reason.HOST_NOT_ALLOWED),
        ],
    )
    def test_an_empty_allowlist_means_loopback_and_never_everything(
        self, context: ToolContext, url: str, reason: Reason | None
    ) -> None:
        """Spec §11.5. An allowlist that defaulted open would be an allowlist in name.

        Asserted through the tool rather than against its private policy, because "loopback only"
        is a statement about which fetches happen.
        """

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

        _spec, tool = http_fetch_tool(
            (), resolve=lambda _host: (), transport=httpx.MockTransport(handler)
        )
        outcome = tool.execute({"url": url}, context)
        if reason is None:
            assert isinstance(outcome, ToolOutput)
        else:
            assert isinstance(outcome, ToolRefusal)
            assert outcome.reason is reason

    @pytest.mark.parametrize("hosts", [("",), ("  ",), (17,)])
    def test_a_host_that_is_not_a_usable_name_raises(self, hosts: tuple[object, ...]) -> None:
        with pytest.raises(ValidationError, match="allowed_hosts"):
            http_fetch_tool(hosts, resolve=lambda _host: ())  # type: ignore[arg-type]

    def test_an_empty_media_type_allowlist_raises(self) -> None:
        """A tool that can never succeed is a misconfiguration, not a closed door."""
        with pytest.raises(ValidationError, match="allowed_media_types"):
            http_fetch_tool(("127.0.0.1",), resolve=lambda _host: (), allowed_media_types=())

    @pytest.mark.parametrize("value", [0, -1, True, "8192", 1023])
    def test_a_cap_below_the_floor_or_of_the_wrong_type_raises(self, value: object) -> None:
        with pytest.raises(ValidationError, match="max_bytes"):
            http_fetch_tool(
                ("127.0.0.1",),
                resolve=lambda _host: (),
                max_bytes=value,  # type: ignore[arg-type]
            )

    def test_a_negative_redirect_cap_raises_and_zero_does_not(self) -> None:
        """Zero means "follow none", which is a policy. Negative is not one."""
        with pytest.raises(ValidationError, match="max_redirects"):
            http_fetch_tool(("127.0.0.1",), resolve=lambda _host: (), max_redirects=-1)
        assert http_fetch_tool(("127.0.0.1",), resolve=lambda _host: (), max_redirects=0)

    @pytest.mark.parametrize("value", [0, -1.0, "5", None])
    def test_a_connect_timeout_that_is_not_a_positive_number_raises(self, value: object) -> None:
        """ADR-0026 §3 requires both timeouts, and "no timeout" is not one of its values."""
        with pytest.raises(ValidationError, match="connect_timeout_seconds"):
            http_fetch_tool(
                ("127.0.0.1",),
                resolve=lambda _host: (),
                connect_timeout_seconds=value,  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize("value", [0, -1.0, "5", None])
    def test_a_read_timeout_that_is_not_a_positive_number_raises(self, value: object) -> None:
        with pytest.raises(ValidationError, match="read_timeout_seconds"):
            http_fetch_tool(
                ("127.0.0.1",),
                resolve=lambda _host: (),
                read_timeout_seconds=value,  # type: ignore[arg-type]
            )


class TestThroughTheExecutor:
    """ADR-0053: every refusal is a result, and it is driven through ``execute()`` to prove it."""

    def test_an_invocation_with_the_default_egress_ceiling_never_reaches_the_handler(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """`max_egress` defaults to NONE, so a caller who never thought about it cannot leak."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)  # pragma: no cover - the point is that this never runs
            return httpx.Response(200, text="x", headers={"content-type": "text/plain"})

        executor = _fetch_executor(store, transport=httpx.MockTransport(handler))
        result = executor.execute(
            ToolCallRequest(name="http_fetch", args={"url": "http://127.0.0.1/x"}), context
        )
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.EGRESS_NOT_PERMITTED.value
        assert seen == []

    def test_a_refused_fetch_is_a_result_and_the_record_names_the_check(
        self, workspace: SandboxPaths, store: InMemoryToolCallStore
    ) -> None:
        executor = _fetch_executor(store)
        result = executor.execute(
            ToolCallRequest(name="http_fetch", args={"url": "file:///etc/passwd"}),
            _open_context(workspace),
        )
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.SCHEME_NOT_ALLOWED.value
        assert store.records[-1].reason == Reason.SCHEME_NOT_ALLOWED.value

    def test_no_refusal_names_the_allowlist_to_the_model(
        self, workspace: SandboxPaths, store: InMemoryToolCallStore
    ) -> None:
        """Refusal text is prompt surface: it names the failed check, never the allowlist."""
        executor = _fetch_executor(store)
        result = executor.execute(
            ToolCallRequest(name="http_fetch", args={"url": "http://elsewhere.example/x"}),
            _open_context(workspace),
        )
        assert result.reason == Reason.HOST_NOT_ALLOWED.value
        assert "127.0.0.1" not in result.content
        assert "127.0.0.1" in store.records[-1].result_summary

    def test_an_absurdly_long_url_is_not_echoed_whole_into_the_prompt(
        self, workspace: SandboxPaths, store: InMemoryToolCallStore
    ) -> None:
        executor = _fetch_executor(store)
        result = executor.execute(
            ToolCallRequest(name="http_fetch", args={"url": "gopher://" + "a" * 4000}),
            _open_context(workspace),
        )
        assert result.status is ToolStatus.REFUSED
        assert len(result.content) < 1_000


class TestNoCredentialEverLeaves:
    """Spec §14: an API key cannot leak through this tool by construction."""

    def test_no_authorization_header_is_sent(self, context: ToolContext) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

        _spec, tool = http_fetch_tool(
            ("127.0.0.1",),
            resolve=lambda _host: ("127.0.0.1",),
            transport=httpx.MockTransport(handler),
        )
        tool.execute({"url": "http://127.0.0.1/x"}, context)
        headers = {name.lower() for name in seen[0].headers}
        assert "authorization" not in headers
        assert "cookie" not in headers

    def test_the_default_media_types_are_text_and_do_not_admit_an_octet_stream(self) -> None:
        assert "application/octet-stream" not in DEFAULT_ALLOWED_MEDIA_TYPES
        assert all(
            kind.startswith(("text/", "application/")) for kind in DEFAULT_ALLOWED_MEDIA_TYPES
        )


class TestTheOriginBehavingBadly:
    """The branches between a well-behaved origin and a traceback in a prompt."""

    def _tool_over(self, handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any) -> Any:
        _spec, tool = http_fetch_tool(
            ("127.0.0.1",),
            resolve=lambda _host: ("127.0.0.1",),
            transport=httpx.MockTransport(handler),
            **kwargs,
        )
        return tool

    def test_a_malformed_location_header_arrives_as_a_transport_failure(
        self, context: ToolContext
    ) -> None:
        """Where an unparsable redirect target actually lands, pinned because it is not obvious.

        httpx parses the ``Location`` header while it builds the response, so a header that is not
        a URL raises inside ``send`` and is caught there — the redirect logic never sees it. That
        is why ``_next_hop`` does not guard its own ``join``: the guard would be unreachable. If a
        future httpx stops pre-parsing, this test changes and someone looks at that branch again.
        """

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "http://127.0.0.1:notaport/y"})

        outcome = self._tool_over(handler).execute({"url": "http://127.0.0.1/x"}, context)
        assert isinstance(outcome, ToolRefusal)
        assert outcome.reason is Reason.TRANSPORT_ERROR
        assert outcome.status is ToolStatus.FAILED

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("http://127.0.0.1:notaport/x", id="a-port-that-is-not-a-number"),
            pytest.param("http://" + "a" * 70_000, id="longer-than-any-url"),
        ],
    )
    def test_a_url_the_parser_itself_rejects_is_a_refusal_and_not_an_exception(
        self, context: ToolContext, url: str
    ) -> None:
        """The parser is the first thing a model's string touches, and it raises on some of them."""

        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

        outcome = self._tool_over(handler).execute({"url": url}, context)
        assert isinstance(outcome, ToolRefusal)
        assert outcome.reason is Reason.MALFORMED_URL
        assert len(outcome.detail) < 500, "the whole URL was echoed back into the prompt"

    def test_a_transport_that_dies_part_way_through_the_body_is_a_failure(
        self, context: ToolContext
    ) -> None:
        """Half a document must not reach the model as a whole one."""

        def chunks() -> Any:
            yield b"the beginning"
            raise httpx.ReadError("connection reset")

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=chunks(), headers={"content-type": "text/plain"})

        outcome = self._tool_over(handler).execute({"url": "http://127.0.0.1/x"}, context)
        assert isinstance(outcome, ToolRefusal)
        assert outcome.reason is Reason.TRANSPORT_ERROR
        assert outcome.status is ToolStatus.FAILED

    def test_a_body_that_is_not_utf8_is_reported_rather_than_decoded_with_replacement(
        self, context: ToolContext
    ) -> None:
        """A text tool that returned mojibake would be a tool that lies about its own contract."""

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=b"\xff\xfe\x00\x01", headers={"content-type": "text/plain"}
            )

        outcome = self._tool_over(handler).execute({"url": "http://127.0.0.1/x"}, context)
        assert isinstance(outcome, ToolRefusal)
        assert outcome.reason is Reason.NOT_UTF8
        assert outcome.status is ToolStatus.FAILED

    def test_a_resolver_answering_with_something_that_is_not_an_address_is_skipped(
        self, context: ToolContext
    ) -> None:
        """The resolver is the application's code; this is a check, not a validator of it."""

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

        _spec, tool = http_fetch_tool(
            ("example.internal",),
            resolve=lambda _host: ("not-an-address", "", "203.0.113.1"),
            transport=httpx.MockTransport(handler),
        )
        assert isinstance(tool.execute({"url": "http://example.internal/x"}, context), ToolOutput)

    def test_a_resolver_answer_carrying_a_zone_index_is_still_compared(
        self, context: ToolContext
    ) -> None:
        """`fe80::1%eth0` is a link-local address wearing an interface name."""

        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

        _spec, tool = http_fetch_tool(
            ("example.internal",),
            resolve=lambda _host: ("fe80::1%eth0",),
            transport=httpx.MockTransport(handler),
        )
        outcome = tool.execute({"url": "http://example.internal/x"}, context)
        assert isinstance(outcome, ToolRefusal)
        assert outcome.reason is Reason.LINK_LOCAL_ADDRESS

    def test_a_url_that_is_not_a_string_is_refused_rather_than_raising(
        self, context: ToolContext
    ) -> None:
        """Reached directly rather than through the executor, whose schema would refuse it first —
        the handler must still hold on its own, because a handler that relies on a check it does
        not make is a handler that breaks when the check moves."""

        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})

        outcome = self._tool_over(handler).execute({"url": "http://"}, context)
        assert isinstance(outcome, ToolRefusal)
        assert outcome.reason in (Reason.NO_HOST, Reason.MALFORMED_URL)
