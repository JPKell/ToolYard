"""``run_command`` — the isolation floor, the environment allowlist, and what the model is told.

Nothing here starts a process. The sandbox's launcher is the injected ``runner`` seam and its
executable lookup is the injected ``which`` seam (D1 §3), so a host with a rung, a host with no rung
and a command that runs long are all reachable without touching this machine's configuration. The
integration suite is where the real rungs run.

Acceptance criterion 3 — *on a host with neither container nor bwrap, ``run_command`` refuses and
the record says why* — is ``TestTheIsolationFloor``'s first test.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from baseaicore import ValidationError

from fakes import ScriptedRunner, captured, which_for
from toolyard import (
    DEFAULT_COMMAND_ENV,
    MIN_PROCESS_COUNT,
    Reason,
    ResourceLimits,
    TieredSandbox,
    ToolCallRequest,
    ToolExecutor,
    ToolRegistry,
    ToolStatus,
    run_command_tool,
)
from toolyard.sandbox import ARGV_REFUSED_PREFIX

if TYPE_CHECKING:
    from toolyard import InMemoryToolCallStore, SandboxPaths, ToolContext, ToolResult

BWRAP_HOST = {"bwrap": "/usr/bin/bwrap", "prlimit": "/usr/bin/prlimit"}
"""A host with the bwrap rung and no container runtime, as the probe would see it."""

BARE_HOST: dict[str, str] = {}
"""A host with neither rung. ADR-0018's floor is what must happen here."""


def _sandbox(available: dict[str, str], runner: ScriptedRunner) -> TieredSandbox:
    """A sandbox whose view of the host is exactly ``available``."""
    return TieredSandbox(which=which_for(available), runner=runner)


def _executor(sandbox: TieredSandbox, store: InMemoryToolCallStore) -> ToolExecutor:
    """An executor holding ``run_command`` bound to that same sandbox instance."""
    registry = ToolRegistry()
    registry.register(*run_command_tool(sandbox))
    return ToolExecutor(registry, sandbox, allowlist=frozenset({"run_command"}), store=store)


def _run(executor: ToolExecutor, context: ToolContext, *argv: str) -> ToolResult:
    """Drive one command through the executor, the way an application would."""
    return executor.execute(ToolCallRequest(name="run_command", args={"argv": list(argv)}), context)


class TestTheDeclarationItself:
    """What the model is shown, and what the executor is told to enforce."""

    def test_it_declares_isolation_so_the_executor_can_refuse_before_a_handler_runs(self) -> None:
        """``requires_isolation`` is load-bearing (spec §11.4): undeclared use is invisible."""
        spec, _handler = run_command_tool(TieredSandbox())
        assert spec.requires_isolation is True

    def test_it_declares_no_egress_because_the_child_has_no_network(self) -> None:
        assert run_command_tool(TieredSandbox())[0].egress.value == "none"

    def test_it_has_no_path_argument_because_argv_is_not_a_path(self) -> None:
        """A path argument would be resolved and substituted; argv[0] is a command name."""
        assert run_command_tool(TieredSandbox())[0].path_args == {}

    def test_the_description_warns_that_a_backgrounded_child_holds_the_call_open(self) -> None:
        """D1 finding 4: a model that tries to "start a server" must know what happens."""
        description = run_command_tool(TieredSandbox())[0].description
        assert "background" in description
        assert "timeout" in description
        assert "server" in description

    def test_the_description_says_there_is_no_shell(self) -> None:
        assert "no shell" in run_command_tool(TieredSandbox())[0].description

    def test_the_argument_schema_admits_only_an_array_of_strings(self) -> None:
        """A shell string is not expressible: there is no place in the schema to put one."""
        schema = run_command_tool(TieredSandbox())[0].args_schema
        assert schema["properties"]["argv"]["type"] == "array"
        assert schema["properties"]["argv"]["items"]["type"] == "string"
        assert schema["properties"]["argv"]["minItems"] == 1
        assert schema["additionalProperties"] is False

    def test_a_process_count_floor_is_documented_for_a_limit_nobody_validates(self) -> None:
        """D1 finding 7. bwrap's count includes bwrap and prlimit, so 1 or 2 refuses everything."""
        assert MIN_PROCESS_COUNT >= 3
        assert ResourceLimits().process_count > MIN_PROCESS_COUNT


class TestTheCallerOwnedInputsRaise:
    """Everything on this tool that a model does not choose is checked at startup."""

    def test_a_sandbox_that_is_not_one_raises(self) -> None:
        with pytest.raises(ValidationError, match="Sandbox"):
            run_command_tool(object())  # type: ignore[arg-type]

    @pytest.mark.parametrize("env", [{"PATH": 1}, {1: "x"}, "PATH=/bin", None])  # noqa: PT007
    def test_a_malformed_environment_raises_rather_than_refusing(self, env: object) -> None:
        """A malformed env discovered in the handler would reach a model as `handler_error`.

        That is a lever: a model cannot choose the environment, but it could learn that this tool
        always fails and stop using it. The environment is the caller's, so it is checked where the
        caller is — at construction (D1 §7).
        """
        with pytest.raises(ValidationError, match="env"):
            run_command_tool(TieredSandbox(), env=env)  # type: ignore[arg-type]


class TestTheIsolationFloor:
    """ADR-0018's rule applied to tools: no rung means refuse, never an unisolated run."""

    def test_a_host_with_no_rung_refuses_and_the_record_says_why(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """Spec §20 criterion 3, proved through the probe's injected view of the host."""
        runner = ScriptedRunner()
        executor = _executor(_sandbox(BARE_HOST, runner), store)
        result = _run(executor, context, "/bin/echo", "hi")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.ISOLATION_UNAVAILABLE.value
        assert runner.calls == [], "a command ran on a host with no isolation tier"
        record = store.records[-1]
        assert record.reason == Reason.ISOLATION_UNAVAILABLE.value
        assert record.tool_name == "run_command"
        assert "isolation" in record.result_summary

    def test_the_fixed_refusal_order_holds_even_on_a_host_that_could_never_run_it(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """Schema is check 3 and isolation is check 5, and being unrunnable does not reorder them.

        An empty argv is refused as ``args_invalid`` even here, because the order is fixed and a
        refusal names the **first** check that failed (spec §11.2). Worth pinning precisely because
        the other answer is tempting: telling the model the unfixable fact would seem kinder, and it
        would make the reported reason depend on the host rather than on the call.
        """
        runner = ScriptedRunner()
        executor = _executor(_sandbox(BARE_HOST, runner), store)
        result = executor.execute(ToolCallRequest(name="run_command", args={"argv": []}), context)
        assert result.reason == Reason.ARGS_INVALID.value
        assert runner.calls == []


class TestRunningACommand:
    """The happy path, and everything the model is told about it."""

    def test_a_command_runs_under_the_probed_rung_and_the_result_names_it(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        runner = ScriptedRunner(outcomes={"bwrap": captured(stdout=b"hello\n")})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/echo", "hello")
        assert result.status is ToolStatus.OK
        assert "exit code: 0" in result.content
        assert "isolation: bwrap" in result.content
        assert "hello" in result.content

    def test_the_argv_reaches_the_launcher_unjoined(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """No shell means the words the model wrote are the words the kernel gets."""
        runner = ScriptedRunner(outcomes={"bwrap": captured()})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        _run(executor, context, "/bin/echo", "a b", "c;d")
        launched = runner.calls[-1].argv
        assert "a b" in launched
        assert "c;d" in launched
        assert not any(";" in word and word != "c;d" for word in launched)

    def test_a_non_zero_exit_is_an_ok_result_carrying_the_code(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """The tool ran. "The command failed" is information, not a failure of the call."""
        runner = ScriptedRunner(outcomes={"bwrap": captured(exit_code=2, stderr=b"nope\n")})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/false")
        assert result.status is ToolStatus.OK
        assert "exit code: 2" in result.content
        assert "nope" in result.content

    def test_an_empty_stream_says_empty_rather_than_showing_nothing(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        runner = ScriptedRunner(outcomes={"bwrap": captured()})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/true")
        assert "stdout: (empty)" in result.content
        assert "stderr: (empty)" in result.content

    def test_a_truncated_output_says_so_beside_its_exit_code(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """D1 finding 3: a model must be able to tell a truncated success from a clean one."""
        runner = ScriptedRunner(
            outcomes={"bwrap": captured(stdout=b"x" * 100, output_truncated=True)}
        )
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/yes")
        assert "TRUNCATED" in result.content
        assert "exit code:" in result.content

    def test_a_timeout_is_reported_as_a_timeout_and_not_as_a_command_that_finished(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        runner = ScriptedRunner(outcomes={"bwrap": captured(exit_code=-9, timed_out=True)})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/sleep", "600")
        assert result.status is ToolStatus.TIMEOUT
        assert result.reason == Reason.TIMEOUT.value
        assert "process tree was killed" in result.content

    def test_an_unlaunchable_argv_is_reported_as_an_invalid_argument(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """A NUL passes the schema and not the launcher. It is the argument that was wrong."""
        runner = ScriptedRunner(outcomes={"bwrap": captured()})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/echo\x00rm")
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.ARGS_INVALID.value
        assert ARGV_REFUSED_PREFIX.strip() not in result.content

    def test_a_command_exiting_127_on_its_own_is_not_mistaken_for_an_unlaunchable_argv(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """127 is a code a real command may return; the launcher's prefix is what distinguishes."""
        runner = ScriptedRunner(outcomes={"bwrap": captured(exit_code=127, stderr=b"not found")})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        result = _run(executor, context, "/bin/sh-that-is-not-there")
        assert result.status is ToolStatus.OK
        assert "exit code: 127" in result.content


class TestTheEnvironment:
    """Spec §14: an explicit allowlist, never ``os.environ``, never the model's."""

    def test_the_default_environment_supplies_path_and_nothing_else(self) -> None:
        assert set(DEFAULT_COMMAND_ENV) == {"PATH"}
        assert DEFAULT_COMMAND_ENV["PATH"].startswith("/")

    def test_the_environment_reaches_the_child_and_holds_nothing_from_this_process(
        self, context: ToolContext, store: InMemoryToolCallStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A variable in this process's environment must not appear in the child's."""
        monkeypatch.setenv("TOOLYARD_SECRET", "must-not-leak")
        runner = ScriptedRunner(outcomes={"bwrap": captured()})
        executor = _executor(_sandbox(BWRAP_HOST, runner), store)
        _run(executor, context, "/bin/env")
        launched = runner.calls[-1]
        assert "must-not-leak" not in str(launched.argv)
        assert "TOOLYARD_SECRET" not in str(launched.argv)

    def test_a_caller_may_replace_the_environment_and_a_model_may_not(
        self, workspace: SandboxPaths, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """There is no argument through which an environment variable could arrive."""
        del workspace
        runner = ScriptedRunner(outcomes={"bwrap": captured()})
        sandbox = _sandbox(BWRAP_HOST, runner)
        registry = ToolRegistry()
        spec, handler = run_command_tool(sandbox, env={"PATH": "/bin", "LANG": "C"})
        registry.register(spec, handler)
        assert "env" not in spec.args_schema["properties"]
        executor = ToolExecutor(
            registry, sandbox, allowlist=frozenset({"run_command"}), store=store
        )
        _run(executor, context, "/bin/true")
        launched = " ".join(runner.calls[-1].argv)
        assert "--setenv LANG C" in launched
        assert "--setenv PATH /bin" in launched

    def test_a_limit_this_host_could_not_apply_is_named_in_the_result(
        self, context: ToolContext, store: InMemoryToolCallStore
    ) -> None:
        """ADR-0016's posture, carried all the way to the model: unenforceable is reported.

        The alternative — reporting the limit as applied — would tell a model its command ran under
        a memory bound that was never set, and the record would say the same. `Unsupported` is not
        zero, and neither is "the rung could not do this".
        """

        class PartialSandbox(TieredSandbox):
            """A rung that runs commands but cannot apply one of the limits."""

            def run_isolated(self, argv, **kwargs):  # type: ignore[no-untyped-def] # noqa: ANN003, ANN201, ANN001
                """Answer as the real one would on a host without cgroup memory accounting."""
                result = super().run_isolated(argv, **kwargs)
                return replace(result, limits_unenforced=("memory_bytes",))

        runner = ScriptedRunner(outcomes={"bwrap": captured(stdout=b"ran\n")})
        sandbox = PartialSandbox(which=which_for(BWRAP_HOST), runner=runner)
        executor = _executor(sandbox, store)
        result = _run(executor, context, "/bin/echo", "ran")
        assert result.status is ToolStatus.OK
        assert "limits not enforced on this host: memory_bytes" in result.content
