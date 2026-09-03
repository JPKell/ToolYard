"""The sandbox: the ladder probed with a canary, both rungs' argv, and a result for everything.

Every test here runs with **no live tier**: the launch boundary is a recording double, so the
assertions are about the argv the sandbox built, the order the rungs were tried in, and the shape of
what comes back. The one class that starts real processes, :class:`TestTheLauncher`, runs this
interpreter under no sandbox at all — it is testing the launcher's capture, cap and kill, which need
a process and need no isolation. The isolation itself is proven in
``tests/integration/test_isolation.py``, under real tiers on the reference machine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from baseaicore import ValidationError

from fakes import (
    BWRAP_HOST,
    DOCKER_HOST,
    FULL_HOST,
    EchoTool,
    ScriptedRunner,
    SteppingMonotonic,
    captured,
    spec,
    which_for,
)
from toolyard import (
    DEFAULT_CONTAINER_IMAGE,
    LIMIT_NAMES,
    UNLAUNCHABLE_EXIT_CODE,
    IsolationTier,
    PathEscape,
    Reason,
    ResourceLimits,
    SandboxPaths,
    TieredSandbox,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
    ToolStatus,
    ToolYardError,
)
from toolyard._safe import TRUNCATION_LABEL_TEMPLATE
from toolyard.sandbox import (
    MAX_ARGV_BYTES,
    MAX_ARGV_ITEMS,
    MIN_OUTPUT_BYTES,
    Captured,
    _kill_group,
    _launch,
    _reap,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

TRUNCATION_MARKER = TRUNCATION_LABEL_TEMPLATE.split("{")[0].strip()


def build(
    available: Mapping[str, str] = FULL_HOST,
    *,
    outcomes: dict[str, Captured | BaseException] | None = None,
    **kwargs: Any,
) -> tuple[TieredSandbox, ScriptedRunner]:
    """A sandbox whose probe sees ``available`` and whose launcher is a recording double."""
    runner = ScriptedRunner(outcomes=outcomes or {})
    sandbox = TieredSandbox(which=which_for(available), runner=runner, platform="linux", **kwargs)
    return sandbox, runner


def after_separator(argv: Sequence[str]) -> list[str]:
    """Everything after the first ``--`` — what bwrap runs inside the sandbox."""
    return list(argv[argv.index("--") + 1 :])


def triples(argv: Sequence[str]) -> list[tuple[str, str, str]]:
    """Every consecutive triple, in order, for asserting ``--flag SRC DEST`` groups."""
    return [(argv[i], argv[i + 1], argv[i + 2]) for i in range(len(argv) - 2)]


def pairs(argv: Sequence[str]) -> list[tuple[str, str]]:
    """Every consecutive pair, in order, for asserting ``--flag VALUE`` groups."""
    return [(argv[i], argv[i + 1]) for i in range(len(argv) - 1)]


class TestTheLadder:
    """Container → bwrap → refuse, each rung proven by a canary rather than a version string."""

    def test_nothing_installed_is_unavailable_and_nothing_is_launched(self) -> None:
        sandbox, runner = build({})
        report = sandbox.report()
        assert report.tier is IsolationTier.UNAVAILABLE
        assert report.runtime is None and report.runtime_path is None
        for name in ("podman", "docker", "bwrap"):
            assert f"{name}: not installed" in report.reason
        assert "never run unisolated" in report.reason
        assert runner.calls == []

    def test_podman_outranks_docker_and_docker_is_never_probed(self) -> None:
        sandbox, runner = build(FULL_HOST)
        report = sandbox.report()
        assert report.tier is IsolationTier.CONTAINER
        assert report.runtime == "podman"
        assert report.runtime_path == "/usr/bin/podman"
        assert [call.argv[0] for call in runner.calls] == ["/usr/bin/podman"]

    def test_a_failing_container_canary_falls_to_bwrap_and_the_report_says_why(self) -> None:
        sandbox, runner = build(
            FULL_HOST,
            outcomes={
                "podman canary": captured(exit_code=125, stderr=b"Error: no such image"),
                "docker canary": captured(
                    exit_code=1, stderr=b"Cannot connect to the Docker daemon"
                ),
            },
        )
        report = sandbox.report()
        assert report.tier is IsolationTier.BWRAP
        assert report.runtime == "bwrap"
        assert "podman: installed at /usr/bin/podman but the canary failed" in report.reason
        assert "no such image" in report.reason
        assert "Cannot connect to the Docker daemon" in report.reason
        assert [call.argv[0] for call in runner.calls] == [
            "/usr/bin/podman",
            "/usr/bin/docker",
            "/usr/bin/bwrap",
        ]

    def test_a_canary_that_times_out_is_a_failed_rung(self) -> None:
        sandbox, _ = build(FULL_HOST, outcomes={"podman canary": captured(timed_out=True)})
        report = sandbox.report()
        assert report.tier is IsolationTier.CONTAINER
        assert report.runtime == "docker"
        assert "podman" in report.reason and "timed out" in report.reason

    def test_a_runtime_that_cannot_be_launched_is_a_failed_rung(self) -> None:
        sandbox, _ = build(FULL_HOST, outcomes={"podman canary": PermissionError("not executable")})
        report = sandbox.report()
        assert report.runtime == "docker"
        assert "PermissionError" in report.reason

    def test_bwrap_installed_but_not_functional_is_unavailable(self) -> None:
        """Installed is not functional: the classic case is a kernel without user namespaces."""
        sandbox, _ = build(
            BWRAP_HOST,
            outcomes={
                "bwrap canary": captured(
                    exit_code=1, stderr=b"bwrap: setting up uid map: Permission denied"
                )
            },
        )
        report = sandbox.report()
        assert report.tier is IsolationTier.UNAVAILABLE
        assert "bwrap: installed at /usr/bin/bwrap but the canary failed" in report.reason
        assert "Permission denied" in report.reason

    def test_a_canary_that_fails_silently_still_names_the_exit_code(self) -> None:
        sandbox, _ = build(BWRAP_HOST, outcomes={"bwrap canary": captured(exit_code=3)})
        assert "exit 3: (no stderr)" in sandbox.report().reason

    def test_a_non_linux_platform_has_no_tier_and_probes_nothing(self) -> None:
        runner = ScriptedRunner()
        sandbox = TieredSandbox(which=which_for(FULL_HOST), runner=runner, platform="darwin")
        report = sandbox.report()
        assert report.tier is IsolationTier.UNAVAILABLE
        assert "darwin" in report.reason and "spec §16" in report.reason
        assert runner.calls == []

    def test_the_probe_runs_once_and_is_cached(self) -> None:
        sandbox, runner = build(BWRAP_HOST)
        tiers = {sandbox.isolation_tier() for _ in range(3)}
        assert tiers == {IsolationTier.BWRAP}
        assert sandbox.report() is sandbox.report()
        assert len(runner.calls) == 1

    def test_the_canary_is_the_real_bwrap_argv_around_bin_true(self) -> None:
        """A canary that ran different flags would prove a different rung than the one used."""
        sandbox, runner = build(BWRAP_HOST)
        sandbox.report()
        argv = runner.calls[0].argv
        assert argv[0] == "/usr/bin/bwrap"
        for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--clearenv"):
            assert flag in argv
        assert argv[-1] == "/bin/true"
        assert after_separator(argv)[0] == "/usr/bin/prlimit"
        bound = [item for item in argv if "toolyard-probe-" in item]
        assert bound, "the canary binds a real, temporary workspace the way a command's is bound"
        assert runner.calls[0].env == {"PATH": "/usr/bin:/bin"}

    def test_the_canary_is_the_real_container_argv_around_bin_true(self) -> None:
        sandbox, runner = build(DOCKER_HOST)
        sandbox.report()
        argv = runner.calls[0].argv
        assert argv[:3] == ("/usr/bin/docker", "run", "--rm")
        assert "--pull=never" in argv and "--network=none" in argv
        assert argv[-2:] == (DEFAULT_CONTAINER_IMAGE, "/bin/true")


class TestRefusalIsTheFloor:
    """No tier means no run — not a warning, not a weaker rung, not the host."""

    def test_run_isolated_without_a_tier_raises_and_launches_nothing(
        self, workspace: SandboxPaths
    ) -> None:
        sandbox, runner = build({})
        with pytest.raises(ToolYardError, match="requires_isolation") as caught:
            sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert caught.value.details["isolation_tier"] == "unavailable"
        assert runner.calls == []

    def test_the_executor_refuses_an_isolation_tool_before_any_handler_runs(
        self, workspace: SandboxPaths
    ) -> None:
        sandbox, runner = build({})
        registry = ToolRegistry()
        registry.register(spec("runner", requires_isolation=True), EchoTool())
        executor = ToolExecutor(registry, sandbox, allowlist=frozenset({"runner"}))
        result = executor.execute(
            ToolCallRequest(name="runner", args={"value": "x"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.status is ToolStatus.REFUSED
        assert result.reason == Reason.ISOLATION_UNAVAILABLE.value
        assert runner.calls == []

    def test_a_runtime_that_vanishes_after_the_probe_is_a_host_fault_not_a_fallback(
        self, workspace: SandboxPaths
    ) -> None:
        """The tier is decided once; a rung that fails at run time raises, never degrades."""
        launches = 0

        def flaky(
            argv: Sequence[str],
            *,
            env: Mapping[str, str],
            timeout_seconds: float,
            max_output_bytes: int,
        ) -> Captured:
            nonlocal launches
            launches += 1
            if launches > 1:
                raise FileNotFoundError(argv[0])
            return captured()

        sandbox = TieredSandbox(which=which_for(BWRAP_HOST), runner=flaky, platform="linux")
        assert sandbox.isolation_tier() is IsolationTier.BWRAP
        with pytest.raises(ToolYardError, match="never a reason to run the command unisolated"):
            sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert launches == 2


class TestTheBwrapArgv:
    """ADR-0018's tier-2 flags, every one, and nothing from the host that was not named."""

    @pytest.fixture
    def launched(self, workspace: SandboxPaths) -> tuple[Sequence[str], ScriptedRunner]:
        sandbox, runner = build(BWRAP_HOST)
        sandbox.run_isolated(["/bin/echo", "hi"], paths=workspace, timeout_seconds=5.0)
        return runner.calls[-1].argv, runner

    def test_the_tier_two_flags_are_all_present(
        self, launched: tuple[Sequence[str], ScriptedRunner]
    ) -> None:
        argv, _ = launched
        assert argv[0] == "/usr/bin/bwrap"
        for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--clearenv"):
            assert flag in argv
        assert ("--proc", "/proc") in pairs(argv)
        assert ("--dev", "/dev") in pairs(argv)
        assert ("--tmpfs", "/tmp") in pairs(argv)  # noqa: S108 — asserting the sandbox's private tmpfs

    def test_the_command_follows_the_separator_and_the_limits(
        self, launched: tuple[Sequence[str], ScriptedRunner]
    ) -> None:
        argv, _ = launched
        inside = after_separator(argv)
        assert inside[0] == "/usr/bin/prlimit"
        assert inside[1:5] == [
            "--cpu=60",
            f"--as={1 << 30}",
            f"--fsize={64 << 20}",
            "--nproc=64",
        ]
        assert inside[5] == "--"
        assert inside[6:] == ["/bin/echo", "hi"]

    def test_network_is_refused_as_a_caller_bug_and_nothing_launches(
        self, workspace: SandboxPaths
    ) -> None:
        """Spec §14: no shipped tool runs a subprocess with network; the door stays shut."""
        sandbox, runner = build(BWRAP_HOST)
        sandbox.report()
        with pytest.raises(ValidationError, match="network"):
            sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0, network=True)
        assert len(runner.calls) == 1, "the canary only"
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert "--share-net" not in runner.calls[-1].argv
        assert "--unshare-all" in runner.calls[-1].argv

    def test_the_workspace_is_bound_in_place_and_is_the_working_directory(
        self, launched: tuple[Sequence[str], ScriptedRunner], workspace: SandboxPaths
    ) -> None:
        argv, _ = launched
        write_root = str(workspace.write_root.resolve())
        read_root = str(workspace.read_roots[0].resolve())
        assert ("--bind", write_root, write_root) in triples(argv)
        assert ("--ro-bind", read_root, read_root) in triples(argv)
        assert ("--chdir", write_root) in pairs(argv)
        assert ("--ro-bind", write_root, write_root) not in triples(argv)
        assert ("--bind", read_root, read_root) not in triples(argv)

    def test_the_runtime_is_bound_read_only_and_etc_only_by_entry(
        self, launched: tuple[Sequence[str], ScriptedRunner]
    ) -> None:
        argv, _ = launched
        for root in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            assert ("--ro-bind-try", root, root) in triples(argv)
        assert "/etc" not in argv, "/etc whole would carry the host's users and configuration"
        assert ("--ro-bind-try", "/etc/alternatives", "/etc/alternatives") in triples(argv)
        assert ("--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache") in triples(argv)
        assert not [item for item in argv if item.startswith(("/home", "/root", "/var"))]
        assert "--bind" not in [flag for flag, src, _ in triples(argv) if src.startswith("/usr")]

    def test_the_environment_is_the_allowlist_and_never_the_process_environment(
        self, workspace: SandboxPaths, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TOOLYARD_TEST_SECRET", "hunter2")
        sandbox, runner = build(BWRAP_HOST)
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert "--setenv" not in runner.calls[-1].argv, "env=None is the empty allowlist"
        sandbox.run_isolated(
            ["/bin/true"], paths=workspace, timeout_seconds=1.0, env={"ALLOWED": "yes"}
        )
        argv = runner.calls[-1].argv
        assert ("--setenv", "ALLOWED", "yes") in triples(argv)
        assert argv.count("--setenv") == 1
        for call in runner.calls:
            assert "hunter2" not in " ".join(call.argv)
            assert "TOOLYARD_TEST_SECRET" not in call.env
            assert call.env == {"PATH": "/usr/bin:/bin"}, "the launcher gets PATH and nothing else"

    def test_the_limits_are_the_callers(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(
            BWRAP_HOST,
            limits=ResourceLimits(
                cpu_seconds=7, memory_bytes=1_000, file_size_bytes=2_000, process_count=3
            ),
        )
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert after_separator(runner.calls[-1].argv)[1:5] == [
            "--cpu=7",
            "--as=1000",
            "--fsize=2000",
            "--nproc=3",
        ]

    def test_without_prlimit_the_rung_runs_and_every_limit_is_reported_unenforced(
        self, workspace: SandboxPaths
    ) -> None:
        """ADR-0016: an unenforceable limit is reported, never assumed."""
        sandbox, runner = build({"bwrap": "/usr/bin/bwrap"})
        report = sandbox.report()
        assert report.tier is IsolationTier.BWRAP
        assert report.limiter_path is None
        assert report.limits_unenforced == LIMIT_NAMES
        assert "unenforced" in report.reason
        result = sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert result.limits_unenforced == LIMIT_NAMES
        assert after_separator(runner.calls[-1].argv) == ["/bin/true"]

    def test_with_prlimit_no_limit_is_unenforced(self, workspace: SandboxPaths) -> None:
        sandbox, _ = build(BWRAP_HOST)
        result = sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert result.limits_unenforced == ()
        assert sandbox.report().limiter_path == "/usr/bin/prlimit"


class TestTheContainerArgv:
    """ADR-0018's tier-1 flags, every one, with ``--pull=never`` so the probe never fetches."""

    @pytest.fixture
    def launched(self, workspace: SandboxPaths) -> tuple[Sequence[str], ScriptedRunner]:
        sandbox, runner = build(DOCKER_HOST)
        sandbox.run_isolated(
            ["/bin/echo", "hi"], paths=workspace, timeout_seconds=5.0, env={"ALLOWED": "yes"}
        )
        return runner.calls[-1].argv, runner

    def test_the_tier_one_flags_are_all_present(
        self, launched: tuple[Sequence[str], ScriptedRunner]
    ) -> None:
        argv, _ = launched
        assert argv[:4] == ("/usr/bin/docker", "run", "--rm", "--pull=never")
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL"):
            assert flag in argv
        assert ("--security-opt", "no-new-privileges") in pairs(argv)
        assert ("--user", f"{os.getuid()}:{os.getgid()}") in pairs(argv)
        assert ("--memory", str(1 << 30)) in pairs(argv)
        assert ("--memory-swap", str(1 << 30)) in pairs(argv)
        assert ("--pids-limit", "64") in pairs(argv)
        assert ("--ulimit", "cpu=60:60") in pairs(argv)
        assert ("--ulimit", f"fsize={64 << 20}:{64 << 20}") in pairs(argv)
        tmpfs = dict(pairs(argv)).get("--tmpfs", "")
        assert tmpfs.startswith("/tmp:") and "noexec" in tmpfs  # noqa: S108 — the container's /tmp
        assert "--userns=keep-id" not in argv, "a docker-only flag set"

    def test_the_command_follows_the_image(
        self, launched: tuple[Sequence[str], ScriptedRunner]
    ) -> None:
        argv, _ = launched
        assert argv[-3:] == (DEFAULT_CONTAINER_IMAGE, "/bin/echo", "hi")

    def test_the_workspace_is_bound_in_place_and_is_the_working_directory(
        self, launched: tuple[Sequence[str], ScriptedRunner], workspace: SandboxPaths
    ) -> None:
        argv, _ = launched
        write_root = str(workspace.write_root.resolve())
        read_root = str(workspace.read_roots[0].resolve())
        assert ("--volume", f"{write_root}:{write_root}:rw") in pairs(argv)
        assert ("--volume", f"{read_root}:{read_root}:ro") in pairs(argv)
        assert ("--workdir", write_root) in pairs(argv)

    def test_the_environment_is_the_allowlist_only(
        self, launched: tuple[Sequence[str], ScriptedRunner], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        argv, runner = launched
        assert ("--env", "ALLOWED=yes") in pairs(argv)
        assert argv.count("--env") == 1
        assert runner.calls[-1].env == {"PATH": "/usr/bin:/bin"}

    def test_the_container_has_an_unguessable_name(
        self, launched: tuple[Sequence[str], ScriptedRunner]
    ) -> None:
        argv, _ = launched
        name = dict(pairs(argv))["--name"]
        assert name.startswith("toolyard-") and len(name) == len("toolyard-") + 32

    def test_podman_keeps_the_callers_id(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(FULL_HOST)
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        argv = runner.calls[-1].argv
        assert argv[0] == "/usr/bin/podman"
        assert "--userns=keep-id" in argv

    def test_the_network_is_always_none(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(DOCKER_HOST)
        sandbox.report()
        with pytest.raises(ValidationError, match="network"):
            sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0, network=True)
        assert len(runner.calls) == 1, "the canary only"
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert "--network=none" in runner.calls[-1].argv

    def test_the_image_is_a_constructor_argument(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(DOCKER_HOST, container_image="alpine:3.20")
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert runner.calls[-1].argv[-2] == "alpine:3.20"

    def test_a_root_with_a_colon_is_refused_because_the_volume_syntax_cannot_carry_it(
        self, tmp_path: Path
    ) -> None:
        odd = tmp_path / "a:b"
        odd.mkdir()
        sandbox, _ = build(DOCKER_HOST)
        with pytest.raises(ValidationError, match="colon"):
            sandbox.run_isolated(
                ["/bin/true"], paths=SandboxPaths(write_root=odd), timeout_seconds=1.0
            )

    def test_a_warning_on_the_canary_reports_the_cgroup_limits_unenforced(
        self, workspace: SandboxPaths
    ) -> None:
        """Docker discards a memory or pids limit the kernel cannot apply, with a warning."""
        sandbox, _ = build(
            DOCKER_HOST,
            outcomes={
                "docker canary": captured(
                    stderr=b"WARNING: Your kernel does not support memory limit capabilities"
                )
            },
        )
        report = sandbox.report()
        assert report.tier is IsolationTier.CONTAINER
        assert report.limits_unenforced == ("memory_bytes", "process_count")
        assert "unenforced" in report.reason
        result = sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert result.limits_unenforced == ("memory_bytes", "process_count")

    def test_a_silent_canary_reports_every_limit_enforced(self) -> None:
        sandbox, _ = build(DOCKER_HOST)
        assert sandbox.report().limits_unenforced == ()

    @pytest.mark.parametrize(
        "outcome",
        [captured(exit_code=-9, timed_out=True), captured(exit_code=-9, output_truncated=True)],
        ids=["timed_out", "output_capped"],
    )
    def test_a_killed_containers_cli_is_followed_by_removing_the_container(
        self, workspace: SandboxPaths, outcome: Captured
    ) -> None:
        """Killing the CLI does not stop the container; the tree must not outlive the call."""
        sandbox, runner = build(DOCKER_HOST, outcomes={"docker run": outcome})
        result = sandbox.run_isolated(["/bin/sleep", "99"], paths=workspace, timeout_seconds=1.0)
        assert result.timed_out is outcome.timed_out
        assert result.exit_code == -9
        run, removal = runner.calls[-2], runner.calls[-1]
        assert run.argv[1] == "run"
        name = dict(pairs(run.argv))["--name"]
        assert removal.argv == ("/usr/bin/docker", "rm", "-f", name)
        assert removal.env == {"PATH": "/usr/bin:/bin"}

    def test_a_completed_container_is_not_removed_again(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(DOCKER_HOST)
        sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert [call.argv[1] for call in runner.calls] == ["run", "run"]

    @pytest.mark.parametrize(
        "removal",
        [captured(exit_code=1, stderr=b"No such container"), OSError("docker vanished")],
        ids=["nonzero", "unlaunchable"],
    )
    def test_a_removal_that_fails_does_not_change_the_result(
        self, workspace: SandboxPaths, removal: Captured | BaseException
    ) -> None:
        sandbox, runner = build(
            DOCKER_HOST,
            outcomes={"docker run": captured(exit_code=-9, timed_out=True), "docker rm": removal},
        )
        result = sandbox.run_isolated(["/bin/sleep", "99"], paths=workspace, timeout_seconds=1.0)
        assert result.timed_out and result.exit_code == -9
        assert runner.calls[-1].argv[1] == "rm"

    def test_a_timed_out_bwrap_run_needs_no_removal(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(
            BWRAP_HOST, outcomes={"bwrap": captured(exit_code=-9, timed_out=True)}
        )
        result = sandbox.run_isolated(["/bin/sleep", "99"], paths=workspace, timeout_seconds=1.0)
        assert result.timed_out
        assert len(runner.calls) == 2, "the canary and the run; nothing to remove under bwrap"


class TestTheWorkspaceBinds:
    """Ancestors first, so the nearest root wins on both rungs, and they agree with each other."""

    def test_a_read_root_resolving_inside_the_write_root_is_bound_after_it_and_read_only(
        self, tmp_path: Path
    ) -> None:
        """Construction refuses overlap as declared; a symlinked alias is what resolution finds."""
        write_root = tmp_path / "work"
        nested = write_root / "reference"
        nested.mkdir(parents=True)
        alias = tmp_path / "alias"
        alias.symlink_to(nested)
        sandbox, runner = build(BWRAP_HOST)
        sandbox.run_isolated(
            ["/bin/true"],
            paths=SandboxPaths(write_root=write_root, read_roots=(alias,)),
            timeout_seconds=1.0,
        )
        argv = list(runner.calls[-1].argv)
        assert argv.index("--bind") < argv.index("--ro-bind")
        assert ("--ro-bind", str(nested.resolve()), str(nested.resolve())) in triples(argv)

    def test_a_write_root_resolving_inside_a_read_root_is_bound_after_it_and_writable(
        self, tmp_path: Path
    ) -> None:
        read_root = tmp_path / "project"
        out = read_root / "out"
        out.mkdir(parents=True)
        alias = tmp_path / "alias-out"
        alias.symlink_to(out)
        sandbox, runner = build(DOCKER_HOST)
        sandbox.run_isolated(
            ["/bin/true"],
            paths=SandboxPaths(write_root=alias, read_roots=(read_root,)),
            timeout_seconds=1.0,
        )
        volumes = [value for flag, value in pairs(runner.calls[-1].argv) if flag == "--volume"]
        assert volumes == [
            f"{read_root.resolve()}:{read_root.resolve()}:ro",
            f"{out.resolve()}:{out.resolve()}:rw",
        ]

    def test_a_missing_read_root_is_skipped_and_a_symlinked_alias_is_bound_once(
        self, tmp_path: Path
    ) -> None:
        """What construction cannot see lexically, the binds deduplicate after resolution."""
        write_root = tmp_path / "work"
        write_root.mkdir()
        reference = tmp_path / "reference"
        reference.mkdir()
        alias_of_write = tmp_path / "alias-work"
        alias_of_write.symlink_to(write_root)
        alias_of_reference = tmp_path / "alias-reference"
        alias_of_reference.symlink_to(reference)
        sandbox, runner = build(BWRAP_HOST)
        sandbox.run_isolated(
            ["/bin/true"],
            paths=SandboxPaths(
                write_root=write_root,
                read_roots=(
                    alias_of_write,
                    reference,
                    tmp_path / "never-created",
                    alias_of_reference,
                ),
            ),
            timeout_seconds=1.0,
        )
        argv = runner.calls[-1].argv
        assert argv.count("--bind") == 1
        assert argv.count("--ro-bind") == 1
        assert "never-created" not in " ".join(argv)
        assert "alias" not in " ".join(argv)

    def test_a_symlinked_root_is_bound_at_its_resolved_path(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        alias = tmp_path / "alias"
        alias.symlink_to(real)
        sandbox, runner = build(BWRAP_HOST)
        sandbox.run_isolated(
            ["/bin/true"], paths=SandboxPaths(write_root=alias), timeout_seconds=1.0
        )
        assert ("--bind", str(real), str(real)) in triples(runner.calls[-1].argv)
        assert str(alias) not in runner.calls[-1].argv

    def test_a_write_root_that_is_not_a_directory_is_a_caller_bug(self, tmp_path: Path) -> None:
        sandbox, _ = build(BWRAP_HOST)
        with pytest.raises(ValidationError, match="not a directory"):
            sandbox.run_isolated(
                ["/bin/true"],
                paths=SandboxPaths(write_root=tmp_path / "never-created"),
                timeout_seconds=1.0,
            )
        as_file = tmp_path / "file.txt"
        as_file.write_text("x", encoding="utf-8")
        with pytest.raises(ValidationError, match="not a directory"):
            sandbox.run_isolated(
                ["/bin/true"], paths=SandboxPaths(write_root=as_file), timeout_seconds=1.0
            )

    def test_a_write_root_that_cannot_be_resolved_is_a_caller_bug(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sandbox, _ = build(BWRAP_HOST)
        sandbox.report()
        real_resolve = Path.resolve

        def selective(self: Path, strict: bool = False) -> Path:
            if self.name == "work":
                raise OSError(5, "input/output error")
            return real_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", selective)
        with pytest.raises(ValidationError, match="cannot be resolved"):
            sandbox.run_isolated(
                ["/bin/true"], paths=SandboxPaths(write_root=tmp_path / "work"), timeout_seconds=1.0
            )

    def test_a_read_root_that_cannot_be_resolved_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        write_root = tmp_path / "work"
        write_root.mkdir()
        sandbox, runner = build(BWRAP_HOST)
        sandbox.report()
        real_resolve = Path.resolve

        def selective(self: Path, strict: bool = False) -> Path:
            if self.name == "reference":
                raise OSError(5, "input/output error")
            return real_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", selective)
        sandbox.run_isolated(
            ["/bin/true"],
            paths=SandboxPaths(write_root=write_root, read_roots=(tmp_path / "reference",)),
            timeout_seconds=1.0,
        )
        assert "--ro-bind" not in runner.calls[-1].argv


class TestTheResult:
    """What comes back: decoded, cleaned, capped, labelled, with the rung and the limits on it."""

    def test_exit_code_streams_tier_and_duration(self, workspace: SandboxPaths) -> None:
        sandbox, _ = build(
            BWRAP_HOST,
            outcomes={"bwrap": captured(exit_code=3, stdout=b"out\n", stderr=b"err\n")},
            monotonic_ns=SteppingMonotonic(step_ns=7_000_000),
        )
        result = sandbox.run_isolated(["/bin/false"], paths=workspace, timeout_seconds=1.0)
        assert result.exit_code == 3
        assert result.stdout == "out\n" and result.stderr == "err\n"
        assert result.tier is IsolationTier.BWRAP
        assert result.duration_ms == 7
        assert result.timed_out is False
        assert result.output_truncated is False
        assert result.limits_unenforced == ()

    def test_a_stream_over_the_cap_is_labelled_as_stopped_not_ended(
        self, workspace: SandboxPaths
    ) -> None:
        cap = 1_024
        sandbox, _ = build(
            BWRAP_HOST,
            outcomes={
                "bwrap": captured(exit_code=-9, stdout=b"x" * (cap + 1), output_truncated=True)
            },
            max_output_bytes=cap,
        )
        result = sandbox.run_isolated(["/bin/yes"], paths=workspace, timeout_seconds=1.0)
        assert TRUNCATION_MARKER in result.stdout
        assert len(result.stdout.encode("utf-8")) <= cap
        assert result.stderr == ""
        assert result.output_truncated is True
        assert result.timed_out is False

    def test_invalid_utf8_and_nul_are_cleaned_never_raised(self, workspace: SandboxPaths) -> None:
        sandbox, _ = build(BWRAP_HOST, outcomes={"bwrap": captured(stdout=b"a\xffb\x00c")})
        result = sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert result.stdout == "a�bc"

    def test_timed_out_passes_through(self, workspace: SandboxPaths) -> None:
        sandbox, _ = build(BWRAP_HOST, outcomes={"bwrap": captured(exit_code=-15, timed_out=True)})
        result = sandbox.run_isolated(["/bin/sleep", "9"], paths=workspace, timeout_seconds=0.5)
        assert result.timed_out and result.exit_code == -15

    @pytest.mark.parametrize("readings", [[1_000_000_000, 0], [0, "not a reading"]])
    def test_a_monotonic_source_that_misbehaves_yields_a_zero_duration(
        self, workspace: SandboxPaths, readings: list[object]
    ) -> None:
        source = iter(readings)
        sandbox, _ = build(BWRAP_HOST, monotonic_ns=lambda: next(source))
        result = sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0)
        assert result.duration_ms == 0


class TestTheArgvIsTheModels:
    """Nothing about the argv raises: an unlaunchable one is a result with exit 127."""

    @pytest.mark.parametrize(
        ("argv", "problem"),
        [
            ([], "empty"),
            ("echo hi", "never a command string"),
            (b"echo", "never a command string"),
            (None, "never a command string"),
            (["echo", 1], "argv[1] is int"),
            (["e\x00cho"], "NUL"),
            (["ec\ud800ho"], "unencodable"),
            ([""], "blank"),
            (["   "], "blank"),
            (["a"] * (MAX_ARGV_ITEMS + 1), "items"),
            (["x" * (MAX_ARGV_BYTES + 1)], "bytes"),
        ],
        ids=[
            "empty",
            "string",
            "bytes",
            "none",
            "non-string-item",
            "nul",
            "surrogate",
            "blank-command",
            "whitespace-command",
            "too-many-items",
            "too-large",
        ],
    )
    def test_an_unlaunchable_argv_is_a_result_and_launches_nothing(
        self, workspace: SandboxPaths, argv: object, problem: str
    ) -> None:
        sandbox, runner = build(BWRAP_HOST)
        sandbox.report()
        launched_before = len(runner.calls)
        result = sandbox.run_isolated(argv, paths=workspace, timeout_seconds=1.0)  # type: ignore[arg-type]
        assert result.exit_code == UNLAUNCHABLE_EXIT_CODE
        assert result.stdout == ""
        assert result.stderr.startswith("toolyard: argv refused before launch: ")
        assert problem in result.stderr
        assert result.tier is IsolationTier.BWRAP
        assert result.timed_out is False
        assert result.output_truncated is False
        assert len(runner.calls) == launched_before

    def test_a_tuple_is_as_good_as_a_list(self, workspace: SandboxPaths) -> None:
        sandbox, runner = build(BWRAP_HOST)
        result = sandbox.run_isolated(("/bin/echo", "hi"), paths=workspace, timeout_seconds=1.0)
        assert result.exit_code == 0
        assert after_separator(runner.calls[-1].argv)[-2:] == ["/bin/echo", "hi"]


class TestCallerBugsRaise:
    """The workspace, the timeout, the environment and the configuration are the caller's."""

    @pytest.mark.parametrize("timeout", [0, -1.0, float("inf"), float("nan"), "1", True, None])
    def test_a_timeout_that_is_not_a_finite_positive_number(
        self, workspace: SandboxPaths, timeout: object
    ) -> None:
        sandbox, _ = build(BWRAP_HOST)
        with pytest.raises(ValidationError, match="timeout_seconds"):
            sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=timeout)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "env",
        [
            [("A", "1")],
            {"1A": "x"},
            {"A=B": "x"},
            {"A B": "x"},
            {"": "x"},
            {3: "x"},
            {"A": 1},
            {"A": "x\x00y"},
            {"A": "x\ud800"},
        ],
        ids=[
            "not-a-mapping",
            "leading-digit",
            "equals",
            "space",
            "empty-name",
            "non-string-name",
            "non-string-value",
            "nul-value",
            "surrogate-value",
        ],
    )
    def test_a_malformed_environment_allowlist(self, workspace: SandboxPaths, env: object) -> None:
        sandbox, runner = build(BWRAP_HOST)
        sandbox.report()
        with pytest.raises(ValidationError, match="env"):
            sandbox.run_isolated(["/bin/true"], paths=workspace, timeout_seconds=1.0, env=env)  # type: ignore[arg-type]
        assert len(runner.calls) == 1, "nothing launched"

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"container_image": "-rm"},
            {"container_image": ""},
            {"container_image": "python:3.12 slim"},
            {"container_image": 3},
            {"limits": {"cpu_seconds": 1}},
            {"max_output_bytes": MIN_OUTPUT_BYTES - 1},
            {"max_output_bytes": True},
            {"max_output_bytes": "1024"},
            {"probe_timeout_seconds": 0},
            {"probe_timeout_seconds": float("inf")},
            {"which": "shutil.which"},
            {"runner": "run"},
            {"platform": 3},
        ],
    )
    def test_a_misconfigured_sandbox_fails_at_construction(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            TieredSandbox(**kwargs)

    @pytest.mark.parametrize("name", LIMIT_NAMES)
    @pytest.mark.parametrize("value", [0, -1, 1.5, True, "1"])
    def test_a_limit_that_is_not_a_positive_integer(self, name: str, value: object) -> None:
        with pytest.raises(ValidationError, match=name):
            ResourceLimits(**{name: value})  # type: ignore[arg-type]

    def test_the_default_limits_are_positive_integers(self) -> None:
        limits = ResourceLimits()
        for name in LIMIT_NAMES:
            assert isinstance(getattr(limits, name), int) and getattr(limits, name) > 0


class TestThroughTheExecutor:
    """The real sandbox satisfies the port: check #5 and a handler that runs a command."""

    def test_an_isolation_tool_runs_when_a_rung_exists(self, workspace: SandboxPaths) -> None:
        sandbox, _ = build(BWRAP_HOST)
        registry = ToolRegistry()
        registry.register(spec("runner", requires_isolation=True), EchoTool())
        executor = ToolExecutor(registry, sandbox, allowlist=frozenset({"runner"}))
        result = executor.execute(
            ToolCallRequest(name="runner", args={"value": "ran"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.status is ToolStatus.OK and result.content == "ran"

    def test_a_handler_that_runs_a_command_gets_its_output_as_a_result(
        self, workspace: SandboxPaths
    ) -> None:
        sandbox, runner = build(BWRAP_HOST, outcomes={"bwrap": captured(stdout=b"done\n")})

        class CommandTool:
            def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
                outcome = sandbox.run_isolated(
                    ["/bin/echo", str(args["value"])],
                    paths=context.workspace,
                    timeout_seconds=context.timeout_seconds or 5.0,
                )
                return ToolOutput(content=outcome.stdout)

        registry = ToolRegistry()
        registry.register(spec("run", requires_isolation=True), CommandTool())
        executor = ToolExecutor(registry, sandbox, allowlist=frozenset({"run"}))
        result = executor.execute(
            ToolCallRequest(name="run", args={"value": "hi"}),
            ToolContext(invocation_id="inv", workspace=workspace, timeout_seconds=2.0),
        )
        assert result.status is ToolStatus.OK and result.content == "done\n"
        assert runner.calls[-1].timeout_seconds == 2.0

    def test_a_handler_that_reaches_for_a_subprocess_without_declaring_it_fails_loudly(
        self, workspace: SandboxPaths
    ) -> None:
        """The load-bearing declaration: ToolYard cannot detect the omission, but it cannot run."""
        sandbox, runner = build({})

        class UndeclaredCommandTool:
            def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput:
                sandbox.run_isolated(["/bin/true"], paths=context.workspace, timeout_seconds=1.0)
                return ToolOutput(content="unreachable")

        registry = ToolRegistry()
        registry.register(spec("sneaky"), UndeclaredCommandTool())
        executor = ToolExecutor(registry, sandbox, allowlist=frozenset({"sneaky"}))
        result = executor.execute(
            ToolCallRequest(name="sneaky", args={"value": "x"}),
            ToolContext(invocation_id="inv", workspace=workspace),
        )
        assert result.status is ToolStatus.FAILED
        assert result.reason == Reason.HANDLER_ERROR.value
        assert "ToolYardError" in (result.reason_detail or "")
        assert runner.calls == []

    def test_the_path_half_is_phase_ones(self, workspace: SandboxPaths) -> None:
        sandbox, _ = build({})
        assert sandbox.resolve_read("notes.md", workspace) == workspace.write_root / "notes.md"
        with pytest.raises(PathEscape):
            sandbox.resolve_write(str(workspace.read_roots[0] / "x"), workspace)
        assert not [name for name in dir(sandbox) if "skip" in name or "unsafe" in name]


def _python(*code: str) -> list[str]:
    return [sys.executable, "-I", "-c", "\n".join(code)]


class TestTheLauncher:
    """The one ``Popen`` in the package: capture, cap, deadline, and the whole group killed.

    Real processes, this interpreter, no sandbox — the launcher is what the sandbox binaries are
    started *through*, and its properties hold without one.
    """

    def test_exit_code_and_both_streams_are_captured(self) -> None:
        outcome = _launch(
            _python("import sys", "print('out')", "print('err', file=sys.stderr)", "sys.exit(3)"),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=10.0,
            max_output_bytes=4_096,
        )
        assert outcome.exit_code == 3
        assert outcome.stdout == b"out\n" and outcome.stderr == b"err\n"
        assert not outcome.timed_out and not outcome.output_truncated

    def test_the_child_environment_is_exactly_what_was_passed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TOOLYARD_TEST_SECRET", "hunter2")
        outcome = _launch(
            _python("import json, os", "print(json.dumps(dict(os.environ)))"),
            env={"PATH": "/usr/bin:/bin", "ALLOWED": "yes"},
            timeout_seconds=10.0,
            max_output_bytes=65_536,
        )
        seen = json.loads(outcome.stdout)
        assert seen["ALLOWED"] == "yes"
        assert "TOOLYARD_TEST_SECRET" not in seen
        assert "HOME" not in seen

    def test_the_deadline_kills_a_sleeping_child(self) -> None:
        started = time.monotonic()
        outcome = _launch(
            _python("import time", "time.sleep(30)"),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=0.3,
            max_output_bytes=4_096,
        )
        assert outcome.timed_out
        assert outcome.exit_code < 0
        assert time.monotonic() - started < 5.0

    def test_the_deadline_kills_the_whole_group_grandchildren_included(self) -> None:
        """Orphaned grandchildren are the plan's named failure mode for a timeout."""
        outcome = _launch(
            _python(
                "import subprocess, sys, time",
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])",
                "print(child.pid, flush=True)",
                "time.sleep(30)",
            ),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=0.5,
            max_output_bytes=4_096,
        )
        assert outcome.timed_out
        grandchild = int(outcome.stdout.strip())
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:  # pragma: no cover — only reached on failure
            os.kill(grandchild, 9)
            pytest.fail("the grandchild outlived the timeout")

    def test_a_child_that_ignores_sigterm_is_killed_after_the_grace_period(self) -> None:
        outcome = _launch(
            _python(
                "import signal, time",
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                "print('armed', flush=True)",
                "time.sleep(30)",
            ),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=0.5,
            max_output_bytes=4_096,
        )
        assert outcome.timed_out
        assert outcome.exit_code == -9

    def test_a_child_that_closes_its_streams_and_keeps_running_is_still_killed(self) -> None:
        outcome = _launch(
            _python("import os, time", "os.close(1)", "os.close(2)", "time.sleep(30)"),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=0.3,
            max_output_bytes=4_096,
        )
        assert outcome.timed_out
        assert outcome.exit_code < 0

    def test_a_child_that_closes_its_streams_and_exits_in_time_is_waited_for(self) -> None:
        outcome = _launch(
            _python("import os, sys", "os.close(1)", "os.close(2)", "sys.exit(4)"),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=10.0,
            max_output_bytes=4_096,
        )
        assert outcome.exit_code == 4 and not outcome.timed_out

    def test_an_output_bomb_is_capped_and_the_child_killed(self) -> None:
        cap = 10_000
        started = time.monotonic()
        outcome = _launch(
            _python("while True:", "    print('x' * 4096)"),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=10.0,
            max_output_bytes=cap,
        )
        assert outcome.output_truncated
        assert not outcome.timed_out
        assert len(outcome.stdout) == cap + 1
        assert outcome.exit_code < 0
        assert time.monotonic() - started < 5.0

    def test_a_bomb_on_stderr_is_capped_the_same_way(self) -> None:
        outcome = _launch(
            _python("import sys", "while True:", "    print('e' * 4096, file=sys.stderr)"),
            env={"PATH": "/usr/bin:/bin"},
            timeout_seconds=10.0,
            max_output_bytes=5_000,
        )
        assert outcome.output_truncated
        assert len(outcome.stderr) == 5_001

    def test_a_missing_executable_is_the_hosts_fault_and_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            _launch(
                ["/nonexistent/toolyard-binary"],
                env={"PATH": "/usr/bin:/bin"},
                timeout_seconds=1.0,
                max_output_bytes=4_096,
            )

    def test_killing_a_group_that_already_exited_is_not_an_error(self) -> None:
        process = subprocess.Popen(  # noqa: S603 — this interpreter, an argv list, a test
            [sys.executable, "-c", "pass"], start_new_session=True
        )
        process.wait()
        _kill_group(process)
        assert process.returncode == 0

    def test_a_process_that_survives_sigkill_is_not_waited_on_forever(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Uninterruptible sleep is real; a wait with no deadline would hang the agent loop."""
        process = subprocess.Popen(  # noqa: S603 — this interpreter, an argv list, a test
            [sys.executable, "-c", "pass"], start_new_session=True
        )
        process.wait()

        def never(timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(process.args, timeout or 0.0)

        monkeypatch.setattr(process, "wait", never)
        _reap(process)  # returns rather than raising or blocking

    def test_a_group_that_vanishes_between_the_grace_period_and_the_kill_is_not_an_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The race the escalation has to tolerate: gone after the poll, before the SIGKILL."""
        process = subprocess.Popen(  # noqa: S603 — this interpreter, an argv list, a test
            [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
        )
        signals: list[int] = []

        def racing(pgid: int, signal_number: int) -> None:
            signals.append(signal_number)
            if signal_number == 9:
                raise ProcessLookupError(pgid)

        monkeypatch.setattr(os, "killpg", racing)
        try:
            _kill_group(process)
        finally:
            process.kill()
            process.wait()
        assert signals == [15, 9]
