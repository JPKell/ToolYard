"""Both rungs of the ladder, for real: what a command inside the sandbox can and cannot reach.

Marked ``isolation`` and **skipped, loudly, where a rung is not available** — never passed. Each
test runs twice, once per rung, and the rung is chosen by shaping the probe's view of the host
rather than by mutating the host: the bwrap case hands the sandbox an executable lookup that
answers ``None`` for ``podman`` and ``docker``, so the ladder's top rung is invisible and the probe
lands on bwrap and runs its real canary. On a machine with a container runtime the container case
runs the same tests under it. That is how the middle rung — the one most deployments actually land
on — is exercised instead of being masked by the top one.

Nothing here needs a network, and the one test that opens a socket listens on loopback, to show
that even loopback is gone from inside.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from baseaicore import ValidationError

from toolyard import IsolationTier, ResourceLimits, SandboxPaths, TieredSandbox
from toolyard._safe import TRUNCATION_LABEL_TEMPLATE

if TYPE_CHECKING:
    from collections.abc import Mapping

    from toolyard import SubprocessResult

pytestmark = pytest.mark.isolation

TRUNCATION_MARKER = TRUNCATION_LABEL_TEMPLATE.split("{")[0].strip()
PYTHON = "python3"
"""The interpreter *inside* the sandbox: the host's under bwrap, the image's under a container."""

LIMITS = ResourceLimits(
    cpu_seconds=30, memory_bytes=256 << 20, file_size_bytes=1 << 20, process_count=32
)
OUTPUT_CAP = 65_536
INSIDE_PATH = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
"""An allowlisted ``PATH`` for the one test whose child must find its own interpreter again."""


def _hide_containers(name: str) -> str | None:
    """The probe's view with no container runtime: the common deployment, forced here."""
    return None if name in ("podman", "docker") else shutil.which(name)


@pytest.fixture(params=[IsolationTier.CONTAINER, IsolationTier.BWRAP], ids=["container", "bwrap"])
def rung(request: pytest.FixtureRequest) -> IsolationTier:
    """Which rung this run of the tests is about."""
    tier: IsolationTier = request.param
    return tier


@pytest.fixture
def sandbox(rung: IsolationTier) -> TieredSandbox:
    """A real sandbox whose probe landed on ``rung``, or a loud skip saying why it could not."""
    if sys.platform != "linux":
        pytest.skip("isolation tiers exist on Linux only (spec §16)")
    which = shutil.which if rung is IsolationTier.CONTAINER else _hide_containers
    built = TieredSandbox(which=which, limits=LIMITS, max_output_bytes=OUTPUT_CAP)
    report = built.report()
    if report.tier is not rung:
        pytest.skip(f"the {rung.value} rung is not available on this host: {report.reason}")
    return built


def run(
    sandbox: TieredSandbox,
    workspace: SandboxPaths,
    *argv: str,
    timeout_seconds: float = 30.0,
    env: Mapping[str, str] | None = None,
    network: bool = False,
) -> SubprocessResult:
    """Run one command in the workspace."""
    return sandbox.run_isolated(
        list(argv), paths=workspace, timeout_seconds=timeout_seconds, env=env, network=network
    )


def python(*code: str) -> tuple[str, ...]:
    """An argv running ``code`` under the in-sandbox interpreter, isolated from any site."""
    return (PYTHON, "-I", "-c", "\n".join(code))


def _lingering_containers() -> list[str]:
    runtime = shutil.which("podman") or shutil.which("docker")
    if runtime is None:
        return []
    listed = subprocess.run(  # noqa: S603 — a fixed argv, in a test
        [runtime, "ps", "-q", "--filter", "name=toolyard-"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return listed.stdout.split()


class TestTheRungItself:
    def test_a_command_runs_and_the_result_names_the_rung(
        self, sandbox: TieredSandbox, workspace: SandboxPaths, rung: IsolationTier
    ) -> None:
        result = run(sandbox, workspace, "/bin/echo", "hello")
        assert result.exit_code == 0
        assert result.stdout == "hello\n"
        assert result.tier is rung
        assert result.timed_out is False

    def test_the_bwrap_rung_was_forced_not_incidental(
        self, sandbox: TieredSandbox, rung: IsolationTier
    ) -> None:
        """The proof that the middle rung was exercised rather than masked by the top one."""
        if rung is not IsolationTier.BWRAP:
            pytest.skip("about the bwrap case")
        report = sandbox.report()
        assert report.runtime == "bwrap"
        assert report.runtime_path == shutil.which("bwrap")
        if shutil.which("docker") or shutil.which("podman"):
            assert "not installed" in report.reason, "the containers were hidden from the probe"

    def test_the_container_rung_names_its_runtime(
        self, sandbox: TieredSandbox, rung: IsolationTier
    ) -> None:
        if rung is not IsolationTier.CONTAINER:
            pytest.skip("about the container case")
        report = sandbox.report()
        assert report.runtime in ("podman", "docker")
        assert report.runtime_path == shutil.which(report.runtime or "")

    def test_every_limit_is_reported_enforced_on_this_machine(self, sandbox: TieredSandbox) -> None:
        """Not a universal truth — a fact about the reference machine, asserted so it is noticed."""
        assert sandbox.report().limits_unenforced == ()

    def test_a_missing_command_is_a_result_not_an_exception(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(sandbox, workspace, "/nonexistent/toolyard-binary")
        assert result.exit_code != 0
        assert result.stderr.strip() != ""


class TestNamespaces:
    def test_the_process_lives_in_its_own_pid_namespace(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(sandbox, workspace, *python("import os", "print(os.getpid())"))
        assert result.exit_code == 0, result.stderr
        assert int(result.stdout) < 50, "a host pid would be in the thousands"

    def test_the_network_is_unreachable(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(
            sandbox,
            workspace,
            *python(
                "import socket",
                "try:",
                "    socket.create_connection(('1.1.1.1', 53), timeout=3)",
                "    print('connected')",
                "except OSError as error:",
                "    print('unreachable', error.errno)",
            ),
        )
        assert result.exit_code == 0, result.stderr
        assert result.stdout.startswith("unreachable")

    def test_network_is_refused_and_even_loopback_is_gone_without_it(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        """Spec §14: the flag is refused in v1, and the namespace it would have kept is absent."""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            probe = python(
                "import socket, sys",
                "try:",
                f"    socket.create_connection(('127.0.0.1', {port}), timeout=3).close()",
                "    print('connected')",
                "except OSError:",
                "    print('unreachable')",
            )
            with pytest.raises(ValidationError, match="network"):
                run(sandbox, workspace, *probe, network=True)
            denied = run(sandbox, workspace, *probe)
        assert denied.stdout.strip() == "unreachable", denied.stderr


class TestTheFilesystemView:
    def test_a_file_outside_the_roots_does_not_exist_inside(
        self, sandbox: TieredSandbox, workspace: SandboxPaths, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        result = run(sandbox, workspace, "/bin/cat", str(outside))
        assert result.exit_code != 0
        assert "No such file" in result.stderr
        assert "secret" not in result.stdout

    def test_a_planted_symlink_reaches_nothing_outside(
        self, sandbox: TieredSandbox, workspace: SandboxPaths, tmp_path: Path
    ) -> None:
        """The symlink race, from inside: the sandbox's view has no target to race for."""
        outside = tmp_path / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        result = run(
            sandbox,
            workspace,
            *python(
                "import os",
                f"os.symlink({str(outside)!r}, 'planted')",
                "try:",
                "    print(open('planted').read())",
                "except FileNotFoundError:",
                "    print('nothing')",
            ),
        )
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == "nothing"
        planted = workspace.write_root / "planted"
        assert planted.is_symlink(), "the link was really created, in the write root"
        assert planted.read_text(encoding="utf-8") == "secret", "and on the host it resolves"

    def test_a_read_root_is_readable_and_not_writable(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        reference = workspace.read_roots[0] / "ref.txt"
        reference.write_text("reference", encoding="utf-8")
        read = run(sandbox, workspace, "/bin/cat", str(reference))
        assert read.exit_code == 0 and read.stdout == "reference"
        write = run(
            sandbox,
            workspace,
            *python(
                "try:",
                f"    open({str(workspace.read_roots[0] / 'new.txt')!r}, 'w')",
                "    print('written')",
                "except OSError as error:",
                "    print('refused', error.errno)",
            ),
        )
        assert write.stdout.strip() == "refused 30", write.stderr  # EROFS
        assert not (workspace.read_roots[0] / "new.txt").exists()

    def test_the_write_root_is_writable_and_the_file_lands_on_the_host(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(
            sandbox,
            workspace,
            *python("open('out.txt', 'w').write('from inside')", "import os", "print(os.getcwd())"),
        )
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == str(workspace.write_root.resolve())
        assert (workspace.write_root / "out.txt").read_text(encoding="utf-8") == "from inside"

    def test_the_runtime_is_read_only(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(
            sandbox,
            workspace,
            *python(
                "try:",
                "    open('/usr/bin/toolyard-planted', 'w')",
                "    print('written')",
                "except OSError as error:",
                "    print('refused', error.errno)",
            ),
        )
        assert result.stdout.startswith("refused"), result.stderr

    def test_tmp_is_private(self, sandbox: TieredSandbox, workspace: SandboxPaths) -> None:
        marker = f"/tmp/toolyard-private-{uuid.uuid4().hex}"  # noqa: S108 — the sandbox's /tmp, asserted absent on the host
        result = run(
            sandbox, workspace, *python(f"open({marker!r}, 'w').write('x')", "print('ok')")
        )
        assert result.exit_code == 0, result.stderr
        assert not Path(marker).exists(), "the sandbox's /tmp is not the host's"


class TestTheEnvironment:
    def test_the_child_sees_the_allowlist_and_not_the_host(
        self,
        sandbox: TieredSandbox,
        workspace: SandboxPaths,
        rung: IsolationTier,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("TOOLYARD_TEST_SECRET", "hunter2")
        result = run(
            sandbox,
            workspace,
            *python("import json, os", "print(json.dumps(dict(os.environ)))"),
            env={"TOOLYARD_ALLOWED": "yes"},
        )
        assert result.exit_code == 0, result.stderr
        seen = json.loads(result.stdout)
        assert seen["TOOLYARD_ALLOWED"] == "yes"
        assert "TOOLYARD_TEST_SECRET" not in seen
        assert "hunter2" not in result.stdout
        for host_only in ("USER", "SHELL", "XDG_RUNTIME_DIR", "SSH_AUTH_SOCK"):
            assert host_only not in seen
        if rung is IsolationTier.BWRAP:
            assert "HOME" not in seen and "PATH" not in seen, "--clearenv means cleared"


class TestTheLimits:
    def test_a_timeout_kills_the_whole_tree(
        self, sandbox: TieredSandbox, workspace: SandboxPaths, rung: IsolationTier
    ) -> None:
        marker = f"toolyard-tree-{uuid.uuid4().hex}"
        started = time.monotonic()
        result = run(
            sandbox,
            workspace,
            *python(
                "import subprocess, sys, time",
                f"nap = 'import time; time.sleep(60) # {marker}'",
                "subprocess.Popen([sys.executable, '-c', nap])",
                "time.sleep(60)",
            ),
            timeout_seconds=1.0,
            env=INSIDE_PATH,
        )
        assert result.timed_out
        assert time.monotonic() - started < 15.0
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            survivors = subprocess.run(  # noqa: S603 — a fixed argv, in a test
                ["/usr/bin/pgrep", "-f", marker], capture_output=True, check=False
            )
            if survivors.returncode != 0:
                break
            time.sleep(0.1)
        else:  # pragma: no cover — only reached on failure
            pytest.fail("a grandchild outlived the timeout")
        if rung is IsolationTier.CONTAINER:
            assert _lingering_containers() == []

    def test_an_output_bomb_is_capped_and_the_tree_killed(
        self, sandbox: TieredSandbox, workspace: SandboxPaths, rung: IsolationTier
    ) -> None:
        started = time.monotonic()
        result = run(
            sandbox,
            workspace,
            *python("while True:", "    print('x' * 1000)"),
            timeout_seconds=30.0,
        )
        assert TRUNCATION_MARKER in result.stdout
        assert len(result.stdout.encode("utf-8")) <= OUTPUT_CAP
        assert result.output_truncated is True
        assert result.timed_out is False
        assert result.exit_code != 0
        assert time.monotonic() - started < 15.0
        if rung is IsolationTier.CONTAINER:
            assert _lingering_containers() == []

    def test_a_fork_attempt_is_bounded(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        attempts = LIMITS.process_count * 4
        result = run(
            sandbox,
            workspace,
            *python(
                "import subprocess, sys",
                "children = []",
                f"for _ in range({attempts}):",
                "    try:",
                "        children.append(subprocess.Popen(['/bin/sleep', '2']))",
                "    except OSError:",
                "        break",
                "print(len(children))",
                "for child in children:",
                "    child.wait()",
            ),
        )
        assert result.exit_code == 0, result.stderr
        spawned = int(result.stdout)
        assert 0 < spawned < attempts, f"{spawned} of {attempts} spawned: the limit did not bite"

    def test_a_file_size_limit_is_enforced(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(
            sandbox,
            workspace,
            *python("open('big.bin', 'wb').write(b'x' * (2 << 20))", "print('unbounded')"),
        )
        assert result.exit_code != 0
        assert "unbounded" not in result.stdout
        assert (workspace.write_root / "big.bin").stat().st_size <= LIMITS.file_size_bytes

    def test_a_memory_limit_is_enforced(
        self, sandbox: TieredSandbox, workspace: SandboxPaths
    ) -> None:
        result = run(
            sandbox,
            workspace,
            *python(
                "block = bytearray(512 << 20)",
                "block[::4096] = b'x' * len(block[::4096])",
                "print('unbounded')",
            ),
        )
        assert result.exit_code != 0
        assert "unbounded" not in result.stdout
