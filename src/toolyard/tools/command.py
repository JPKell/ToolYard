"""``run_command`` — argv, isolated, no network, no shell, and no process started here.

This module launches nothing. It calls :meth:`~toolyard.containment.Sandbox.run_isolated` on the
sandbox it was built with, which is the **same instance the executor holds** (spec §7 as amended at
D1, decision A): the tier the executor checked at its containment rung is then, necessarily, the
tier the command runs under. A handler that constructed its own sandbox could be refused by an
executor that found a tier and then run under one that did not exist, or the reverse.

``tests/unit/test_boundaries.py`` pins this package to exactly one process-launch site, in
:mod:`toolyard.sandbox`, and this module is not it. There is no ``shell=True`` anywhere in the
package and a test greps for it; the argv arrives as a list of strings from a schema that admits
nothing else, and it is passed through unjoined.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final

from baseaicore import ValidationError

from toolyard.executor import DEFAULT_TIMEOUT_SECONDS
from toolyard.sandbox import ARGV_REFUSED_PREFIX, UNLAUNCHABLE_EXIT_CODE
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
    from toolyard.containment import Sandbox, SubprocessResult
    from toolyard.types import ToolContext, ToolHandler

__all__ = [
    "DEFAULT_COMMAND_ENV",
    "MIN_PROCESS_COUNT",
    "run_command_tool",
]

DEFAULT_COMMAND_ENV: Final[Mapping[str, str]] = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
"""The child's whole environment unless the caller replaces it.

``PATH`` and nothing else. Under bwrap ``--clearenv`` leaves the child no environment at all, and
while a bare command still resolves through libc's built-in default, anything the command spawns by
looking itself up sees an empty ``PATH``. Spec §14's rule is that the child's environment is an
explicit allowlist and never ``os.environ``, and this is that allowlist at its smallest useful size.

It is the **caller's** value, never the model's: nothing in ``run_command``'s argument schema
reaches it. A model-chosen environment variable is a model-chosen ``LD_PRELOAD``.
"""

MIN_PROCESS_COUNT: Final[int] = 8
"""A documented floor for ``ResourceLimits.process_count``, which is not validated anywhere.

The limit counts every process in the sandbox's user namespace, and under bwrap that includes
``bwrap``'s own init and the ``prlimit`` that applies the limits — so 1 or 2 refuses every command,
including the probe's canary. The default is 64 and the integration suite runs at 32. Eight is the
lowest value at which an ordinary command still has room to be a command; below it the failures
look like the command's and are the limit's. Nothing enforces this, deliberately: ``ResourceLimits``
is the caller's object and D1 chose not to validate a number that is legitimately host-specific.
This constant is here so the choice is an informed one.
"""

_ARGV_SCHEMA: Final[Mapping[str, Any]] = {
    "type": "object",
    "properties": {
        "argv": {
            "type": "array",
            "items": {"type": "string", "maxLength": 4096},
            "minItems": 1,
            "maxItems": 256,
            "description": (
                "The command and its arguments, already split. There is no shell: no globbing, no "
                "pipes, no redirection, no variable expansion, and no quoting to get right."
            ),
        }
    },
    "required": ["argv"],
    "additionalProperties": False,
}


class _RunCommand:
    """``run_command``'s handler, bound to the executor's own sandbox."""

    __slots__ = ("_env", "_sandbox")

    def __init__(self, sandbox: Sandbox, env: Mapping[str, str]) -> None:
        """Bind the handler to the sandbox instance and the environment allowlist."""
        self._sandbox = sandbox
        self._env = env

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """Run one command under the probed isolation rung and render what it did.

        The timeout is the invocation's — ``run_isolated`` kills the whole process tree on expiry —
        and it is passed through rather than reinvented, so a caller that shortened this
        invocation's limit shortens the command's.

        Args:
            args: ``argv``, a non-empty list of strings. Never joined, never given to a shell.
            context: The invocation. Supplies the workspace the command runs in and the timeout.

        Returns:
            The command's exit code, stdout and stderr, with the rung that ran it, whether output
            was truncated, and any limit this platform could not apply. A command that exits
            non-zero is an ``OK`` result carrying a non-zero exit code — the tool ran, and "the
            command failed" is information for the model rather than a failure of the call. A
            timeout is ``TIMEOUT``; an argv the launcher would not accept is ``args_invalid``; a
            host with no tier is refused by the executor before this runs at all (spec §11.4).
        """
        argv = [str(item) for item in args["argv"]]
        timeout_seconds = (
            context.timeout_seconds
            if context.timeout_seconds is not None
            else DEFAULT_TIMEOUT_SECONDS
        )
        result = self._sandbox.run_isolated(
            argv,
            paths=context.workspace,
            timeout_seconds=timeout_seconds,
            env=self._env,
        )
        if result.timed_out:
            return ToolRefusal(
                Reason.TIMEOUT,
                f"the command did not finish within {timeout_seconds:.3f} s and its whole process "
                "tree was killed; a command that backgrounds a child holds the call open until "
                "this limit",
                status=ToolStatus.TIMEOUT,
                record_detail=f"argv[0]={argv[0]!r}, tier={result.tier.value}",
            )
        if result.exit_code == UNLAUNCHABLE_EXIT_CODE and result.stderr.startswith(
            ARGV_REFUSED_PREFIX
        ):
            return ToolRefusal(
                Reason.ARGS_INVALID,
                "the command could not be launched: "
                f"{result.stderr[len(ARGV_REFUSED_PREFIX) :].strip()}",
                record_detail=f"tier={result.tier.value}",
            )
        return ToolOutput(content=_render(result), structured=_structured(result))


def _render(result: SubprocessResult) -> str:
    """Render a finished command for the model, exit code and truncation both visible.

    Both figures are stated because a model that cannot tell a truncated success from a clean one
    will answer from half a stream, and one that cannot see the exit code will read a failed
    command's empty stdout as an empty answer.
    """
    lines = [f"exit code: {result.exit_code}", f"isolation: {result.tier.value}"]
    if result.output_truncated:
        lines.append("output: TRUNCATED at the capture limit; the process tree was then killed")
    if result.limits_unenforced:
        lines.append(f"limits not enforced on this host: {', '.join(result.limits_unenforced)}")
    lines.append(f"stdout:\n{result.stdout}" if result.stdout else "stdout: (empty)")
    lines.append(f"stderr:\n{result.stderr}" if result.stderr else "stderr: (empty)")
    return "\n".join(lines)


def _structured(result: SubprocessResult) -> Mapping[str, Any]:
    """The same facts, for the application's record rather than the model's prompt."""
    return {
        "exit_code": result.exit_code,
        "tier": result.tier.value,
        "duration_ms": result.duration_ms,
        "output_truncated": result.output_truncated,
        "limits_unenforced": list(result.limits_unenforced),
    }


def run_command_tool(
    sandbox: Sandbox, *, env: Mapping[str, str] = DEFAULT_COMMAND_ENV
) -> tuple[ToolSpec, ToolHandler]:
    """Build ``run_command``: one argv, run under the isolation ladder or not at all.

    Args:
        sandbox: The **same instance the executor was built with**. Passing a different one makes
            the executor's tier check and the command's rung two answers to one question.
        env: The child's whole environment. The caller's, never the model's; see
            :data:`DEFAULT_COMMAND_ENV`.

    Returns:
        The ``(spec, handler)`` pair for ``registry.register(*run_command_tool(sandbox))``.

    Raises:
        ValidationError: If ``sandbox`` is not a sandbox, or ``env`` is not a mapping of strings to
            strings. Both are the caller's inputs and a mistake in either is a caller bug, surfaced
            at startup rather than on the first call — a malformed environment discovered inside
            the handler would reach a model as ``handler_error``, which would hand it a lever it
            has no business holding.
    """
    if not callable(getattr(sandbox, "run_isolated", None)) or not callable(
        getattr(sandbox, "isolation_tier", None)
    ):
        raise ValidationError(
            "run_command_tool needs the Sandbox the executor holds: the tier the executor checks "
            "and the rung the command runs under must be the same answer to the same question.",
            details={"field": "sandbox"},
        )
    if not isinstance(env, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in env.items()
    ):
        raise ValidationError(
            "run_command_tool's env must be a mapping of str to str. It is the caller's value and "
            "the child's whole environment; a model never chooses it.",
            details={"field": "env"},
        )
    spec = ToolSpec(
        name="run_command",
        description=(
            "Run one command in the workspace, isolated and without network. Supply argv already "
            "split: there is no shell, so no globbing, pipes, redirection or variable expansion. "
            "The workspace is the working directory and the only writable place. A command that "
            "backgrounds a child and returns holds this call open until the timeout, when the "
            "whole process tree is killed — do not start a server with it. The exit code and "
            "whether output was truncated are both reported."
        ),
        args_schema=_ARGV_SCHEMA,
        result_schema=None,
        risk_class=RiskClass.MUTATING,
        egress=EgressClass.NONE,
        requires_isolation=True,
    )
    return spec, _RunCommand(sandbox, dict(env))
