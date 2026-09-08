"""A ten-line ToolYard quickstart: register a tool, execute it, and see a refusal recorded.

Needs nothing but `pip install toolyard`. No server, no model, no configuration file.
"""

import tempfile
from pathlib import Path

from toolyard import (
    EgressClass,
    InMemoryToolCallStore,
    PathContainment,
    RiskClass,
    SandboxPaths,
    ToolCallRequest,
    ToolContext,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
    ToolSpec,
)


class Echo:
    """The one tool this quickstart registers."""

    def execute(self, args, context):
        """Return `args["text"]` unchanged."""
        return ToolOutput(content=args["text"])


spec = ToolSpec(
    name="echo",
    description="Echo text back.",
    args_schema={
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
        "additionalProperties": False,
    },
    result_schema=None,
    risk_class=RiskClass.READ_ONLY,
    egress=EgressClass.NONE,
    path_args={},
)

registry = ToolRegistry()
registry.register(spec, Echo())
store = InMemoryToolCallStore()
executor = ToolExecutor(registry, PathContainment(), allowlist=frozenset({"echo"}), store=store)
write_root = Path(tempfile.gettempdir())
context = ToolContext(invocation_id="inv-1", workspace=SandboxPaths(write_root=write_root))

ok = executor.execute(ToolCallRequest(name="echo", args={"text": "hi"}), context)
refused = executor.execute(ToolCallRequest(name="rm_rf", args={}), context)

print(ok.status, repr(ok.content))
print(refused.status, refused.reason)
