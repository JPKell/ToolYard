# ToolYard — Quickstart

ToolYard runs a model-directed tool call under a fixed discipline: schema validation,
allowlisting, path containment and a persisted record — and a refusal is a result, never an
exception.

## Install

```bash
pip install toolyard
```

Runtime dependencies: `baseaicore`, `jsonschema`, `httpx` — the whole budget.

## Run it

[`quickstart.py`](quickstart.py) in this directory is a standalone script that registers one tool,
executes it, and then executes an unregistered tool name to show a refusal. It needs nothing but
`toolyard`: no server, no model, no configuration file.

```bash
pip install toolyard
python docs/quickstart.py
```

Its real output:

```text
ok 'hi'
refused unknown_tool
```

The second call never raises — `unknown_tool` is a `ToolResult.reason` from the same closed set
every refusal uses, recorded exactly like the successful call. See
[the README](../README.md) for the fixed refusal order and the isolation ladder.
