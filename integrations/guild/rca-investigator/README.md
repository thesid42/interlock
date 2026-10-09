# Interlock RCA Investigator

Committed Python LangGraph code for bounded incident reconstruction. No shell
commands, filesystem worker installation, or LLM-selected execution tools are
used.

The initial capability probe accepts a JSON text message:

```json
{"protocol":"interlock-rca-probe-v1","input_nonce":"unique-probe-nonce"}
```

It emits a Guild `console_log` event containing a JSON report with
`protocol_version: 2`, `probe: true`, the input nonce, and
`python_execution: true`. It also returns an `AIMessage`, but the observed Guild
driver does not surface deterministic state messages as final text. The
machine receipt is the task-bound `agent_console` event. This establishes
only that committed Python executed and returned the requested binding. It does
not attest container isolation, network policy, lifecycle cleanup, or RCA.

Guild currently prepends three metadata lines to the text. The parser accepts
only that observed header before one complete JSON object; other surrounding
text and trailing input are rejected.

The production branch accepts `interlock-sandbox-rca-v2` packets validated by
the byte-identical shared `rca_contract.py`. Python controls at most three
conditions and two repetitions per condition. It calls only the declared
`interlock_qwen_complete` Guild integration tool, with no model-selected tools,
and dispatches proposals into capability-limited simulated tools. No production
credentials or actual external effects are available to the replay.

The graph checks the exact declared tool names before experiments and awaits
a single JSON console receipt after completion, using the documented
`message` and `level` arguments. Guild validates those arguments; the generic
LangChain invocation schema is not the operation schema. Report collection
must bind that event to this pinned task and validate the shared report contract;
arbitrary console strings or the final text placeholder are not evidence.

The root project must copy the final shared contract into this directory before
publication and declare the published Qwen integration in `guild.yaml`. The
graph checks the contract's runtime file hash against the checkpoint binding.
Until those dependencies are present, only the capability probe is runnable.

Guild supplies Python, LangGraph, and LangChain. This project deliberately has no
custom runtime environment or additional package dependencies. Runtime
isolation and lifecycle cleanup still require provider-side verification;
successful Python execution or a report is not that verification.
