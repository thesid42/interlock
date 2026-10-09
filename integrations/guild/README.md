# Guild Hosted Investigation

The intended protocol-v2 path is a committed LangGraph Python agent, not a Goose
shell recipe. It reruns the protected agent contract against frozen public/synthetic
inputs, uses external Akash-hosted Qwen through one restricted mediated integration,
and dispatches functional in-memory tools. Local Docker and a custom Guild environment
are not required. Publication, tool connectivity and a terminal task do not establish
successful end-to-end RCA or independent isolation.

## Prepare The Python Investigator

1. Use a dedicated private workspace with `restrict_account_credentials=true`.
   Keep production context, publishing permissions and unrelated credentials out.
2. Review [qwen-input.schema.json](qwen-input.schema.json) and
   [qwen-output.schema.json](qwen-output.schema.json), then publish a private
   integration for the confirmed inference endpoint. Import
   [qwen-inline-openapi.yaml](qwen-inline-openapi.yaml), which embeds those schemas.
   Referenced schemas produced a zero-argument tool, while manually creating the
   REST operation produced invalid null hook metadata. The inline OpenAPI generator
   avoids both setup paths. Expose only `interlock_qwen_complete`:
   fixed model and destination, nonstreaming responses, bounded messages, at most
   1,600 output tokens and optional temperature no greater than 1. The current HTTP
   public-demo integration uses a nonsecret marker association, never a real bearer
   or management key. That marker is not inference authentication.
3. Review [rca-investigator](rca-investigator), including `graph.py`,
   `langgraph.json` and `guild.yaml`. Copy the exact shared
   `app/security/rca_contract.py` bytes into the package. Declare only the pinned
   Qwen operation and the approved `console_log` report builtin; no environment,
   sub-agents, publishing tools or other integrations. Publish, install and pin the
   reviewed version, disable automatic updates and verify saved source readback.
4. Set `GUILD_API_KEY` to the complete account `id:secret` with
   `workspaces:read`, `agents:read` and `integrations:read`. The last scope is needed
   to read the nonempty credential association. Set the workspace, investigator and pinned
   version IDs. Choose `GUILD_SANDBOX_PROTOCOL_VERSION=2`; set
   `GUILD_SANDBOX_QWEN_INTEGRATION` to the exact qualified integration name and
   `GUILD_SANDBOX_QWEN_CREDENTIAL_ID` to its sole approved marker association.
   Protocol v2 does not require the legacy environment/image variables.
5. Create an API trigger for the installed investigator in Guild's workspace UI.
   Put its complete `id:secret` in `GUILD_TRIGGER_API_KEY` and its separate record
   ID in `GUILD_TRIGGER_ID`. These are backend secrets, never agent/browser inputs.
   Trigger capabilities can cover the workspace; keep it dedicated.
6. Enable `GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED=true` only after reviewing the
   bounded public export. It remains false in the template. Restart the backend
   after local configuration changes.

Create the REST operation in the integration's draft version, then build and publish
that version before updating the investigator's exact integration pin:

```powershell
guild integration operation create siddharthbhat44~interlock-qwen --openapi integrations/guild/qwen-inline-openapi.yaml
guild integration version build siddharthbhat44~interlock-qwen --version-number 1.0.2
guild integration version publish siddharthbhat44~interlock-qwen --version-number 1.0.2
```

Guild CLI is setup and diagnostic tooling only. Application session creation and
reads use the HTTPS API trigger, not CLI/OAuth execution or a silent fallback.
Do not activate a different source version or extra capability merely to make a
connectivity check green.

## Frozen Inputs and Actual Reruns

The live workload and Python investigator share prompt construction, proposal/schema
validation, authorization and in-memory sandbox adapters from `rca_contract.py`.
The backend persists the effective request before inference, including public-only
transformations, model parameters, source IDs and contract/checkpoint hashes.
Returned model metadata is retained without claiming a model alias identifies
immutable weights.

Only already-sanitized public/synthetic effective input is exported: up to four
4,000-character source rows and a bounded packet of 100,000 bytes. Private missions,
memory, original draft bodies, destinations and credentials stay local. HTTP inference
cannot be used for private context. A missing, private or incompatible original
checkpoint becomes `reconstruction_not_exact`, not a fabricated exact capture.
The current controlled demo is reconstructed; it is not an exact observed attack.

The runner uses up to three conditions, with two repetitions each and at most six
model calls:

- Original effective input, or its explicitly labeled public reconstruction.
- Remove one candidate suspect source without changing other inputs.
- Replace that same source with a neutral no-facts marker.

Model parameters and policy are held fixed. A permitted publish creates an in-memory
artifact and returns its hash; a forbidden dispatch records a denial. Each run
records the effective-input hash, changed source IDs, model response metadata,
proposal, policy decision and functional tool-call/result trace. No real brief,
external message or transfer is executed. The old backend diagnostic probes are
not used for protocol v2.

The workload does not feed independent persistent memory to Qwen, so memory-removal
controls are N/A. Source selection is a hypothesis, not attribution. Repeated
differences support behavioral explanations, not definite causality; failures,
refusals and variation remain visible. The attack need not reproduce, and two
consistent runs are not a general safety guarantee.

## Report, Runtime and Cleanup Evidence

The full sealed packet is persisted before dispatch. A returned report is checked
against that packet, not only its claimed hash: incident/checkpoint identity, exact
planned inputs, case/repetition counts, deterministic tool results and comparisons
must match. Reports must belong to the exact pinned root task and its terminal
`DONE` state, not a child task.

The current driver dropped a Python probe's `AIMessage` despite root `DONE`.
Direct runner-generated report delivery through the declared `console_log` builtin
is now being verified. This is not model-written narration or a claim that any
log line proves container isolation.

Normal runtime cleanup is automatic; Interlock requires API-observed runtime
destruction before releasing a finalized advisory report. It does not implement a
force-destroy API or assume terminal root status alone proves cleanup. Pinned code,
root status, report binding and cleanup are separate from independent isolation
or exact execution attestation. Missing session-lock/runtime evidence stays unknown.

A validated report with terminal root and confirmed cleanup finishes
`review_required`. Qwen's follow-up remains advisory, and
`isolation_verified`/`replay_execution_verified` remain false when independent
attestation is unavailable. Manual review is required; the managed agent stays
contained and no model output can resume it.

`GUILD_SANDBOX_TIMEOUT_SECONDS` is a local polling deadline, not a remote spending
or execution limit. An uncertain session create is never automatically retried.
If terminal/cleanup evidence is unavailable at the deadline, retain the exact
session reference for reconciliation rather than creating a replacement. The
application exposes no force-stop operation.

## Current Verification Status

- The committed Python investigator is published.
- Its restricted mediated Qwen operation returned HTTP `200`.
- A Python probe reached `DONE`, but its `AIMessage` was not delivered.
- Direct `console_log` report delivery, root binding and cleanup are awaiting
  verification. No completed end-to-end protocol-v2 RCA is claimed.

Historical Goose attempts included missing installed workers and a final frozen-hash
mismatch; the `v1.0.5` demo failed, containment remained and advisory analysis did not
run. Runtime destruction was verified separately. Qwen HTTP connectivity and 24
demo ClickHouse audit events were independently verified, with pending outbox zero.
Those facts do not turn the failed replay into a pass. The files under
`incident-investigator` are the legacy protocol-v1 path, not the intended architecture.

## Official Contracts

- [Live public OpenAPI](https://api.guild.ai/v1/openapi.yaml)
- [Security architecture](https://docs.guild.ai/platform/security-architecture)
- [LangGraph agents](https://docs.guild.ai/guide/langgraph-agents)
- [Guild manifest](https://docs.guild.ai/guide/guild-yaml)
- [API authentication](https://docs.guild.ai/api-reference/introduction)
- [HTTP API triggers](https://docs.guild.ai/platform/api-triggers)
- [Session runtimes](https://docs.guild.ai/api-reference/sessions/fetch-session-runtimes)
- [Session tasks](https://docs.guild.ai/api-reference/sessions/fetch-session-sub-tasks)
- [Session controls](https://docs.guild.ai/platform/sessions)
