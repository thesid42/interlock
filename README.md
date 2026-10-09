# Interlock

A standalone Agent Security Operations application: operate a bounded web-connected
agent, contain unauthorized behavior, preserve evidence and investigate it in a
Guild-hosted sandbox. The product and sponsor contracts live in [SPEC.md](SPEC.md).
There is no separate build-plan document.

Interlock is the product and configuration name. Local state defaults to
`data/interlock.sqlite3`, configured through `INTERLOCK_DB_PATH`; the development
launcher uses `INTERLOCK_API_URL`. The default ClickHouse database is `interlock`.
Internal Python class names and versioned replay protocols are independent of the
product name and remain unchanged.

## Current implementation

- FastAPI backend, React/Vite operator console and durable SQLite state.
- App-owned research agents with approved HTTPS sources, scheduled execution and
  cited in-app briefs using the user's Akash-hosted Qwen deployment.
- Deterministic tool/destination checks, pre-dispatch containment, frozen incident
  snapshots, provenance restrictions and explicit resolution/resumption.
- Asynchronous Guild Python investigator, bounded repeated agent reruns, functional
  canary tools and advisory RCA, with runtime evidence distinct from model claims.
- ClickHouse event outbox, acknowledged export, timelines, source rankings and
  analytics. SQLite remains authoritative when analytics is unavailable.
- Optional official Slack MCP delivery with fixed channel and pinned tool schema.
- Operations, incident dossiers, Connections, Analytics, Memory and a separate
  recorded Simulation view.

The console uses a restrained light theme: white surfaces, charcoal text, cobalt
commands and distinct severity colors. Dense tables and evidence inspectors stay
central; the application opens directly to Operations.

Adapters are not live-verified until your resources are configured and a relevant
request succeeds. This is a local prototype, not universal agent protection or a
production-ready public service. The included agent only publishes within the app;
it does not execute arbitrary generated code. Recorded incidents are labeled and
never masquerade as real-world discoveries. No test suite or benchmark was added.

## Run locally

Python 3.10+ and Node.js 20.19+ or 22.12+ are required. In PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd app/dashboard
npm install
cd ../..
.\scripts\dev.ps1
```

The launcher binds to loopback, selects available ports and prints URLs/process
IDs. Defaults: console `http://127.0.0.1:5173`, API `http://127.0.0.1:8000/docs`.
Logs are under `logs/`. Stop the printed process IDs to stop the worker as well.
Closing the browser does not stop autonomous execution.

Create a local `.env` from [.env.example](.env.example) and restart the API after
changes. Keep secrets server-side; never use frontend `VITE_` credentials or commit
them. Connections separates configured, reachable and verified capabilities.

## Prepare the resources

### Akash Console / Qwen

Use your existing deployment, not AkashML. Set `LLM_BASE_URL` to the protected HTTPS
inference endpoint ending in `/v1`, `LLM_API_KEY` to its inference bearer credential,
and `AGENT_MODEL`/`JUDGE_MODEL` to the actual served alias for `Qwen/Qwen3.8-27B`.
Do not provide the Console deployment-management key.

The client also accepts the service root or its exact `/v1/chat/completions` URL
and derives the `/v1` base. A service without authentication needs explicit
`LLM_ALLOW_UNAUTHENTICATED=true`; no empty bearer header is sent. For the user's
HTTP-only hackathon deployment, `LLM_HTTP_PUBLIC_ONLY=true` restricts inference
to bounded public-source and synthetic prompts. It omits operator missions,
private memories, draft bodies, raw destinations and credentials. Legacy
private-context flows remain blocked; HTTPS is required for normal operation.
These flags default off in the example environment.

In Connections, discover models and separately check a small inference request.
Thinking parameters and constrained JSON output depend on your serving engine/build;
the corresponding switches in `.env.example` are configurable. Final JSON is always
validated locally. Qwen proposes actions but never grants execution permissions.

### Guild-hosted sandbox

No local Docker daemon is needed. The intended protocol-v2 investigator is the
committed Python LangGraph agent under
[integrations/guild/rca-investigator](integrations/guild/rca-investigator), with no
custom environment. It reuses the live agent contract, makes fresh external Qwen
requests through one restricted Guild-mediated integration and dispatches functional
in-memory tool stubs. It does not ask Goose to generate or transcribe shell commands.

Set `GUILD_API_KEY` to the complete account `id:secret` for `agents:read` and
`workspaces:read` metadata checks, plus the exact
`GUILD_SANDBOX_WORKSPACE_ID`, `GUILD_SANDBOX_AGENT_ID` and installed version
from your account. Select `GUILD_SANDBOX_PROTOCOL_VERSION=2` only with the reviewed
Python investigator. Set its exact `GUILD_SANDBOX_QWEN_INTEGRATION` qualified name and
`GUILD_SANDBOX_QWEN_CREDENTIAL_ID` for the dedicated nonsecret public-demo marker.
Permit only that association, its bounded Qwen operation and `console_log` report
delivery; no publishing or extra service credentials. Follow the setup guide
for scopes, credential restrictions and version pinning. Legacy simulation Guild
raw-snapshot export is disabled; use the bounded Operations investigation path.

Create an API trigger for the installed investigator through Guild's workspace
UI. Set its complete `id:secret` in `GUILD_TRIGGER_API_KEY` and its separate trigger
record ID in `GUILD_TRIGGER_ID`. The backend uses Basic authentication on
`POST /workspaces/{owner}/{workspace}/sessions`, sending
`session_type: api_trigger` and a bounded `agent_input.text` envelope. Session reads
use the same key. No agent override or CLI/OAuth runtime fallback is used.
Trigger capability can cover the entire workspace, so keep it dedicated and free
of production credentials. These secrets never belong in the frontend.

Connections checks the account key independently of investigator configuration
and offers read-only workspace/agent/version discovery. The current live identity
contract exposes `permissions` objects; a missing `scopes` field is not missing
permissions. Authentication alone never verifies hosted execution. Discovery
does not publish an agent, install it, or silently select unrelated resources.
Environment/image fields apply only to legacy Goose protocol v1; v2 does not require
an environment template or filesystem-installed replay worker.

`GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED` defaults to false. Enable it only for the
approved bounded payload: public/synthetic effective prompts, source IDs/hashes,
canonical policy/action checks and canary cases. The v2 packet preserves up to four
already-sanitized source rows of 4,000 characters for request fidelity. Private
memory, operator mission, original draft bodies,
arbitrary destinations and credentials are excluded. The user's consent covers
this bounded payload, not unrestricted production data export.

Interlock captures the effective model request before inference and persists the
complete frozen experiment packet before dispatch. V2 runs original input, one-source
removal and neutral replacement twice each, at most six model calls. Old, private or
incompatible checkpoints become explicitly `reconstruction_not_exact` public inputs.
The controlled demo is not an exact observed attack, and the attack need not reproduce.
Independent memory is not supplied by this workload; memory-removal controls are N/A.

Pinned source/report verification, root `DONE` and API-confirmed automatic runtime
cleanup remain separate from container isolation attestation. A validated report with
confirmed cleanup finishes `review_required`; missing isolation/execution-attestation
flags stay false. Qwen's follow-up is advisory only, manual review remains required
and the agent stays contained. There is no product force-destroy API or automatic rerun.
The timeout is a polling deadline, not remote termination. A verified terminal root
with missing evidence fails as evidence-unavailable; an unverified terminal state
requires reconciliation because provider work may continue. End that exact session
in Guild when needed and do not blindly start another investigation.

The legacy Goose demo failed on a missing worker/hash mismatch; containment remained.
Qwen HTTP connectivity and 24 ClickHouse demo events were verified separately with
pending outbox count zero. The replacement Python agent is published and its mediated
Qwen operation returned `200`. A Python probe reached `DONE`, but the driver dropped
its `AIMessage`; direct `console_log` delivery, root binding and cleanup still await
verification. No end-to-end v2 success is claimed. CLI is setup/diagnostic tooling only;
application execution remains HTTP API-trigger based.

### ClickHouse

Provide `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_USERNAME`,
`CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DATABASE` and `CLICKHOUSE_SECURE`. For Cloud, use
the console's HTTPS connection details; defaults are port 8443, TLS enabled and
database `interlock`. For optional local ClickHouse, explicitly set port 8123 and
`CLICKHOUSE_SECURE=false`.
Use dedicated credentials and authorize the destination before enabling export.

Initialize the bundled schema in Connections, then inspect real queries and export
freshness. Background export retains failed batches in the SQLite outbox. Stable
event/batch IDs and a unique-event view reduce retry duplicates; no exactly-once
external-delivery guarantee is claimed. The optional local Compose setup in
`clickhouse/` is not required when using ClickHouse Cloud and is not the sandbox.
Export applies bounded redaction, not a general-purpose secret-removal guarantee;
do not ingest private production traces without reviewing that data policy.

### Slack MCP (optional, not a listed sponsor)

Prepare an eligible registered Slack app with its own user authorization and an
approved workspace/channel. Set the server-side `SLACK_MCP_ACCESS_TOKEN`, app,
workspace and channel IDs. A Codex Slack connection does not authorize this backend.

Discover the actual send tool in Connections, set its name/schema hash and only
then enable `SLACK_DELIVERY_ENABLED`. Definition drift blocks dispatch. The official
endpoint is `https://mcp.slack.com/mcp`; no fake response or Web API substitute is
used. Recorded incidents never send production messages. Ambiguous sends need
operator reconciliation. Full OAuth onboarding/token renewal UI is not implemented.

## Other sponsor documentation

All documentation links from the actual event page were reviewed; findings and
sources are in SPEC.md section 7.

- **Senso:** proposed, not implemented. Context-only retrieval can ground RCA in
  approved runbooks while retaining Akash Qwen. Use a restricted viewer key and an
  application-owned document/version approval registry, not trust tags alone.
- **Semgrep Guardian:** proposed code-artifact assessment, not a prompt-injection
  detector or sandbox. Our current research agent does not generate code. Its
  plugin can help development, but that is not automatically runtime sponsor use.
- **Pi:** the event explicitly says product/technology access is not provided.
- **AkashML:** docs read for comparison; not selected because your access is Console.

Akash hosting, ClickHouse and Guild are the intended three substantive integrations.
The event does not explicitly settle Console-only or build-time tool eligibility;
confirm those judging details with organizers. Do not count unconfigured adapters.

## First workflow

Open Operations and register a short mission with 1-4 approved public HTTPS sources.
The configured hostname allowlist is authoritative; redirects/private targets are
not followed. Keep intervals at least 60 seconds. Review brief citations and run
status, then use the labeled controlled incident to inspect containment/RCA flow.
The fixture is recorded, not an attempt to attack an external agent.

For the fastest containment demo, click **Run blocked-agent demo** in Operations.
Interlock creates a labeled recorded agent whose synthetic vendor input proposes
uploading an evidence bundle to an unauthorized external destination. The policy
boundary denies the capability before dispatch, contains the agent, quarantines
the implicated evidence and opens a frozen incident dossier. No external request
or real data transfer is performed.

The separate live scripted Qwen demo (`POST /api/operations/demo/live`) makes a real
completion under a fixed, deliberately compromised-agent prompt. Its synthetic marker
requests a fake canary proposal to `attacker.invalid`; the normal policy gate blocks
any forbidden proposal and queues investigation. The exact effective checkpoint is
retained for source-removal and neutral-replacement controls. This demonstrates
containment of intentional scripted behavior, not discovery of a Qwen vulnerability.
Refusal, invalid output or provider failure remains visible without a fabricated attack.

After a bound protocol-2 report, terminal root and verified runtime cleanup, successful
experiment observations produce an advisory investigation report in Briefs. Partial
results disclose failed counts; a bound all-error receipt produces an explicitly
incomplete status report with zero successful reruns and no established root cause. The
blocked proposal is never published, and the agent remains contained.

Resolve an incident with a reason, then explicitly resume the agent. Resolution
does not automatically unquarantine source memory or demonstrate safe recovery.
The current detector is deliberately narrow; authorization is the primary control.

## Layout

```text
app/api/                 Operator APIs and backend lifecycle
app/security/            Managed workload, scheduling, containment and RCA jobs
app/sandbox/             Guild-hosted session/runtime adapter
app/core/                Existing memory, ancestry and policy controls
app/storage/             SQLite, ClickHouse queries and durable export outbox
app/integrations/        Akash inference, Guild and official Slack MCP clients
app/dashboard/           Operations console and preserved inspectors
integrations/guild/      Investigator source and provisioning instructions
clickhouse/              SQL schema and optional local service
sim/fixtures/            Explicit synthetic report sources
scripts/dev.ps1          Local launcher
SPEC.md                  Product, security boundaries and sponsor research
```

Public hosting requires operator authentication/authorization, TLS and deployment
review. Loopback/Origin checks are local-console safeguards, not multi-user auth.
