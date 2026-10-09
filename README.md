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
- Asynchronous Guild sandbox integration, bounded diagnostic proposals and advisory
  RCA, with runtime evidence distinct from model-generated claims.
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

No local Docker daemon is needed for investigation. Prepare a dedicated private
workspace, a reviewed coding-agent environment and the pinned published investigator
under [integrations/guild](integrations/guild). Use a supported Guild inference provider
for its host agent; do not assume Guild routes a model alias to your Akash endpoint.
The backend uses your Akash Qwen to produce frozen typed diagnostic cases.

Set `GUILD_API_KEY` to the complete account `id:secret`, plus the exact
`GUILD_SANDBOX_WORKSPACE_ID`, `GUILD_SANDBOX_AGENT_ID`, installed version,
environment and image IDs from your account. Follow the investigator's setup guide
for scopes, credential restrictions and version pinning. Legacy simulation Guild
raw-snapshot export is disabled; use the bounded Operations investigation path.

Connections checks the account key independently of investigator configuration
and offers read-only workspace/agent/version discovery. The current live identity
contract exposes `permissions` objects; a missing `scopes` field is not missing
permissions. Authentication alone never verifies hosted execution. Discovery
does not publish an agent, install it, or silently select unrelated resources.
Set `GUILD_SANDBOX_ENVIRONMENT_ID` to the exact pinned runtime environment UUID;
its qualified display name is not evidence of that identity.

`GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED` defaults to false. Enable it only for the
approved bounded payload: public source excerpts, evidence IDs/hashes, canonical
policy/action checks and canary cases. Private memory, mission, draft bodies,
arbitrary destinations and credentials are excluded. The user's consent covers
this bounded payload, not unrestricted production data export.

A successful chat is not proof of a sandbox. Interlock records session/runtime IDs,
checks exclusive session ownership and validates replay observations. Missing or
ambiguous evidence remains unavailable/incomplete/uncertain. Guild results cannot
resume agents. Live hosted isolation still needs verification in your account.
The Goose recipe requests a fixed command but does not enforce a shell allowlist.
Do not treat its instructions as a security boundary. The public task API cannot
authenticate the exact worker command; such reports
remain incomplete rather than verified replay. The timeout is a polling deadline,
not remote termination: end the exact session in Guild UI if it expires, reconcile
its status/spend and do not blindly start another investigation.

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
