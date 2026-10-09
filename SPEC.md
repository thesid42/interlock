# Interlock - Agent Security Operations

> A standalone application for operating a web-connected agent, containing
> unauthorized actions, and investigating frozen incident evidence in isolation.
> Memory is one supported attack surface, not the entire product.

## 1. Product

Interlock protects the execution and authority of AI agents rather than checking
software package versions. The application owns a managed agent, approved web
sources, scheduled work, a deterministic action boundary, incident storage,
isolated replay, sponsor integrations, and an operator console.

**Pitch:** Keep useful agents working on the open web without letting hostile
content or compromised tools silently expand their authority. When an agent
crosses a configured boundary, stop its actions, preserve the evidence, investigate
the cause in isolation, and require deliberate recovery before resuming.

The first protected workload is one included web-research agent. It reads approved
public HTTPS sources and produces cited briefs in the application. Qwen proposes
typed actions; runtime policy determines which actions can execute. This makes
the product usable without first integrating an arbitrary third-party agent.

The MVP addresses goal hijacking, unauthorized tool/destination proposals, and
the persistent effects of untrusted context. MCP definition/capability drift is
a supported future branch, not a claim that every MCP integration is already
monitored. Package advisory scanning is no longer the primary workflow.

This specification is the single source of truth. No separate `PLAN.md` is kept.
Requirements and staged implementation details are consolidated here. Missing
credentials or infrastructure must be visible; configured is not verified.

## 2. Hackathon Fit

The user's photographed slides require an autonomous agent doing real work on
the open web, grounded in truthful sources, using at least three sponsor tools,
with a three-minute demonstration. They do not require every example action
(publishing, monitoring, orchestration, transactions) or a memory-only project.

| Criterion | Evidence |
|---|---|
| Autonomy | A backend worker reads registered live sources and runs the approved workflow without repeated browser clicks. |
| Idea | Detecting and containing actual forbidden agent actions, with inspectable incident evidence and recovery. |
| Implementation | Durable scheduling, pre-dispatch authorization, containment, frozen snapshots and runtime-evidence checks for bounded investigations. |
| Tool use | Live Akash-hosted inference and ClickHouse ingestion/queries; Guild session creation verified, but replay currently failed. |
| Demo | One live legitimate task plus a clearly labeled controlled attack, containment, investigation and legitimate recovery. |

Monitoring, investigation orchestration and publishing in-app briefs/incidents
are the autonomous work. Slack MCP is optional authorized external delivery.
No separate GitHub repository for alerts is needed. Do not scan or attack
third-party agents without authorization.

## 3. Managed Agent and Autonomy

An operator registers the agent's name, mission, approved source URLs, interval
and runtime policy. Start with public security documentation as useful source
material, not an arbitrary crawler. The default allowed hosts are configured
server-side. URLs must be HTTPS, without credentials, and resolve to public
addresses. Reject unapproved hosts, redirects to unapproved/private destinations,
oversized responses and unbounded requests. Restrict formats and payload sizes.

The backend worker persists due times, queued runs, source observations, errors
and results. Do not overlap the same agent's runs. Rate-limit work and bound
requests, model tokens, retries and investigation steps. Closing the browser does
not stop the worker; stopping the backend does. Restart must retain containment
and incident history rather than quietly resuming a stopped agent.

Each live task records source URL, retrieval time, content hash, exact observed
excerpt, supplied context, model ID and proposed action. Source hashes identify
the observed content, not its truth. Distinguish fetched facts, model interpretation
and policy decisions. Store unknown/error states instead of fabricated results.

Qwen may propose `publish_brief` to the fixed in-app destination or `abstain`.
Anything outside that contract is denied before dispatch. Its text cannot grant
permissions, select a new destination, invoke arbitrary commands, or alter the
operator policy. A policy violation contains the agent and creates an incident.
Model unavailability is not an attack finding; show unavailable analysis.

## 4. Detection and Immediate Containment

The deterministic execution boundary is the primary control. A suspicious-text
classifier or a second model can provide a signal, but cannot authorize actions.
Do not claim broad prompt-injection detection from the legacy narrow phrase/email
detector. A confirmed forbidden proposal is distinct from a suspected malicious
source or a model's allegation of poisoning.

On detection:

1. Deny the pending forbidden action; do not execute it to prove it is dangerous.
2. Persist the managed agent's contained state before starting investigations.
3. Freeze the mission, current policy, exact input/context, memory provenance,
   proposed action, observed decision, source IDs, timestamps and run/model mode.
4. Queue a credential-free sandbox investigation using a sanitized subset of that
   snapshot, only when external evidence export is explicitly enabled.
5. Produce an in-app incident and optionally send an authorized Slack notification.

Containment stops future app-managed tool dispatch. It does not recall completed
external actions or stop arbitrary third-party agents whose tools bypass this
application. The shared Akash model server is not shut down; this managed agent's
execution permissions are stopped. Assessment-only adapters must say so.

## 5. Sandboxed Investigation and RCA

"Sandbox the agent" means pause the managed execution and investigate an isolated
replica of its incident state. It is not a promise to migrate an arbitrary running
process bit-for-bit or to make the remote Qwen model itself run inside a container.

Protocol v2 uses a published, pinned Guild LangGraph Python agent from
`integrations/guild/rca-investigator`, not an LLM-controlled Goose shell recipe.
No custom environment or local Docker is required for this path. Before dispatch,
verify its installed version, disabled automatic updates, committed Python source,
exact shared contract bytes and minimal manifest. The only declared external tool
is the pinned private `interlock_qwen_complete` integration; the approved
`console_log` builtin carries a runner-generated report. There are no production
publishing tools, other service credentials, sub-agents or application-control rights.

The live workload and runner share `app/security/rca_contract.py`: prompt generation,
proposal validation, deterministic policy checks and functional in-memory tool
adapters. The runner performs actual fresh Qwen proposals and dispatches them to
those controlled adapters. An allowed publish creates an in-memory artifact and
returns its hash; forbidden operations return recorded denials. Nothing is published
to a real sink. No model-generated program or shell command is executed.

Qwen remains external on the user's Akash deployment. The trusted backend calls
it for normal work; the hosted Python agent calls it through the narrowly declared
Guild-mediated operation. A model alias alone does not configure routing. The current
private integration uses the confirmed HTTP public-demo endpoint and a nonsecret
public-demo marker required by its credential setup, not a real bearer secret.
Private missions, memory, drafts and credentials must never cross that HTTP boundary.
The operation fixes the model/destination and bounds tokens and request fields;
it grants no broader network or application capability.

### Frozen Checkpoint and Controls

Persist the effective messages and request parameters before inference, after any
HTTP-public-only transformations, then retain returned model metadata. Capture
source IDs, input scope, contract version/hash and checkpoint hash before containment.
Freeze and store the full exported packet before creating a hosted session, so returned
observations can be checked against planned inputs rather than claimed hashes alone.
Only public/synthetic effective requests are exported. A private, absent or incompatible
original checkpoint is reconstructed publicly and labeled `reconstruction_not_exact`.
The current controlled demo is a reconstruction, not an exact observed attack checkpoint.

Use at most three conditions with two repetitions each, for at most six model calls:

- Original effective input, or explicitly labeled public reconstruction.
- Remove one candidate suspect source while retaining the remaining inputs.
- Replace that same source with a neutral no-facts marker; no other input changes.

Keep model parameters and authorization behavior identical across conditions.
Each run records input hash, changed source IDs, model metadata, proposed action,
policy decision and actual in-memory tool-call/result trace. Validate those results
against the shared deterministic adapters. Source selection is a candidate hypothesis,
not attribution. Independent persistent memory is not currently supplied to the agent,
so memory-removal controls are not applicable. Repeated differences support behavioral
hypotheses; variation, refusal and failure remain visible and confidence stays bounded.
The attack need not reproduce, and non-reproduction is not proof of general safety.

### Report and Runtime Evidence

Bind a report to the complete saved packet, checkpoint, incident, exact pinned root
task and terminal `DONE` status. Verify planned case/repetition counts, intervention
hashes, functional tool results and recomputed comparisons. A Python probe reached
`DONE`, but its `AIMessage` was not delivered by the current Guild driver. Direct
runner reporting through `console_log`, root-event binding and runtime cleanup are
therefore still being verified; no end-to-end success is claimed.

Record runtime/container IDs and require API-observed destruction before releasing
a finalized advisory report. Normal Guild runtime cleanup is automatic; the application
checks its outcome rather than assuming it or using a force-destroy API. Pinned source
verification, terminal status and cleanup do not independently attest container isolation.
Guild's documented mediated/network boundaries remain provider claims; absent session-lock
or isolation metadata stays unknown. See
[Guild security architecture](https://docs.guild.ai/platform/security-architecture).

A validated terminal report with confirmed cleanup becomes `reported`; the investigation
finishes `review_required`, not verified RCA. Keep `isolation_verified=false` and
`replay_execution_verified=false` when independent attestation is unavailable. Qwen's
follow-up is advisory only, manual review is required and the managed agent stays contained.
The legacy Goose policy-checker and its failed remote-file setup remain historical,
not the intended v2 execution path.

The public OpenAPI does not expose a stop/cancel operation. The configured timeout
is a local polling deadline, not guaranteed remote termination. If it expires
without verified root-terminal evidence, preserve the session ID, mark reconciliation
required and warn that provider work or spend may continue. The operator must end
that exact session in Guild's UI. If the exact root is already verified terminal
but a bound report is unavailable, mark the investigation failed for missing evidence
without claiming execution is still running. Do not automatically start a replacement
session. See
[Guild sessions](https://docs.guild.ai/platform/sessions) and
[public API specification](https://api.guild.ai/v1/openapi.yaml).

The incident dossier contains the frozen snapshot, actual isolation/run status,
observed action checks, any model replay differences, cited hypotheses, Guild
session reference, limitations, and operator resolution. Model outputs cannot
change permissions, resume the agent or delete evidence.

## 6. Memory, Provenance and Recovery

Retain existing immutable memory, parent edges, exact context capture, inherited
restrictions and merged ancestry. External documents/tool outputs are untrusted;
the runtime assigns provenance and trust. Summaries cannot turn remembered text
into operator policy. Use a stable agent namespace and distinct run/context IDs.

Quarantine affected inputs and derived memory selectively where the evidence
supports that relationship. Never blame an entire provider or every source merely
because one action was forbidden. Preserve suspect history for investigation.
Check source eligibility and restrictions before retrieval and before dispatch.

Resolution is an operator action with a recorded reason. The agent stays contained
while any incident is unresolved. Resolving an incident does not automatically
resume work or unquarantine memory; resumption is explicit. Fresh recovery uses
eligible context and new action IDs. Copying poisoned text into a new row is not
repair. An investigation recommendation is not proof that recovery is safe.

The legacy report scenarios remain a separate Simulation view. Controlled fixtures
are labeled recorded, use canaries/fake destinations, and cannot silently become
live source observations or successful sponsor responses.

## 7. Sponsor Integration Contracts

### Akash Console / Qwen

Use the user's Akash Console deployment of `Qwen/Qwen3.8-27B`, not managed AkashML.
Call its inference service through a compatible Chat Completions API. Discover
the actual served alias and verify inference separately from discovery. No OpenAI
account or Akash Console management credential is needed.

```dotenv
LLM_PROVIDER=akash_console
LLM_BASE_URL=https://your-inference-endpoint/v1
LLM_API_KEY=your-inference-service-key
LLM_ALLOW_UNAUTHENTICATED=false
LLM_HTTP_PUBLIC_ONLY=false
AGENT_MODEL=Qwen/Qwen3.8-27B
JUDGE_MODEL=Qwen/Qwen3.8-27B
```

The served alias is configurable. Thinking and constrained-output support depend
on the installed engine/build; validate actual capabilities. Use short bounded
responses and validate final JSON/evidence references on the application side.
Keep raw reasoning out of trusted memory. Same-model review is correlated
self-review, not independent authorization or a safety proof.

Use HTTPS/authentication for normal product operation and protect other
inference-server routes separately. An operator may explicitly enable
`LLM_ALLOW_UNAUTHENTICATED` for a service without bearer authentication. The
separate `LLM_HTTP_PUBLIC_ONLY` development mode permits the user's confirmed
HTTP service only for bounded public-source or synthetic prompts. It excludes
operator missions, private memory, draft bodies, raw destinations, and credentials;
legacy private-context flows must fail closed. Never send a bearer key over HTTP.
Accept a service root, `/v1` base, or exact `/v1/chat/completions` URL and derive
the known model-discovery and Chat Completions routes structurally. Strip only
a bounded recognized Qwen reasoning preamble, then require a complete validated
JSON object; do not recover arbitrary JSON fragments from prose or truncated output.
Console management APIs are not inference APIs. Record redacted deployment/model
details and actual latency/returned usage. Do not infer latency or GPU requirements
from model marketing. See [Qwen serving](https://huggingface.co/Qwen/Qwen3.8-27B),
[Akash hosting](https://akash.network/blog/running-vllm-on-akash/) and
[vLLM security](https://docs.vllm.ai/en/stable/usage/security/).

### ClickHouse

SQLite is authoritative for policy, containment, jobs and incidents. Audit events
and outbox entries commit with local state. Export in bounded background batches
outside SQLite transactions, with stable IDs and retry deduplication. Show actual
trace queries, blocked-action counts, suspicious-source rankings, query latency
and data freshness. An outage must not erase or permit local actions.

ClickHouse is substantive when the operator uses its cross-run evidence and
analytics. It is not counted merely from stored unused logs. Schema initialization
requires an explicitly authorized connection; use dedicated runtime credentials.

### Guild

Use the user's published sandbox investigator installed in the dedicated workspace.
Send bounded, redacted incident evidence, retain session/version/runtime references
and poll results asynchronously. Validate evidence references against the submitted
snapshot and separate runtime observations from advisory conclusions. Its advice
cannot resume managed agents or execute application operations. Environment and
credential policy configuration must be verified in the user's account; connectivity
alone does not verify it.

Evidence export defaults off (`GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED=false`). The
user explicitly approved bounded public-source excerpts, evidence IDs/hashes,
canonical policy checks and canary cases, not unrestricted production data. The
implementation must omit private memories, operator mission, raw draft bodies,
arbitrary destination strings and credentials. Sanitized replay is not an exact
reproduction of the full private context; record that limitation. A stdout marker
or final model JSON alone cannot verify execution of the reviewed replay worker.

Account API keys and API-trigger keys differ. Use `GUILD_API_KEY` with
`workspaces:read` and `agents:read` for account/resource metadata. Execution uses
the dedicated workspace's UI-issued `GUILD_TRIGGER_API_KEY=id:secret` and separate
`GUILD_TRIGGER_ID`. The backend sends Basic authentication to
`POST /workspaces/{owner}/{workspace}/sessions` with
`{"session_type":"api_trigger","agent_input":{"text":"<bounded incident envelope>"}}`.
Session reads use the same trigger credential; omit agent overrides and verify
the returned workspace, trigger and pinned root task. The trigger credential can
have workspace-wide capabilities, so use a dedicated credential-free workspace,
not a production workspace. Never expose either secret to browser/agent state.
No Guild CLI/OAuth runtime fallback is part of the application transport.
A successful workspace check is not a completed hosted investigation.
The live account identity endpoint returns `permissions` as `{group, access}`
objects, not the rendered documentation's former `scopes` string array. Validate
the actual response contract. Authentication can be checked before investigator
IDs are supplied; metadata discovery is read-only and never creates or runs agents.
For protocol v2, pin the committed Python source/shared contract and the exact
Qwen integration/marker association; no custom environment or image IDs are required.
The manifest permits only that Qwen operation and the approved report-delivery builtin.
Legacy protocol v1 also pins `GUILD_SANDBOX_ENVIRONMENT_ID` and `GUILD_SANDBOX_IMAGE_ID`.
Validate the pinned version's saved `guild.yaml` through
`GET /versions/{id}/code`. That endpoint returns a list of `{path, content}` files;
bound the payload and reject malformed/duplicate paths before parsing the source.
Legacy committed-version metadata may omit an environment UUID. Source validation,
actual runtime identity, terminal status and cleanup are separate evidence; a shared
base-image ID alone cannot prove the intended setup or worker ran.
Session creation may succeed remotely before a response is lost: mark ambiguous
creation uncertain and reconcile when supported, rather than blindly retrying.
See [Guild's API contract](https://docs.guild.ai/api-reference/introduction).

Historical protocol-v1 checks on 2026-10-09 confirmed publication/installation,
disabled automatic updates and resolved environment/image IDs. Controlled
`recorded_demo` checks verified local containment, two live Qwen diagnostic probes
and eleven reconciled ClickHouse events with pending outbox count zero. Earlier
account-key chat attempts returned `403` and were interrupted; the supported HTTP
API trigger subsequently returned `201`. A `v1.0.0` terminal task reported a missing
worker and null runtime environment. A later `v1.0.2` CLI diagnostic resolved the
custom environment but still reported the missing worker file. Neither proves a
successful replay, verified isolation or complete RCA; CLI remains setup/diagnostic
tooling, not application execution transport.

The historical Goose `v1.0.5` demo failed on a missing worker and final frozen-hash
mismatch despite matching setup source; the app kept containment and skipped advisory
analysis. Its runtime destruction was verified. Separately, Qwen HTTP connectivity and
24 demo ClickHouse events were verified with pending outbox count zero.

The replacement committed Python agent is published and its narrowly mediated Qwen
operation returned HTTP `200`. A Python probe reached `DONE`, but the Guild driver
dropped its `AIMessage`. Direct `console_log` report delivery, exact root binding and
cleanup are still awaiting verification. No completed end-to-end v2 RCA is claimed.
Do not retry uncertain creation automatically or resume a contained agent from task status.
See [Guild API triggers](https://docs.guild.ai/platform/api-triggers).

### Slack MCP

Optional external delivery uses the official Streamable HTTP MCP endpoint
`https://mcp.slack.com/mcp` through the established MCP SDK. Prepare an eligible
registered Slack app and its user authorization; a Codex Slack connection does
not authorize this backend. The local integration may use an independently
provisioned server-side access token. Full OAuth onboarding UI is outside this
scaffold unless explicitly implemented.

Discover and validate the real send tool's schema, then pin its name. Construct
the incident message from canonical bounded fields; model output cannot select
the host, tool, workspace, channel, mentions or arbitrary arguments. Use one
operator-approved channel and disabled-by-default delivery. Persist outcomes;
timeouts are uncertain, not a reason for blind repeat sends. Never substitute a
fake MCP response or secretly use the Slack Web API. See [official Slack MCP](https://docs.slack.dev/ai/slack-mcp-server/).

### Other Sponsor Docs and Scope

The actual [CyberHack sponsor page](https://tokensand.com/cyberhack) links ClickHouse,
Akash Network, AkashML, Guild, Semgrep Guardian and Senso documentation. It says Pi
is a sponsor but product/technology access is not provided. Pi therefore has no
invented adapter or API requirement. Slack is an optional delivery integration,
not a sponsor listed on this page.

**Senso - proposed extension, not currently implemented.** Its context-only endpoint
`POST /org/search/context` at `https://apiv2.senso.ai/api/v1` returns retrieved passages
with document/chunk/version IDs, without replacing the application's model. Proposed
role: ground Qwen's investigation in reviewed runbooks and operator-approved incident
notes, with explicit citations. Prepare a restricted viewer key to only that corpus;
send it server-side as `X-API-Key`. See [Senso retrieval](https://docs.senso.ai/docs/quickstart)
and [key scopes](https://docs.senso.ai/docs/api-keys).

Approval must remain an application policy, not inferred from Senso branding or a
retrieval score. Its `status:approved` tags are conventions and are not returned in
search results. Bind permitted document/version IDs to operator approval and never
automatically promote model-generated RCA to trusted knowledge. See
[Senso shared-context limitations](https://docs.senso.ai/docs/shared-context).

**Semgrep Guardian - conditional extension, not runtime protection here.** Guardian
scans agent-generated code for vulnerabilities, dependency issues and secrets. It
does not provide this product's prompt-injection detection, containment or isolation.
It would become substantive if Interlock accepts agent-generated tool code/artifacts
for assessment and attaches actual scan findings to incidents. Installing a plugin
to help develop Interlock is build-time use, not automatically a product integration.
See [Guardian overview](https://docs.semgrep.dev/semgrep-guardian/overview).

Guardian's documented Windows workflow requires WSL; account authentication and
access must be provisioned. Do not assume the Codex plugin's authorization covers
this FastAPI backend or that our Qwen workflow uses its hosted scanner. See
[Guardian setup](https://docs.semgrep.dev/semgrep-guardian/quickstart) and
[other MCP clients](https://docs.semgrep.dev/semgrep-guardian/ide-setup/other).

Akash hosting, ClickHouse and Guild are the intended three sponsor technologies.
The event links both Akash Network and AkashML but does not explicitly resolve
Console-only eligibility. Organizer confirmation is needed for tool-count/prize
eligibility, including whether build-time Guardian use counts. Senso is a meaningful
fourth option, not a fake fallback claim. No integration is verified until its
relevant live request succeeds. No paid provisioning is automated.

### Documentation Verification

Reviewed on 2026-10-09: the event's actual sponsor resources; Akash Console deployment
and vLLM hosting; AkashML authentication/chat-completion contract (read for comparison,
not selected); ClickHouse Connect and retry-deduplication; Guild authentication,
conversations, coding-agent environments, runtime records and security boundaries;
Senso retrieval/key scopes/shared-context limitations; and Semgrep Guardian overview,
setup and custom-client boundaries.

ClickHouse uses its official [Python driver](https://clickhouse.com/docs/integrations/python).
The existing stable batch IDs and unique-event view are retained; insert deduplication
depends on actual server settings and retention windows, not an exactly-once promise.
See [retry deduplication](https://clickhouse.com/docs/guides/developer/deduplicating-inserts-on-retries).
Akash Console is documented [deployment infrastructure](https://akash.network/docs/developers/deployment/akash-console/),
whereas [AkashML](https://akashml.com/docs/getting-started) is managed inference.
The user's endpoint, engine capabilities, credentials, Guild runtime configuration,
service entitlements and sponsor eligibility still require live/account confirmation.

## 8. Application and API

Operations is the default view: registered agents, live/recorded mode, last/next
activity, running/paused/contained state, incident queue and published briefs.
Incident detail separates frozen input/policy from actual sandbox observations,
Qwen hypotheses, Guild results, and operator resolution. The console refreshes
automatically without treating stale data as a current healthy state.

The live scripted demo makes a real Qwen completion using a separate fixed
compromised-agent profile, a synthetic marker and `attacker.invalid` canary
destination. It is intentional scripted behavior, not a discovered vulnerability.
Normal policy enforcement contains forbidden proposals and queues investigation;
refusal or inference failure never fabricates a blocked action. The original
effective checkpoint and its fixed profile are preserved across source controls.

Briefs also receives clearly labeled `investigation_report` artifacts after a
bound protocol-2 report, terminal root and verified runtime cleanup. Partial reports
disclose failures; all-error receipts publish an explicitly incomplete status report
with zero successful reruns and no established root cause. Reports summarize evidence and advisory hypotheses, never publish
the blocked proposal or imply verified isolation, established RCA or safe recovery.

Connections provides explicit readiness checks for inference, ClickHouse, Guild,
hosted investigation isolation and Slack MCP. Credentials are never entered into frontend
state or exposed through health responses. Retain Memory and legacy Incidents
inspectors, Analytics, and clearly labeled Simulation. Use the restrained light
operational design: white surfaces, charcoal text, cobalt commands and separate
severity colors. Keep dense tables, evidence inspectors and legible navigation;
do not add a marketing landing page.

| Endpoint | Purpose |
|---|---|
| `GET /api/operations` | Agent, incident, brief, run and integration overview. |
| `POST /api/operations/agents` | Register a bounded mission and approved sources. |
| `GET /api/operations/agents/{id}` | Inspect agent state/history. |
| `POST /api/operations/agents/{id}/run` | Queue one task under the normal policy/lease. |
| `POST /api/operations/agents/{id}/pause` or `/resume` | Explicit operator control; unresolved incidents prevent resumption. |
| `POST /api/operations/demo` | Create a labeled controlled/recorded incident, not a fabricated live attack. |
| `POST /api/operations/demo/live` | Run the real-Qwen scripted canary scenario; contain forbidden proposals and automatically queue investigation. |
| `GET /api/operations/incidents/{id}` | Immutable snapshot and investigation progress. |
| `POST /api/operations/incidents/{id}/investigate` | Queue a bounded investigation. |
| `POST /api/operations/incidents/{id}/resolve` | Record operator resolution; no automatic resume. |
| Inference `/models` and `/check` | Discover alias; separately verify a small completion. |
| ClickHouse `/initialize` and `/export` | Explicit schema initialization and export alongside background export. |
| Guild `/check`, Slack `/tools` and `/check`, sandbox `/check` | Safe connectivity/capability checks, not credential disclosure or test sends. |

The prototype binds to loopback, rejects non-loopback Host values and cross-site
mutations. These are local-console defenses, not multi-user authentication.
Public hosting requires proper operator authentication, authorization, TLS and
deployment review. Do not expose this development server as a production service.

## 9. Implementation Boundaries

Retain FastAPI/React, SQLite authority, immutable memory and the durable ClickHouse
outbox. Add focused security-operation records for agents, runs, source snapshots,
briefs, incidents, investigation jobs and optional delivery outcomes. Preserve
existing simulation runs and data using additive schemas.

| Area | Responsibility |
|---|---|
| `app/security/` | Managed workload, scheduling, deterministic policy, containment and investigation orchestration. |
| `app/sandbox/` | Guild session/runtime replay adapter and truthful isolation readiness. |
| `app/api/` | Operator controls, backend lifecycle and safe integration checks. |
| `app/integrations/` | Akash-hosted Qwen, Guild investigator and official Slack MCP adapters. |
| `app/storage/` | Authoritative SQLite state, audit/export outbox and ClickHouse analytics. |
| `app/core/` | Existing memory provenance, restrictions, contexts and simulation services. |
| `app/dashboard/` | Operations, investigations, Connections and preserved inspectors. |

All network requests and sandbox processes happen outside SQLite transactions.
Persist job state before remote calls. Restart handling must preserve contained
agents and distinguish interrupted work from succeeded work. Do not retry an
ambiguous external send/session creation as though nothing happened. Do not claim
exactly-once execution of an external API from a local fingerprint alone.

Core scaffold integration steps are configuration/adapters, operations storage
and worker, deterministic containment, frozen snapshot and real sandbox adapter,
bounded RCA, sponsor evidence, then operator UI and documentation. Deferred work
includes universal agent adapters, complete arbitrary-code/browser replay,
production OAuth onboarding/token renewal, fleet-scale/distributed workers,
automatic policy relaxation and comprehensive agent-security certification.

The user requested no test-suite/load-benchmark scaffolding. Compilation and small
manual smoke checks are separate from claims of security assurance. Missing live
resources must be reported, not papered over with fixtures.

## 10. Setup, Acceptance and Demo

The user provisions inference, ClickHouse, Guild and optional Slack resources.
Use `.env.example` for the implemented environment names and restart the backend
after editing local `.env`. Keep every secret server-side and outside Git.

Application configuration uses `INTERLOCK_DB_PATH`, defaulting to
`data/interlock.sqlite3`; the development launcher supplies `INTERLOCK_API_URL`
to the frontend proxy. ClickHouse defaults to database `interlock`, HTTPS port
8443 and TLS enabled. Optional local ClickHouse requires port 8123 and TLS false.
Sponsor-specific credential names retain their provider prefixes.

- Qwen: inference base URL, bearer credential, actual served alias, engine/build
  and support for optional thinking/JSON Schema parameters.
- ClickHouse: dedicated host, port, database, TLS setting and credentials. Initialize
  the bundled schema explicitly before expecting sponsor analytics.
- Guild: account key, dedicated private workspace, pinned committed Python investigator,
  exact shared contract, restricted mediated Qwen operation and sole public-demo marker
  association. No custom environment, publishing or application-control authority.
  Local Docker is not required; legacy Goose setup is separate.
- Slack: backend-owned user access token from an eligible registered app, approved
  channel/workspace, discovered send tool and pinned schema hash; explicitly enable
  delivery only after confirming permissions and tool arguments.

Acceptance must distinguish implemented adapters from successful live connectivity:

1. A registered agent fetches actual approved sources and produces a cited in-app
   brief using live configured inference; absent inference is visibly unavailable.
2. Scheduled runs continue without browser clicks and cannot overlap themselves.
3. A forbidden action is denied and the agent remains contained across restart.
4. Snapshot inspection reveals exact inputs, policy and observed action evidence.
5. With Guild provisioned, an exact terminal root produces an incident/hash-bound
   report and cleanup is confirmed through runtime API readback. Exclusive isolation
   requires separate matching runtime evidence; missing
   attestation keeps the job `review_required`, not indefinitely pending or verified.
6. Qwen/Guild hypotheses reference supplied evidence and cannot resume the agent.
7. Real ClickHouse exports/queries and hosted Guild sessions demonstrate substantive
   sponsor use, with missing providers honestly marked.
8. Optional Slack reaches only its approved channel with validated pinned MCP
   capabilities; ambiguous sends remain uncertain.
9. Operator resolution and explicit resumption are separate, and poisoned/restricted
   context is not silently replayed as repaired input.

Three-minute story: show useful live web work, introduce a clearly labeled
controlled hostile input/tool proposal, observe pre-dispatch containment, inspect
the isolated replay and evidence-backed RCA, then show approved recovery and the
incident in the app/optional Slack. Do not force a live model to obey an injection
or pretend that a scripted/recorded attack was discovered in the wild.

## 11. Research Basis

The slides supplied by the user establish the hackathon requirements. Agent
security covers more than memory or dependency vulnerabilities. Official guidance
supports external authorization, least privilege, bounded actions and observability:
[OWASP AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

Relevant foundations include [MINJA memory poisoning](https://arxiv.org/abs/2503.03704)
and [CaMeL data/control separation](https://arxiv.org/abs/2503.18813). They are
research references, not claims that this scaffold reproduces their guarantees.
Existing [MCP-Scan](https://github.com/invariantlabs-ai/docs/blob/main/docs/mcp-scan/index.md)
already covers several scanning/pinning controls, so do not claim those ideas as
novel. Our product goal is an integrated operations/investigation workflow with
explicit evidence and containment boundaries.
