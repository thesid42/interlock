# Guild Hosted Investigation

Guild owns the incident investigation runtime. Interlock does not run a local
Docker sandbox and does not silently substitute one. Its dedicated investigator
is installed with automatic updates disabled. Environment and image record IDs
come from actual Guild metadata, not names or Docker tags. The HTTP API trigger
has returned `201`; successful session creation is not successful replay or RCA.
The fixed-path worker recipe is published, installed and pinned as `v1.0.5`, confirmed
through CLI readback. Its actual end-to-end demo failed; no valid worker report was
accepted. See Integration Status below for the observed failures.

## Prepare The Runtime

1. Create a dedicated private Guild workspace for incident investigations. Set
   `restrict_account_credentials=true`. Do not grant or connect service
   credentials to its investigator. Leave workspace context and variables free
   of production secrets, private memory and publishing permissions.
2. Create a private runtime environment named `interlock-incident` using
   the documented Goose base image `guildai~goosebox`. The image must provide
   Bash and Python 3. Use `incident-investigator/environment_setup.sh` as its setup
   script. It checks Python, verifies the reviewed worker hash and runs a synthetic
   self-check before atomically installing `/tmp/interlock/replay.py` with mode
   `0444` inside a mode `0755` directory. It requires no particular runtime home.
   Apply the updated script, Save, run Test setup and inspect the logs. A passing
   setup check alone does not attest a later incident runtime or replay.
3. Set its qualified `<owner>~interlock-incident` reference in
   `incident-investigator/guild.yaml`. Publish
   `recipe.yaml` and `guild.yaml` as a Goose agent, install its reviewed version
   in the dedicated workspace and disable automatic updates. Do not add service
   integrations, sub-agents or platform mutation tools.
4. Create an account API key with `workspaces:read` and `agents:read` for metadata
   in `GUILD_API_KEY`. In the dedicated workspace's Guild UI, create an API trigger
   for its installed investigator. Set the separate complete `id:secret` trigger
   credential in `GUILD_TRIGGER_API_KEY` and its trigger record ID in
   `GUILD_TRIGGER_ID`. These are server-side secrets, never browser/agent variables.
   Trigger credentials can have workspace-wide capabilities; pinning an ID in
   Interlock does not narrow the credential itself. Do not reuse a production
   workspace. The deployed runner
   uses Guild's own configured model. Akash-hosted Qwen proposals are generated
   separately by the Interlock backend; Guild does not automatically route
   `task.llm` to that custom inference URL.
5. Configure `GUILD_SANDBOX_WORKSPACE_ID`, `GUILD_SANDBOX_AGENT_ID`,
   `GUILD_SANDBOX_AGENT_VERSION_ID`, `GUILD_SANDBOX_ENVIRONMENT`,
   `GUILD_SANDBOX_ENVIRONMENT_ID` and `GUILD_SANDBOX_IMAGE_ID` in the local
   environment. Resolve the environment UUID through Guild's actual environment
   metadata and its image ID through the actual image record. Do not expect
   `GET /versions/{id}` to expose `runtime_environment_id`: the live published
   version response omits it. Read the pinned version's saved `guild.yaml` instead
   and validate its qualified environment declaration. A later session runtime
   must independently match the configured environment UUID and image record ID.
   The qualified name is a source declaration, not runtime attestation.
6. Enable `GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED=true` only after reviewing the
   export boundary. It is intentionally false in the template. No hosted
   investigation session is started while it is false.

The reviewed setup script installs the worker at `/tmp/interlock/replay.py` only
after verifying SHA-256
`d9032c6b242afd05454b670da010fe068e737a9e4cfdc4b2cd69b007dbcf8937`.
Interlock also checks its trusted local `incident-investigator/replay.py` source
hash. Each incident request sends only a short fixed `python3 -I -B -c` bootstrap
that reads the installed path, verifies the hash and executes those bytes. It does
not send the full worker code for Goose to transcribe. Evidence is a separate
`--base64` argument, never Python source. The worker uses fake publish/deny canaries,
makes no external calls and performs no filesystem writes. No runtime-home path,
downloaded code or privilege escalation is needed. Python's isolation flags are not
container attestation, and base64 is encoding, not encryption or a security boundary.

Setup uses Python's standard library for the hash and synthetic no-external-effect
checks, atomic installation and installed-byte readback. It prints `setup_complete`
only after these checks; failure output includes the stage, not credentials.
Setup never consumes suspect incident data. Changing the reviewed worker requires
an explicit source/hash/recipe review rather than model-generated replacement code.
Read-only file mode is not immutability: a user able to write its parent directory
can replace the file. Hash checking and setup readback do not attest task execution.

The Goose recipe requests fixed worker execution but does not enforce a command
allowlist. A model can still propose other shell commands. Real isolation and
credential restrictions must come from Guild's runtime and account policies,
not these prompt instructions. Stronger command guarantees require a documented
deterministic hosted tool contract, which is not implemented by this recipe.

## Evidence Boundary

The backend uses Guild's HTTPS API-trigger interface, not CLI execution or an
account-key chat request. It sends Basic authentication using the separate trigger
`id:secret` credential and creates a session on the metadata-verified named route:

```text
POST /workspaces/{owner}/{workspace}/sessions
{"session_type":"api_trigger","agent_input":{"text":"<bounded incident envelope>"}}
```

Session reads use the same trigger credential. The request omits an agent override;
the installed investigator and returned workspace/trigger/root-version bindings
are checked independently. API-trigger capability can cover the whole workspace,
so the workspace must remain dedicated and credential-free. The product does not
invoke Guild CLI/OAuth execution or silently fall back to it.

The exported packet contains at most four approved public HTTPS source excerpts
of 512 characters each, source IDs/hashes, canonical app-owned policy, and at
most three typed diagnostic cases. A labeled recorded canary source is allowed
only in recorded demonstrations. Private memories, missions, draft titles and
bodies, arbitrary destination strings and credentials are omitted. Local frozen
evidence remains unchanged; the exported packet has its own snapshot hash.

Before dispatch, Interlock verifies the committed installed version, disabled
automatic updates, workspace credential policy and absence of attached service
credentials. It reads that exact version's saved files using
`GET /versions/{id}/code`: the public response is a list of `{path, content}`
records, not a JSON object keyed by filename. The adapter bounds and validates
the list, rejects duplicate paths, and parses the pinned `guild.yaml` environment
declaration. Saved source validation does not establish which runtime executed.

An actual session record is not proof of isolation. Interlock separately reads
Guild runtime and task metadata and checks the workspace, session lock, exact
environment UUID, image record ID, and executed pinned agent version.
Workspace-shared or mismatched runtimes remain
unverified. A report must belong to the unique matching root task, not a child
task, and that root must have documented status `DONE`. Remote terminal status
is recorded independently using `DONE`, `ERROR` or `INTERRUPTED`. Ambiguous
tasks never authorize an automatic replacement session. Guild documents network-isolated coding containers with mediated
egress and server-side credentials; setup still has network access.
Runtime `created_by` matching the root task is provenance only; it does not replace
an actual `locked_for_session_id` match or establish exclusive isolation.

The public task API does not authenticate an exact worker command. An event from
the exact pinned root task with status `DONE` can supply a `reported` result when
its incident ID, snapshot hash and bounded observations match the submitted packet.
Missing environment or session-lock attestation does not leave that valid report
pending indefinitely: the investigation finishes `review_required`, with the missing
`isolation_verified` evidence false and `replay_execution_verified=false`.
Qwen's follow-up remains advisory and carries those limitations. Manual review is
required and the managed agent stays contained. A stdout marker
or a model claim cannot attest worker execution or complete RCA. Stronger execution
verification needs a documented deterministic runner or evidence contract.

A successful bounded integration check proves only the stages recorded in its
result: authentication, publication/installation binding, session creation,
reported output, terminal status and runtime metadata must remain distinct.
Do not turn publication success, a passing setup control or one model reply into
"RCA complete".

## Integration Status

The controlled `recorded_demo` path on 2026-10-09 showed:

- Successful local containment and two completed live Qwen diagnostic probes.
- Eleven real audit events visible in ClickHouse after reconciliation: ten
  original run events plus `security_hosted_session_reconciled`. Pending outbox
  count remained zero at the final check.
- Earlier account-key chat requests returned HTTP `403`. Their two sessions were
  subsequently interrupted; these requests are not the supported product transport.

A genuine HTTP API-trigger request returned `201` for the configured workspace
and trigger. Its pinned `v1.0.0` root reached `DONE`, but reported a missing runtime
worker and null environment metadata. A later `v1.0.2` CLI diagnostic resolved the
custom environment but still reported the missing file. These are troubleshooting
observations, not verified replay or RCA; CLI remains setup/diagnostic tooling, not
the application's runtime transport.

An inline-worker attempt failed after Goose altered the static command. The current
fixed-path recipe is published, installed and pinned as `v1.0.5`, version UUID
`01a122bc-4340-cf83-0000-dfe1ad80c828`, with automatic updates disabled, confirmed
through CLI readback. Remote setup-script content matches the reviewed local script.
The actual demo session `01a122bd-409f-f9c4-0000-f3f6ff6bcb91` failed. Its first
recorded Goose shell attempt raised `FileNotFoundError` for `/tmp/interlock/replay.py`
despite correct CLI runtime-environment metadata. Its final reply failed with
`Frozen diagnostic hash did not match`; it was not a valid worker report. Public
API readback confirmed the exact pinned root `DONE` at `22:17:54Z` and runtime
`DESTROYED` at `22:18:24Z`. The app marked the investigation failed, kept the agent
contained and did not run Qwen advisory analysis. Qwen's HTTP connection was verified
separately; 24 demo audit events reached ClickHouse with pending outbox count zero.
The setup/runtime fix has not succeeded. Preserve the actual flags and provider
evidence; no automatic retry, replacement session or contained-agent resumption
is authorized.

`GUILD_SANDBOX_TIMEOUT_SECONDS` is a local polling deadline, not an enforced
remote wall-clock or spending limit. Guild's current public OpenAPI exposes no
session stop endpoint. If a deadline expires without verified root-terminal status,
inspect the saved session ID and use Guild's End session control; provider work may
continue. If the exact root is already verified terminal but required report
evidence is unavailable, the job fails for missing evidence without claiming it
is still running. Session-creation timeouts remain uncertain and are never
automatically retried.

## Official Contracts

- [Live public OpenAPI](https://api.guild.ai/v1/openapi.yaml)
- [Security architecture](https://docs.guild.ai/platform/security-architecture)
- [Runtime environments](https://docs.guild.ai/platform/environments)
- [Goose recipes](https://docs.guild.ai/guide/goose-agents)
- [Environment declaration](https://docs.guild.ai/guide/guild-yaml)
- [API authentication](https://docs.guild.ai/api-reference/introduction)
- [HTTP API triggers](https://docs.guild.ai/platform/api-triggers)
- [Session runtimes](https://docs.guild.ai/api-reference/sessions/fetch-session-runtimes)
- [Session execution tasks](https://docs.guild.ai/api-reference/sessions/fetch-session-sub-tasks)
- [Session controls](https://docs.guild.ai/platform/sessions)
