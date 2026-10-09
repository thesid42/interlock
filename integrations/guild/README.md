# Guild Hosted Investigation

Guild owns the incident investigation runtime. Interlock does not run a local
Docker sandbox and does not silently substitute one. The investigator has been
published as internal version `v1.0.0` and installed in its dedicated workspace.
The installation's automatic updates were disabled and read back as disabled.
Environment and image record IDs were resolved through Guild's official CLI,
not inferred from names or Docker tags. These setup records are not a hosted
investigation result or proof of exact replay-worker execution.

## Prepare The Runtime

1. Create a dedicated private Guild workspace for incident investigations. Set
   `restrict_account_credentials=true`. Do not grant or connect service
   credentials to its investigator. Leave workspace context and variables free
   of production secrets, private memory and publishing permissions.
2. Create a private runtime environment named `interlock-incident` using
   the documented Goose base image `guildai~goosebox`. The image must provide
   Bash and Python 3. Use `incident-investigator/environment_setup.sh` as its setup
   script, or preinstall the same `replay.py` at
   `$HOME/.local/share/interlock/replay.py` in a registered image. The setup account
   needs a nonempty absolute `HOME` and permission to prepare that path.
   Run Guild's Test setup control and inspect its runtime logs before publishing.
   A later bounded investigator run must also confirm that its runtime user and
   `HOME` can access the same worker; setup success alone does not establish this.
3. Set its qualified `<owner>~interlock-incident` reference in
   `incident-investigator/guild.yaml`. Publish
   `recipe.yaml` and `guild.yaml` as a Goose agent, install its reviewed version
   in the dedicated workspace and disable automatic updates. Do not add service
   integrations, sub-agents or platform mutation tools.
4. Create a Guild account API key with `sessions:write`, `workspaces:read` and
   `agents:read`. Interlock expects the complete `id:secret` value in
   `GUILD_API_KEY`; never put it in the agent or environment. The deployed runner
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

The setup script uses Python's standard library rather than GNU `install` or
shell process substitution. It explicitly uses `$HOME/.local/share/interlock`,
creates a user-only directory (mode `0700` for a new directory), and atomically installs fixed
hash-checked worker bytes with mode `0444`, and prints `setup_complete` only after
reading the installed file back. A failure reports its exact filesystem stage
and errno without printing environment variables or requesting privileges.
The user's hosted test confirmed that `/opt/interlock` is not writable by the
setup user (errno `13`). The user reports that the new home-based path passed
Guild's Test setup. Guild's docs do not specify unchanged setup/runtime user and
home. A later investigator run must still verify runtime accessibility, not merely
provisioning.
If directory creation fails, inspect Guild's raw setup stderr; do not add `sudo`
or silently use another path. The runtime command fails if `HOME` is unset or empty.
File mode and hash checks describe provisioning, not runtime immutability or
attestation. A runtime user able to modify the parent directory can replace the
worker, so the investigation's existing incomplete-evidence limits still apply.

The worker is provisioned in the runtime environment because Guild does not
load arbitrary files placed beside a Goose recipe. It uses fake publish/deny
canaries and makes no external calls. The runner receives a fixed worker path
and one base64 data argument to avoid interpolating evidence into shell syntax.
Base64 is transport encoding, not encryption or a security boundary.
The Goose recipe requests fixed worker execution but does not enforce a command
allowlist. A model can still propose other shell commands. Real isolation and
credential restrictions must come from Guild's runtime and account policies,
not these prompt instructions. Stronger command guarantees require a documented
deterministic hosted tool contract, which is not implemented by this recipe.

## Evidence Boundary

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

The public task API does not expose enough information to authenticate an exact
shell command. Consequently the current adapter labels a valid runtime-bound
report `reported`, with `replay_execution_verified=false`. It does not call RCA
complete, treat a stdout marker as attestation, or claim that the fixed worker
ran solely because the model says so. Correlated Qwen explanations remain
hypotheses. Full worker execution verification needs a documented stronger
execution-evidence contract or a supported deterministic hosted runner.

A successful bounded integration check proves only the stages recorded in its
result: authentication, publication/installation binding, session creation,
reported output, terminal status and runtime metadata must remain distinct.
Do not turn publication success, a passing setup control or one model reply into
"RCA complete".

## One Integration Run

On 2026-10-09, one operator-requested controlled `recorded_demo` run produced:

- Successful local containment and two completed live Qwen diagnostic probes.
- Eleven real audit events visible in ClickHouse after reconciliation: ten
  original run events plus `security_hosted_session_reconciled`. Pending outbox
  count remained zero at the final check.
- Guild chat returned HTTP `403` after persisting the session and exported user
  message. Read-only reconciliation matched that message to the frozen incident
  packet and its exact export hash. The session's `root_task` matched the scoped
  task listing, verifying root-task identity on the pinned version. That task
  remained `CREATED`; no runtime or task-to-runtime association was reported.

This is a partial integration result, not verified hosted worker execution or
complete RCA. The provider's exact denial reason remains unknown. Preserve the
existing session and failure details for manual reconciliation; do not retry,
create another session or resume the contained agent automatically.

`GUILD_SANDBOX_TIMEOUT_SECONDS` is a local polling deadline, not an enforced
remote wall-clock or spending limit. Guild's current public OpenAPI exposes no
session stop endpoint. On a deadline, inspect the saved session ID and use
Guild's End session control. The provider may continue until that happens.
Session-creation timeouts are uncertain and are never automatically retried.

## Official Contracts

- [Live public OpenAPI](https://api.guild.ai/v1/openapi.yaml)
- [Security architecture](https://docs.guild.ai/platform/security-architecture)
- [Runtime environments](https://docs.guild.ai/platform/environments)
- [Goose recipes](https://docs.guild.ai/guide/goose-agents)
- [Environment declaration](https://docs.guild.ai/guide/guild-yaml)
- [API authentication](https://docs.guild.ai/api-reference/introduction)
- [Session runtimes](https://docs.guild.ai/api-reference/sessions/fetch-session-runtimes)
- [Session execution tasks](https://docs.guild.ai/api-reference/sessions/fetch-session-sub-tasks)
- [Session controls](https://docs.guild.ai/platform/sessions)
