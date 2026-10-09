# Guild Hosted Investigation

Guild owns the incident investigation runtime. Interlock does not run a local
Docker sandbox and does not silently substitute one. These deployment files
have not been published or verified against your account yet.

## Prepare The Runtime

1. Create a dedicated private Guild workspace for incident investigations. Set
   `restrict_account_credentials=true`. Do not grant or connect service
   credentials to its investigator. Leave workspace context and variables free
   of production secrets, private memory and publishing permissions.
2. Create a private runtime environment named `memguard-incident` using
   a supported Goose base image. The image must provide Bash, Python 3, `install`
   and `base64`. Use `incident-investigator/environment_setup.sh` as its setup
   script, or preinstall the same `replay.py` at `/opt/memguard/replay.py` in a
   registered image. The setup account needs permission to prepare that path.
   Run Guild's Test setup control and inspect its runtime logs before publishing.
3. Set its qualified `<owner>~memguard-incident` reference in
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
   `GUILD_SANDBOX_AGENT_VERSION_ID`, `GUILD_SANDBOX_ENVIRONMENT`, and
   `GUILD_SANDBOX_IMAGE_ID` in the local environment. Use the actual image record
   ID returned in Guild runtime metadata, not an invented Docker tag.
6. Enable `GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED=true` only after reviewing the
   export boundary. It is intentionally false in the template. No hosted
   investigation session is started while it is false.

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

An actual session record is not proof of isolation. Interlock separately reads
Guild runtime and task metadata and checks the workspace, session lock, image
ID, and executed agent version. Workspace-shared or mismatched runtimes remain
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

`GUILD_SANDBOX_TIMEOUT_SECONDS` is a local polling deadline, not an enforced
remote wall-clock or spending limit. Guild's current public OpenAPI exposes no
session stop endpoint. On a deadline, inspect the saved session ID and use
Guild's End session control. The provider may continue until that happens.
Session-creation timeouts are uncertain and are never automatically retried.

## Official Contracts

- [Security architecture](https://docs.guild.ai/platform/security-architecture)
- [Runtime environments](https://docs.guild.ai/platform/environments)
- [Goose recipes](https://docs.guild.ai/guide/goose-agents)
- [Environment declaration](https://docs.guild.ai/guide/guild-yaml)
- [API authentication](https://docs.guild.ai/api-reference/introduction)
- [Session runtimes](https://docs.guild.ai/api-reference/sessions/fetch-session-runtimes)
- [Session execution tasks](https://docs.guild.ai/api-reference/sessions/fetch-session-sub-tasks)
- [Session controls](https://docs.guild.ai/platform/sessions)
