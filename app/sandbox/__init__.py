"""Guild-hosted incident reconstruction; no local runtime or fallback sandbox."""

import base64
import hashlib
import json
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from app.integrations.common import IntegrationError, IntegrationUnavailable
from app.integrations.guild import GuildClient


WORKER_SHA256 = "d9032c6b242afd05454b670da010fe068e737a9e4cfdc4b2cd69b007dbcf8937"


def _worker_command(payload: dict) -> str:
    path = Path(__file__).resolve().parents[2] / "integrations/guild/incident-investigator/replay.py"
    try:
        worker = path.read_bytes()
    except OSError:
        raise IntegrationUnavailable("The fixed Guild replay program is missing from this deployment") from None
    if hashlib.sha256(worker).hexdigest() != WORKER_SHA256:
        raise IntegrationUnavailable("The fixed Guild replay program does not match its published hash")
    bootstrap = (
        'import hashlib; code=open("/tmp/interlock/replay.py","rb").read(); '
        'assert hashlib.sha256(code).hexdigest()=="' + WORKER_SHA256 + '"; '
        'exec(compile(code,"<interlock-replay>","exec"))'
    )
    data = base64.b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
    return "python3 -I -B -c " + shlex.quote(bootstrap) + " --base64 " + shlex.quote(data)


class _ManifestLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("Guild manifest contains invalid or duplicate keys")
        result[key] = loader.construct_object(value_node)
    return result


_ManifestLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _check_manifest(files, environment):
    text = files.get("guild.yaml")
    if not isinstance(text, str) or len(text.encode()) > 16384:
        raise ValueError("The pinned investigator needs a bounded root guild.yaml")
    try:
        if any(getattr(event, "anchor", None) or isinstance(event, yaml.events.AliasEvent)
               for event in yaml.parse(text)):
            raise ValueError("Guild manifest aliases are not allowed")
        manifest = yaml.load(text, Loader=_ManifestLoader)
    except yaml.YAMLError:
        raise ValueError("The pinned Guild manifest is not valid YAML") from None
    if not isinstance(manifest, dict) or manifest.get("environment") != environment:
        raise ValueError("The pinned manifest must declare the exact configured Guild environment name")
    if set(manifest) - {"environment", "integrations", "sub_agents", "builtins", "models"}:
        raise ValueError("The investigator manifest declares unsupported configuration")
    if any(manifest.get(key) not in (None, []) for key in ("integrations", "sub_agents", "builtins", "models")):
        raise ValueError("The investigator manifest must not declare extra tools, agents or models")


def _identifier(value) -> str:
    value = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", value):
        raise ValueError("Invalid evidence identifier")
    return value


def _excerpt(value) -> str:
    text = str(value)[:512]
    text = re.sub(r"(?i)(bearer\s+|api[_-]?key\s*[:=]\s*|token\s*[:=]\s*)\S+", "[redacted]", text)
    text = re.sub(r"\b(?:sk-|xox[baprs]-|glda_)[A-Za-z0-9_-]+", "[redacted]", text)
    return re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[redacted email]", text)


class IncidentSandbox:
    def __init__(self, settings, guild=None):
        self.settings = settings
        self.guild = guild or GuildClient(settings,
            workspace_id=settings.guild_sandbox_workspace_id,
            agent_id=settings.guild_sandbox_agent_id)
        self._owns_guild = guild is None
        self._setup_verified = False
        self._runtime_verified = False
        self._workspace_id = None
        self._environment_id = None
        self._detail = ("Configured; run the setup check to verify the pinned Guild investigator"
                        if settings.sandbox_enabled and not self._missing_configuration()
                        else "Configure and publish the dedicated Guild Goose investigator")

    def _missing_configuration(self) -> list[str]:
        required = {"GUILD_API_KEY": self.guild.api_key,
                    "GUILD_TRIGGER_API_KEY": self.guild.trigger_api_key,
                    "GUILD_TRIGGER_ID": self.guild.trigger_id,
                    "GUILD_SANDBOX_WORKSPACE_ID": self.settings.guild_sandbox_workspace_id,
                    "GUILD_SANDBOX_AGENT_ID": self.settings.guild_sandbox_agent_id,
                    "GUILD_SANDBOX_AGENT_VERSION_ID": self.settings.guild_sandbox_agent_version_id,
                    "GUILD_SANDBOX_ENVIRONMENT": self.settings.guild_sandbox_environment,
                    "GUILD_SANDBOX_ENVIRONMENT_ID": getattr(self.settings, "guild_sandbox_environment_id", ""),
                    "GUILD_SANDBOX_IMAGE_ID": self.settings.guild_sandbox_image_id}
        return [name for name, value in required.items() if not value]

    def readiness(self) -> dict:
        missing = self._missing_configuration()
        configured = bool(self.settings.sandbox_enabled and not missing)
        authentication = self.guild.readiness()
        return {"provider": "guild_sandbox", "configured": configured,
                "verified": self._runtime_verified, "setup_verified": self._setup_verified,
                "detail": self._detail, "environment": self.settings.guild_sandbox_environment,
                "environment_id": getattr(self.settings, "guild_sandbox_environment_id", ""),
                "key_configured": authentication["key_configured"],
                "authentication_verified": authentication["authentication_verified"],
                "permissions_verified": authentication["permissions_verified"],
                "missing_configuration": missing,
                "evidence_export_enabled": self.settings.guild_sandbox_evidence_export_enabled,
                "scope": "sanitized typed reconstruction in a Guild-hosted coding runtime"}

    def check(self) -> dict:
        self._setup_verified = False
        self._environment_id = None
        if not self.readiness()["configured"]:
            self._runtime_verified = False
            self._detail = "Missing Guild investigator configuration: " + ", ".join(self.readiness()["missing_configuration"])
            if not self.settings.sandbox_enabled:
                self._detail = "Guild sandbox is disabled"
            return self.readiness()
        try:
            authentication = self.guild.readiness()
            if not authentication["authentication_verified"]:
                authentication = self.guild.authenticate()["readiness"]
            if not authentication["permissions_verified"]:
                raise ValueError("Guild account key must have agents:read and workspaces:read")
            workspace = self.guild.get_workspace()
            if workspace.get("owner_id") != authentication["account"]["id"] or workspace.get("archived_at"):
                raise ValueError("Diagnostic workspace must be active and owned by the authenticated account")
            if workspace.get("restrict_account_credentials") is not True:
                raise ValueError("Diagnostic workspace must restrict account credential fallback")
            agents = [row for row in self.guild.installed_agents()
                      if row.get("agent", {}).get("id") == self.guild.agent_id]
            if len(agents) != 1:
                raise ValueError("Install the dedicated investigator in the diagnostic workspace")
            installed = agents[0]
            if installed.get("agent", {}).get("agent_type") != "GOOSE":
                raise ValueError("A Goose coding-runtime investigator is required, not a native prompt agent")
            if (installed.get("version_id") != self.settings.guild_sandbox_agent_version_id
                    or installed.get("should_autoupdate") is not False or installed.get("archived_at")):
                raise ValueError("Pin the installed investigator version and disable automatic updates")
            version = self.guild.get_version(self.settings.guild_sandbox_agent_version_id)
            if (version.get("id") != self.settings.guild_sandbox_agent_version_id
                    or version.get("agent_id") != self.guild.agent_id
                    or version.get("validation_status") != "PASSED"
                    or not isinstance(version.get("published_at"), str) or not version["published_at"]):
                raise ValueError("The pinned investigator must be its own validated, published agent version")
            environment_id = getattr(self.settings, "guild_sandbox_environment_id", "")
            if ("runtime_environment_id" in version
                    and version["runtime_environment_id"] != environment_id):
                raise ValueError("The version environment metadata conflicts with the configured Guild environment ID")
            _check_manifest(self.guild.get_version_code(version["id"]), self.settings.guild_sandbox_environment)
            if version.get("raw_tools") or version.get("tools"):
                raise ValueError("The investigator version must not declare integrations, sub-agents or extra platform tools")
            if self.guild.credential_associations(installed["id"]):
                raise ValueError("The diagnostic investigator must have no service credential associations")
            self._workspace_id = workspace["id"]
            self._environment_id = environment_id
            self._setup_verified = True
            self._detail = "Guild setup and pinned manifest verified; resolved environment and isolated execution still require runtime evidence"
        except (IntegrationError, ValueError, KeyError, TypeError, AttributeError) as exc:
            self._runtime_verified = False
            self._detail = str(exc) if isinstance(exc, ValueError) else "Guild sandbox setup check failed"
        return self.readiness()

    def _payload(self, snapshot: dict) -> dict:
        sources = []
        for source in snapshot.get("sources", [])[:4]:
            url = urlsplit(str(source.get("url", "")))
            recorded = snapshot.get("mode") == "recorded_demo" and url.geturl() == "recorded://controlled-injection"
            approved = (url.scheme == "https" and url.hostname in self.settings.security_source_hosts
                        and not url.username and not url.password and not url.query and not url.fragment)
            if not (recorded or approved):
                continue
            content = _excerpt(source.get("excerpt", source.get("content", "")))
            sources.append({"source_id": _identifier(source["source_id"]),
                            "url": url.geturl(), "excerpt": content,
                            "content_hash": source.get("content_hash", "") if re.fullmatch(
                                r"[a-f0-9]{64}", str(source.get("content_hash", ""))) else "unavailable",
                            "excerpt_hash": hashlib.sha256(content.encode()).hexdigest()})
        source_ids = {source["source_id"] for source in sources}
        allowed = {"publish_brief", "abstain", "exfiltrate"}
        cases = snapshot.get("diagnostic_cases") or [{"case": "observed_proposal",
            "proposed_action": snapshot.get("proposed_action", {}), "source_ids": list(source_ids)}]
        rows = []
        for case in cases[:3]:
            proposal = case.get("proposed_action", {})
            action = proposal.get("action")
            action = action if action in allowed else "unsupported_operation"
            destination = "app" if proposal.get("destination") == "app" else "unauthorized_destination"
            refs = [ref for ref in proposal.get("evidence_ids", [])[:12] if isinstance(ref, str) and ref in source_ids]
            active = [ref for ref in case.get("source_ids", list(source_ids))[:4] if ref in source_ids]
            label = case.get("case", "observed_proposal")
            if label not in {"observed_proposal", "original_frozen_sources", "source_removed_control"}:
                label = "observed_proposal"
            rows.append({"case": label, "source_ids": active,
                         "proposed_action": {"action": action, "destination": destination, "evidence_ids": refs}})
        payload = {"protocol_version": 1, "incident_id": _identifier(snapshot["incident_id"]),
                   "policy": {"allowed_actions": ["publish_brief", "abstain"], "destination": "app"},
                   "sources": sources, "diagnostic_cases": rows,
                   "mode": "live" if snapshot.get("mode") == "live" else "recorded_demo"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode()) > 9000:
            raise ValueError("Sanitized Guild payload exceeded its export limit")
        payload["snapshot_hash"] = hashlib.sha256(encoded.encode()).hexdigest()
        return payload

    def investigate(self, snapshot: dict) -> dict:
        if not self.settings.guild_sandbox_evidence_export_enabled:
            return {"state": "unavailable", "result": None,
                    "error": "Operator consent for sanitized Guild evidence export is disabled"}
        if not self.check()["setup_verified"]:
            return {"state": "unavailable", "result": None, "error": self._detail}
        try:
            payload = self._payload(snapshot)
        except (KeyError, ValueError, TypeError):
            return {"state": "failed", "result": None, "error": "Snapshot failed sanitized export requirements"}
        try:
            envelope = {"protocol": "memguard-guild-replay-v1", "snapshot_hash": payload["snapshot_hash"],
                        "worker_sha256": WORKER_SHA256, "worker_command": _worker_command(payload)}
            session = self.guild.start_session(json.dumps(envelope, separators=(",", ":")))
        except IntegrationUnavailable as exc:
            return {"state": "unavailable", "result": None, "error": str(exc)}
        except IntegrationError as exc:
            return {"state": "uncertain", "result": None,
                    "snapshot_hash": payload["snapshot_hash"], "incident_id": payload["incident_id"],
                    "provider_detail": str(exc),
                    "error": "Guild session creation outcome is uncertain; reconcile before retrying"}
        return {"state": "started", "session_id": session["id"], "snapshot_hash": payload["snapshot_hash"],
                "incident_id": payload["incident_id"], "result": None, "error": None,
                "isolation_verified": False}

    def poll(self, session_id: str, from_id: str | None = None, *,
             expected_snapshot_hash: str | None = None, incident_id: str | None = None) -> dict:
        base = {"session_id": session_id, "result": None, "error": None,
                "poll_warning": None, "poll_retryable": False,
                "isolation_verified": False, "replay_execution_verified": False,
                "session_runtime_verified": False, "root_task_verified": False,
                "root_runtime_binding_verified": False,
                "remote_terminal_verified": False, "root_task_id": None, "root_task_status": None,
                "next_cursor": from_id, "has_more": False, "runtimes": [], "events": []}
        if not expected_snapshot_hash or not re.fullmatch(r"[a-f0-9]{64}", expected_snapshot_hash) or not incident_id:
            return {**base, "state": "failed", "error": "Persist the exact exported snapshot hash and incident ID"}
        if not self.settings.guild_sandbox_evidence_export_enabled or not self.check()["setup_verified"]:
            return {**base, "state": "failed", "error": "Guild sandbox consent or pinned setup is no longer valid"}
        try:
            session = self.guild.get_session(session_id)
            runtimes = self.guild.fetch_runtimes(session_id)
            tasks = self.guild.fetch_tasks(session_id)
        except IntegrationError:
            return {**base, "state": "pending", "error": None, "poll_retryable": True,
                    "poll_warning": "Guild metadata polling is temporarily delayed; the existing session is preserved and will be checked again"}
        base.update(runtimes=runtimes, tasks=tasks)
        if (session.get("id") != session_id or session.get("workspace_id") != self._workspace_id
                or session.get("interrupted_at")):
            return {**base, "state": "failed", "error": "Guild session was interrupted or belongs to another workspace"}
        def image_matches(row):
            image = row.get("image")
            value = image.get("id") if isinstance(image, dict) else image
            return value == self.settings.guild_sandbox_image_id
        isolated = [row for row in runtimes if row.get("id")
                    and row.get("workspace_id") == self._workspace_id
                    and row.get("runtime_environment_id") == self._environment_id
                    and row.get("locked_for_session_id") == session_id and image_matches(row)]
        runtime_ids = {row["id"] for row in isolated}
        # The live scoped task list omits session/runtime IDs; bind its root to the session's own reference.
        reference = session.get("root_task")
        reference = reference if isinstance(reference, dict) else {}
        root_tasks = [task for task in tasks if isinstance(reference.get("id"), str)
                      and task.get("id") == reference["id"]
                      and ("session_id" not in task or task["session_id"] == session_id)
                      and "parent_task_id" in task and task["parent_task_id"] is None
                      and task.get("version_id") == self.settings.guild_sandbox_agent_version_id
                      and isinstance(reference.get("status"), str)
                      and task.get("status") == reference["status"]]
        root = root_tasks[0] if len(root_tasks) == 1 else None
        actual_tasks = [root] if root and (root.get("runtime_id") in runtime_ids or any(
            row.get("created_by_id") == root.get("id") for row in isolated)) else []
        if root:
            base.update(root_task_id=root.get("id"), root_task_status=root.get("status"),
                        root_task_verified=True,
                        remote_terminal_verified=root.get("status") in {"DONE", "ERROR", "INTERRUPTED"})
        base["session_runtime_verified"] = bool(isolated)
        base["root_runtime_binding_verified"] = bool(actual_tasks)
        base["isolation_verified"] = bool(isolated and actual_tasks)
        if root and root.get("status") in {"ERROR", "INTERRUPTED"}:
            return {**base, "state": "failed", "error": "Guild investigation reported a runtime error or interruption"}
        if root and root.get("status") == "CREATED" and not runtimes:
            return {**base, "state": "pending", "error": "Guild root task exists; awaiting runtime startup"}
        if root and root.get("status") != "DONE":
            return {**base, "state": "pending"}
        try:
            if root and root.get("status") == "DONE":
                page = self.guild.poll(session_id, from_id, event_types="runtime_done")
            else:
                page = self.guild.poll(session_id, from_id)
        except IntegrationError:
            return {**base, "state": "pending", "error": None, "poll_retryable": True,
                    "poll_warning": "Guild event polling is temporarily delayed; the existing session is preserved and will be checked again"}
        base.update(next_cursor=page["next_cursor"], has_more=page["has_more"],
                    events=[{"id": event.get("id"), "type": event.get("type"),
                             "task_id": event.get("task_id")} for event in page.get("events", [])])
        if root and (root.get("status") in {"ERROR", "INTERRUPTED"} or any(
                event.get("task_id") == root.get("id") and event.get("type") in {
                    "runtime_error", "system_error", "interrupted"} for event in page.get("events", []))):
            return {**base, "state": "failed", "error": "Guild investigation reported a runtime error or interruption"}
        for reply in page.get("replies", []):
            if not root or reply.get("task_id") != root.get("id"):
                continue
            try:
                text = reply["text"]
                if len(text) > 32768:
                    raise ValueError("Oversized reply")
                result = json.loads(text)
                if isinstance(result, dict) and result.get("type") == "text" and isinstance(result.get("text"), str):
                    result = json.loads(result["text"])
                if (not isinstance(result, dict) or result.get("protocol_version") != 1
                        or result.get("incident_id") != incident_id
                        or result.get("snapshot_hash") != expected_snapshot_hash
                        or not isinstance(result.get("observations"), list)
                        or not 1 <= len(result["observations"]) <= 3):
                    raise ValueError("Reply did not match frozen evidence")
                for observation in result["observations"]:
                    if (not isinstance(observation, dict) or type(observation.get("allowed")) is not bool
                            or observation.get("external_effects") != 0):
                        raise ValueError("Invalid bounded replay observation")
            except (KeyError, ValueError, TypeError):
                return {**base, "state": "failed", "error": "Guild returned an invalid or unbound replay report"}
            result["evidence_kind"] = "hash_bound_report_from_pinned_guild_task"
            result["replay_execution_verified"] = False
            result["limitations"] = [
                "Sanitized typed reconstruction, not a clone of the original agent process.",
                "The session, pinned task version and report hash are API-verified; a final report is not independent proof of shell execution.",
                "Guild's public API may omit private environment and session-lock metadata; missing metadata is not treated as verified isolation.",
                "The public task API does not expose a fixed shell command to authenticate worker execution.",
                "Goose prompt instructions request the fixed worker but are not an enforced shell-command allowlist.",
                "Model explanations are hypotheses, not root-cause certainty or sandbox escape guarantees."]
            if root.get("status") != "DONE":
                return {**base, "state": "pending", "result": result,
                        "error": "Report received; awaiting terminal root-task evidence"}
            if not base["isolation_verified"]:
                return {**base, "state": "reported", "result": result,
                        "error": None, "verification_limitation": "Report received from the pinned Guild task; runtime isolation metadata is unavailable through the public API"}
            self._runtime_verified = True
            self._detail = "Guild session-locked coding runtime and pinned task version verified"
            return {**base, "state": "reported", "result": result}
        return {**base, "state": "pending"}

    def cancel(self, session_id: str) -> dict:
        return {"state": "unsupported", "session_id": session_id,
                "operator_action_required": True, "remote_stop_verified": False,
                "error": "Guild's public API exposes no documented stop endpoint; end this exact session in Guild"}

    def close(self) -> None:
        if self._owns_guild:
            self.guild.close()
