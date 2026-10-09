"""Guild-hosted incident reconstruction; no local runtime or fallback sandbox."""

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit

from app.integrations.common import IntegrationError, IntegrationUnavailable
from app.integrations.guild import GuildClient


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
        self._detail = "Configure and publish the dedicated Guild Goose investigator"

    def readiness(self) -> dict:
        configured = bool(self.settings.sandbox_enabled and self.guild.configured
            and self.settings.guild_sandbox_agent_version_id
            and self.settings.guild_sandbox_environment and self.settings.guild_sandbox_image_id)
        return {"provider": "guild_sandbox", "configured": configured,
                "verified": self._runtime_verified, "setup_verified": self._setup_verified,
                "detail": self._detail, "environment": self.settings.guild_sandbox_environment,
                "evidence_export_enabled": self.settings.guild_sandbox_evidence_export_enabled,
                "scope": "sanitized typed reconstruction in a Guild-hosted coding runtime"}

    def check(self) -> dict:
        self._setup_verified = False
        if not self.readiness()["configured"]:
            self._detail = "Missing Guild sandbox workspace, agent, pinned version, environment or image IDs"
            return self.readiness()
        try:
            workspace = self.guild.get_workspace()
            if workspace.get("restrict_account_credentials") is not True:
                raise ValueError("Diagnostic workspace must restrict account credential fallback")
            agents = [row for row in self.guild.installed_agents()
                      if row.get("agent", {}).get("id") == self.guild.agent_id]
            if len(agents) != 1:
                raise ValueError("Install the dedicated investigator in the diagnostic workspace")
            installed = agents[0]
            if installed.get("agent", {}).get("agent_type") != "GOOSE":
                raise ValueError("A Goose coding-runtime investigator is required, not a native prompt agent")
            if installed.get("version_id") != self.settings.guild_sandbox_agent_version_id or installed.get("should_autoupdate"):
                raise ValueError("Pin the installed investigator version and disable automatic updates")
            if self.guild.credential_associations(installed["id"]):
                raise ValueError("The diagnostic investigator must have no service credential associations")
            self._workspace_id = workspace["id"]
            self._setup_verified = True
            self._detail = "Guild setup verified; actual isolated execution is not yet verified"
        except (IntegrationError, ValueError, KeyError, TypeError, AttributeError) as exc:
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
            encoded = base64.b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode()
            envelope = {"protocol": "memguard-guild-replay-v1", "snapshot_hash": payload["snapshot_hash"],
                        "worker_command": "python3 -I -B /opt/memguard/replay.py --base64 '" + encoded + "'"}
            session = self.guild.start_session(json.dumps(envelope, separators=(",", ":")))
        except IntegrationUnavailable as exc:
            return {"state": "unavailable", "result": None, "error": str(exc)}
        except IntegrationError:
            return {"state": "uncertain", "result": None,
                    "error": "Guild session creation outcome is uncertain; reconcile before retrying"}
        return {"state": "started", "session_id": session["id"], "snapshot_hash": payload["snapshot_hash"],
                "incident_id": payload["incident_id"], "result": None, "error": None,
                "isolation_verified": False}

    def poll(self, session_id: str, from_id: str | None = None, *,
             expected_snapshot_hash: str | None = None, incident_id: str | None = None) -> dict:
        base = {"session_id": session_id, "result": None, "error": None,
                "isolation_verified": False, "replay_execution_verified": False,
                "remote_terminal_verified": False, "root_task_id": None, "root_task_status": None,
                "next_cursor": from_id, "has_more": False, "runtimes": [], "events": []}
        if not expected_snapshot_hash or not re.fullmatch(r"[a-f0-9]{64}", expected_snapshot_hash) or not incident_id:
            return {**base, "state": "failed", "error": "Persist the exact exported snapshot hash and incident ID"}
        if not self.settings.guild_sandbox_evidence_export_enabled or not self.check()["setup_verified"]:
            return {**base, "state": "failed", "error": "Guild sandbox consent or pinned setup is no longer valid"}
        try:
            page = self.guild.poll(session_id, from_id)
            session = self.guild.get_session(session_id)
            runtimes = self.guild.fetch_runtimes(session_id)
            tasks = self.guild.fetch_tasks(session_id)
        except IntegrationError:
            return {**base, "state": "pending", "error": "Guild evidence polling failed; existing session was not restarted"}
        base.update(next_cursor=page["next_cursor"], has_more=page["has_more"],
                    events=[{"id": event.get("id"), "type": event.get("type"),
                             "task_id": event.get("task_id")} for event in page.get("events", [])],
                    runtimes=runtimes, tasks=tasks)
        if session.get("workspace_id") != self._workspace_id or session.get("interrupted_at"):
            return {**base, "state": "failed", "error": "Guild session was interrupted or belongs to another workspace"}
        def image_matches(row):
            image = row.get("image")
            value = image.get("id") if isinstance(image, dict) else image
            return value == self.settings.guild_sandbox_image_id
        isolated = [row for row in runtimes if row.get("id")
                    and row.get("workspace_id") == self._workspace_id
                    and row.get("locked_for_session_id") == session_id and image_matches(row)]
        runtime_ids = {row["id"] for row in isolated}
        root_tasks = [task for task in tasks if task.get("session_id") == session_id
                      and "parent_task_id" in task and task["parent_task_id"] is None
                      and task.get("version_id") == self.settings.guild_sandbox_agent_version_id]
        root = root_tasks[0] if len(root_tasks) == 1 else None
        actual_tasks = [root] if root and root.get("runtime_id") in runtime_ids else []
        if root:
            base.update(root_task_id=root.get("id"), root_task_status=root.get("status"),
                        remote_terminal_verified=root.get("status") in {"DONE", "ERROR", "INTERRUPTED"})
        base["isolation_verified"] = bool(isolated and actual_tasks)
        if not page.get("replies") and root and root.get("status") == "DONE":
            try:
                completed = self.guild.poll(session_id, event_types="runtime_done")
                page["replies"] = completed.get("replies", [])
            except IntegrationError:
                pass
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
            result["evidence_kind"] = "validated_report_from_isolated_runtime"
            result["replay_execution_verified"] = False
            result["limitations"] = [
                "Sanitized typed reconstruction, not a clone of the original agent process.",
                "Runtime and pinned task version are API-verified; a final report is not proof that the fixed worker ran.",
                "The public task API does not expose a fixed shell command to authenticate worker execution.",
                "Goose prompt instructions request the fixed worker but are not an enforced shell-command allowlist.",
                "Model explanations are hypotheses, not root-cause certainty or sandbox escape guarantees."]
            if not base["isolation_verified"] or root.get("status") != "DONE":
                return {**base, "state": "pending", "result": result,
                        "error": "Report received; session-locked runtime/image or terminal root-task evidence is still missing"}
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
