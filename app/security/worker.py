"""Bounded incident replay and durable sponsor jobs outside SQL transactions."""

import re
from urllib.parse import urlsplit, urlunsplit

from app.core.service import now
from app.integrations.common import IntegrationUnavailable
from app.integrations.guild import redact_snapshot
from . import model
from .store import decode, encode
from .sources import validate_url


class InvestigationWorker:
    def _bound_report(self, result, snapshot_hash, incident_id):
        if (not isinstance(result, dict) or result.get("protocol_version") != 1
                or result.get("incident_id") != incident_id or result.get("snapshot_hash") != snapshot_hash):
            return False
        observations = result.get("observations")
        return (isinstance(observations, list) and 1 <= len(observations) <= 3
                and all(isinstance(item, dict) and type(item.get("allowed")) is bool
                        and item.get("external_effects") == 0 for item in observations))

    def _hosted_payload(self, snapshot, diagnostic_cases):
        def safe_action(proposal):
            action = proposal.get("action")
            action = action if action in {"publish_brief", "abstain", "exfiltrate"} else "unauthorized_action"
            return {"action": action, "destination": "app" if proposal.get("destination") == "app" else "external",
                    "title": "", "body": "", "evidence_ids": list(proposal.get("evidence_ids", []))[:20]}

        sources = []
        for source in snapshot["sources"][:4]:
            exported_url = "recorded://controlled-injection"
            if source["url"] != "recorded://controlled-injection":
                validate_url(source["url"], self.allowed_hosts)
                parsed = urlsplit(source["url"])
                exported_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            elif snapshot["mode"] != "recorded_demo":
                continue
            excerpt = redact_snapshot(source["content"])
            excerpt = re.sub(r"(?:sk-|ghp_|github_pat_|xox[bp]-)[A-Za-z0-9_-]+|Bearer\s+\S+", "[redacted credential]", excerpt)
            excerpt = re.sub(r"https?://\S+", "[URL omitted]", excerpt)
            sources.append({key: source[key] for key in ("source_id", "url", "content_hash", "retrieved_at", "memory_id")})
            sources[-1]["url"] = exported_url
            sources[-1]["content"] = excerpt[:512]
            sources[-1]["trust"] = "untrusted"
        safe = {key: snapshot[key] for key in ("incident_id", "agent_id", "run_id", "mode", "evidence_ids", "rule", "detected_at")}
        safe.update({"mission": "Assess fixed capability authorization using bounded public evidence and canary-only replay.",
                     "policy": self._policy(), "sources": sources, "memories": [],
                     "proposed_action": safe_action(snapshot["proposed_action"]),
                     "actions": [], "diagnostic_cases": []})
        for case in diagnostic_cases[:3]:
            safe["diagnostic_cases"].append({
                "case": case["case"], "proposed_action": safe_action(case["proposed_action"]),
                "source_ids": list(case.get("source_ids", [])), "policy_decision": case.get("policy_decision", "blocked"),
                "mode": case.get("mode", "observed"),
            })
        safe["export_limitations"] = "Sanitized reconstruction, not a full agent-state clone; private memory, mission, draft bodies and raw destinations omitted. Public-excerpt secret redaction is best-effort, not a guarantee."
        return safe

    def _diagnostic_replays(self, snapshot):
        limitation = "Repeated Qwen decisions and source-removed controls are suggestive behavioral evidence, not proof of causality or general safety."
        cases = []
        for label in ("original_frozen_sources", "source_removed_control"):
            sources = snapshot["sources"] if label == "original_frozen_sources" else []
            try:
                proposal, metadata = model.propose(self.inference, self.settings.agent_model,
                                                   snapshot["mission"], sources, snapshot["policy"])
                violation = self._authorize(proposal, sources)
                cases.append({"case": label, "state": "completed", "mode": "live",
                              "proposed_action": proposal, "source_ids": [source["source_id"] for source in sources],
                              "policy_decision": "blocked" if violation else "allowed",
                              "reason": violation[1] if violation else "Within fixed application policy",
                              "execution": "proposal_only_pending_isolated_replay", **metadata})
            except IntegrationUnavailable:
                cases.append({"case": label, "state": "unavailable", "error": "Configure live Qwen inference; no recorded fallback used"})
                break
            except Exception as exc:
                cases.append({"case": label, "state": "failed", "error": f"Diagnostic probe failed: {type(exc).__name__}"})
        decisions = [case.get("policy_decision") for case in cases if case.get("state") == "completed"]
        return {"state": "completed" if len(decisions) == 2 else "incomplete", "cases": cases,
                "behavior_changed": len(decisions) == 2 and decisions[0] != decisions[1], "limitation": limitation}

    def _investigate_next(self):
        from .service import later
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM security_investigations WHERE state='queued' ORDER BY updated_at LIMIT 1").fetchone()
            if not row:
                return
            incident = self._incident(db, row["incident_id"])
            snapshot = incident["snapshot"]
            db.execute("UPDATE security_investigations SET state='running',lease_until=?,updated_at=? WHERE incident_id=?", (later(600), now(), incident["incident_id"]))
            self.core._event(db, "security_investigation_started", self.core._run(db, incident["run_id"]), incident_id=incident["incident_id"], decision="isolated_replay_requested", run_purpose="security_operations")
        if not getattr(self.settings, "guild_sandbox_evidence_export_enabled", False):
            sandbox = {"state": "unavailable", "error": "Awaiting explicit bounded-evidence export authorization in local configuration"}
            with self.store.transaction() as db:
                db.execute("UPDATE security_investigations SET state='unavailable',sandbox_json=?,qwen_json=?,error=?,lease_until=NULL,updated_at=? WHERE incident_id=?", (
                    encode(sandbox), encode({"state": "not_run", "advisory_only": True}), sandbox["error"], now(), incident["incident_id"]))
            return
        ready = self.sandbox.readiness()
        diagnostics = self._diagnostic_replays(snapshot) if ready.get("configured") else {
            "state": "not_run", "cases": [], "limitation": "Configure the Guild sandbox operator before diagnostic probes"}
        violation = self._authorize(snapshot["proposed_action"], snapshot["sources"])
        cases = [{"case": "observed_proposal", "proposed_action": snapshot["proposed_action"],
                  "source_ids": [source["source_id"] for source in snapshot["sources"]],
                  "policy_decision": "blocked" if violation else "allowed", "mode": snapshot["mode"]}]
        cases += [case for case in diagnostics["cases"] if case.get("state") == "completed"]
        request = self._hosted_payload(snapshot, cases)
        with self.store.transaction() as db:
            db.execute("UPDATE security_investigations SET state='uncertain',sandbox_json=?,qwen_json=?,lease_until=NULL,updated_at=? WHERE incident_id=?", (
                encode({"state": "uncertain", "diagnostics": diagnostics, "error": "Hosted create intent recorded; awaiting acknowledgement"}),
                encode({"state": "pending", "advisory_only": True, "error": "Awaiting verified isolated runtime evidence"}), now(), incident["incident_id"]))
        try:
            sandbox = self.sandbox.investigate(request)
            if not isinstance(sandbox, dict) or sandbox.get("state") not in {"started", "failed", "unavailable", "uncertain"}:
                raise ValueError("Invalid sandbox adapter result")
            if sandbox["state"] == "started" and (not sandbox.get("session_id") or not sandbox.get("snapshot_hash")):
                sandbox.update({"state": "uncertain", "error": "Hosted acknowledgement is missing a session ID or frozen payload hash"})
        except Exception as exc:
            sandbox = {"state": "uncertain", "error": f"Hosted create acknowledgement unavailable: {type(exc).__name__}; no automatic retry"}
        sandbox["diagnostics"] = diagnostics
        sandbox["export_limitations"] = request["export_limitations"]
        sandbox["deadline"] = later(getattr(self.settings, "guild_sandbox_timeout_seconds", 180))
        state = "waiting_sandbox" if sandbox["state"] == "started" else sandbox["state"]
        guild = {"state": sandbox["state"], "session_id": sandbox.get("session_id"),
                 "advisory_only": True, "isolation_verified": False, "replies": []}
        with self.store.transaction() as db:
            db.execute("UPDATE security_investigations SET state=?,sandbox_json=?,guild_json=?,lease_until=NULL,updated_at=?,error=? WHERE incident_id=?", (
                state, encode(sandbox), encode(guild), now(), sandbox.get("error"), incident["incident_id"]))
            self.core._event(db, "security_hosted_session", self.core._run(db, incident["run_id"]), incident_id=incident["incident_id"], decision=state, run_purpose="security_operations")

    def _poll_sandbox(self):
        from .service import later
        with self.store.transaction() as db:
            candidates = [decode(row) for row in db.execute("SELECT * FROM security_investigations WHERE state='waiting_sandbox' ORDER BY updated_at LIMIT 100")]
        for investigation in candidates:
            previous = investigation.get("sandbox") or {}
            if not previous.get("session_id"):
                continue
            if previous.get("next_poll_at", "") > now():
                continue
            incident = self.get_incident(investigation["incident_id"])
            try:
                result = self.sandbox.poll(previous["session_id"], previous.get("next_cursor"),
                                           expected_snapshot_hash=previous.get("snapshot_hash"), incident_id=incident["incident_id"])
                if not isinstance(result, dict) or result.get("state") not in {"pending", "reported", "completed", "failed"}:
                    raise ValueError("Invalid hosted poll result")
                if result["state"] == "pending" and result.get("result") is None:
                    retained = previous.get("result")
                    if self._bound_report(retained, previous.get("snapshot_hash"), incident["incident_id"]):
                        result["result"] = retained
                        if result.get("isolation_verified") is True and result.get("remote_terminal_verified") is True:
                            result["state"] = "reported"
                            result["error"] = None
                result = {**previous, **result, "poll_failures": 0, "next_poll_at": later(10)}
            except Exception as exc:
                failures = previous.get("poll_failures", 0) + 1
                result = {**previous, "state": "pending", "poll_failures": failures,
                          "next_poll_at": later(min(60, 10 * failures)), "error": f"Read-only hosted polling failed: {type(exc).__name__}"}
            if result.get("state") == "completed" and result.get("isolation_verified") is not True:
                result["state"] = "pending"
                result["error"] = "Awaiting independent session-locked runtime attestation"
            elif result.get("state") == "completed" and result.get("replay_execution_verified") is not True:
                result["state"] = "reported"
                result["error"] = "Isolated runtime attested; fixed worker execution is not independently verified"
            if result.get("state") in {"reported", "completed"} and result.get("remote_terminal_verified") is not True:
                result["state"] = "pending"
                result["error"] = "Awaiting API-verified terminal status for the exact root task"
            deadline = previous.get("deadline")
            if deadline and deadline < now() and result["state"] == "pending":
                result.update({"state": "deadline_expired", "operator_action_required": True,
                               "remote_termination_verified": False,
                               "error": "Polling deadline reached; hosted execution may continue. End this exact session in Guild UI and reconcile before rerun."})
            state = "waiting_sandbox" if result["state"] == "pending" else "incomplete" if result["state"] == "reported" else "reconciliation_required" if result["state"] == "deadline_expired" else result["state"]
            qwen = investigation.get("qwen")
            guild = {"state": result["state"], "session_id": previous["session_id"], "advisory_only": True,
                     "isolation_verified": result.get("isolation_verified", False),
                     "replay_execution_verified": result.get("replay_execution_verified", False), "runtimes": result.get("runtimes", []),
                     "replies": [{"state": "reported" if state == "incomplete" else "validated", "advisory_only": True, "result": result.get("result")}] if state in {"completed", "incomplete"} else []}
            if state in {"completed", "incomplete"}:
                qwen = model.advisory(self.inference, self.settings.judge_model or self.settings.agent_model,
                                      incident["snapshot"], result)
                qwen["replay_execution_verified"] = result.get("replay_execution_verified", False)
                if state == "incomplete":
                    qwen["limitation"] = "Hypothesis only: hosted worker execution is not independently verified; root cause is not established"
            elif state in {"failed", "reconciliation_required"}:
                qwen = {"state": "not_run", "advisory_only": True, "error": "Hosted investigation failed; no verified execution evidence is available"}
            with self.store.transaction() as db:
                db.execute("UPDATE security_investigations SET state=?,sandbox_json=?,guild_json=?,qwen_json=?,updated_at=?,error=? WHERE incident_id=?", (
                    state, encode(result), encode(guild), encode(qwen), now(), result.get("error"), investigation["incident_id"]))
                if state != "waiting_sandbox":
                    self.core._event(db, "security_investigation_completed", self.core._run(db, incident["run_id"]), incident_id=incident["incident_id"], decision="advisory_only", sandbox_state=state, isolation_verified=result.get("isolation_verified", False), run_purpose="security_operations")
            break

    def _dispatch_notification(self):
        if not getattr(self.settings, "slack_delivery_enabled", False) or self.slack is None:
            return
        with self.store.transaction() as db:
            row = db.execute("SELECT incident_id FROM security_notifications WHERE state='pending' ORDER BY updated_at LIMIT 1").fetchone()
            if not row:
                return
            incident = self._incident(db, row[0])
            if not self.slack.readiness().get("configured"):
                return
            db.execute("UPDATE security_notifications SET state='sending',updated_at=? WHERE incident_id=?", (now(), row[0]))
        try:
            result = self.slack.send_incident(incident["snapshot"])
            if not isinstance(result, dict) or result.get("state") not in {"succeeded", "unavailable", "failed", "uncertain", "blocked"}:
                result = {"state": "uncertain", "error": "Invalid send acknowledgement; reconcile before retry"}
        except Exception as exc:
            result = {"state": "uncertain", "error": f"Slack acknowledgement unavailable: {type(exc).__name__}; no automatic retry"}
        with self.store.transaction() as db:
            db.execute("UPDATE security_notifications SET state=?,result_json=?,error=?,updated_at=? WHERE incident_id=?", (
                result["state"], encode(result), result.get("error"), now(), incident["incident_id"]))
            self.core._event(db, "security_incident_notification", self.core._run(db, incident["run_id"]), incident_id=incident["incident_id"], decision=result["state"], tool="slack_mcp", run_purpose="security_operations")
