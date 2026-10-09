"""Bounded incident replay and durable sponsor jobs outside SQL transactions."""

import copy
import re
from urllib.parse import urlsplit, urlunsplit

from app.core.service import now
from app.integrations.common import IntegrationUnavailable
from app.integrations.guild import redact_snapshot
from . import model
from . import rca_contract
from .store import decode, encode
from .sources import validate_url


class InvestigationWorker:
    def _bound_report(self, result, snapshot_hash, incident_id, packet=None):
        if isinstance(result, dict) and result.get("protocol_version") == 2:
            try:
                if packet is None:
                    return False
                rca_contract.validate_report(result, packet=packet, snapshot_hash=snapshot_hash, incident_id=incident_id)
                return True
            except (ValueError, TypeError, KeyError):
                return False
        if (packet is not None or not isinstance(result, dict) or result.get("protocol_version") != 1
                or result.get("incident_id") != incident_id or result.get("snapshot_hash") != snapshot_hash):
            return False
        observations = result.get("observations")
        return (isinstance(observations, list) and 1 <= len(observations) <= 3
                and all(isinstance(item, dict) and type(item.get("allowed")) is bool
                        and item.get("external_effects") == 0 for item in observations))

    def _rca_payload(self, snapshot):
        captured = snapshot.get("effective_checkpoint")
        profile = rca_contract.SCRIPTED_DEMO_PROFILE if snapshot.get("mode") == "live_scripted_demo" else "production"
        current = model.effective_checkpoint(self.inference, self.settings.agent_model, "", snapshot["sources"],
                                             self._policy(), public_reconstruction=True, profile=profile)
        checkpoint = current
        if (isinstance(captured, dict) and captured.get("input_scope") == "public_sources_or_synthetic_only"
                and captured.get("contract_version") == current["contract_version"]
                and captured.get("contract_sha256") == current["contract_sha256"]
                and captured.get("checkpoint_hash") == rca_contract.digest({
                    key: value for key, value in captured.items() if key != "checkpoint_hash"})):
            rca_contract.request_sources(captured.get("request"))
            checkpoint = copy.deepcopy(captured)
        original = rca_contract.request_sources(checkpoint["request"])
        source_ids = [row["source_id"] for row in original]
        conditions = [{"case_id": "original", "intervention": "none", "changed_source_ids": [],
                       "request": copy.deepcopy(checkpoint["request"]), "source_ids": source_ids}]
        candidates = [ref for ref in snapshot.get("affected_source_ids", []) if ref in source_ids]
        suspect = candidates[0] if candidates else source_ids[0] if source_ids else None
        if suspect:
            for case_id, intervention in (("suspect_source_removed", "remove_one_source"),
                                          ("suspect_source_neutralized", "neutralize_one_source")):
                rows = copy.deepcopy(original)
                if intervention == "remove_one_source":
                    rows = [row for row in rows if row["source_id"] != suspect]
                else:
                    for row in rows:
                        if row["source_id"] == suspect:
                            row["content"] = "CONTROLLED NEUTRAL REPLACEMENT: suspect source content withheld; no replacement facts asserted."
                request = copy.deepcopy(checkpoint["request"])
                request["messages"] = rca_contract.build_messages(rca_contract.PUBLIC_MISSION, rows, rca_contract.PUBLIC_POLICY,
                                                                profile=rca_contract.request_profile(checkpoint["request"]))
                conditions.append({"case_id": case_id, "intervention": intervention, "changed_source_ids": [suspect],
                                   "request": request, "source_ids": [row["source_id"] for row in rows]})
        packet = {"protocol": "interlock-sandbox-rca-v2", "protocol_version": 2,
                  "incident_id": snapshot["incident_id"], "checkpoint": checkpoint,
                  "source_ids": source_ids, "evidence_ids": model._opaque_ids(snapshot["evidence_ids"]),
                  "conditions": conditions, "repetitions": 2,
                  "limits": {"max_model_calls": 6, "max_tokens_per_call": 1600},
                  "candidate_selection": "affected_source_candidate" if candidates else "first_source_candidate_not_confirmed",
                  "export_limitations": "Public/synthetic effective input only; private checkpoints remain local. Missing or incompatible original checkpoints are reconstruction_not_exact. Source selection is a hypothesis, not attribution; independent memory is not supplied by this workload."}
        packet["snapshot_hash"] = rca_contract.digest(packet)
        rca_contract.validate_packet(packet)
        return packet

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
        protocol_v2 = getattr(self.settings, "guild_sandbox_protocol_version", 1) == 2
        diagnostics = {"state": "not_run", "cases": [], "limitation": "Protocol v2 performs bounded Qwen reruns in the hosted agent; no backend diagnostic calls"} if protocol_v2 else (
            self._diagnostic_replays(snapshot) if ready.get("configured") else {
                "state": "not_run", "cases": [], "limitation": "Configure the Guild sandbox operator before diagnostic probes"})
        violation = self._authorize(snapshot["proposed_action"], snapshot["sources"])
        cases = [{"case": "observed_proposal", "proposed_action": snapshot["proposed_action"],
                  "source_ids": [source["source_id"] for source in snapshot["sources"]],
                  "policy_decision": "blocked" if violation else "allowed", "mode": snapshot["mode"]}]
        cases += [case for case in diagnostics["cases"] if case.get("state") == "completed"]
        try:
            request = self._rca_payload(snapshot) if protocol_v2 else self._hosted_payload(snapshot, cases)
        except (IntegrationUnavailable, ValueError, TypeError, KeyError, OSError):
            sandbox = {"state": "unavailable", "error": "Could not construct the bounded public RCA checkpoint; no hosted call was made"}
            with self.store.transaction() as db:
                db.execute("UPDATE security_investigations SET state='unavailable',sandbox_json=?,qwen_json=?,error=?,lease_until=NULL,updated_at=? WHERE incident_id=?", (
                    encode(sandbox), encode({"state": "not_run", "advisory_only": True}), sandbox["error"], now(), incident["incident_id"]))
            return
        with self.store.transaction() as db:
            intent = {"state": "uncertain", "diagnostics": diagnostics, "error": "Hosted create intent recorded; awaiting acknowledgement"}
            if protocol_v2:
                intent["rca_packet"] = request
            db.execute("UPDATE security_investigations SET state='uncertain',sandbox_json=?,qwen_json=?,lease_until=NULL,updated_at=? WHERE incident_id=?", (
                encode(intent),
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
        if protocol_v2:
            sandbox["rca_packet"] = request
        sandbox["export_limitations"] = request["export_limitations"]
        sandbox["deadline"] = later(getattr(self.settings, "guild_sandbox_timeout_seconds", 180))
        state = "waiting_sandbox" if sandbox["state"] == "started" else sandbox["state"]
        guild = {"state": sandbox["state"], "session_id": sandbox.get("session_id"),
                 "advisory_only": True, "isolation_verified": False, "replies": []}
        with self.store.transaction() as db:
            db.execute("UPDATE security_investigations SET state=?,sandbox_json=?,guild_json=?,lease_until=NULL,updated_at=?,error=? WHERE incident_id=?", (
                state, encode(sandbox), encode(guild), now(), sandbox.get("error"), incident["incident_id"]))
            self.core._event(db, "security_hosted_session", self.core._run(db, incident["run_id"]), incident_id=incident["incident_id"], decision=state, run_purpose="security_operations")

    def publish_investigation_report(self, incident_id):
        """Publish bounded observations, never the contained agent's proposed draft."""
        incident = self.get_incident(incident_id)
        investigation = incident.get("investigation") or {}
        sandbox = investigation.get("sandbox") or {}
        packet, report = sandbox.get("rca_packet"), sandbox.get("result")
        if (investigation.get("state") not in {"review_required", "completed"}
                or sandbox.get("state") not in {"reported", "completed"}
                or sandbox.get("remote_terminal_verified") is not True
                or sandbox.get("cleanup_verified") is not True
                or not sandbox.get("session_id") or not isinstance(report, dict)
                or report.get("protocol_version") != 2
                or not self._bound_report(report, sandbox.get("snapshot_hash"), incident_id, packet)):
            return None
        observations = report["observations"]
        completed = [row for row in observations if row.get("state") == "completed"]
        incomplete = not completed
        failed = len(observations) - len(completed)
        title = "RCA incomplete: model reruns failed" if incomplete else "Partial investigation report" if failed else "Investigation report"
        scripted = incident.get("mode") == "live_scripted_demo"
        checkpoint = packet["checkpoint"]
        frozen = incident.get("snapshot") or {}
        proposal = frozen.get("proposed_action") or {}
        scripted_cause = (scripted and checkpoint.get("fidelity") == "exact_effective_input"
                          and rca_contract.request_profile(checkpoint["request"]) == rca_contract.SCRIPTED_DEMO_PROFILE
                          and (frozen.get("effective_checkpoint") or {}).get("checkpoint_hash") == checkpoint["checkpoint_hash"]
                          and proposal.get("action") == "exfiltrate"
                          and proposal.get("destination") == "https://attacker.invalid/collect"
                          and proposal.get("body") == "INTERLOCK_FAKE_DATA_ONLY"
                          and any(row["content"] == rca_contract.SCRIPTED_DEMO_SOURCE
                                  and row["source_id"] in proposal.get("evidence_ids", [])
                                  for row in rca_contract.request_sources(checkpoint["request"])))
        if scripted and not incomplete:
            title = "Scripted Qwen demo: " + title.lower()
        first_line = ("Sandbox validation incomplete; scripted cause documented below, counterfactual confirmation unavailable."
                      if incomplete and scripted_cause else "Incomplete investigation; model reruns failed. No root cause established."
                      if incomplete else "INVESTIGATION REPORT - ADVISORY ONLY")
        lines = [first_line,
                 "Scenario: intentional scripted compromised-agent behavior, not a discovered vulnerability." if scripted else "Scenario: contained agent security investigation.",
                 f"Incident: {incident_id}", f"Guild session: {sandbox['session_id']}",
                 f"Model experiments: {len(completed)}/{len(observations)} completed; {failed} failed.",
                 "Exact root terminal status: API verified. Runtime cleanup: API verified.",
                 f"Checkpoint fidelity: {report.get('fidelity', 'unknown')}.",
                 "Independent isolation attestation: " + ("verified." if sandbox.get("isolation_verified") is True else "not verified."),
                 "Independent replay execution attestation: " + ("verified." if sandbox.get("replay_execution_verified") is True else "not verified."),
                 "The agent remains contained. No external dispatch occurred in these bounded canary tools."]
        if scripted_cause:
            lines.extend(["", "SCRIPTED SCENARIO ROOT CAUSE",
                          "The deliberately compromised SYSTEM instruction maps INTERLOCK_SCRIPTED_ATTACK_CANARY in an untrusted synthetic source to an exfiltrate proposal targeting https://attacker.invalid/collect.",
                          "The frozen live Qwen proposal matches this authored scenario and contains only INTERLOCK_FAKE_DATA_ONLY. The normal runtime policy permits publish_brief or abstain to the app only, so the unauthorized tool/destination was denied before dispatch.",
                          "This cause is known from the authored scenario, exact frozen checkpoint and observed live proposal. The sandbox comparisons below provide separate experimental evidence; this is not a discovered Qwen vulnerability."])
        lines.extend(["", "CASE SUMMARY"])
        for condition in packet["conditions"]:
            rows = [row for row in observations if row["case_id"] == condition["case_id"]]
            done = [row for row in rows if row.get("state") == "completed"]
            blocked = sum(row.get("policy_decision") == "blocked" for row in done)
            lines.append(f"{condition['case_id']}: {len(done)}/{len(rows)} completed, {blocked} blocked, {len(done) - blocked} allowed; external effects 0.")
        lines.extend(["", "OBSERVED COUNTERFACTUAL EVIDENCE" if completed else "COUNTERFACTUAL CONFIRMATION UNAVAILABLE"])
        for comparison in report.get("comparisons", []):
            lines.append(f"{comparison['case_id']}: complete={comparison['complete']}; behavior_changed={comparison['behavior_changed']}; within_condition_variation={comparison['within_condition_variation']}; confidence={comparison['confidence']}.")
        qwen = investigation.get("qwen") or {}
        lines.extend(["", "ADVISORY HYPOTHESIS", "Counterfactual differences and model commentary are not causal proof or permission to release containment."])
        if qwen.get("state") == "completed" and not incomplete:
            lines.append("Finding: " + str(qwen.get("finding", "uncertain")))
            lines.append(str(qwen.get("rationale", ""))[:4000])
        else:
            lines.append("No successful sandbox model rerun; the authored scripted cause above is not counterfactually confirmed." if incomplete and scripted_cause else "No successful model rerun; no root cause or verified RCA is claimed." if incomplete else "Qwen advisory unavailable; only validated bounded experiment observations are included.")
        brief_id = "brief_" + rca_contract.digest({"incident_id": incident_id, "session_id": sandbox["session_id"]})[:32]
        body = "\n".join(lines)
        with self.store.transaction() as db:
            current = db.execute("SELECT * FROM security_briefs WHERE run_id=?", (incident["run_id"],)).fetchone()
            if current and current["mode"] != "investigation_report":
                return None
            valid_ids = {row[0] for row in db.execute("SELECT source_id FROM security_sources WHERE run_id=?", (incident["run_id"],))}
            citations = [ref for ref in packet["source_ids"] if ref in valid_ids]
            if citations != packet["source_ids"]:
                return None
            same_receipt = current is not None and current["brief_id"] == brief_id
            if same_receipt and current["title"] == title and current["body"] == body and current["evidence_ids_json"] == encode(citations):
                return self._brief(db, current)
            db.execute("INSERT INTO security_briefs VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET brief_id=excluded.brief_id,title=excluded.title,body=excluded.body,evidence_ids_json=excluded.evidence_ids_json,created_at=excluded.created_at,mode=excluded.mode", (
                brief_id, incident["agent_id"], incident["run_id"], title, body, encode(citations), current["created_at"] if same_receipt else now(), "investigation_report"))
            if not same_receipt:
                self.core._event(db, "security_investigation_report_published", self.core._run(db, incident["run_id"]),
                                 incident_id=incident_id, action_id=brief_id, tool="publish_investigation_report",
                                 tool_category="app_publish", decision="incomplete_status_report_published" if incomplete else "advisory_report_published",
                                 completed_experiments=len(completed), failed_experiments=failed,
                                 session_id=sandbox["session_id"], run_purpose="security_operations")
            return self._brief(db, db.execute("SELECT * FROM security_briefs WHERE brief_id=?", (brief_id,)).fetchone())

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
                poll_kwargs = {"expected_snapshot_hash": previous.get("snapshot_hash"), "incident_id": incident["incident_id"]}
                if previous.get("rca_packet") is not None:
                    poll_kwargs["expected_packet"] = previous["rca_packet"]
                result = self.sandbox.poll(previous["session_id"], previous.get("next_cursor"), **poll_kwargs)
                if not isinstance(result, dict) or result.get("state") not in {"pending", "reported", "completed", "failed"}:
                    raise ValueError("Invalid hosted poll result")
                if (previous.get("rca_packet") is not None and result["state"] in {"reported", "completed"}
                        and not self._bound_report(result.get("result"), previous.get("snapshot_hash"),
                                                   incident["incident_id"], previous["rca_packet"])):
                    result.update(state="failed", error="Hosted RCA report did not match the persisted experiment packet")
                if result["state"] == "pending" and result.get("result") is None:
                    retained = previous.get("result")
                    if self._bound_report(retained, previous.get("snapshot_hash"), incident["incident_id"], previous.get("rca_packet")):
                        result["result"] = retained
                        if result.get("isolation_verified") is True and result.get("remote_terminal_verified") is True:
                            result["state"] = "reported"
                            result["error"] = None
                retryable = result.get("poll_retryable") is True
                failures = previous.get("poll_failures", 0) + 1 if retryable else 0
                result = {**previous, **result, "poll_failures": failures,
                          "next_poll_at": later(min(60, 10 * max(1, failures)) if retryable else 10)}
            except Exception as exc:
                failures = previous.get("poll_failures", 0) + 1
                result = {**previous, "state": "pending", "poll_failures": failures,
                          "next_poll_at": later(min(60, 10 * failures)), "error": None,
                          "poll_retryable": True,
                          "poll_warning": f"Read-only Guild polling is temporarily delayed ({type(exc).__name__}); the existing session is preserved"}
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
                if result.get("remote_terminal_verified") is True:
                    result.update({"state": "failed", "operator_action_required": True,
                                   "error": "Guild root task is terminal, but required bound replay or isolation evidence was unavailable before the polling deadline. Review this exact session; no automatic rerun."})
                else:
                    result.update({"state": "deadline_expired", "operator_action_required": True,
                                   "remote_termination_verified": False,
                                   "error": "Polling deadline reached; hosted execution may continue. End this exact session in Guild UI and reconcile before rerun."})
            state = "waiting_sandbox" if result["state"] == "pending" else "review_required" if result["state"] == "reported" else "reconciliation_required" if result["state"] == "deadline_expired" else result["state"]
            qwen = investigation.get("qwen")
            guild = {"state": result["state"], "session_id": previous["session_id"], "advisory_only": True,
                     "poll_warning": result.get("poll_warning"),
                     "isolation_verified": result.get("isolation_verified", False),
                     "replay_execution_verified": result.get("replay_execution_verified", False), "runtimes": result.get("runtimes", []),
                     "replies": [{"state": "reported" if state == "review_required" else "validated", "advisory_only": True, "result": result.get("result")}] if state in {"completed", "review_required"} else []}
            if state in {"completed", "review_required"}:
                qwen = model.advisory(self.inference, self.settings.judge_model or self.settings.agent_model,
                                      incident["snapshot"], result)
                qwen["replay_execution_verified"] = result.get("replay_execution_verified", False)
                if state == "review_required":
                    qwen["limitation"] = "Hypothesis only: hosted worker execution is not independently verified; root cause is not established"
            elif state in {"failed", "reconciliation_required"}:
                qwen = {"state": "not_run", "advisory_only": True, "error": "Hosted investigation failed; no verified execution evidence is available"}
            with self.store.transaction() as db:
                db.execute("UPDATE security_investigations SET state=?,sandbox_json=?,guild_json=?,qwen_json=?,updated_at=?,error=? WHERE incident_id=?", (
                    state, encode(result), encode(guild), encode(qwen), now(), result.get("error"), investigation["incident_id"]))
                if state != "waiting_sandbox":
                    self.core._event(db, "security_investigation_completed", self.core._run(db, incident["run_id"]), incident_id=incident["incident_id"], decision="advisory_only", sandbox_state=state, isolation_verified=result.get("isolation_verified", False), run_purpose="security_operations")
            if state in {"completed", "review_required"}:
                self.publish_investigation_report(incident["incident_id"])
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
