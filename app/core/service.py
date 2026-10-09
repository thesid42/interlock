"""Local application services for memory, investigation, and simulated dispatch."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.storage.sqlite import AuditRejection, SQLiteStore
from .policy import explicit_routing, fingerprint, valid_recipient


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class MemGuardService:
    def __init__(self, db_path: str | Path):
        self.store = SQLiteStore(db_path)

    def _run(self, db, run_id):
        row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown run: {run_id}")
        return dict(row)

    def _event(self, db, event_type, run=None, **values):
        timestamp = now()
        payload = {
            "event_id": new_id("evt"), "event_ts": timestamp,
            "recorded_ts": timestamp, "event_type": event_type,
            "namespace_id": "", "run_id": "", "task_id": "", "agent_id": "",
            "memory_id": "", "source_id": "", "source_type": "", "trust": "",
            "root_ids": [], "parent_ids": [], "context_memory_ids": [],
            "action_id": "", "context_id": "", "incident_id": "",
            "control_mode": "", "planner_mode": "", "rule": "", "decision": "",
        }
        if run:
            for key in ("namespace_id", "run_id", "task_id", "agent_id", "control_mode", "planner_mode"):
                payload[key] = run[key]
        payload.update(values)
        cursor = db.execute(
            "INSERT INTO audit_events(event_id,event_ts,recorded_ts,event_type,payload_json) VALUES(?,?,?,?,?)",
            (payload["event_id"], timestamp, timestamp, event_type, "{}"),
        )
        payload["event_seq"] = cursor.lastrowid
        db.execute("UPDATE audit_events SET payload_json=? WHERE event_id=?",
                   (json.dumps(payload), payload["event_id"]))
        db.execute("INSERT INTO outbox(event_id) VALUES(?)", (payload["event_id"],))
        return payload

    def _reject(self, db, run, reason, event_type="provenance_reject", **values):
        self._event(db, event_type, run, decision="blocked", reason=reason, **values)
        raise AuditRejection(reason)

    def create_run(self, scenario="dormant", control_mode="full_system", planner_mode="recorded",
                   namespace_id=None, task_id="weekly_report"):
        if control_mode not in {"full_system", "ingestion_filter_only", "unguarded"}:
            raise ValueError("Unsupported control mode")
        if planner_mode not in {"recorded", "live"}:
            raise ValueError("Unsupported planner mode")
        run = dict(run_id=new_id("run"), namespace_id=namespace_id or new_id("ns"),
                   task_id=task_id, agent_id="report_assistant", scenario=scenario,
                   control_mode=control_mode, planner_mode=planner_mode, created_at=now(),
                   finished_at=None, outcome="running")
        with self.store.transaction() as db:
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?)", tuple(run.values()))
            self._event(db, "run_create", run)
        return run

    def list_runs(self):
        with self.store.transaction() as db:
            return [dict(row) for row in db.execute("SELECT * FROM runs ORDER BY created_at DESC")]

    def get_run(self, run_id):
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            run["memories"] = [self._memory(db, row[0]) for row in db.execute("SELECT memory_id FROM memories WHERE namespace_id=? ORDER BY created_at", (run["namespace_id"],))]
            for key in ("actions", "deliveries", "incidents", "contexts"):
                run[key] = [dict(row) for row in db.execute(f"SELECT * FROM {key} WHERE run_id=? ORDER BY created_at", (run_id,))]
            for context in run["contexts"]:
                context["memory_ids"] = [row[0] for row in db.execute("SELECT memory_id FROM context_memories WHERE context_id=?", (context["context_id"],))]
            row = db.execute("SELECT * FROM task_policies WHERE run_id=? ORDER BY version DESC LIMIT 1", (run_id,)).fetchone()
            run["policy"] = dict(row) if row else None
            run["analyses"] = [self._analysis(row) for row in db.execute("SELECT * FROM analyses WHERE run_id=? ORDER BY created_at", (run_id,))]
            return run

    def finish_run(self, run_id, outcome):
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            db.execute("UPDATE runs SET outcome=?,finished_at=? WHERE run_id=?", (outcome, now(), run_id))
            self._event(db, "run_finish", run, decision=outcome)
            return self._run(db, run_id)

    def _ancestors(self, db, memory_id):
        return [row[0] for row in db.execute(
            "WITH RECURSIVE ancestors(id) AS (SELECT ? UNION SELECT e.parent_id FROM memory_edges e JOIN ancestors a ON e.child_id=a.id) SELECT id FROM ancestors",
            (memory_id,),
        )]

    def _memory(self, db, memory_id):
        row = db.execute(
            "SELECT m.*,s.lifecycle,s.replacement_id FROM memories m JOIN memory_state s USING(memory_id) WHERE m.memory_id=?",
            (memory_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown memory: {memory_id}")
        memory = dict(row)
        memory["parents"] = [r[0] for r in db.execute("SELECT parent_id FROM memory_edges WHERE child_id=? ORDER BY parent_id", (memory_id,))]
        ancestors = self._ancestors(db, memory_id)
        roots = []
        restrictions = []
        for ancestor_id in ancestors:
            if not db.execute("SELECT 1 FROM memory_edges WHERE child_id=?", (ancestor_id,)).fetchone():
                roots.append(ancestor_id)
            restrictions.extend(dict(r) for r in db.execute("SELECT * FROM restrictions WHERE memory_id=?", (ancestor_id,)))
        memory["roots"] = sorted(roots)
        memory["effective_quarantined"] = bool(restrictions)
        memory["restrictions"] = restrictions
        memory["quarantined"] = any(r["memory_id"] == memory_id for r in restrictions)
        return memory

    def _memory_values(self, memory):
        return dict(memory_id=memory["memory_id"], source_id=memory["source_id"],
                    source_type=memory["source_type"], trust=memory["trust_tier"],
                    root_ids=memory["roots"], parent_ids=memory["parents"],
                    generation=memory["generation"], preview=memory["content"][:512])

    def _unavailable(self, memory, control_mode):
        if memory["lifecycle"] != "active":
            return True
        if control_mode == "full_system":
            return memory["effective_quarantined"]
        if control_mode == "ingestion_filter_only":
            return memory["quarantined"]
        return False

    def _incident(self, db, run, rule, reason, memory_id=None, action_id=None):
        incident = dict(incident_id=new_id("inc"), run_id=run["run_id"], rule=rule,
                        memory_id=memory_id, action_id=action_id, status="open",
                        reason=reason, created_at=now())
        db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?)", tuple(incident.values()))
        self._event(db, "incident_open", run, incident_id=incident["incident_id"],
                    memory_id=memory_id or "", action_id=action_id or "", rule=rule, reason=reason)
        return incident

    def _write(self, db, run, content, source_type, source_id, parent_ids, replaces_memory_id=None):
        if source_type not in {"doc", "tool", "agent", "operator"}:
            self._reject(db, run, "Unsupported source type", rule="R5")
        if not isinstance(content, str) or not content.strip() or len(content) > 100_000:
            self._reject(db, run, "Memory content must contain 1-100000 characters", rule="R5")
        parent_ids = list(dict.fromkeys(parent_ids or []))
        parents = []
        for parent_id in parent_ids:
            try:
                parent = self._memory(db, parent_id)
            except KeyError:
                self._reject(db, run, "Unknown parent memory", parent_ids=parent_ids, rule="R5")
            if parent["namespace_id"] != run["namespace_id"]:
                self._reject(db, run, "Parent belongs to another namespace", parent_ids=parent_ids, rule="R5")
            if self._unavailable(parent, run["control_mode"]):
                self._reject(db, run, "Parent is unavailable for summarization", event_type="summary_block",
                             parent_ids=parent_ids, memory_id=parent_id, rule="R4")
            parents.append(parent)
        trust = "trusted" if source_type == "operator" else "untrusted"
        if parents:
            trust = "trusted" if all(p["trust_tier"] == "trusted" for p in parents) else "untrusted"
            source_type = "agent"
        memory_id = new_id("mem")
        generation = 1 + max(p["generation"] for p in parents) if parents else 0
        db.execute("INSERT INTO memories VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (memory_id, run["run_id"], run["namespace_id"], source_type, source_id,
                    trust, content, hashlib.sha256(content.encode()).hexdigest(), generation,
                    now(), replaces_memory_id))
        db.execute("INSERT INTO memory_state(memory_id) VALUES(?)", (memory_id,))
        db.executemany("INSERT INTO memory_edges VALUES(?,?)", [(p, memory_id) for p in parent_ids])
        memory = self._memory(db, memory_id)
        self._event(db, "summary_create" if parents else "memory_write", run, **self._memory_values(memory))
        if trust == "untrusted" and run["control_mode"] != "unguarded" and explicit_routing(content):
            reason = "Untrusted content contains an explicit routing directive and destination"
            db.execute("INSERT INTO restrictions VALUES(?,?,?,?,?)", (new_id("res"), memory_id, "R1", reason, now()))
            incident = self._incident(db, run, "R1", reason, memory_id=memory_id)
            self._event(db, "memory_quarantine", run, **self._memory_values(memory), rule="R1",
                        reason=reason, decision="quarantined", incident_id=incident["incident_id"])
            memory = self._memory(db, memory_id)
            memory["incident_id"] = incident["incident_id"]
        if generation >= 2:
            self._event(db, "analysis_requested", run, **self._memory_values(memory), rule="R3",
                        decision="advisory_only", analysis_mode="unavailable")
        return memory

    def write_memory(self, run_id, content, source_type="doc", source_id="fixture", parent_ids=None):
        with self.store.transaction() as db:
            return self._write(db, self._run(db, run_id), content, source_type, source_id, parent_ids)

    def derive_memory(self, run_id, parent_ids, content):
        if not parent_ids:
            raise ValueError("A summary must have at least one parent")
        return self.write_memory(run_id, content, "agent", "summary", parent_ids)

    def get_memory(self, memory_id):
        with self.store.transaction() as db:
            return self._memory(db, memory_id)

    def list_memories(self, namespace_id=None):
        with self.store.transaction() as db:
            query = "SELECT memory_id FROM memories"
            args = ()
            if namespace_id:
                query += " WHERE namespace_id=?"
                args = (namespace_id,)
            return [self._memory(db, row[0]) for row in db.execute(query + " ORDER BY created_at DESC", args)]

    def lineage(self, memory_id):
        with self.store.transaction() as db:
            memory = self._memory(db, memory_id)
            nodes = [self._memory(db, ancestor) for ancestor in self._ancestors(db, memory_id)]
            edges = [{"parent_id": parent, "child_id": node["memory_id"]} for node in nodes for parent in node["parents"]]
            return dict(nodes=nodes, edges=edges, root_ids=memory["roots"])

    def retrieve_memories(self, run_id, memory_ids=None):
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            if memory_ids is None:
                memory_ids = [row[0] for row in db.execute("SELECT memory_id FROM memories WHERE namespace_id=?", (run["namespace_id"],))]
            result = []
            for memory_id in memory_ids:
                memory = self._memory(db, memory_id)
                if memory["namespace_id"] != run["namespace_id"]:
                    self._reject(db, run, "Memory belongs to another namespace", rule="R5")
                unavailable = self._unavailable(memory, run["control_mode"])
                self._event(db, "memory_read", run, **self._memory_values(memory),
                            decision="blocked" if unavailable else "allowed", rule="R4" if unavailable else "")
                if not unavailable:
                    result.append(memory)
            return result

    def capture_context(self, run_id, memory_ids):
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            memory_ids = list(dict.fromkeys(memory_ids))
            roots = set()
            for memory_id in memory_ids:
                memory = self._memory(db, memory_id)
                if memory["namespace_id"] != run["namespace_id"] or self._unavailable(memory, run["control_mode"]):
                    self._reject(db, run, "Context includes unavailable or foreign memory", event_type="context_block", rule="R4", memory_id=memory_id)
                roots.update(memory["roots"])
            context = dict(context_id=new_id("ctx"), run_id=run_id, task_id=run["task_id"],
                           namespace_id=run["namespace_id"], created_at=now(), memory_ids=memory_ids)
            db.execute("INSERT INTO contexts VALUES(?,?,?,?,?)", tuple(context[k] for k in ("context_id", "run_id", "task_id", "namespace_id", "created_at")))
            db.executemany("INSERT INTO context_memories VALUES(?,?)", [(context["context_id"], m) for m in memory_ids])
            self._event(db, "context_capture", run, context_id=context["context_id"],
                        context_memory_ids=memory_ids, root_ids=sorted(roots))
            return context

    def set_policy(self, run_id, recipient, report_id="weekly_report"):
        recipient = recipient.strip().lower()
        if not valid_recipient(recipient):
            raise ValueError("Invalid policy recipient")
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM task_policies WHERE run_id=?", (run_id,)).fetchone()[0]
            policy = dict(policy_id=new_id("pol"), run_id=run_id, version=version,
                          tool="send_report", report_id=report_id, recipient=recipient,
                          origin="trusted_runtime", created_at=now())
            db.execute("INSERT INTO task_policies VALUES(?,?,?,?,?,?,?,?)", tuple(policy.values()))
            self._event(db, "policy_change", run, policy_version=version, recipient=recipient, report_id=report_id)
            return policy

    def get_policy(self, run_id):
        with self.store.transaction() as db:
            self._run(db, run_id)
            row = db.execute("SELECT * FROM task_policies WHERE run_id=? ORDER BY version DESC LIMIT 1", (run_id,)).fetchone()
            return dict(row) if row else None

    def propose_action(self, run_id, context_id, recipient, report_id="weekly_report", tool="send_report", action_id=None):
        recipient = recipient.strip().lower()
        action_id = action_id or new_id("act")
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            proposal = dict(run_id=run_id, namespace_id=run["namespace_id"], task_id=run["task_id"],
                            context_id=context_id, tool=tool, recipient=recipient, report_id=report_id)
            proposal_hash = fingerprint(proposal)
            existing = db.execute("SELECT * FROM actions WHERE action_id=?", (action_id,)).fetchone()
            if existing:
                if existing["fingerprint"] != proposal_hash:
                    self._reject(db, run, "Action ID is already bound to different arguments", event_type="action_retry_reject", action_id=action_id)
                return dict(existing)
            context = db.execute("SELECT * FROM contexts WHERE context_id=?", (context_id,)).fetchone()
            ids = [row[0] for row in db.execute("SELECT memory_id FROM context_memories WHERE context_id=?", (context_id,))]
            context_matches = context and all(context[k] == run[k] for k in ("run_id", "task_id", "namespace_id"))
            roots = set()
            reason = "Authorized by current task policy"
            blocked = False
            if not context_matches:
                reason, blocked = "Context does not belong to this run and task", True
                ids = []
            else:
                for memory_id in ids:
                    memory = self._memory(db, memory_id)
                    roots.update(memory["roots"])
                    if self._unavailable(memory, run["control_mode"]):
                        reason, blocked = "Context contains quarantined or superseded memory", True
            row = db.execute("SELECT * FROM task_policies WHERE run_id=? ORDER BY version DESC LIMIT 1", (run_id,)).fetchone()
            policy = dict(row) if row else None
            if tool != "send_report" or not valid_recipient(recipient) or not report_id:
                reason, blocked = "Unsupported tool or invalid tool arguments", True
            if run["control_mode"] == "full_system" and not blocked:
                if not policy:
                    reason, blocked = "No trusted task policy", True
                elif any(proposal[k] != policy[k] for k in ("tool", "recipient", "report_id")):
                    reason, blocked = "Proposed destination or report does not match trusted task policy", True
            if run["control_mode"] != "full_system" and not blocked:
                reason = "Isolated comparison simulation; pre-action authorization disabled"
            event_values = dict(action_id=action_id, context_id=context_id, context_memory_ids=ids,
                                root_ids=sorted(roots), tool=tool, tool_category="send", recipient=recipient,
                                report_id=report_id, policy_version=policy["version"] if policy else None)
            self._event(db, "action_propose", run, **event_values)
            incident = self._incident(db, run, "R2", reason, action_id=action_id) if blocked else None
            action = dict(action_id=action_id, run_id=run_id, context_id=context_id,
                          fingerprint=proposal_hash, tool=tool, recipient=recipient, report_id=report_id,
                          policy_version=policy["version"] if policy else None,
                          outcome="blocked" if blocked else "executed", reason=reason,
                          incident_id=incident["incident_id"] if incident else None, created_at=now())
            db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", tuple(action.values()))
            if not blocked:
                db.execute("INSERT INTO deliveries VALUES(?,?,?,?,?,?,1)",
                           (new_id("delivery"), action_id, run_id, recipient, report_id, now()))
            self._event(db, "action_block" if blocked else "action_execute", run,
                        **event_values, decision=action["outcome"], reason=reason,
                        incident_id=action["incident_id"] or "", rule="R2" if blocked else "")
            return action

    def list_actions(self, run_id):
        with self.store.transaction() as db:
            self._run(db, run_id)
            return [dict(row) for row in db.execute("SELECT * FROM actions WHERE run_id=? ORDER BY created_at", (run_id,))]

    def list_deliveries(self, run_id):
        with self.store.transaction() as db:
            self._run(db, run_id)
            return [dict(row) for row in db.execute("SELECT * FROM deliveries WHERE run_id=? ORDER BY created_at", (run_id,))]

    def quarantine_memory(self, memory_id, reason):
        if not reason.strip():
            raise ValueError("Containment requires a reason")
        with self.store.transaction() as db:
            memory = self._memory(db, memory_id)
            run = self._run(db, memory["run_id"])
            if not memory["quarantined"]:
                db.execute("INSERT INTO restrictions VALUES(?,?,?,?,?)", (new_id("res"), memory_id, "operator", reason, now()))
                self._event(db, "memory_quarantine", run, **self._memory_values(memory), rule="operator", decision="quarantined", reason=reason)
            db.execute("UPDATE incidents SET status='contained' WHERE memory_id=? AND status='open'", (memory_id,))
            result = self._memory(db, memory_id)
            result["affected_descendant_count"] = db.execute(
                "WITH RECURSIVE children(id) AS (SELECT ? UNION SELECT e.child_id FROM memory_edges e JOIN children c ON e.parent_id=c.id) SELECT COUNT(*)-1 FROM children", (memory_id,),
            ).fetchone()[0]
            return result

    def replace_memory(self, memory_id, run_id, content):
        with self.store.transaction() as db:
            original = self._memory(db, memory_id)
            run = self._run(db, run_id)
            if original["namespace_id"] != run["namespace_id"]:
                self._reject(db, run, "Replacement belongs to another namespace", rule="R5")
            replacement = self._write(db, run, content, "operator", "reviewed_operator_input", [], memory_id)
            db.execute("UPDATE memory_state SET lifecycle='superseded',replacement_id=? WHERE memory_id=?", (replacement["memory_id"], memory_id))
            self._event(db, "memory_supersede", run, **self._memory_values(original),
                        replacement_id=replacement["memory_id"], decision="superseded")
            return replacement

    def list_incidents(self):
        with self.store.transaction() as db:
            return [dict(row) for row in db.execute("SELECT * FROM incidents ORDER BY created_at DESC")]

    def get_incident(self, incident_id):
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown incident: {incident_id}")
            incident = dict(row)
            incident["analyses"] = [self._analysis(r) for r in db.execute("SELECT * FROM analyses WHERE incident_id=? ORDER BY created_at", (incident_id,))]
        incident["run"] = self.get_run(incident["run_id"])
        if incident["memory_id"]:
            incident["memory"] = self.get_memory(incident["memory_id"])
            incident["lineage"] = self.lineage(incident["memory_id"])
        if incident["action_id"]:
            incident["action"] = next((a for a in incident["run"]["actions"] if a["action_id"] == incident["action_id"]), None)
        return incident

    def get_snapshot(self, incident_id):
        incident = self.get_incident(incident_id)
        run = incident["run"]
        memories = run["memories"]
        evidence_ids = [incident_id, run["run_id"]] + [m["memory_id"] for m in memories]
        evidence_ids += [a["action_id"] for a in run["actions"]]
        return {"incident_id": incident_id, "run_id": run["run_id"], "rule": incident["rule"],
                "reason": incident["reason"], "policy": run["policy"], "actions": run["actions"],
                "memories": [{k: m[k] for k in ("memory_id", "content", "source_type", "trust_tier", "parents", "roots", "effective_quarantined")} for m in memories],
                "evidence_ids": evidence_ids, "simulated": True}

    def _analysis(self, row):
        result = dict(row)
        payload = json.loads(result.pop("payload_json"))
        return {**payload, **result}

    def record_analysis(self, run_id, result, incident_id=None, mode="recorded", provider="recorded", model=None, allowed_evidence_ids=None):
        if mode not in {"recorded", "live", "unavailable"}:
            raise ValueError("Unsupported analysis mode")
        payload = dict(result)
        state = payload.get("state", "completed")
        if state == "completed":
            valid = (payload.get("finding") in {"benign", "suspicious", "uncertain"}
                     and type(payload.get("score")) is int and 0 <= payload["score"] <= 100
                     and isinstance(payload.get("rationale"), str)
                     and isinstance(payload.get("evidence_ids", []), list))
            if allowed_evidence_ids is not None:
                valid = valid and all(isinstance(e, str) and e in allowed_evidence_ids for e in payload.get("evidence_ids", []))
            if not valid:
                payload = {"state": "failed", "error": "Invalid advisory schema or evidence references"}
                state = "failed"
        with self.store.transaction() as db:
            run = self._run(db, run_id)
            if incident_id:
                incident = db.execute("SELECT run_id FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
                if not incident or incident["run_id"] != run_id:
                    self._reject(db, run, "Analysis incident does not belong to this run")
            analysis = dict(analysis_id=new_id("ana"), incident_id=incident_id, run_id=run_id,
                            mode=mode, provider=provider, model=model, state=state,
                            payload_json=json.dumps(payload), created_at=now())
            db.execute("INSERT INTO analyses VALUES(?,?,?,?,?,?,?,?,?)", tuple(analysis.values()))
            self._event(db, "analysis_complete" if state == "completed" else "analysis_failure", run,
                        incident_id=incident_id or "", analysis_id=analysis["analysis_id"],
                        analysis_mode=mode, analysis_model=model or "", score=payload.get("score"),
                        rationale=payload.get("rationale", ""), decision="advisory_only")
            return {**payload, **{k: v for k, v in analysis.items() if k != "payload_json"}}

    def list_events(self, limit=100):
        limit = min(max(int(limit), 1), 5000)
        with self.store.transaction() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload_json FROM audit_events ORDER BY event_seq DESC LIMIT ?", (limit,))]

    def analytics_local(self):
        with self.store.transaction() as db:
            counts = {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in ("runs", "memories", "incidents", "deliveries", "audit_events")}
            counts["blocked_actions"] = db.execute("SELECT COUNT(*) FROM actions WHERE outcome='blocked'").fetchone()[0]
            counts["executed_actions"] = db.execute("SELECT COUNT(*) FROM actions WHERE outcome='executed'").fetchone()[0]
            counts["quarantined_memories"] = sum(self._memory(db, row[0])["effective_quarantined"] for row in db.execute("SELECT memory_id FROM memories"))
            backlog = db.execute("SELECT COUNT(*) FROM outbox WHERE exported_at IS NULL").fetchone()[0]
            return {"source": "sqlite", "status": "local_only", "counts": counts,
                    "outbox_backlog": backlog, "source_rankings": [],
                    "query_latency_ms": None, "ingestion_lag_ms": None}
