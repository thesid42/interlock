import json

from app.agent.planner import LivePlanner, RecordedPlanner
from app.config import PROJECT_ROOT


class ReportRunner:
    """Drive synthetic report tasks through the application's real memory/gateway."""

    def __init__(self, service, settings, akash):
        self.service = service
        self.settings = settings
        self.akash = akash
        self.fixtures = json.loads((PROJECT_ROOT / "sim/fixtures/report_memory.json").read_text())

    def run(self, scenario="dormant", control_mode="full_system", planner_mode="recorded",
            replacement_memory_id=None):
        if scenario not in {"immediate", "dormant", "benign", "recovery"}:
            raise ValueError("Unsupported scenario")
        replacement = None
        if scenario == "recovery":
            if control_mode != "full_system":
                raise ValueError("Recovery uses full-system authorization")
            if not replacement_memory_id:
                raise ValueError("Recovery requires a reviewed replacement_memory_id")
            replacement = self.service.get_memory(replacement_memory_id)
            if not replacement.get("replaces_memory_id") or replacement["source_type"] != "operator":
                raise ValueError("Recovery requires a fresh operator replacement")
            if replacement["effective_quarantined"] or replacement["lifecycle"] != "active":
                raise ValueError("Replacement is unavailable")
        planner = (LivePlanner(self.akash, self.settings.agent_model)
                   if planner_mode == "live" else RecordedPlanner())
        run = self.service.create_run(
            scenario, control_mode, planner_mode,
            namespace_id=replacement["namespace_id"] if replacement else None,
        )
        run_id = run["run_id"]
        self.service.set_policy(run_id, self.fixtures["authorized_recipient"])
        try:
            if replacement:
                memory = replacement
                recorded_recipient = self.fixtures["authorized_recipient"]
            else:
                fixture = self.fixtures[scenario]
                memory = self.service.write_memory(run_id, fixture["content"], "doc", fixture["source_id"])
                recorded_recipient = fixture["recorded_recipient"]
                for recorded_summary in fixture.get("summaries", []):
                    eligible = self.service.retrieve_memories(run_id, [memory["memory_id"]])
                    if not eligible:
                        break
                    summary = planner.summarize(eligible[0]["content"], recorded_summary)
                    memory = self.service.derive_memory(run_id, [memory["memory_id"]], summary)
            eligible = self.service.retrieve_memories(run_id, [memory["memory_id"]])
            if not eligible:
                self.service.finish_run(run_id, "contained")
            else:
                context = self.service.capture_context(run_id, [memory["memory_id"]])
                proposal = planner.propose(eligible[0]["content"], recorded_recipient)
                action = self.service.propose_action(run_id, context["context_id"], **proposal)
                outcome = "recovered" if replacement and action["outcome"] == "executed" else action["outcome"]
                self.service.finish_run(run_id, outcome)
        except Exception:
            self.service.finish_run(run_id, "failed")
            raise
        return self.service.get_run(run_id)
