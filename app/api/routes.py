from fastapi import APIRouter, Body, Query

from app.api.schemas import (ActionRequest, InvestigationRequest, QuarantineRequest,
                             ReplacementRequest, RunRequest)
from app.integrations.judge import AdvisoryJudge, RecordedJudge


def create_router(service, runner, settings, akash, guild, analytics, exporter,
                  sandbox=None, slack=None, worker_status=None):
    router = APIRouter(prefix="/api")

    @router.get("/health")
    def health():
        def status(client):
            value = client.readiness()
            value["status"] = ("verified" if value["verified"] else
                               "configured" if value["configured"] else "unconfigured")
            return value
        primary_guild = sandbox.guild if sandbox is not None else guild
        integrations = {"akash": status(akash), "guild": status(primary_guild), "clickhouse": status(analytics)}
        if sandbox is not None:
            integrations["sandbox"] = status(sandbox)
        if slack is not None:
            integrations["slack"] = status(slack)
        return {"status": "ok", "simulated_delivery": True,
                "worker": worker_status, "integrations": integrations}

    @router.get("/runs")
    def runs():
        return {"items": service.list_runs()}

    @router.post("/runs", status_code=201)
    def start_run(body: RunRequest):
        return runner.run(**body.model_dump())

    @router.get("/runs/{run_id}")
    def get_run(run_id: str):
        return service.get_run(run_id)

    @router.get("/memories")
    def memories(namespace_id: str | None = None):
        return {"items": service.list_memories(namespace_id)}

    @router.get("/memories/{memory_id}")
    def memory(memory_id: str):
        return service.get_memory(memory_id)

    @router.get("/memories/{memory_id}/lineage")
    def lineage(memory_id: str):
        return service.lineage(memory_id)

    @router.post("/memories/{memory_id}/quarantine")
    def quarantine(memory_id: str, body: QuarantineRequest):
        return service.quarantine_memory(memory_id, body.reason)

    @router.post("/memories/{memory_id}/replace", status_code=201)
    def replace(memory_id: str, body: ReplacementRequest):
        return service.replace_memory(memory_id, body.run_id, body.content)

    @router.post("/actions/propose")
    def propose(body: ActionRequest):
        return service.propose_action(**body.model_dump())

    @router.get("/incidents")
    def incidents():
        return {"items": service.list_incidents()}

    @router.get("/incidents/{incident_id}")
    def incident(incident_id: str):
        return service.get_incident(incident_id)

    @router.post("/incidents/{incident_id}/investigate")
    def investigate(incident_id: str, body: InvestigationRequest = Body(default=InvestigationRequest())):
        snapshot = service.get_snapshot(incident_id)
        if body.provider == "guild":
            from app.integrations.common import IntegrationUnavailable
            raise IntegrationUnavailable("Use Operations investigation for the approved bounded Guild evidence payload; legacy raw snapshot export is disabled")
        if body.provider == "recorded":
            judge = RecordedJudge({"score": 80, "finding": "suspicious",
                "rationale": "Recorded annotation: inspect untrusted ancestry and the deterministic rule violation. This is not a live model finding.",
                "evidence_ids": [incident_id]})
        else:
            judge = AdvisoryJudge(akash, settings.judge_model)
        result = judge.analyze(snapshot, snapshot["evidence_ids"]).as_dict()
        result["evidence_ids"] = list(result.get("evidence_ids") or [])
        return service.record_analysis(snapshot["run_id"], result, incident_id,
            mode=result["mode"], provider=result["provider"], model=result["model"],
            allowed_evidence_ids=snapshot["evidence_ids"])

    @router.get("/events")
    def events(limit: int = Query(default=100, ge=1, le=5000)):
        return {"items": service.list_events(limit)}

    @router.get("/analytics")
    def get_analytics(namespace_id: str | None = None):
        local = service.analytics_local()
        counts = local["counts"]
        result = {**local, "total_events": counts["audit_events"],
                  "blocked_actions": counts["blocked_actions"],
                  "executed_actions": counts["executed_actions"],
                  "memory_count": counts["memories"], "incident_count": counts["incidents"]}
        if analytics.readiness()["configured"]:
            if namespace_id is None:
                recent_runs = service.list_runs()
                namespace_id = recent_runs[0]["namespace_id"] if recent_runs else None
            if namespace_id is None:
                return {**result, "status": "clickhouse_configured_no_runs"}
            try:
                metrics = analytics.metrics(namespace_id)
                rows = metrics["rows"]
                values = rows[0] if rows else {}
                result.update(total_events=values.get("unique_events", 0),
                              blocked_actions=values.get("blocked_actions", 0),
                              executed_actions=values.get("executed_actions", 0),
                              ingestion_lag_ms=values.get("delivery_lag_p95_ms"),
                              query_latency_ms=metrics["query_ms"], namespace_id=namespace_id)
                result["source_rankings"] = analytics.source_rankings(namespace_id)["rows"]
                result["source"] = "clickhouse"
                result["status"] = "live"
            except Exception:
                result["status"] = "clickhouse_unavailable"
        return result

    @router.get("/integrations/akash/models")
    def models():
        return {"items": akash.discover_models()}

    @router.post("/integrations/clickhouse/initialize")
    def initialize_clickhouse():
        return analytics.initialize_schema()

    @router.post("/integrations/clickhouse/export")
    def export():
        return exporter.flush()

    @router.get("/integrations/clickhouse/timeline")
    def timeline(namespace_id: str, run_id: str):
        result = analytics.timeline(namespace_id, run_id)
        return {"items": result["rows"], "query_latency_ms": result["query_ms"]}

    @router.get("/integrations/guild/conversations/{session_id}")
    def guild_session(session_id: str):
        return guild.poll(session_id)

    return router
