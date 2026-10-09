from fastapi import APIRouter
from pydantic import Field

from app.api.schemas import Request


class AgentRequest(Request):
    name: str = Field(min_length=1, max_length=80)
    mission: str = Field(min_length=10, max_length=2000)
    source_urls: list[str] = Field(min_length=1, max_length=4)
    interval_seconds: int = Field(default=900, ge=60, le=86400)


class ResolutionRequest(Request):
    reason: str = Field(min_length=10, max_length=1000)


def create_operations_router(operations, inference, settings, guild, sandbox, slack):
    router = APIRouter(prefix="/api")

    @router.get("/operations")
    def summary():
        return operations.summary()

    @router.post("/operations/agents", status_code=201)
    def create_agent(body: AgentRequest):
        return operations.create_agent(**body.model_dump())

    @router.get("/operations/agents/{agent_id}")
    def agent(agent_id: str):
        return operations.get_agent(agent_id)

    @router.post("/operations/agents/{agent_id}/pause")
    def pause(agent_id: str):
        return operations.set_agent_state(agent_id, "paused", "Operator paused execution")

    @router.post("/operations/agents/{agent_id}/resume")
    def resume(agent_id: str):
        return operations.set_agent_state(agent_id, "active", "Operator resumed execution")

    @router.post("/operations/agents/{agent_id}/run", status_code=202)
    def run(agent_id: str):
        return operations.queue_run(agent_id)

    @router.post("/operations/demo", status_code=201)
    def demo():
        return operations.create_demo()

    @router.get("/operations/incidents/{incident_id}")
    def incident(incident_id: str):
        return operations.get_incident(incident_id)

    @router.post("/operations/incidents/{incident_id}/investigate", status_code=202)
    def investigate(incident_id: str):
        return operations.queue_investigation(incident_id)

    @router.post("/operations/incidents/{incident_id}/resolve")
    def resolve(incident_id: str, body: ResolutionRequest):
        return operations.resolve_incident(incident_id, body.reason)

    @router.get("/integrations/inference/models")
    def models():
        return {"items": inference.discover_models()}

    @router.post("/integrations/inference/check")
    def check_inference():
        return inference.check_inference()

    @router.post("/integrations/sandbox/check")
    def check_sandbox():
        return sandbox.check()

    @router.get("/integrations/slack/tools")
    def slack_tools():
        return {"items": slack.discover_tools()}

    @router.post("/integrations/slack/check")
    def check_slack():
        tools = slack.discover_tools()
        return {"state": "verified", "tool_count": len(tools), "readiness": slack.readiness()}

    @router.post("/integrations/guild/check")
    def check_guild():
        client = sandbox.guild if sandbox.guild.configured else guild
        if not client.configured:
            from app.integrations.common import IntegrationUnavailable
            raise IntegrationUnavailable("Configure the Guild account key, workspace and published investigator first")
        client.installed_agents()
        return {"state": "reachable", "readiness": client.readiness(),
                "detail": "Workspace access checked; hosted investigation is verified by an actual session."}

    return router
