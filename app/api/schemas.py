from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunRequest(Request):
    scenario: Literal["immediate", "dormant", "benign", "recovery"] = "dormant"
    control_mode: Literal["full_system", "ingestion_filter_only", "unguarded"] = "full_system"
    planner_mode: Literal["recorded", "live"] = "recorded"
    replacement_memory_id: str | None = None


class QuarantineRequest(Request):
    reason: str = Field(min_length=1, max_length=500)


class ReplacementRequest(Request):
    run_id: str
    content: str = Field(min_length=1, max_length=100_000)


class ActionRequest(Request):
    run_id: str
    context_id: str
    recipient: str
    report_id: str = "weekly_report"
    tool: str = "send_report"
    action_id: str | None = None


class InvestigationRequest(Request):
    provider: Literal["akash", "guild", "recorded"] = "akash"
