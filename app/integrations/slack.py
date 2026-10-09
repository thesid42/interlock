"""Official Slack MCP delivery with an operator-pinned tool and fixed destination."""

import asyncio
import hashlib
import json
import re
from datetime import timedelta

import httpx
from jsonschema import Draft202012Validator
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation

from app.integrations.common import IntegrationError, IntegrationUnavailable


SLACK_MCP_URL = "https://mcp.slack.com/mcp"


class SlackMCPClient:
    def __init__(self, settings):
        self.settings = settings
        self._verified = False
        self._detail = "Configured; Slack MCP discovery has not been verified"

    def _configuration_error(self) -> str | None:
        if not self.settings.slack_mcp_access_token:
            return "Missing SLACK_MCP_ACCESS_TOKEN from registered app user OAuth"
        if not re.fullmatch(r"A[A-Z0-9]{8,}", self.settings.slack_mcp_app_id):
            return "Configure the registered SLACK_MCP_APP_ID"
        return None

    def readiness(self) -> dict:
        error = self._configuration_error()
        pin_ready = all((self.settings.slack_mcp_tool_name, self.settings.slack_mcp_tool_schema_hash,
                         self.settings.slack_channel_id, self.settings.slack_workspace_id))
        return {"provider": "slack_mcp", "configured": error is None,
                "verified": self._verified, "detail": error or self._detail,
                "delivery_enabled": self.settings.slack_delivery_enabled,
                "delivery_policy_configured": bool(pin_ready), "endpoint": SLACK_MCP_URL,
                "channel_id": self.settings.slack_channel_id,
                "workspace_id": self.settings.slack_workspace_id,
                "workspace_identity_verified": False}

    @staticmethod
    def _tool_record(tool) -> dict:
        record = {"name": tool.name, "description": tool.description or "",
                  "inputSchema": tool.inputSchema}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > 32768:
            raise IntegrationError("Slack tool schema exceeds the bounded discovery limit")
        return {**record, "schema_hash": hashlib.sha256(encoded).hexdigest()}

    async def _list_tools(self, session) -> list[dict]:
        tools = []
        cursor = None
        for _ in range(4):
            page = await session.list_tools(cursor=cursor)
            tools.extend(self._tool_record(tool) for tool in page.tools)
            if len(tools) > 256:
                raise IntegrationError("Slack tool catalog exceeds the bounded discovery limit")
            cursor = page.nextCursor
            if not cursor:
                return tools
        raise IntegrationError("Slack tool catalog pagination is incomplete")

    async def _operate(self, operation):
        async with asyncio.timeout(self.settings.slack_timeout_seconds):
            async with httpx.AsyncClient(
                    headers={"Authorization": "Bearer " + self.settings.slack_mcp_access_token},
                    timeout=self.settings.slack_timeout_seconds, follow_redirects=False) as http:
                async with streamable_http_client(SLACK_MCP_URL, http_client=http) as streams:
                    async with ClientSession(streams[0], streams[1],
                            read_timeout_seconds=timedelta(seconds=self.settings.slack_timeout_seconds),
                            client_info=Implementation(name="memguard-" + self.settings.slack_mcp_app_id,
                                                       version="0.1.0")) as session:
                        await session.initialize()
                        return await operation(session)

    def discover_tools(self) -> list[dict]:
        error = self._configuration_error()
        if error:
            raise IntegrationUnavailable(error)
        try:
            tools = asyncio.run(self._operate(self._list_tools))
        except Exception:
            self._verified = False
            self._detail = "Slack MCP discovery failed; check app enablement, user token and scopes"
            raise IntegrationError(self._detail) from None
        self._verified = True
        self._detail = "Official Slack MCP discovery verified; no message was sent"
        return tools

    @staticmethod
    def _references_safe(node) -> bool:
        if isinstance(node, dict):
            ref = node.get("$ref")
            return (ref is None or isinstance(ref, str) and ref.startswith("#/")) and all(
                SlackMCPClient._references_safe(value) for value in node.values())
        if isinstance(node, list):
            return all(SlackMCPClient._references_safe(value) for value in node)
        return True

    def _arguments(self, tool: dict, snapshot: dict) -> dict:
        if tool["schema_hash"] != self.settings.slack_mcp_tool_schema_hash:
            raise ValueError("Pinned Slack tool definition changed; operator approval is required")
        schema = tool["inputSchema"]
        if not isinstance(schema, dict) or not self._references_safe(schema):
            raise ValueError("Unsupported Slack tool schema")
        fields = schema.get("properties", {})
        channel_field = "channel_id" if "channel_id" in fields else "channel"
        text_field = "text" if "text" in fields else "message"
        if channel_field not in fields or text_field not in fields:
            raise ValueError("Selected tool is not a supported plain-text message tool")
        for field in (channel_field, text_field):
            if fields[field].get("type") != "string":
                raise ValueError("Unsupported Slack message parameter structure")
        safe_id = lambda value: str(value)[:80] if re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", str(value)) else "withheld"
        incident_id = safe_id(snapshot.get("incident_id", "unknown"))
        agent_id = safe_id(snapshot.get("agent_id", "unknown"))
        run_id = safe_id(snapshot.get("run_id", "unknown"))
        mode = "recorded demonstration" if snapshot.get("mode") == "recorded_demo" else "live monitoring"
        message = ("Interlock security incident contained.\n"
                   f"Incident: {incident_id}\nAgent: {agent_id}\nRun: {run_id}\n"
                   f"Mode: {mode}\nInspect the incident and its evidence in the Interlock application.")
        arguments = {channel_field: self.settings.slack_channel_id, text_field: message}
        for field in ("team_id", "workspace_id"):
            if field in fields:
                arguments[field] = self.settings.slack_workspace_id
        for field in ("mrkdwn", "link_names", "unfurl_links", "unfurl_media"):
            if field in fields and fields[field].get("type") == "boolean":
                arguments[field] = False
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(arguments)
        return arguments

    def _receipt(self, response) -> dict | None:
        candidates = []
        if isinstance(response.structuredContent, dict):
            candidates.append(response.structuredContent)
        for content in response.content[:8]:
            text = getattr(content, "text", None)
            if isinstance(text, str) and len(text) <= 32768:
                try:
                    value = json.loads(text)
                    if isinstance(value, dict):
                        candidates.append(value)
                except ValueError:
                    pass
        for candidate in list(candidates):
            for key in ("data", "result", "response"):
                if isinstance(candidate.get(key), dict):
                    candidates.append(candidate[key])
        for candidate in candidates:
            timestamp = candidate.get("ts")
            if (candidate.get("ok") is True and candidate.get("channel") == self.settings.slack_channel_id
                    and isinstance(timestamp, str) and re.fullmatch(r"\d+\.\d+", timestamp)):
                return {"channel_id": self.settings.slack_channel_id, "message_ts": timestamp}
        return None

    def send_incident(self, snapshot: dict) -> dict:
        if not self.settings.slack_delivery_enabled:
            return {"state": "blocked", "result": None, "error": "Slack delivery is disabled"}
        if snapshot.get("mode") != "live":
            return {"state": "blocked", "result": None,
                    "error": "Recorded demonstrations never dispatch to production Slack"}
        error = self._configuration_error()
        if error:
            return {"state": "unavailable", "result": None, "error": error}
        if (not self.settings.slack_mcp_tool_name
                or not re.fullmatch(r"[a-f0-9]{64}", self.settings.slack_mcp_tool_schema_hash)
                or not re.fullmatch(r"[CG][A-Z0-9]{8,}", self.settings.slack_channel_id)
                or not re.fullmatch(r"T[A-Z0-9]{8,}", self.settings.slack_workspace_id)):
            return {"state": "blocked", "result": None,
                    "error": "Pin the discovered message tool schema and approved workspace/channel first"}
        attempted = False

        async def dispatch(session):
            nonlocal attempted
            tools = await self._list_tools(session)
            selected = [tool for tool in tools if tool["name"] == self.settings.slack_mcp_tool_name]
            if len(selected) != 1:
                return {"state": "blocked", "result": None,
                        "error": "Pinned Slack message tool is missing or ambiguous"}
            try:
                arguments = self._arguments(selected[0], snapshot)
            except Exception:
                return {"state": "blocked", "result": None,
                        "error": "Pinned Slack definition or fixed-destination arguments were rejected"}
            attempted = True
            response = await session.call_tool(self.settings.slack_mcp_tool_name, arguments=arguments,
                read_timeout_seconds=timedelta(seconds=self.settings.slack_timeout_seconds))
            if response.isError:
                return {"state": "uncertain", "result": None,
                        "error": "Slack tool reported an error after dispatch; reconciliation is required"}
            receipt = self._receipt(response)
            if receipt is None:
                return {"state": "uncertain", "result": None,
                        "error": "Slack returned no verified channel/message receipt; do not resend blindly"}
            return {"state": "succeeded", "result": receipt, "error": None}

        try:
            return asyncio.run(self._operate(dispatch))
        except ValueError:
            return {"state": "blocked", "result": None,
                    "error": "Pinned Slack tool schema or fixed-destination arguments were rejected"}
        except Exception:
            return {"state": "uncertain" if attempted else "failed", "result": None,
                    "error": ("Slack dispatch outcome is uncertain; reconcile before retrying" if attempted
                              else "Slack MCP connection or tool discovery failed before dispatch")}

    def close(self) -> None:
        pass
