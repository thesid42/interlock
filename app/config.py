from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _boolean(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_path: Path
    llm_provider: str = "akash_console"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_allow_unauthenticated: bool = False
    llm_http_public_only: bool = False
    agent_model: str = "Qwen/Qwen3.8-27B"
    judge_model: str = "Qwen/Qwen3.8-27B"
    llm_timeout_seconds: float = 30.0
    llm_enable_thinking: bool = False
    llm_send_thinking_parameter: bool = True
    llm_structured_outputs: bool = False
    security_source_hosts: tuple[str, ...] = (
        "genai.owasp.org", "docs.slack.dev", "docs.guild.ai",
        "docs.docker.com", "huggingface.co",
    )
    security_tick_seconds: float = 5.0
    security_default_interval_seconds: int = 300
    sandbox_enabled: bool = True
    guild_sandbox_evidence_export_enabled: bool = False
    guild_sandbox_workspace_id: str = ""
    guild_sandbox_agent_id: str = ""
    guild_sandbox_agent_version_id: str = ""
    guild_sandbox_environment: str = ""
    guild_sandbox_environment_id: str = ""
    guild_sandbox_image_id: str = ""
    guild_sandbox_timeout_seconds: float = 180.0
    slack_mcp_access_token: str = ""
    slack_mcp_app_id: str = ""
    slack_mcp_tool_name: str = ""
    slack_mcp_tool_schema_hash: str = ""
    slack_channel_id: str = ""
    slack_workspace_id: str = ""
    slack_delivery_enabled: bool = False
    slack_timeout_seconds: float = 20.0
    clickhouse_host: str = ""
    clickhouse_port: int = 8443
    clickhouse_username: str = "default"
    clickhouse_password: str = ""
    clickhouse_database: str = "interlock"
    clickhouse_secure: bool = True
    guild_base_url: str = "https://api.guild.ai/v1"
    guild_api_key: str = ""
    guild_trigger_api_key: str = ""
    guild_trigger_id: str = ""
    guild_workspace_id: str = ""
    guild_agent_id: str = ""

    @classmethod
    def from_environment(cls) -> "Settings":
        load_dotenv(PROJECT_ROOT / ".env", override=False)
        database_path = Path(os.getenv("INTERLOCK_DB_PATH", "data/interlock.sqlite3"))
        if not database_path.is_absolute():
            database_path = PROJECT_ROOT / database_path
        return cls(
            database_path=database_path,
            llm_provider=os.getenv("LLM_PROVIDER", cls.llm_provider),
            llm_base_url=os.getenv("LLM_BASE_URL", cls.llm_base_url),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_allow_unauthenticated=_boolean("LLM_ALLOW_UNAUTHENTICATED"),
            llm_http_public_only=_boolean("LLM_HTTP_PUBLIC_ONLY"),
            agent_model=os.getenv("AGENT_MODEL", cls.agent_model),
            judge_model=os.getenv("JUDGE_MODEL", cls.judge_model),
            llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "30")),
            llm_enable_thinking=_boolean("LLM_ENABLE_THINKING"),
            llm_send_thinking_parameter=_boolean("LLM_SEND_THINKING_PARAMETER", True),
            llm_structured_outputs=_boolean("LLM_STRUCTURED_OUTPUTS"),
            security_source_hosts=tuple(
                host.strip().lower() for host in os.getenv(
                    "SECURITY_SOURCE_HOSTS", ",".join(cls.security_source_hosts),
                ).split(",") if host.strip()
            ),
            security_tick_seconds=max(1.0, float(os.getenv("SECURITY_TICK_SECONDS", "5"))),
            security_default_interval_seconds=max(60, int(os.getenv("SECURITY_DEFAULT_INTERVAL_SECONDS", "300"))),
            sandbox_enabled=_boolean("SANDBOX_ENABLED", True),
            guild_sandbox_evidence_export_enabled=_boolean("GUILD_SANDBOX_EVIDENCE_EXPORT_ENABLED"),
            guild_sandbox_workspace_id=os.getenv("GUILD_SANDBOX_WORKSPACE_ID", ""),
            guild_sandbox_agent_id=os.getenv("GUILD_SANDBOX_AGENT_ID", ""),
            guild_sandbox_agent_version_id=os.getenv("GUILD_SANDBOX_AGENT_VERSION_ID", ""),
            guild_sandbox_environment=os.getenv("GUILD_SANDBOX_ENVIRONMENT", ""),
            guild_sandbox_environment_id=os.getenv("GUILD_SANDBOX_ENVIRONMENT_ID", ""),
            guild_sandbox_image_id=os.getenv("GUILD_SANDBOX_IMAGE_ID", ""),
            guild_sandbox_timeout_seconds=min(600.0, max(30.0, float(os.getenv("GUILD_SANDBOX_TIMEOUT_SECONDS", "180")))),
            slack_mcp_access_token=os.getenv("SLACK_MCP_ACCESS_TOKEN", ""),
            slack_mcp_app_id=os.getenv("SLACK_MCP_APP_ID", ""),
            slack_mcp_tool_name=os.getenv("SLACK_MCP_TOOL_NAME", ""),
            slack_mcp_tool_schema_hash=os.getenv("SLACK_MCP_TOOL_SCHEMA_HASH", ""),
            slack_channel_id=os.getenv("SLACK_CHANNEL_ID", ""),
            slack_workspace_id=os.getenv("SLACK_WORKSPACE_ID", ""),
            slack_delivery_enabled=_boolean("SLACK_DELIVERY_ENABLED"),
            slack_timeout_seconds=min(60.0, max(5.0, float(os.getenv("SLACK_TIMEOUT_SECONDS", "20")))),
            clickhouse_host=os.getenv("CLICKHOUSE_HOST", ""),
            clickhouse_port=int(os.getenv("CLICKHOUSE_PORT", "8443")),
            clickhouse_username=os.getenv("CLICKHOUSE_USERNAME", "default"),
            clickhouse_password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            clickhouse_database=os.getenv("CLICKHOUSE_DATABASE", "interlock"),
            clickhouse_secure=_boolean("CLICKHOUSE_SECURE", True),
            guild_base_url=os.getenv("GUILD_BASE_URL", cls.guild_base_url),
            guild_api_key=os.getenv("GUILD_API_KEY", ""),
            guild_trigger_api_key=os.getenv("GUILD_TRIGGER_API_KEY", ""),
            guild_trigger_id=os.getenv("GUILD_TRIGGER_ID", ""),
            guild_workspace_id=os.getenv("GUILD_WORKSPACE_ID", ""),
            guild_agent_id=os.getenv("GUILD_AGENT_ID", ""),
        )
