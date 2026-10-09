"""Optional ClickHouse Connect adapter; SQLite remains enforcement authority.

Uses a 26.3-compatible schema and acknowledged asynchronous inserts. Every
analytics query uses the unique-event view, preserving first ingestion timestamps.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from app.integrations.common import IntegrationError, IntegrationUnavailable, ProviderState
from app.integrations.guild import redact_snapshot


EVENT_COLUMNS = (
    "event_id", "event_seq", "event_ts", "recorded_ts", "event_type", "namespace_id",
    "run_id", "task_id", "agent_id", "memory_id", "context_id", "action_id", "incident_id",
    "parent_ids", "root_ids", "context_memory_ids", "source_id", "source_type", "trust",
    "generation", "rule", "decision", "control_mode", "planner_mode", "tool", "tool_category",
    "policy_version", "analysis_mode", "analysis_model", "analysis_score", "redacted_preview", "payload_json",
)
OPERATIONAL_FILTER = """
control_mode = 'full_system'
AND JSONExtractString(payload_json, 'run_purpose') NOT IN ('baseline', 'load_test', 'evaluation')
AND NOT startsWith(namespace_id, 'baseline_') AND NOT startsWith(namespace_id, 'load_')
"""


def _timestamp(value):
    if not isinstance(value, datetime):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Audit timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def event_row(event: dict) -> list:
    data = {column: event.get(column, "") or "" for column in EVENT_COLUMNS}
    for column in ("event_ts", "recorded_ts"):
        data[column] = _timestamp(event[column])
    for column in ("event_seq", "generation"):
        data[column] = int(event.get(column, 0))
    for column in ("parent_ids", "root_ids", "context_memory_ids"):
        data[column] = list(event.get(column, []))
    for column in ("policy_version", "analysis_score"):
        data[column] = event.get(column)
    data["analysis_score"] = event.get("analysis_score", event.get("score"))
    data["redacted_preview"] = redact_snapshot(str(event.get("redacted_preview", event.get("preview", ""))))[:512]
    data["payload_json"] = json.dumps(redact_snapshot(event), sort_keys=True, separators=(",", ":"))
    return [data[column] for column in EVENT_COLUMNS]


class ClickHouseAnalytics:
    def __init__(self, settings=None, *, client=None):
        self.settings = settings
        self.database = getattr(settings, "clickhouse_database", "interlock")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.database):
            raise ValueError("Invalid ClickHouse database identifier")
        self._client = client
        self._owns_client = client is None
        self.configured = bool(client is not None or getattr(settings, "clickhouse_host", ""))
        self._verified = False
        self._detail = "Configured; connectivity and schema have not been verified" if self.configured else "Missing CLICKHOUSE_HOST"

    def readiness(self) -> dict:
        return ProviderState("clickhouse", self.configured, self._verified, self._detail).as_dict()

    def _connect(self):
        if not self.configured:
            raise IntegrationUnavailable("ClickHouse unavailable: missing CLICKHOUSE_HOST")
        if self._client is None:
            try:
                import clickhouse_connect
                self._client = clickhouse_connect.get_client(
                    host=self.settings.clickhouse_host, port=self.settings.clickhouse_port,
                    username=self.settings.clickhouse_username, password=self.settings.clickhouse_password,
                    secure=self.settings.clickhouse_secure, database="default",
                    connect_timeout=5, send_receive_timeout=15, autogenerate_session_id=False,
                )
            except ImportError:
                raise IntegrationUnavailable("Install the project's ClickHouse dependency before enabling analytics") from None
            except Exception:
                self._verified = False
                self._detail = "Connection failed"
                raise IntegrationError("ClickHouse connection failed") from None
        return self._client

    def initialize_schema(self) -> dict:
        client = self._connect()
        schema_path = Path(__file__).resolve().parents[2] / "clickhouse"
        try:
            client.command(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            for filename in ("table.sql", "unique_events.sql"):
                client.command((schema_path / filename).read_text(encoding="utf-8").format(database=self.database))
        except Exception:
            self._verified = False
            self._detail = "Schema initialization failed"
            raise IntegrationError("ClickHouse schema initialization failed") from None
        self._verified = True
        self._detail = "Connection and schema initialization verified"
        return self.readiness()

    def insert_events(self, events: list[dict], batch_id: str) -> int:
        if not events:
            return 0
        rows = [event_row(event) for event in events]
        try:
            self._connect().insert(f"{self.database}.memory_events", rows, column_names=list(EVENT_COLUMNS), settings={
                "async_insert": 1, "wait_for_async_insert": 1,
                "async_insert_use_adaptive_busy_timeout": 0, "async_insert_busy_timeout_ms": 200,
                "deduplicate_insert": "enable", "insert_deduplication_token": batch_id,
            })
        except IntegrationUnavailable:
            raise
        except Exception:
            self._verified = False
            self._detail = "Acknowledged insert failed; outbox must retain events"
            raise IntegrationError("ClickHouse acknowledged insert failed") from None
        self._verified = True
        self._detail = "Live acknowledged insert verified"
        return len(events)

    def _query(self, sql: str, parameters: dict) -> dict:
        started = perf_counter()
        try:
            result = self._connect().query(sql, parameters=parameters)
            rows = list(result.named_results())
        except IntegrationUnavailable:
            raise
        except Exception:
            self._verified = False
            self._detail = "Analytics query failed"
            raise IntegrationError("ClickHouse analytics query failed") from None
        self._verified = True
        self._detail = "Live analytics query verified"
        return {"provider": "clickhouse", "mode": "live", "rows": rows,
                "query_ms": (perf_counter() - started) * 1000}

    def timeline(self, namespace_id: str, run_id: str, limit: int = 200) -> dict:
        return self._query(f"""
            SELECT * FROM {self.database}.unique_memory_events
            WHERE namespace_id = {{namespace:String}} AND run_id = {{run:String}}
            ORDER BY event_ts, event_seq LIMIT {{limit:UInt32}}
        """, {"namespace": namespace_id, "run": run_id, "limit": max(1, min(limit, 1000))})

    def source_rankings(self, namespace_id: str) -> dict:
        return self._query(f"""
            WITH eligible AS (
                SELECT * FROM {self.database}.unique_memory_events
                WHERE namespace_id = {{namespace:String}} AND {OPERATIONAL_FILTER}
            ), roots AS (
                SELECT memory_id, source_id FROM eligible
                WHERE event_type = 'memory_write' AND generation = 0 AND source_id != ''
            ), implicated AS (
                SELECT event_id, event_type, action_id, arrayJoin(root_ids) AS root_id
                FROM eligible WHERE event_type = 'action_block'
                    OR (event_type = 'memory_read' AND decision = 'blocked')
            )
            SELECT roots.source_id,
                uniqExactIf(implicated.action_id, implicated.event_type = 'action_block' AND implicated.action_id != '') AS blocked_actions,
                uniqExactIf(implicated.event_id, implicated.event_type != 'action_block') AS blocked_retrievals
            FROM implicated INNER JOIN roots ON implicated.root_id = roots.memory_id
            GROUP BY roots.source_id ORDER BY blocked_actions DESC, blocked_retrievals DESC
        """, {"namespace": namespace_id})

    def metrics(self, namespace_id: str) -> dict:
        return self._query(f"""
            SELECT count() AS unique_events,
                countIf(event_type = 'action_block') AS blocked_actions,
                countIf(event_type = 'action_execute') AS executed_actions,
                if(count() = 0, 0.0, quantile(0.95)(greatest(0, dateDiff('microsecond', recorded_ts, ingested_ts) / 1000.0))) AS delivery_lag_p95_ms
            FROM {self.database}.unique_memory_events
            WHERE namespace_id = {{namespace:String}} AND {OPERATIONAL_FILTER}
        """, {"namespace": namespace_id})

    def close(self):
        if self._client is not None and self._owns_client:
            self._client.close()
