"""Authoritative local state. Sponsor analytics never participates in enforcement."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path


class AuditRejection(ValueError):
    """A rejected operation whose audit event should still commit."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL, task_id TEXT NOT NULL,
    agent_id TEXT NOT NULL, scenario TEXT NOT NULL, control_mode TEXT NOT NULL,
    planner_mode TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT,
    outcome TEXT NOT NULL DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS memories (
    memory_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
    namespace_id TEXT NOT NULL, source_type TEXT NOT NULL, source_id TEXT NOT NULL,
    trust_tier TEXT NOT NULL, content TEXT NOT NULL, content_hash TEXT NOT NULL,
    generation INTEGER NOT NULL, created_at TEXT NOT NULL,
    replaces_memory_id TEXT REFERENCES memories(memory_id)
);
CREATE TABLE IF NOT EXISTS memory_edges (
    parent_id TEXT NOT NULL REFERENCES memories(memory_id),
    child_id TEXT NOT NULL REFERENCES memories(memory_id),
    PRIMARY KEY(parent_id, child_id)
);
CREATE TABLE IF NOT EXISTS memory_state (
    memory_id TEXT PRIMARY KEY REFERENCES memories(memory_id),
    lifecycle TEXT NOT NULL DEFAULT 'active', replacement_id TEXT REFERENCES memories(memory_id)
);
CREATE TABLE IF NOT EXISTS restrictions (
    restriction_id TEXT PRIMARY KEY, memory_id TEXT NOT NULL REFERENCES memories(memory_id),
    rule TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contexts (
    context_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
    task_id TEXT NOT NULL, namespace_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS context_memories (
    context_id TEXT NOT NULL REFERENCES contexts(context_id),
    memory_id TEXT NOT NULL REFERENCES memories(memory_id),
    PRIMARY KEY(context_id, memory_id)
);
CREATE TABLE IF NOT EXISTS task_policies (
    policy_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
    version INTEGER NOT NULL, tool TEXT NOT NULL, report_id TEXT NOT NULL,
    recipient TEXT NOT NULL, origin TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(run_id, version)
);
CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
    context_id TEXT NOT NULL, fingerprint TEXT NOT NULL, tool TEXT NOT NULL,
    recipient TEXT NOT NULL, report_id TEXT NOT NULL, policy_version INTEGER,
    outcome TEXT NOT NULL, reason TEXT NOT NULL, incident_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id TEXT PRIMARY KEY, action_id TEXT NOT NULL UNIQUE REFERENCES actions(action_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id), recipient TEXT NOT NULL,
    report_id TEXT NOT NULL, created_at TEXT NOT NULL, simulated INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
    rule TEXT NOT NULL, memory_id TEXT REFERENCES memories(memory_id),
    action_id TEXT, status TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id TEXT PRIMARY KEY, incident_id TEXT REFERENCES incidents(incident_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id), mode TEXT NOT NULL, provider TEXT NOT NULL,
    model TEXT, state TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    event_ts TEXT NOT NULL, recorded_ts TEXT NOT NULL, event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id), exported_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_memories_namespace ON memories(namespace_id);
CREATE INDEX IF NOT EXISTS idx_edges_child ON memory_edges(child_id);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(exported_at);
"""


class SQLiteStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        connection = self.connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
            connection.commit()
        finally:
            connection.close()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def transaction(self):
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except AuditRejection:
            connection.commit()
            raise
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
