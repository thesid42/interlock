"""Operations state shares the core SQLite authority and audit outbox."""

import json


SCHEMA = """
CREATE TABLE IF NOT EXISTS security_agents (
    agent_id TEXT PRIMARY KEY, name TEXT NOT NULL, mission TEXT NOT NULL,
    source_urls_json TEXT NOT NULL, interval_seconds INTEGER NOT NULL,
    state TEXT NOT NULL, reason TEXT NOT NULL, namespace_id TEXT NOT NULL,
    created_at TEXT NOT NULL, next_check_at TEXT NOT NULL,
    last_check_at TEXT, last_outcome TEXT
);
CREATE TABLE IF NOT EXISTS security_runs (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id), agent_id TEXT NOT NULL,
    state TEXT NOT NULL, mode TEXT NOT NULL, created_at TEXT NOT NULL,
    started_at TEXT, finished_at TEXT, lease_until TEXT,
    error TEXT, sources_count INTEGER NOT NULL DEFAULT 0,
    proposal_json TEXT, context_id TEXT
);
CREATE TABLE IF NOT EXISTS security_sources (
    source_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, agent_id TEXT NOT NULL,
    url TEXT NOT NULL, content TEXT NOT NULL, content_hash TEXT NOT NULL,
    retrieved_at TEXT NOT NULL, memory_id TEXT NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS security_incidents (
    incident_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, run_id TEXT NOT NULL,
    status TEXT NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL,
    mode TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at TEXT NOT NULL,
    resolved_at TEXT, resolution_reason TEXT
);
CREATE TABLE IF NOT EXISTS security_investigations (
    incident_id TEXT PRIMARY KEY, state TEXT NOT NULL, sandbox_json TEXT,
    qwen_json TEXT, guild_json TEXT, error TEXT, updated_at TEXT NOT NULL,
    lease_until TEXT, guild_started INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS security_briefs (
    brief_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, run_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL, body TEXT NOT NULL, evidence_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL, mode TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_notifications (
    incident_id TEXT PRIMARY KEY, state TEXT NOT NULL,
    result_json TEXT, error TEXT, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_runs_queue ON security_runs(state,created_at);
CREATE INDEX IF NOT EXISTS idx_security_incidents_agent ON security_incidents(agent_id,status);
CREATE INDEX IF NOT EXISTS idx_security_sources_agent ON security_sources(agent_id,url);
CREATE INDEX IF NOT EXISTS idx_security_sources_run ON security_sources(run_id);
"""


def initialize(store):
    db = store.connect()
    try:
        db.executescript(SCHEMA)
        db.commit()
    finally:
        db.close()


def decode(row):
    if row is None:
        return None
    result = dict(row)
    for key in list(result):
        if key.endswith("_json"):
            value = result.pop(key)
            result[key[:-5]] = json.loads(value) if value else None
    return result


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
