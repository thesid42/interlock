CREATE TABLE IF NOT EXISTS {database}.memory_events
(
    event_id String,
    event_seq UInt64,
    event_ts DateTime64(6, 'UTC'),
    recorded_ts DateTime64(6, 'UTC'),
    ingested_ts DateTime64(6, 'UTC') DEFAULT now64(6),
    event_type LowCardinality(String),
    namespace_id String,
    run_id String,
    task_id String,
    agent_id String,
    memory_id String,
    context_id String,
    action_id String,
    incident_id String,
    parent_ids Array(String),
    root_ids Array(String),
    context_memory_ids Array(String),
    source_id String,
    source_type LowCardinality(String),
    trust LowCardinality(String),
    generation UInt32,
    rule LowCardinality(String),
    decision LowCardinality(String),
    control_mode LowCardinality(String),
    planner_mode LowCardinality(String),
    tool LowCardinality(String),
    tool_category LowCardinality(String),
    policy_version Nullable(UInt32),
    analysis_mode LowCardinality(String),
    analysis_model String,
    analysis_score Nullable(UInt8),
    redacted_preview String,
    payload_json String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(recorded_ts)
ORDER BY (namespace_id, run_id, event_ts, event_seq)
SETTINGS non_replicated_deduplication_window = 10000
