-- Logical unique-event view keeps the first ingestion even outside retry windows.
-- Analytics must query this view, never count directly from memory_events.
CREATE VIEW IF NOT EXISTS {database}.unique_memory_events AS
SELECT
    event_id,
    first.1 AS event_seq, first.2 AS event_ts, first.3 AS recorded_ts,
    first.4 AS event_type, first.5 AS namespace_id, first.6 AS run_id,
    first.7 AS task_id, first.8 AS agent_id, first.9 AS memory_id,
    first.10 AS context_id, first.11 AS action_id, first.12 AS incident_id,
    first.13 AS parent_ids, first.14 AS root_ids, first.15 AS context_memory_ids,
    first.16 AS source_id, first.17 AS source_type, first.18 AS trust,
    first.19 AS generation, first.20 AS rule, first.21 AS decision,
    first.22 AS control_mode, first.23 AS planner_mode,
    first.24 AS tool, first.25 AS tool_category, first.26 AS policy_version,
    first.27 AS analysis_mode, first.28 AS analysis_model, first.29 AS analysis_score,
    first.30 AS redacted_preview, first.31 AS payload_json,
    first_ingested_ts AS ingested_ts
FROM (
    SELECT event_id,
        argMin(tuple(event_seq, event_ts, recorded_ts, event_type, namespace_id,
            run_id, task_id, agent_id, memory_id, context_id, action_id, incident_id,
            parent_ids, root_ids, context_memory_ids, source_id, source_type, trust,
            generation, rule, decision, control_mode, planner_mode, tool,
            tool_category, policy_version, analysis_mode, analysis_model,
            analysis_score, redacted_preview, payload_json), ingested_ts) AS first,
        min(ingested_ts) AS first_ingested_ts
    FROM {database}.memory_events
    GROUP BY event_id
)
