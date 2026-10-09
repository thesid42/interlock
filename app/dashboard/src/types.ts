export type DataRecord = Record<string, unknown>;

export interface Integration {
  configured: boolean;
  verified: boolean;
  status: string;
  error?: string;
  message?: string;
  detail?: string;
  details?: DataRecord;
  key_configured?: boolean;
  authentication_verified?: boolean;
  permissions_verified?: boolean;
  missing_permissions?: string[];
  missing_configuration?: string[];
  account?: DataRecord | null;
  discovery_available?: boolean;
  setup_verified?: boolean;
  evidence_export_enabled?: boolean;
  transport?: 'https' | 'http';
  public_data_only?: boolean;
  authentication?: 'bearer' | 'none';
  models_discovered?: boolean;
  discovered_models?: string[];
  inference_verified?: boolean;
  requested_model?: string;
  served_model?: string | null;
  model_identity_match?: boolean | null;
}

export interface Health {
  status: string;
  integrations: Record<string, Integration>;
}

export interface Run extends DataRecord {
  run_id: string;
  namespace_id?: string;
  scenario: string;
  control_mode: string;
  planner_mode: string;
  outcome: string;
  created_at?: string;
  actions?: Action[];
  memories?: Memory[];
  incidents?: Incident[];
  events?: DataRecord[];
}

export interface Action extends DataRecord {
  action_id?: string;
  tool?: string;
  action_type?: string;
  status?: string;
  decision?: string;
  outcome?: string;
  args?: DataRecord;
  arguments?: DataRecord;
  reason?: string;
}

export interface Memory extends DataRecord {
  memory_id: string;
  run_id?: string;
  namespace_id?: string;
  content: string;
  source_type?: string;
  source_id?: string;
  state?: string;
  status?: string;
  generation?: number;
  trust_tier?: string;
  lifecycle?: string;
  effective_quarantined?: boolean;
  parent_ids?: string[];
  created_at?: string;
}

export interface Incident extends DataRecord {
  incident_id: string;
  run_id?: string;
  memory_id?: string;
  title?: string;
  reason?: string;
  status?: string;
  severity?: string;
  created_at?: string;
}

export interface Analytics extends DataRecord {
  source: string;
  total_events: number;
  blocked_actions: number;
  executed_actions: number;
  memory_count: number;
  incident_count: number;
  outbox_backlog: number;
}

export interface Lineage {
  nodes: Memory[];
  edges: { parent_id?: string; child_id?: string; source?: string; target?: string }[];
  root_ids: string[];
}

export interface RunInput {
  scenario: string;
  control_mode: string;
  planner_mode: string;
  namespace_id?: string;
  replacement_memory_id?: string;
}

export interface SecurityAgent extends DataRecord {
  agent_id: string;
  name: string;
  mission: string;
  state: 'active' | 'paused' | 'contained';
  source_urls: string[];
  interval_seconds: number;
  created_at?: string;
  last_check_at?: string;
  next_check_at?: string;
  last_outcome?: string;
  last_error?: string;
  reason?: string;
  sources?: SourceCitation[];
}

export interface SecurityIncident extends DataRecord {
  incident_id: string;
  agent_id: string;
  run_id?: string;
  status: string;
  rule?: string;
  title?: string;
  reason?: string;
  mode: string;
  created_at?: string;
  resolved_at?: string;
  investigation?: DataRecord;
  notification?: DataRecord;
}

export interface SecurityBrief extends DataRecord {
  brief_id: string;
  agent_id: string;
  title: string;
  body: string;
  evidence_ids: string[];
  created_at?: string;
  mode: string;
  citations?: SourceCitation[];
}

export interface SourceCitation {
  source_id: string;
  url: string;
  retrieved_at?: string;
  content_hash?: string;
  run_id?: string;
  memory_id?: string;
  quarantined?: boolean | number;
}

export interface Operations {
  agents: SecurityAgent[];
  incidents: SecurityIncident[];
  briefs: SecurityBrief[];
  runs: DataRecord[];
  activity: DataRecord[];
  readiness: Record<string, Integration>;
  counts: Record<string, number>;
}

export interface AgentInput {
  name: string;
  mission: string;
  source_urls: string[];
  interval_seconds: number;
}

export interface SecurityIncidentDetail extends SecurityIncident {
  snapshot?: DataRecord;
}
