import type { AgentInput, Analytics, DataRecord, Health, Incident, Lineage, Memory, Operations, Run, RunInput, SecurityAgent, SecurityIncidentDetail } from './types';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = body?.detail ?? body?.message;
    throw new Error(typeof detail === 'string' ? detail : `Request failed (${response.status}).`);
  }
  return body as T;
}

export const api = {
  operations: () => request<Operations>('/operations'),
  securityAgent: (id: string) => request<SecurityAgent>(`/operations/agents/${encodeURIComponent(id)}`),
  createAgent: (input: AgentInput) => request<SecurityAgent>('/operations/agents', { method: 'POST', body: JSON.stringify(input) }),
  agentCommand: (id: string, command: 'run' | 'pause' | 'resume') => request<DataRecord>(`/operations/agents/${encodeURIComponent(id)}/${command}`, { method: 'POST' }),
  securityIncident: (id: string) => request<SecurityIncidentDetail>(`/operations/incidents/${encodeURIComponent(id)}`),
  investigateSecurityIncident: (id: string) => request<DataRecord>(`/operations/incidents/${encodeURIComponent(id)}/investigate`, { method: 'POST' }),
  resolveSecurityIncident: (id: string, reason: string) => request<DataRecord>(`/operations/incidents/${encodeURIComponent(id)}/resolve`, { method: 'POST', body: JSON.stringify({ reason }) }),
  controlledIncident: () => request<DataRecord>('/operations/demo', { method: 'POST' }),
  inferenceModels: () => request<DataRecord>('/integrations/inference/models'),
  checkInference: () => request<DataRecord>('/integrations/inference/check', { method: 'POST' }),
  checkGuild: () => request<DataRecord>('/integrations/guild/check', { method: 'POST' }),
  guildDiscovery: () => request<DataRecord>('/integrations/guild/discovery'),
  checkSandbox: () => request<DataRecord>('/integrations/sandbox/check', { method: 'POST' }),
  slackTools: () => request<DataRecord>('/integrations/slack/tools'),
  checkSlack: () => request<DataRecord>('/integrations/slack/check', { method: 'POST' }),
  health: () => request<Health>('/health'),
  runs: () => request<{ items: Run[] }>('/runs'),
  run: (id: string) => request<Run>(`/runs/${encodeURIComponent(id)}`),
  createRun: (input: RunInput) => request<Run>('/runs', { method: 'POST', body: JSON.stringify(input) }),
  memories: () => request<{ items: Memory[] }>('/memories'),
  lineage: (id: string) => request<Lineage>(`/memories/${encodeURIComponent(id)}/lineage`),
  incidents: () => request<{ items: Incident[] }>('/incidents'),
  incident: (id: string) => request<Incident>(`/incidents/${encodeURIComponent(id)}`),
  investigate: (id: string, provider: string) => request<DataRecord>(`/incidents/${encodeURIComponent(id)}/investigate`, {
    method: 'POST', body: JSON.stringify({ provider }),
  }),
  initializeClickHouse: () => request<DataRecord>('/integrations/clickhouse/initialize', { method: 'POST' }),
  exportClickHouse: () => request<DataRecord>('/integrations/clickhouse/export', { method: 'POST' }),
  analytics: () => request<Analytics>('/analytics'),
  quarantine: (id: string, reason: string) => request<Memory>(`/memories/${encodeURIComponent(id)}/quarantine`, {
    method: 'POST', body: JSON.stringify({ reason }),
  }),
  replace: (id: string, runId: string, content: string) => request<Memory>(`/memories/${encodeURIComponent(id)}/replace`, {
    method: 'POST', body: JSON.stringify({ run_id: runId, content }),
  }),
};
