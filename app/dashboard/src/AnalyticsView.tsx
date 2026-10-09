import { useState } from 'react';
import { Database, DatabaseZap, Gauge, Upload } from 'lucide-react';
import { Badge, Empty, ErrorNotice, JsonPreview, label, shortId } from './components';
import { api } from './api';
import type { Analytics, DataRecord, Health } from './types';

export default function AnalyticsView({ analytics, loading, health, onRefresh }: { analytics: Analytics | null; loading: boolean; health: Health | null; onRefresh: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<DataRecord | null>(null);
  async function sync(initialize: boolean) {
    setBusy(true); setError(''); setResult(null);
    try { setResult(await (initialize ? api.initializeClickHouse() : api.exportClickHouse())); await onRefresh(); }
    catch (e) { setError(e instanceof Error ? e.message : 'ClickHouse request failed.'); }
    finally { setBusy(false); }
  }
  if (!analytics) return <><div className="page-heading"><div><h1>Event analytics</h1><p>Security activity</p></div></div><Empty title={loading ? 'Loading analytics' : 'Analytics unavailable'} /></>;
  const metrics = [
    { name: 'Audit events', value: analytics.total_events },
    { name: 'Blocked actions', value: analytics.blocked_actions, tone: 'danger' },
    { name: 'Simulated executions', value: analytics.executed_actions, tone: 'success' },
    { name: 'Memory versions', value: analytics.memory_count },
    { name: 'Incidents', value: analytics.incident_count, tone: 'warning' },
    { name: 'Pending export', value: analytics.outbox_backlog },
  ];
  const rankings = Array.isArray(analytics.source_rankings) ? analytics.source_rankings as DataRecord[] : [];
  return <>
    <div className="page-heading"><div><h1>Event analytics</h1><p>Security activity</p></div><span className="analytics-source"><Database size={16} />{analytics.source === 'clickhouse' ? 'ClickHouse' : 'Local SQLite'}<Badge value={analytics.source === 'clickhouse' ? 'verified' : 'local'} /></span></div>
    <div className="analytics-toolbar"><span>ClickHouse event pipeline</span><div><button className="secondary-button" disabled={busy || !health?.integrations?.clickhouse?.configured} onClick={() => void sync(true)} title="Initialize ClickHouse tables"><DatabaseZap size={15} />Initialize</button><button className="secondary-button" disabled={busy || !health?.integrations?.clickhouse?.configured} onClick={() => void sync(false)} title="Export pending audit events to ClickHouse"><Upload size={15} />Export events</button></div></div>
    {error && <ErrorNotice>{error}</ErrorNotice>}{result && <div className="pipeline-result"><JsonPreview value={result} /></div>}
    <section className="metric-band" aria-label="Activity totals">{metrics.map((metric) => <div className="metric" key={metric.name}><span>{metric.name}</span><strong className={metric.tone ?? ''}>{typeof metric.value === 'number' ? metric.value.toLocaleString() : '--'}</strong></div>)}</section>
    <section className="analytics-section"><div className="section-heading"><h2>Source investigation ranking</h2><span>{typeof analytics.namespace_id === 'string' ? `Namespace ${shortId(analytics.namespace_id)}` : `${rankings.length} sources`}</span></div>{rankings.length === 0 ? <Empty title="No source rankings available" /> : <div className="table-scroll"><table><thead><tr><th>Source</th><th>Blocked actions</th><th>Blocked retrievals</th></tr></thead><tbody>{rankings.map((source, i) => <tr key={String(source.source_id ?? i)}><td>{label(source.source_id)}</td><td>{label(source.blocked_actions ?? source.blocked_action_count, '--')}</td><td>{label(source.blocked_retrievals, '--')}</td></tr>)}</tbody></table></div>}</section>
    <section className="analytics-section"><div className="section-heading"><h2><Gauge size={17} />Query evidence</h2><span>{analytics.source === 'clickhouse' ? 'ClickHouse result' : 'Local result'}</span></div><div className="analytics-evidence"><JsonPreview value={analytics} /></div></section>
  </>;
}
