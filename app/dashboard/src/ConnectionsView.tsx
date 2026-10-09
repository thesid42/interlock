import { useState } from 'react';
import { Boxes, Check, ChevronDown, Database, Fingerprint, List, Plug, Upload, Zap } from 'lucide-react';
import { api } from './api';
import { Badge, ErrorNotice, JsonPreview, label } from './components';
import type { DataRecord, Health } from './types';

const connections = [
  { key: 'akash', name: 'Akash Console', meta: 'Qwen3.8-27B inference', icon: Zap, check: api.checkInference, extra: api.inferenceModels, extraLabel: 'Discover models', extraIcon: List },
  { key: 'clickhouse', name: 'ClickHouse', meta: 'Security event analytics', icon: Database, check: api.initializeClickHouse, extra: api.exportClickHouse, extraLabel: 'Export events', extraIcon: Upload },
  { key: 'guild', name: 'Guild', meta: 'Hosted incident investigator', icon: Fingerprint, check: api.checkGuild },
  { key: 'sandbox', name: 'Investigation sandbox', meta: 'Runtime isolation capability', icon: Boxes, check: api.checkSandbox },
  { key: 'slack', name: 'Slack MCP', meta: 'Optional external delivery', icon: Plug, check: api.checkSlack, extra: api.slackTools, extraLabel: 'Discover tools', extraIcon: List },
];

export default function ConnectionsView({ health, onRefresh }: { health: Health | null; onRefresh: () => Promise<void> }) {
  const [busy, setBusy] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [results, setResults] = useState<Partial<Record<string, DataRecord>>>({});
  const [expanded, setExpanded] = useState<string>();
  async function run(key: string, request: () => Promise<DataRecord>) {
    setBusy(key); setErrors((current) => ({ ...current, [key]: '' }));
    try { setResults((current) => ({ ...current, [key]: undefined })); const result = await request(); setResults((current) => ({ ...current, [key]: result })); setExpanded(key); await onRefresh(); }
    catch (e) { setErrors((current) => ({ ...current, [key]: e instanceof Error ? e.message : 'Connection failed.' })); }
    finally { setBusy(''); }
  }
  return <>
    <div className="page-heading"><div><h1>Connections</h1><p>Runtime resources</p></div><span className="plain-meta">{connections.filter((item) => health?.integrations?.[item.key]?.verified).length} / {connections.length} verified</span></div>
    <div className="connections-list">{connections.map(({ key, name, meta, icon: Icon, check, extra, extraLabel, extraIcon: ExtraIcon }) => {
      const integration = health?.integrations?.[key];
      const state = integration?.verified ? 'verified' : integration?.configured ? 'configured, unverified' : 'not configured';
      return <section className="connection-record" key={key}>
        <div className="connection-row"><div className="connection-identity"><Icon size={19} /><div><h2>{name}</h2><span>{meta}</span></div></div><div className="connection-state"><Badge value={state} /><small>{integration ? label(integration.status) : 'Unavailable'}</small></div><div className="connection-actions">{extra && ExtraIcon && <button className="icon-button" disabled={Boolean(busy)} onClick={() => void run(key, extra)} title={extraLabel} aria-label={`${extraLabel} for ${name}`}><ExtraIcon size={16} /></button>}<button className="secondary-button" disabled={Boolean(busy)} onClick={() => void run(key, check)}><Check size={15} />{busy === key ? 'Checking...' : key === 'clickhouse' ? 'Initialize' : 'Check'}</button>{results[key] && <button className="icon-button" onClick={() => setExpanded(expanded === key ? undefined : key)} title="Toggle connection evidence" aria-label={`Toggle ${name} evidence`}><ChevronDown size={16} className={expanded === key ? 'chevron-open' : ''} /></button>}</div></div>
        {errors[key] && <ErrorNotice>{errors[key]}</ErrorNotice>}
        {!errors[key] && integration?.error && <p className="connection-error">{integration.error}</p>}
        {expanded === key && results[key] && <div className="connection-evidence"><JsonPreview value={results[key]} /></div>}
      </section>;
    })}</div>
  </>;
}
