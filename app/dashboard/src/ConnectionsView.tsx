import { useState } from 'react';
import { AlertTriangle, Boxes, Check, ChevronDown, Database, Fingerprint, List, Plug, Upload, Zap } from 'lucide-react';
import { api } from './api';
import { Badge, ErrorNotice, Field, JsonPreview, label } from './components';
import type { DataRecord, Health, Integration } from './types';

const connections = [
  { key: 'akash', name: 'Akash Console', meta: 'Qwen3.8-27B inference', icon: Zap, check: api.checkInference, extra: api.inferenceModels, extraLabel: 'Discover models', extraIcon: List },
  { key: 'clickhouse', name: 'ClickHouse', meta: 'Security event analytics', icon: Database, check: api.initializeClickHouse, extra: api.exportClickHouse, extraLabel: 'Export events', extraIcon: Upload },
  { key: 'guild', name: 'Guild', meta: 'Hosted incident investigator', icon: Fingerprint, check: api.checkGuild, extra: api.guildDiscovery, extraLabel: 'Discover metadata', extraIcon: List },
  { key: 'sandbox', name: 'Investigation sandbox', meta: 'Runtime isolation capability', icon: Boxes, check: api.checkSandbox },
  { key: 'slack', name: 'Slack MCP', meta: 'Optional external delivery', icon: Plug, check: api.checkSlack, extra: api.slackTools, extraLabel: 'Discover tools', extraIcon: List },
];

function proofState(key: string, integration?: Integration): string {
  if (!integration) return 'unavailable';
  if (key === 'akash') return integration.inference_verified ? 'inference verified' : integration.models_discovered ? 'models discovered' : 'inference unverified';
  if (key === 'guild') return integration.authentication_verified ? 'authentication verified' : 'authentication unverified';
  if (key === 'sandbox') return integration.verified ? 'runtime verified' : integration.setup_verified ? 'setup verified, runtime unverified' : 'runtime unverified';
  return integration.verified ? 'connection verified' : 'connection unverified';
}

function proofVerified(key: string, integration?: Integration): boolean {
  if (key === 'akash') return integration?.inference_verified === true;
  if (key === 'guild') return integration?.authentication_verified === true;
  return integration?.verified === true;
}

function MetadataIds({ result }: { result: DataRecord }) {
  const resources = [['workspaces', 'Workspaces'], ['agents', 'Agents'], ['versions', 'Agent versions']];
  const available = resources.filter(([key]) => Array.isArray(result[key]));
  if (!available.length) return null;
  const limitations = Array.isArray(result.limitations) ? result.limitations.filter((item): item is string => typeof item === 'string') : [];
  const discoveryErrors = Array.isArray(result.discovery_errors) ? result.discovery_errors.filter((item): item is DataRecord => Boolean(item) && typeof item === 'object' && !Array.isArray(item)) : [];
  return <div className="connection-evidence">
    <dl className="detail-grid">{available.map(([key, name]) => {
      const rows = (result[key] as unknown[]).filter((item): item is DataRecord => Boolean(item) && typeof item === 'object' && !Array.isArray(item));
      return <Field key={key} name={name} value={rows.length ? <>{rows.slice(0, 12).map((row, index) => <div key={String(row.id ?? index)}>
        {label(row.qualified_name ?? row.name, 'Unnamed')} <code>{typeof row.id === 'string' ? row.id : 'ID unavailable'}</code>
        {typeof row.runtime_environment_id === 'string' && <div>Environment ID: <code>{row.runtime_environment_id}</code></div>}
      </div>)}{rows.length > 12 && <div className="plain-meta">{rows.length - 12} additional records in connection evidence</div>}</> : 'None returned'} />;
    })}</dl>
    {discoveryErrors.map((item, index) => <p className="connection-error" key={index}>{label(item.resource)}: {label(item.detail, 'Discovery unavailable')}</p>)}
    {limitations.map((item) => <p className="plain-meta" key={item}>{item}</p>)}
  </div>;
}

export default function ConnectionsView({ health, onRefresh }: { health: Health | null; onRefresh: () => Promise<void> }) {
  const [busy, setBusy] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [results, setResults] = useState<Partial<Record<string, DataRecord>>>({});
  const [expanded, setExpanded] = useState<string>();
  async function run(key: string, action: string, request: () => Promise<DataRecord>) {
    setBusy(`${key}:${action}`); setErrors((current) => ({ ...current, [key]: '' }));
    try { setResults((current) => ({ ...current, [key]: undefined })); const result = await request(); setResults((current) => ({ ...current, [key]: result })); setExpanded(key); await onRefresh(); }
    catch (e) { setErrors((current) => ({ ...current, [key]: e instanceof Error ? e.message : 'Connection failed.' })); }
    finally { setBusy(''); }
  }
  return <>
    <div className="page-heading"><div><h1>Connections</h1><p>Runtime resources</p></div><span className="plain-meta">{connections.filter((item) => proofVerified(item.key, health?.integrations?.[item.key])).length} / {connections.length} checks verified</span></div>
    <div className="connections-list">{connections.map(({ key, name, meta, icon: Icon, check, extra, extraLabel, extraIcon: ExtraIcon }) => {
      const integration = health?.integrations?.[key];
      const missing = integration?.missing_configuration ?? (key === 'guild' ? health?.integrations?.sandbox?.missing_configuration : undefined);
      const missingPermissions = integration?.missing_permissions;
      return <section className="connection-record" key={key}>
        <div className="connection-row">
          <div className="connection-identity"><Icon size={19} /><div><h2>{name}</h2><span>{meta}</span></div></div>
          <div className="connection-state">
            <Badge value={integration?.configured ? 'configured' : 'not configured'} />
            <Badge value={proofState(key, integration)} />
            <small>{integration ? integration.detail ?? integration.message ?? label(integration.status) : 'Unavailable'}</small>
          </div>
          <div className="connection-actions">
            {extra && ExtraIcon && <button className="icon-button" disabled={Boolean(busy)} onClick={() => void run(key, 'discover', extra)} title={extraLabel} aria-label={`${extraLabel} for ${name}`}><ExtraIcon size={16} /></button>}
            <button className="secondary-button" disabled={Boolean(busy)} onClick={() => void run(key, 'check', check)}><Check size={15} />{busy === `${key}:check` ? 'Checking...' : key === 'clickhouse' ? 'Initialize' : 'Check'}</button>
            {results[key] && <button className="icon-button" onClick={() => setExpanded(expanded === key ? undefined : key)} title="Toggle connection evidence" aria-label={`Toggle ${name} evidence`}><ChevronDown size={16} className={expanded === key ? 'chevron-open' : ''} /></button>}
          </div>
        </div>
        {key === 'akash' && integration && <>
          {(integration.transport === 'http' || integration.public_data_only) && <div className="readiness-strip" role="status"><AlertTriangle size={16} /><span>Public-data-only demo endpoint. HTTP traffic is unencrypted; no credentials or private content.</span></div>}
          <dl className="detail-grid connection-evidence">
            <Field name="Model catalog" value={integration.models_discovered ? integration.discovered_models?.join(', ') || 'Discovered' : 'Not discovered'} />
            <Field name="Inference completion" value={integration.inference_verified ? 'Verified' : 'Not verified'} />
            <Field name="Requested model" value={integration.requested_model || '--'} />
            <Field name="Served model" value={integration.served_model || '--'} />
            <Field name="Transport" value={integration.transport?.toUpperCase() || '--'} />
            <Field name="Request authentication" value={integration.authentication === 'none' ? 'No credentials' : integration.authentication === 'bearer' ? 'Bearer token' : '--'} />
            {integration.model_identity_match === false && <Field name="Model identity" value={<Badge value="unverified">Different returned model alias</Badge>} />}
          </dl>
        </>}
        {(key === 'guild' || key === 'sandbox') && integration && <dl className="detail-grid connection-evidence">
          {key === 'guild' && <Field name="API authentication" value={integration.authentication_verified ? 'Verified' : integration.key_configured ? 'Key present; not verified' : 'Key missing'} />}
          {key === 'guild' && <Field name="Required permissions" value={integration.permissions_verified ? 'Verified' : missingPermissions?.length ? missingPermissions.join(', ') : 'Not verified'} />}
          {key === 'sandbox' && <Field name="Investigator setup" value={integration.setup_verified ? 'Verified' : 'Not verified'} />}
          {key === 'sandbox' && <Field name="Isolated execution" value={integration.verified ? 'Runtime metadata verified' : 'Not verified'} />}
          {key === 'sandbox' && <Field name="Evidence export" value={integration.evidence_export_enabled ? 'Enabled for bounded public evidence' : 'Disabled'} />}
          {missing?.length ? <Field name="Missing settings" value={missing.map((setting) => <div key={setting}><code>{setting}</code></div>)} /> : null}
        </dl>}
        {errors[key] && <ErrorNotice>{errors[key]}</ErrorNotice>}
        {!errors[key] && integration?.error && <p className="connection-error">{integration.error}</p>}
        {expanded === key && results[key] && <>
          {key === 'guild' && <MetadataIds result={results[key]} />}
          <div className="connection-evidence"><JsonPreview value={results[key]} /></div>
        </>}
      </section>;
    })}</div>
  </>;
}
