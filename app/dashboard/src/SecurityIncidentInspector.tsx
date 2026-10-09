import { useEffect, useState } from 'react';
import { Boxes, CheckCircle2, FileLock2, Fingerprint, FlaskConical, ScanSearch, ShieldAlert, X } from 'lucide-react';
import { Badge, Empty, Field, JsonPreview, label, shortId, time } from './components';
import type { DataRecord, SecurityIncidentDetail } from './types';

function record(value: unknown): DataRecord {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataRecord : {};
}
function rows(value: unknown): DataRecord[] {
  return Array.isArray(value) ? value.map(record) : [];
}
function concise(value: unknown, fallback: string, maxLength = 420): string {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  const text = value.trim();
  if (text.length <= maxLength) return text;
  const sentenceEnd = text.slice(0, maxLength).match(/^.*?[.!?](?=\s|$)/)?.[0];
  return sentenceEnd && sentenceEnd.length >= 80 ? sentenceEnd : `${text.slice(0, maxLength).trimEnd()}…`;
}

export default function IncidentInspector({ incident, busy, onClose, onInvestigate, onResolve }: {
  incident: SecurityIncidentDetail | null;
  busy: boolean;
  onClose: () => void;
  onInvestigate: () => void;
  onResolve: (reason: string) => void;
}) {
  const [resolution, setResolution] = useState('');
  useEffect(() => setResolution(''), [incident?.incident_id]);
  const investigation = record(incident?.investigation);
  const sandbox = record(investigation.sandbox);
  const sandboxResult = record(sandbox.result);
  const diagnostics = record(sandbox.diagnostics);
  const qwen = record(investigation.qwen);
  const guild = record(investigation.guild);
  const snapshot = record(incident?.snapshot);
  const sources = rows(snapshot.sources);
  const memories = rows(snapshot.memories);
  const actions = rows(snapshot.actions);
  const attemptedAction = actions[0] ?? {};
  const proposal = record(snapshot.proposed_action);
  const running = investigation.state === 'running' || investigation.state === 'queued' || investigation.state === 'waiting_sandbox';
  const sandboxState = typeof sandbox.state === 'string' ? sandbox.state : 'not started';
  const qwenState = typeof qwen.state === 'string' ? qwen.state : 'not run';
  const guildState = typeof guild.state === 'string' ? guild.state : 'not started';
  const hasRca = typeof qwen.rationale === 'string';
  const rcaSummary = concise(qwen.summary, incident?.reason ?? 'A policy violation was detected.', 300);
  const rootCause = concise(qwen.root_cause ?? qwen.rationale, 'The available evidence does not establish a likely cause.');
  const impact = concise(qwen.impact, 'Interlock denied the proposed action before dispatch. No external action was executed.', 800);
  const confidence = typeof qwen.confidence === 'string' ? qwen.confidence : qwen.replay_execution_verified === true ? 'high' : 'limited';

  return <aside className="security-inspector" aria-label="Incident investigation"><div className="peek-heading"><span className="peek-title"><ShieldAlert size={16} />Incident investigation</span><button className="icon-button" onClick={onClose} title="Close investigation" aria-label="Close investigation"><X size={16} /></button></div>{!incident ? <Empty title="Loading incident" /> : <div className="inspector-content">
    <div className="peek-summary"><code>{shortId(incident.incident_id)}</code><Badge value={incident.status} /></div><h2 className="peek-run-name">{incident.title ?? label(incident.rule, 'Policy violation')}</h2><p className="incident-reason">{incident.reason}</p>
    <dl className="detail-grid"><Field name="Agent" value={shortId(incident.agent_id)} /><Field name="Captured" value={time(incident.created_at)} /><Field name="Input" value={incident.mode === 'recorded_demo' ? <Badge value="recorded fixture">Recorded controlled fixture</Badge> : <Badge value="live">Live source</Badge>} /><Field name="Investigation" value={<Badge value={typeof investigation.state === 'string' ? investigation.state : 'not started'} />} /></dl>
    <section className="inspector-block rca-block"><div className="record-heading"><h3><ScanSearch size={16} />Root-cause analysis</h3><Badge value={hasRca && typeof qwen.finding === 'string' ? qwen.finding : qwenState} /></div>{hasRca ? <><div className="rca-callout"><span>What happened</span><strong>{rcaSummary}</strong></div><div className="rca-grid"><article><span>Likely cause</span><p>{rootCause}</p></article><article><span>Impact</span><p>{impact}</p></article></div><div className="rca-confidence"><span>Analysis confidence</span><Badge value={confidence} /><small>{qwen.replay_execution_verified === true ? 'Supported by independently verified replay execution.' : 'Advisory hypothesis; replay execution was not independently verified.'}</small></div>{Array.isArray(qwen.recovery_steps) && qwen.recovery_steps.length > 0 && <div className="rca-actions"><span>Recommended next steps</span><ol className="recovery-steps">{qwen.recovery_steps.map((step, i) => <li key={i}>{typeof step === 'string' ? step : JSON.stringify(step)}</li>)}</ol></div>}<details><summary>Technical rationale and evidence</summary><p className="reason">{label(qwen.rationale)}</p>{Array.isArray(qwen.evidence_ids) && <div className="brief-evidence">{qwen.evidence_ids.map((id) => <code key={String(id)}>{shortId(String(id))}</code>)}</div>}</details><span className="plain-meta rca-model">{label(qwen.model, 'Model unavailable')}</span></> : <p className="muted">{label(qwen.error, 'Run the investigation to generate a root-cause analysis.')}</p>}</section>
    <section className="inspector-block"><div className="record-heading"><h3><ShieldAlert size={16} />Pre-dispatch control</h3><Badge value={typeof attemptedAction.decision === 'string' ? attemptedAction.decision : 'unknown'} /></div><dl className="detail-grid"><Field name="Attempted capability" value={label(proposal.action, 'Unknown')} /><Field name="Attempted destination" value={label(proposal.destination, 'Unknown')} /><Field name="Policy result" value="Denied before dispatch" /><Field name="External action" value="Not executed" /></dl>{incident.mode === 'recorded_demo' && <p className="muted">Controlled synthetic demonstration; no external attack or data transfer occurred.</p>}</section>
    <section className="inspector-block"><div className="record-heading"><h3><Boxes size={16} />Sandbox investigation</h3><Badge value={sandboxState} /></div>{sandbox.error ? <p className="reason danger-text">{label(sandbox.error)}</p> : null}{sandbox.poll_warning ? <p className="reason">{label(sandbox.poll_warning)}</p> : null}{sandboxResult.observations !== undefined ? <><span className="inspector-kicker">Observed evidence</span><JsonPreview value={sandboxResult.observations} /></> : <p className="muted">{running && sandbox.session_id ? 'Existing Guild session preserved; awaiting provider evidence.' : 'No sandbox observations recorded.'}</p>}{sandboxResult.control !== undefined && <details><summary>Replay controls</summary><JsonPreview value={sandboxResult.control} /></details>}{sandboxResult.limitations !== undefined && <details><summary>Replay limitations</summary><JsonPreview value={sandboxResult.limitations} /></details>}{Object.keys(diagnostics).length > 0 && <details><summary>Qwen diagnostic probes</summary><JsonPreview value={diagnostics} /></details>}<button className="secondary-button investigation-command" disabled={busy || running} onClick={onInvestigate}><FlaskConical size={15} />{running ? 'Investigation running' : 'Run investigation'}</button></section>
    <section className="inspector-block"><div className="record-heading"><h3><Fingerprint size={16} />Guild investigator</h3><Badge value={guildState} /></div>{guild.poll_warning ? <p className="reason">{label(guild.poll_warning)}</p> : null}{guild.session_id !== undefined && <span className="inspector-kicker">Session {shortId(String(guild.session_id))}</span>}{guild.replies !== undefined ? <JsonPreview value={guild.replies} /> : <p className="muted">{label(guild.error, 'No investigator replies recorded.')}</p>}</section>
    <section className="inspector-block"><h3><FileLock2 size={16} />Frozen evidence</h3><details><summary>Proposed action and authorization policy</summary><JsonPreview value={{ policy: snapshot.policy, proposed_action: snapshot.proposed_action, actions: snapshot.actions }} /></details><details><summary>Sources ({sources.length})</summary><div className="snapshot-evidence">{sources.map((source, i) => <div key={String(source.source_id ?? i)}><strong>{label(source.url ?? source.source_id)}</strong><p>{label(source.content, 'Content not supplied')}</p></div>)}</div></details><details><summary>Memory lineage ({memories.length})</summary><JsonPreview value={memories} /></details><details><summary>Snapshot record</summary><JsonPreview value={snapshot} /></details></section>
    {incident.notification && <section className="inspector-block"><h3>Slack delivery</h3><JsonPreview value={incident.notification} /></section>}
    {incident.status !== 'resolved' ? <form className="operator-form" onSubmit={(event) => { event.preventDefault(); onResolve(resolution); }}><label>Resolution reason<textarea required minLength={4} maxLength={2000} placeholder="Containment reviewed; recovery decision..." value={resolution} onChange={(event) => setResolution(event.target.value)} /></label><button className="secondary-button" type="submit" disabled={busy || running || resolution.trim().length < 4}><CheckCircle2 size={15} />Resolve incident</button></form> : <div className="recovery-action"><CheckCircle2 size={16} />Resolved {time(incident.resolved_at)}</div>}
  </div>}</aside>;
}
