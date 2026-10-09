import { ArrowRight, FileText, ShieldAlert, X } from 'lucide-react';
import { Badge, Empty, Field, JsonPreview, label, memoryState, shortId, time } from './components';
import type { Action, Run } from './types';

interface Props {
  run: Run | null;
  loading: boolean;
  onClose: () => void;
  onMemory: (id: string) => void;
  onIncident: (id: string) => void;
}

function textValue(...values: unknown[]) {
  const value = values.find((item) => typeof item === 'string' || typeof item === 'number');
  return value === undefined ? 'Not recorded' : String(value);
}

function Decision({ action }: { action: Action }) {
  const args = action.arguments ?? action.args ?? {};
  return <article className="decision-record">
    <div className="record-heading"><strong>{label(action.tool ?? action.action_type, 'Proposed action')}</strong><Badge value={action.outcome ?? action.decision ?? action.status} /></div>
    <dl className="decision-meta"><Field name="Recipient" value={textValue(args.recipient, action.recipient)} /><Field name="Report" value={textValue(args.report_id, action.report_id)} /></dl>
    {action.reason && <p className="decision-reason">{action.reason}</p>}
  </article>;
}

export default function RunPeek({ run, loading, onClose, onMemory, onIncident }: Props) {
  return <aside className="run-peek" aria-label="Selected run details">
    <div className="peek-heading"><div className="peek-title"><span>Run details</span>{run && <code title={run.run_id}>{shortId(run.run_id)}</code>}</div><button className="icon-button" onClick={onClose} aria-label="Close run details" title="Close run details"><X size={18} /></button></div>
    {loading ? <Empty title="Loading run" /> : !run ? <Empty title="Run unavailable" /> : <div className="peek-body">
      <div className="peek-summary"><Badge value={run.outcome} /><span>{time(run.created_at)}</span></div>
      <h2 className="peek-run-name">{label(run.scenario)}</h2>
      <dl className="detail-grid"><Field name="Protection" value={label(run.control_mode)} /><Field name="Planner" value={label(run.planner_mode)} /><Field name="Namespace" value={<code title={run.namespace_id}>{shortId(run.namespace_id)}</code>} /></dl>
      <section className="peek-section"><div className="section-heading"><h3>Action decisions</h3><span>{run.actions?.length ?? 0}</span></div>
        {!run.actions?.length ? <p className="muted">No proposed actions recorded.</p> : run.actions.map((action, index) => <Decision action={action} key={action.action_id ?? index} />)}
      </section>
      <section className="peek-section"><div className="section-heading"><h3>Memory evidence</h3><span>{run.memories?.length ?? 0}</span></div>
        {!run.memories?.length ? <p className="muted">No memory context recorded.</p> : <div className="evidence-list">{run.memories.map((memory) => <button className="evidence-item" key={memory.memory_id} onClick={() => onMemory(memory.memory_id)}><div className="evidence-heading"><FileText size={15} /><code>{shortId(memory.memory_id)}</code><Badge value={memoryState(memory)} /><ArrowRight size={14} /></div><p className="evidence-snippet">{memory.content}</p><span className="evidence-source">{label(memory.source_type)} / {label(memory.trust_tier)} / Generation {memory.generation ?? 0}</span></button>)}</div>}
      </section>
      {!!run.incidents?.length && <section className="peek-section"><div className="section-heading"><h3>Incidents</h3><span>{run.incidents.length}</span></div><div className="context-list">{run.incidents.map((incident) => <button className="context-item" key={incident.incident_id} onClick={() => onIncident(incident.incident_id)}><ShieldAlert size={17} /><span><strong>{incident.title ?? shortId(incident.incident_id)}</strong><small>{label(incident.status)}</small></span><ArrowRight size={14} /></button>)}</div></section>}
      {!!run.events?.length && <details className="peek-section raw-evidence"><summary>Event data ({run.events.length})</summary><JsonPreview value={run.events} /></details>}
    </div>}
  </aside>;
}
