import { useEffect, useState } from 'react';
import { ArrowRight, FileText, ScanSearch, ShieldAlert, X } from 'lucide-react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, Field, JsonPreview, label, shortId, time } from './components';
import type { DataRecord, Health, Incident } from './types';

interface Props {
  incidents: Incident[];
  loading: boolean;
  selectedId?: string;
  onSelect: (id: string) => void;
  onMemory: (id: string) => void;
  health: Health | null;
}

export default function IncidentsView({ incidents, loading, selectedId, onSelect, onMemory, health }: Props) {
  const [selected, setSelected] = useState<Incident | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState('');
  const [provider, setProvider] = useState('recorded');
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<DataRecord | null>(null);

  useEffect(() => {
    if (!selectedId) {
      setSelected(null); setReport(null); setError(''); setDetailLoading(false);
      return;
    }
    let cancelled = false;
    setDetailLoading(true); setError(''); setSelected(null); setReport(null);
    api.incident(selectedId).then((value) => { if (!cancelled) setSelected(value); })
      .catch((e: Error) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setDetailLoading(false); });
    return () => { cancelled = true; };
  }, [selectedId]);

  async function investigate() {
    if (!selected) return;
    setBusy(true); setError('');
    try {
      setReport(await api.investigate(selected.incident_id, provider));
      setSelected(await api.incident(selected.incident_id));
    } catch (e) { setError(e instanceof Error ? e.message : 'Investigation failed.'); }
    finally { setBusy(false); }
  }

  const memoryIds = selected ? [...new Set([
    ...(selected.memory_id ? [selected.memory_id] : []),
    ...(Array.isArray(selected.memory_ids) ? selected.memory_ids.filter((id): id is string => typeof id === 'string') : []),
  ])] : [];

  return <>
    <div className="page-heading"><div><h1>Memory incidents</h1><p>Evidence and containment</p></div><span className="plain-meta">{incidents.length} incidents</span></div>
    {error && <ErrorNotice>{error}</ErrorNotice>}
    <div className={`investigation-workspace ${selectedId ? 'is-inspecting' : ''}`}>
      <section className="record-list"><div className="section-heading"><h2>Incident queue</h2><span>{loading ? 'Refreshing' : `${incidents.length} records`}</span></div>
        {incidents.length === 0 ? <Empty title={loading ? 'Loading incidents' : 'No incidents recorded'} /> : <div className="table-scroll">
          <table><thead><tr><th>Incident</th><th>Severity</th><th>State</th><th>Recorded</th></tr></thead>
            <tbody>{incidents.map((incident) => <tr className={selectedId === incident.incident_id ? 'selected-row' : ''} key={incident.incident_id}>
              <td><button className="table-link" onClick={() => onSelect(incident.incident_id)}><ShieldAlert size={16} />{incident.title ?? label(incident.reason, `Incident ${shortId(incident.incident_id)}`)}<ArrowRight size={13} /></button><small>{shortId(incident.incident_id)} / Run {shortId(incident.run_id)}</small></td>
              <td><Badge value={incident.severity} /></td><td><Badge value={incident.status} /></td><td>{time(incident.created_at)}</td>
            </tr>)}</tbody>
          </table>
        </div>}
      </section>
      {selectedId && <section className="inspector"><div className="section-heading"><h2>Incident detail</h2><div className="section-heading-actions">{selected && <Badge value={selected.status} />}<button className="icon-button" onClick={() => onSelect('')} title="Close incident detail" aria-label="Close incident detail"><X size={17} /></button></div></div>
        {detailLoading ? <Empty title="Loading evidence" /> : !selected ? <Empty title="Evidence unavailable" /> : <div className="inspector-content"><span className="inspector-kicker">{shortId(selected.incident_id)}</span><h3>{selected.title ?? `Incident ${shortId(selected.incident_id)}`}</h3><p className="incident-reason">{selected.reason ?? 'No incident rationale recorded.'}</p><dl className="detail-grid"><Field name="Run" value={<code>{shortId(selected.run_id)}</code>} /><Field name="Severity" value={label(selected.severity)} /><Field name="Created" value={time(selected.created_at)} /></dl>
          <section className="inspector-block"><h3><FileText size={16} />Implicated memory</h3>{memoryIds.length === 0 ? <p className="muted">No memory references recorded.</p> : <div className="context-list">{memoryIds.map((id) => <button className="context-item" key={id} onClick={() => onMemory(id)}><FileText size={17} /><span><strong>{shortId(id)}</strong><small>Memory evidence</small></span><ArrowRight size={14} /></button>)}</div>}</section>
          <section className="inspector-block"><h3>Evidence snapshot</h3><JsonPreview value={selected.evidence ?? selected} /></section>
          <section className="inspector-block"><h3><ScanSearch size={16} />Advisory investigation</h3><form className="investigator-controls" onSubmit={(e) => { e.preventDefault(); void investigate(); }}><label>Investigator<select value={provider} disabled={busy} onChange={(e) => setProvider(e.target.value)}><option value="recorded">Recorded analysis</option><option value="akash" disabled={!health?.integrations?.akash?.configured}>Live Akash Qwen</option><option value="guild" disabled={!health?.integrations?.guild?.configured}>Hosted Guild</option></select></label><button className="secondary-button" disabled={busy}><ScanSearch size={15} />{busy ? 'Investigating...' : 'Investigate'}</button></form>{report || selected.analyses || selected.investigation ? <JsonPreview value={report ?? selected.analyses ?? selected.investigation} /> : <p className="muted">No advisory analysis recorded.</p>}</section>
        </div>}
      </section>}
    </div>
  </>;
}
