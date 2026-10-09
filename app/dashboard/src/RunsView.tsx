import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, ArrowRight, Filter, Play, Plus, Search, X } from 'lucide-react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, label, shortId, time } from './components';
import RunPeek from './RunPeek';
import type { Run, RunInput } from './types';

interface Props {
  runs: Run[];
  loading: boolean;
  onRefresh: () => Promise<void>;
  onMemory: (id: string) => void;
  onIncident: (id: string) => void;
  initialRunId?: string;
}

export default function RunsView({ runs, loading, onRefresh, onMemory, onIncident, initialRunId }: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [input, setInput] = useState<RunInput>({ scenario: 'immediate', control_mode: 'full_system', planner_mode: 'recorded' });
  const [query, setQuery] = useState('');
  const [outcome, setOutcome] = useState('all');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [selectedId, setSelectedId] = useState<string | undefined>(initialRunId);
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const outcomes = useMemo(() => [...new Set(runs.map((run) => run.outcome))].filter(Boolean).sort(), [runs]);
  const filteredRuns = useMemo(() => runs.filter((run) => {
    const text = `${run.run_id} ${label(run.scenario)} ${label(run.control_mode)} ${label(run.planner_mode)} ${label(run.outcome)}`.toLowerCase();
    return (outcome === 'all' || run.outcome === outcome) && text.includes(query.trim().toLowerCase());
  }), [runs, query, outcome]);

  useEffect(() => { if (initialRunId) setSelectedId(initialRunId); }, [initialRunId]);

  useEffect(() => {
    if (!selectedId) { setSelectedRun(null); setDetailLoading(false); return; }
    let cancelled = false;
    setDetailLoading(true);
    setSelectedRun(null);
    api.run(selectedId).then((run) => { if (!cancelled) setSelectedRun(run); })
      .catch((e: Error) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setDetailLoading(false); });
    return () => { cancelled = true; };
  }, [selectedId]);

  async function startRun() {
    setBusy(true);
    setError('');
    try {
      const run = await api.createRun(input);
      setSelectedId(run.run_id);
      setSelectedRun(run);
      dialogRef.current?.close();
      await onRefresh();
    } catch (e) { setError(e instanceof Error ? e.message : 'Run could not be started.'); }
    finally { setBusy(false); }
  }

  return <>
    <div className="page-heading"><div className="heading-title"><h1>Simulation</h1><span className="plain-meta">Controlled report-assistant fixtures</span></div><div className="page-toolbar"><button className="primary-button" onClick={() => { setError(''); dialogRef.current?.showModal(); }}><Plus size={16} />New run</button></div></div>
    <div className="run-toolbar"><label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search runs" aria-label="Search runs" />{query && <button className="icon-button" onClick={() => setQuery('')} title="Clear search" aria-label="Clear search"><X size={14} /></button>}</label><div className="filter-select"><Filter size={14} /><select value={outcome} onChange={(event) => setOutcome(event.target.value)} aria-label="Filter by outcome"><option value="all">All outcomes</option>{outcomes.map((value) => <option key={value} value={value}>{label(value)}</option>)}</select></div><span className="view-count">{loading ? 'Refreshing...' : `${filteredRuns.length} ${filteredRuns.length === 1 ? 'run' : 'runs'}`}</span></div>
    {error && <ErrorNotice>{error}</ErrorNotice>}
    <div className={`run-workspace ${selectedId ? 'is-inspecting' : ''}`}>
      <section className="run-history" aria-label="Run history">
        {filteredRuns.length === 0 ? <Empty title={loading ? 'Loading runs' : runs.length ? 'No matching runs' : 'No simulation runs yet'} /> : <div className="table-scroll"><table className="run-table"><thead><tr><th>Run</th><th>Scenario</th><th>Protection</th><th>Planner</th><th>Outcome</th><th>Created</th></tr></thead><tbody>{filteredRuns.map((run) => <tr key={run.run_id} className={selectedId === run.run_id ? 'selected-row' : ''}><td><button className="table-link run-id-link" onClick={() => { setError(''); setSelectedId(run.run_id); }} title={run.run_id}><Activity size={14} /><code>{shortId(run.run_id)}</code><ArrowRight size={13} /></button></td><td>{label(run.scenario)}</td><td>{label(run.control_mode)}</td><td><span className="planner-label">{run.planner_mode === 'live' ? 'Akash Qwen' : label(run.planner_mode)}</span></td><td><Badge value={run.outcome} /></td><td className="date-cell">{time(run.created_at)}</td></tr>)}</tbody></table></div>}
      </section>
      {selectedId && <RunPeek run={selectedRun} loading={detailLoading} onClose={() => setSelectedId(undefined)} onMemory={onMemory} onIncident={onIncident} />}
    </div>
    <dialog ref={dialogRef} className="run-dialog" aria-labelledby="new-run-title" onCancel={(event) => { if (busy) event.preventDefault(); }}>
      <div className="dialog-heading"><h2 id="new-run-title">New run</h2><button className="icon-button" onClick={() => dialogRef.current?.close()} disabled={busy} title="Close new run" aria-label="Close new run"><X size={18} /></button></div>
      <form className="dialog-form" onSubmit={(event) => { event.preventDefault(); void startRun(); }}>
        <label>Scenario<select value={input.scenario} onChange={(event) => setInput({ ...input, scenario: event.target.value })} disabled={busy}><option value="immediate">Immediate poisoning</option><option value="dormant">Dormant poisoning</option><option value="benign">Benign external source</option></select></label>
        <label>Protection<select value={input.control_mode} onChange={(event) => setInput({ ...input, control_mode: event.target.value })} disabled={busy}><option value="full_system">Full system</option><option value="ingestion_filter_only">Ingestion filter only</option><option value="unguarded">Unguarded</option></select></label>
        <fieldset className="planner-mode"><legend>Planner</legend><div className="segmented">{['recorded', 'live'].map((mode) => <button type="button" key={mode} disabled={busy} aria-pressed={input.planner_mode === mode} className={input.planner_mode === mode ? 'selected' : ''} onClick={() => setInput({ ...input, planner_mode: mode })}>{mode === 'recorded' ? 'Recorded' : 'Live Akash Qwen'}</button>)}</div></fieldset>
        {error && <ErrorNotice>{error}</ErrorNotice>}
        <div className="dialog-actions"><button type="button" className="secondary-button" onClick={() => dialogRef.current?.close()} disabled={busy}>Cancel</button><button type="submit" className="primary-button" disabled={busy}><Play size={15} />{busy ? 'Running...' : 'Start run'}</button></div>
      </form>
    </dialog>
  </>;
}
