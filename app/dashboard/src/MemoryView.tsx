import { useEffect, useState } from 'react';
import { ArrowRight, FileText, GitBranch, LockKeyhole, Play, Search, SquarePen, X } from 'lucide-react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, Field, label, memoryState, shortId, time } from './components';
import type { Lineage, Memory, Run } from './types';

interface Props {
  memories: Memory[];
  runs: Run[];
  loading: boolean;
  selectedId?: string;
  onSelect: (id: string) => void;
  onRefresh: () => Promise<void>;
  onRecovered: (runId: string) => void;
}

export default function MemoryView({ memories, runs, loading, selectedId, onSelect, onRefresh, onRecovered }: Props) {
  const [query, setQuery] = useState('');
  const [lineage, setLineage] = useState<Lineage | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState('');
  const [content, setContent] = useState('');
  const [runId, setRunId] = useState('');
  const [replacementMemory, setReplacementMemory] = useState<Memory | null>(null);
  const selected = memories.find((memory) => memory.memory_id === selectedId);
  const filtered = memories.filter((memory) => `${memory.memory_id} ${memory.content} ${memory.source_id ?? ''}`.toLowerCase().includes(query.toLowerCase()));

  useEffect(() => {
    setLineage(null); setError(''); setNotice(''); setReason(''); setContent('');
    if (!selectedId) return;
    let cancelled = false;
    api.lineage(selectedId).then((value) => { if (!cancelled) setLineage(value); })
      .catch((e: Error) => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [selectedId]);

  useEffect(() => {
    setRunId(selected?.run_id ?? runs.find((run) => run.namespace_id === selected?.namespace_id)?.run_id ?? runs[0]?.run_id ?? '');
  }, [selected?.run_id, selected?.namespace_id, runs]);

  async function quarantine() {
    if (!selected || !reason.trim()) return;
    setBusy(true); setError(''); setNotice('');
    try { await api.quarantine(selected.memory_id, reason.trim()); await onRefresh(); setNotice('Quarantine recorded.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Quarantine failed.'); }
    finally { setBusy(false); }
  }

  async function replace() {
    if (!selected || !content.trim() || !runId) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const replacement = await api.replace(selected.memory_id, runId, content);
      await onRefresh(); onSelect(replacement.memory_id); setReplacementMemory(replacement); setNotice('Replacement recorded.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Replacement failed.'); }
    finally { setBusy(false); }
  }

  async function recover() {
    if (!replacementMemory) return;
    setBusy(true); setError('');
    try {
      const run = await api.createRun({ scenario: 'recovery', control_mode: 'full_system', planner_mode: 'recorded', replacement_memory_id: replacementMemory.memory_id });
      await onRefresh(); onRecovered(run.run_id);
    } catch (e) { setError(e instanceof Error ? e.message : 'Recovery run failed.'); }
    finally { setBusy(false); }
  }

  return <>
    <div className="page-heading"><div><h1>Memory</h1><p>Managed sources and provenance</p></div><span className="plain-meta">{memories.length} versions</span></div>
    {error && <ErrorNotice>{error}</ErrorNotice>}{notice && <div className="notice success" role="status">{notice}</div>}
    <div className={`investigation-workspace ${selected ? 'is-inspecting' : ''}`}>
      <section className="record-list"><div className="section-heading"><h2>Memory versions</h2><span>{filtered.length} records</span></div><div className="search-field"><Search size={16} /><input aria-label="Search memory" placeholder="Search memory" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
        {filtered.length === 0 ? <Empty title={loading ? 'Loading memory' : query ? 'No matching memory' : 'No memory stored'} /> : <div className="table-scroll">
          <table><thead><tr><th>Source / content</th><th>Trust</th><th>Generation</th><th>State</th></tr></thead>
            <tbody>{filtered.map((memory) => <tr key={memory.memory_id} className={selectedId === memory.memory_id ? 'selected-row' : ''}>
              <td><button className="table-link" onClick={() => onSelect(memory.memory_id)} title={memory.memory_id}>{label(memory.source_type, 'Memory')}<ArrowRight size={13} /></button><span className="record-preview">{memory.content?.slice(0, 140) || 'No content stored.'}</span><small>{shortId(memory.memory_id)} / {shortId(memory.source_id)}</small></td>
              <td>{label(memory.trust_tier)}</td><td>{memory.generation ?? 0}</td><td><Badge value={memoryState(memory)} /></td>
            </tr>)}</tbody>
          </table>
        </div>}
      </section>
      {selected && <section className="inspector"><div className="section-heading"><h2>Memory detail</h2><div className="section-heading-actions"><Badge value={memoryState(selected)} /><button className="icon-button" onClick={() => onSelect('')} title="Close memory detail" aria-label="Close memory detail"><X size={17} /></button></div></div>
        <div className="inspector-content">
          <div className="document-preview"><div className="document-header"><FileText size={18} /><strong>Stored content</strong><span className="inspector-kicker">{label(selected.source_type)}</span></div><pre>{selected.content || 'No content available.'}</pre></div>
          <section className="inspector-block">
            <h3><GitBranch size={16} />Provenance</h3>
            <dl className="detail-grid"><Field name="Memory" value={<code>{shortId(selected.memory_id)}</code>} /><Field name="Trust" value={label(selected.trust_tier)} /><Field name="Source ID" value={<code>{selected.source_id ?? '--'}</code>} /><Field name="Generation" value={selected.generation ?? 0} /><Field name="Run" value={<code>{shortId(selected.run_id)}</code>} /><Field name="Created" value={time(selected.created_at)} /></dl>
            {!lineage ? <p className="muted">Lineage unavailable.</p> : <div className="lineage-list">{lineage.nodes?.map((node) => <button key={node.memory_id} className="lineage-node" onClick={() => onSelect(node.memory_id)}><span className="lineage-point" /><span><code>{shortId(node.memory_id)}</code><small>{lineage.root_ids?.includes(node.memory_id) ? 'Origin' : `Generation ${node.generation ?? 0}`}</small></span><Badge value={memoryState(node)} /></button>)}{lineage.edges?.map((edge, index) => <div className="lineage-edge" key={index}><code>{shortId(edge.parent_id ?? edge.source)}</code><ArrowRight size={13} /><code>{shortId(edge.child_id ?? edge.target)}</code></div>)}</div>}
          </section>
          <form className="operator-form" onSubmit={(e) => { e.preventDefault(); void quarantine(); }}><h3><LockKeyhole size={16} />Containment</h3><label>Quarantine reason<textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} required disabled={busy} /></label><button className="danger-button" disabled={busy || !reason.trim() || /quarant/i.test(memoryState(selected))}><LockKeyhole size={15} />Quarantine memory</button></form>
          <form className="operator-form" onSubmit={(e) => { e.preventDefault(); void replace(); }}><h3><SquarePen size={16} />Reviewed replacement</h3><label>Run<select value={runId} onChange={(e) => setRunId(e.target.value)} disabled={busy} required><option value="">Select run</option>{runs.map((run) => <option key={run.run_id} value={run.run_id}>{shortId(run.run_id)} / {label(run.scenario)}</option>)}</select></label><label>Fresh operator input<textarea value={content} onChange={(e) => setContent(e.target.value)} rows={3} required disabled={busy} /></label><button className="secondary-button" disabled={busy || !content.trim() || !runId}><SquarePen size={15} />Create replacement</button></form>
          {replacementMemory && <div className="recovery-action"><span>Replacement <code>{shortId(replacementMemory.memory_id)}</code></span><button className="primary-button" onClick={() => void recover()} disabled={busy}><Play size={15} />Run recovery</button></div>}
        </div>
      </section>}
    </div>
  </>;
}
