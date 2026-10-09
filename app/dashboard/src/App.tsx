import { useCallback, useEffect, useState } from 'react';
import { Activity, BarChart3, ChevronDown, ChevronRight, Database, LockKeyhole, Moon, Plug, Radar, RefreshCw, ShieldAlert, Sun } from 'lucide-react';
import { api } from './api';
import { ErrorNotice, label } from './components';
import RunsView from './RunsView';
import MemoryView from './MemoryView';
import IncidentsView from './IncidentsView';
import AnalyticsView from './AnalyticsView';
import OperationsView from './OperationsView';
import ConnectionsView from './ConnectionsView';
import type { Analytics, Health, Incident, Memory, Run } from './types';

type View = 'operations' | 'runs' | 'memory' | 'incidents' | 'analytics' | 'connections';
const views = [
  { id: 'operations' as const, name: 'Operations', icon: Radar },
  { id: 'runs' as const, name: 'Simulation', icon: Activity },
  { id: 'memory' as const, name: 'Memory', icon: Database },
  { id: 'incidents' as const, name: 'Memory incidents', icon: ShieldAlert },
  { id: 'analytics' as const, name: 'Analytics', icon: BarChart3 },
  { id: 'connections' as const, name: 'Connections', icon: Plug },
];

export default function App() {
  const [view, setView] = useState<View>('operations');
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try { return localStorage.getItem('interlock-theme') === 'dark' ? 'dark' : 'light'; }
    catch { return 'light'; }
  });
  const [health, setHealth] = useState<Health | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [memories, setMemories] = useState<Memory[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [memoryId, setMemoryId] = useState<string>();
  const [incidentId, setIncidentId] = useState<string>();
  const [runId, setRunId] = useState<string>();
  const refresh = useCallback(async () => {
    setLoading(true);
    const results = await Promise.allSettled([api.health(), api.runs(), api.memories(), api.incidents(), api.analytics()]);
    const names = ['health', 'runs', 'memory', 'incidents', 'analytics'];
    const failures: Record<string, string> = {};
    results.forEach((result, i) => {
      if (result.status === 'rejected') failures[names[i]] = result.reason instanceof Error ? result.reason.message : 'API unavailable.';
    });
    if (results[0].status === 'fulfilled') setHealth(results[0].value as Health);
    if (results[1].status === 'fulfilled') setRuns((results[1].value as { items: Run[] }).items ?? []);
    if (results[2].status === 'fulfilled') setMemories((results[2].value as { items: Memory[] }).items ?? []);
    if (results[3].status === 'fulfilled') setIncidents((results[3].value as { items: Incident[] }).items ?? []);
    if (results[4].status === 'fulfilled') setAnalytics(results[4].value as Analytics);
    setErrors(failures);
    setLoading(false);
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const timer = window.setInterval(() => {
      api.health().then((value) => {
        setHealth(value);
        setErrors((current) => { const next = { ...current }; delete next.health; return next; });
      }).catch(() => undefined);
    }, 10000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('interlock-theme', theme); } catch { /* Theme still works without browser storage. */ }
  }, [theme]);

  function openMemory(id: string) { setMemoryId(id); setView('memory'); }
  function openIncident(id: string) { setIncidentId(id); setView('incidents'); }

  return <div className="app-shell command-shell">
    <aside className="icon-rail">
      <button className="rail-brand" onClick={() => setView('operations')} title="Interlock" aria-label="Interlock operations"><span className="brand-symbol"><LockKeyhole size={19} /></span><span className="brand-wordmark">Interlock</span></button>
      <div className="nav-group-label">Workspace</div>
      <nav className="rail-nav" aria-label="Main navigation">{views.map(({ id, name, icon: Icon }) => <button key={id} className={`rail-button ${view === id ? 'active' : ''}`} onClick={() => setView(id)} aria-current={view === id ? 'page' : undefined} title={name} aria-label={id === 'incidents' && incidents.length > 0 ? `${name}, ${incidents.length} recorded` : name}><Icon size={18} /><span className="nav-label">{name}</span>{id === 'incidents' && incidents.length > 0 && <span className="rail-count">{incidents.length > 9 ? '9+' : incidents.length}</span>}</button>)}</nav>
      <div className="rail-bottom"><span className="workspace-name">Local workspace</span><span className="rail-status" title={loading && !health ? 'Connecting' : errors.health ? 'API unavailable' : 'Local API connected'}><span className={`status-dot ${health && !errors.health ? 'online' : ''}`} /><span className="connection-label">{loading && !health ? 'Connecting' : errors.health ? 'API unavailable' : health ? 'API connected' : 'API unavailable'}</span></span></div>
    </aside>
    <main>
      <header className="topbar"><div className="breadcrumb"><strong className="product-name">Interlock</strong><span className="header-context">Workspace</span><ChevronRight size={14} /><span className="current-view">{views.find((item) => item.id === view)?.name}</span></div><div className="topbar-actions">
        <details className="integration-menu"><summary className="integration-trigger" title="Sponsor integrations" aria-label="Sponsor integrations"><Plug size={16} /><span>Integrations</span><ChevronDown size={13} /></summary><div className="integration-popover"><div className="popover-heading">Connections</div>{['akash', 'clickhouse', 'guild', 'sandbox', 'slack'].map((name) => {
        const integration = health?.integrations?.[name];
        const status = !integration ? (loading ? 'Connecting' : 'Unavailable') : integration.verified ? 'Verified' : integration.configured ? 'Configured, unverified' : 'Not configured';
        return <div className="integration" key={name} title={integration ? label(integration.status) : status}><span className={`status-dot ${integration?.verified ? 'online' : integration?.configured ? 'pending' : ''}`} /><div><strong>{name === 'akash' ? 'Akash Console' : name === 'guild' ? 'Guild' : name === 'clickhouse' ? 'ClickHouse' : name === 'slack' ? 'Slack MCP' : 'Investigation sandbox'}</strong><span>{status}</span></div></div>;
      })}<button className="popover-open" onClick={() => setView('connections')}>Open connections<ChevronRight size={14} /></button></div></details>
        <button className="icon-button theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}</button>
        <button className="icon-button" onClick={() => void refresh()} disabled={loading} title="Refresh workspace" aria-label="Refresh workspace"><RefreshCw size={17} className={loading ? 'spin' : ''} /></button>
      </div></header>
      <div className="workspace-content">
        {errors[view] && <ErrorNotice>{errors[view]}</ErrorNotice>}
        {errors.health && !errors[view] && <ErrorNotice>Backend connection unavailable. {errors.health}</ErrorNotice>}
        {view === 'operations' && <OperationsView health={health} onConnections={() => setView('connections')} />}
        {view === 'runs' && <RunsView runs={runs} loading={loading} onRefresh={refresh} onMemory={openMemory} onIncident={openIncident} initialRunId={runId} />}
        {view === 'memory' && <MemoryView memories={memories} runs={runs} loading={loading} selectedId={memoryId} onSelect={setMemoryId} onRefresh={refresh} onRecovered={(id) => { setRunId(id); setView('runs'); }} />}
        {view === 'incidents' && <IncidentsView incidents={incidents} loading={loading} selectedId={incidentId} onSelect={setIncidentId} onMemory={openMemory} health={health} />}
        {view === 'analytics' && <AnalyticsView analytics={analytics} loading={loading} health={health} onRefresh={refresh} />}
        {view === 'connections' && <ConnectionsView health={health} onRefresh={refresh} />}
      </div>
    </main>
  </div>;
}
