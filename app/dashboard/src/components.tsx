import { AlertCircle, FileText } from 'lucide-react';
import type { ReactNode } from 'react';
import type { Memory } from './types';

export function memoryState(memory: Memory): string {
  return memory.effective_quarantined ? 'quarantined' : memory.lifecycle ?? memory.state ?? memory.status ?? 'unknown';
}

export function label(value: unknown, fallback = 'Unavailable'): string {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value).replaceAll('_', ' ');
}

export function shortId(value: string | undefined): string {
  return value ? value.slice(0, 10) : '--';
}

export function time(value: string | undefined): string {
  if (!value) return '--';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function Badge({ children, value }: { children?: ReactNode; value?: string }) {
  const normalized = (value ?? '').toLowerCase();
  const tone = /block|quarant|contain|fail|attack|error|suspicious/.test(normalized) ? 'danger'
    : /pending|review|unconfigured|not configured|unverified|unavailable|open|uncertain/.test(normalized) ? 'warning'
      : /allow|execut|complete|healthy|verified|recovered|resolved|active/.test(normalized) ? 'success' : 'neutral';
  return <span className={`badge ${tone}`}>{children ?? label(value)}</span>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><FileText size={28} strokeWidth={1.4} /><strong>{title}</strong>{children && <p>{children}</p>}</div>;
}

export function ErrorNotice({ children }: { children: ReactNode }) {
  return <div className="notice error" role="alert"><AlertCircle size={17} /><span>{children}</span></div>;
}

export function JsonPreview({ value }: { value: unknown }) {
  return <pre className="json-preview">{JSON.stringify(value, null, 2)}</pre>;
}

export function Field({ name, value }: { name: string; value: ReactNode }) {
  return <div className="detail-field"><dt>{name}</dt><dd>{value}</dd></div>;
}
