import { ExternalLink } from 'lucide-react';
import { shortId, time } from './components';
import type { SourceCitation } from './types';

export function publicSourceUrl(value: string): string | undefined {
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    if (url.protocol !== 'https:' || url.username || url.password || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return undefined;
    return url.href;
  } catch { return undefined; }
}

export default function SourceCitations({ citations }: { citations: SourceCitation[] }) {
  if (!citations.length) return null;
  return <div className="source-citations">{citations.map((citation) => {
    const href = publicSourceUrl(citation.url);
    return <div className="source-citation" key={citation.source_id}>
      {href ? <a href={href} target="_blank" rel="noopener noreferrer"><ExternalLink size={13} /><span>{citation.url}</span></a> : <span className="citation-record">{citation.url.startsWith('recorded://') ? 'Recorded source' : citation.url}</span>}
      <div className="citation-metadata"><code title={citation.source_id}>{shortId(citation.source_id)}</code><time>{time(citation.retrieved_at)}</time>{citation.content_hash && <code title={citation.content_hash}>Hash {citation.content_hash.slice(0, 12)}</code>}</div>
    </div>;
  })}</div>;
}
