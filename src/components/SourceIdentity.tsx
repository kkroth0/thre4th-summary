import { useState } from 'react';
import { Globe2 } from 'lucide-react';
import { cn } from '@/lib/utils';

function sourceHostname(url?: string): string | undefined {
  try {
    const parsed = new URL(url || '');
    const host = parsed.hostname.replace(/^www\./, '');
    if (!['http:', 'https:'].includes(parsed.protocol) || !host.includes('.')
      || host.includes(':') || /^[\d.]+$/.test(host) || /\.(local|localhost|internal|test|invalid)$/.test(host)) return undefined;
    return host;
  } catch {
    return undefined;
  }
}

function Favicon({ host }: { host?: string }) {
  const [failed, setFailed] = useState(false);
  if (!host || failed) return <Globe2 aria-hidden="true" className="h-4 w-4 shrink-0 text-muted-foreground" />;
  return <img
    src={`https://www.google.com/s2/favicons?sz=32&domain=${encodeURIComponent(host)}`}
    alt="" aria-hidden="true" width={16} height={16}
    className="h-4 w-4 shrink-0 rounded-sm object-contain"
    loading="lazy" decoding="async" referrerPolicy="no-referrer"
    onError={() => setFailed(true)}
  />;
}

export function SourceIdentity({ name, url, className }: { name?: string; url?: string; className?: string }) {
  const host = sourceHostname(url);
  const label = name?.trim() || host || '—';
  return <span className={cn('inline-flex min-w-0 items-center gap-2', className)} title={label}>
    <Favicon key={host || 'unknown'} host={host} />
    <span className="min-w-0 truncate">{label}</span>
  </span>;
}

export function SourceList({ sources, limit = 2 }: {
  sources: { link: string; source?: string; name?: string }[]; limit?: number;
}) {
  const unique = [...new Map(sources.map(item => {
    const name = item.source?.trim() || item.name?.trim() || sourceHostname(item.link) || '—';
    return [name.toLocaleLowerCase(), { ...item, name }] as const;
  })).values()];
  if (!unique.length) return <span className="text-muted-foreground">—</span>;
  return <div className="flex flex-col items-start gap-1.5">
    {unique.slice(0, limit).map(item => <SourceIdentity key={item.name} name={item.name} url={item.link} className="max-w-52" />)}
    {unique.length > limit && <span className="text-xs text-muted-foreground">+{unique.length - limit}</span>}
  </div>;
}
