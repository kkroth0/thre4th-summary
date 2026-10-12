import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Bookmark, FileText, Layers } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { StoryCard, StorySource } from '@/pages/newsletterView';
import type { StoryDetail } from '@/services/threatApi';
import { DataPager } from './DataPager';
import { RecordDrawer } from './RecordDrawer';
import { SourceIdentity, SourceList } from '@/components/SourceIdentity';
import { collectNewsIndicators } from '@/utils/newsIndicators';

type Row = StorySource & { description?: string; severity?: string; kev?: boolean; ttps?: string[] };
function StoryIndicators({ story, pt, onSelect }: { story: StoryCard<Row>; pt: boolean; onSelect?: (id: string, kind: 'ip' | 'domain') => void }) {
  const indicators = collectNewsIndicators([story]);
  if (!indicators.length) return null;
  return <div className="mt-2 flex gap-3 text-[11px] text-muted-foreground">{(['ip', 'domain'] as const).map(kind => {
    const count = indicators.filter(item => item.kind === kind).length;
    return count ? <button key={kind} type="button" onClick={() => onSelect?.(story.storyId, kind)} className="rounded-sm hover:text-primary focus-visible:ring-2 focus-visible:ring-ring">{kind === 'ip' ? 'IPs' : pt ? 'Domínios' : 'Domains'}: {count}</button> : null;
  })}</div>;
}
const date = (value: string, pt: boolean) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleDateString(pt ? 'pt-BR' : 'en-US') : '—';
const safeLink = (value: string) => /^https?:\/\//i.test(value);
function Severity({ sources, pt }: { sources: Row[]; pt: boolean }) {
  const value = ['Critical', 'High', 'Medium', 'Low'].find(level => sources.some(source => source.severity === level));
  if (!value) return null;
  const labels: Record<string, string> = { Critical: 'Crítico', High: 'Alto', Medium: 'Médio', Low: 'Baixo' };
  return <span className={`rounded border px-1.5 py-0.5 text-[10px] ${value === 'Critical' ? 'border-red-500/30 text-red-500' : value === 'High' ? 'border-orange-500/30 text-orange-500' : 'border-border text-muted-foreground'}`}>{pt ? labels[value] : value}</span>;
}

export function StoryTable<T extends Row>({ rows, pt, onSave, onReport, onSelect, evidence, initialId, isSaved, isReporting, onIndicators }: {
  rows: StoryCard<T>[]; pt: boolean; onSave?: (row: StoryCard<T>) => void; onReport?: (row: StoryCard<T>) => void;
  onSelect?: (id: string) => void; evidence?: Record<string, { loading: boolean; data?: StoryDetail }>; initialId?: string | null;
  isSaved?: (row: StoryCard<T>) => boolean; isReporting?: (row: StoryCard<T>) => boolean;
  onIndicators?: (id: string, kind: 'ip' | 'domain') => void;
}) {
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [selectedId, setSelectedId] = useState<string | null>(initialId || null);
  useEffect(() => { setPage(1); }, [rows]);
  useEffect(() => { if (initialId) setSelectedId(initialId); }, [initialId]);
  const selected = rows.find(row => row.storyId === selectedId);
  const open = (row: StoryCard<T>) => { setSelectedId(row.storyId); onSelect?.(row.storyId); };
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const current = Math.min(page, pages);
  const details = selected ? evidence?.[selected.storyId] : undefined;
  const names = (items: { name: string }[]): ReactNode => items.length ? items.map(item => item.name).join(', ') : <span className="text-muted-foreground">—</span>;
  return <div className="intel-panel overflow-hidden">
    <DataPager total={rows.length} page={current} pageSize={size} onPage={setPage} onPageSize={value => { setSize(value); setPage(1); }} pt={pt} />
    <div className="overflow-x-auto"><table className="intel-table min-w-[760px]">
      <thead><tr><th className="w-[42%]">{pt ? 'Evento / publicação' : 'Event / publication'}</th><th>{pt ? 'Fontes' : 'Sources'}</th><th>{pt ? 'Ator' : 'Actor'}</th><th>Malware / CVE</th><th>{pt ? 'Última publicação' : 'Latest publication'}</th></tr></thead>
      <tbody>{rows.slice((current - 1) * size, current * size).map(row => <tr key={row.storyId}>
        <td><button type="button" className="text-left font-medium leading-relaxed text-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" onClick={() => open(row)}>{row.title}</button><p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">{row.sources[0]?.description}</p><StoryIndicators story={row} pt={pt} onSelect={onIndicators} /><div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground"><Severity sources={row.sources} pt={pt} />{row.primaryCategory && <span>{row.primaryCategory}</span>}{row.sources.some(source => source.kev) && <span className="text-red-500">KEV</span>}{row.sources.length > 1 && <span className="inline-flex items-center gap-1"><Layers className="h-3 w-3" />{row.sources.length} {pt ? 'publicações correlacionadas' : 'correlated publications'}</span>}</div></td>
        <td><SourceList sources={row.sources} /></td><td>{names(row.actors)}</td><td>{row.cves.length ? <span className="font-mono text-[11px]">{row.cves.slice(0, 2).join(', ')}</span> : names(row.malware)}</td><td className="whitespace-nowrap font-mono text-xs">{date(row.lastSeen, pt)}</td>
      </tr>)}</tbody>
    </table></div>
    <DataPager total={rows.length} page={current} pageSize={size} onPage={setPage} pt={pt} />
    <RecordDrawer open={Boolean(selected)} onClose={() => setSelectedId(null)} title={selected?.title || ''} description={pt ? 'Inteligência • evento e fontes' : 'Intelligence • event and sources'}>
      {selected && <>
        <div className="flex flex-wrap gap-2">{onSave && <Button size="sm" variant="outline" disabled={isSaved?.(selected)} onClick={() => onSave(selected)}><Bookmark className="mr-2 h-3.5 w-3.5" />{isSaved?.(selected) ? (pt ? 'Publicação salva' : 'Publication saved') : (pt ? 'Salvar publicação' : 'Save publication')}</Button>}{onReport && <Button size="sm" variant="outline" disabled={isReporting?.(selected)} onClick={() => onReport(selected)}><FileText className="mr-2 h-3.5 w-3.5" />{isReporting?.(selected) ? (pt ? 'Enfileirando…' : 'Queuing…') : (pt ? 'Gerar relatório' : 'Generate report')}</Button>}</div>
        <div className="grid grid-cols-2 gap-4 text-xs"><div><p className="intel-eyebrow">{pt ? 'Atores citados' : 'Mentioned actors'}</p>{selected.actors.length ? selected.actors.map(actor => <Link key={actor.id} to={`/atores?actor=${encodeURIComponent(actor.id)}`} className="mr-2 inline-block py-2 text-primary hover:underline">{actor.name}</Link>) : <p className="mt-2 text-muted-foreground">{pt ? 'Não identificado' : 'Not identified'}</p>}</div><div><p className="intel-eyebrow">{pt ? 'Malware / vulnerabilidades' : 'Malware / vulnerabilities'}</p><p className="mt-2">{selected.cves.concat(selected.malware.map(item => item.name)).join(', ') || '—'}</p></div></div>
        <section><h3 className="intel-eyebrow">{pt ? 'Evidências da correlação' : 'Correlation evidence'}</h3>{details?.loading ? <p role="status" className="mt-2 text-sm text-muted-foreground">{pt ? 'Carregando vínculos…' : 'Loading relationships…'}</p> : details?.data?.correlationEvidence.length ? <ul className="mt-3 space-y-2">{details.data.correlationEvidence.map((item, index) => <li key={index} className="rounded-md border px-3 py-2 text-xs"><span className="text-muted-foreground">{item.type}</span><span className="ml-3 break-all font-mono">{item.value}</span></li>)}</ul> : <p className="mt-2 text-sm text-muted-foreground">{pt ? 'Revise as fontes abaixo. O agrupamento segue a identidade de evento do coletor.' : 'Review the sources below. Grouping follows the collector’s event identity.'}</p>}</section>
        <section><h3 className="intel-eyebrow">{pt ? 'Publicações e referências' : 'Publications and references'} · {selected.sources.length}</h3><div className="mt-3 divide-y rounded-lg border">{selected.sources.map(source => <article key={source.link} className="p-4"><div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground"><SourceIdentity name={source.source} url={source.link} /><span>· {date(source.pubDate, pt)}</span></div>{safeLink(source.link) ? <a href={source.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-start gap-2 text-sm font-medium hover:text-primary">{source.title}<ArrowUpRight className="h-4 w-4 shrink-0" /></a> : <p className="text-sm font-medium">{source.title}</p>}<p className="mt-3 whitespace-pre-line text-sm leading-relaxed text-muted-foreground">{source.description || (pt ? 'Resumo indisponível.' : 'Summary unavailable.')}</p></article>)}</div></section>
      </>}
    </RecordDrawer>
  </div>;
}
