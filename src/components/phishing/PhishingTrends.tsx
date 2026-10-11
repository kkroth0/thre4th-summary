import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Download, ExternalLink, Loader2, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useLanguage } from '@/contexts/LanguageContext';
import { toast } from 'sonner';
import { fetchPhishingReports, type PhishingDataset, type PhishingFilters, type PhishingReport } from '@/services/threatApi';
import { exportPhishingTrendsExcel } from '@/utils/phishingTrendsExport';

type Query = PhishingFilters & { from?: string; to?: string };
const inputStyle = 'min-w-0 w-full rounded border border-border bg-background px-3 py-2 text-sm text-foreground';
const calendarDate = (value: Date) => `${value.getFullYear()}-${String(value.getMonth() + 1).padStart(2, '0')}-${String(value.getDate()).padStart(2, '0')}`;
const preset = (days: number): Query => {
  const end = new Date();
  const start = new Date(end);
  start.setDate(start.getDate() - days + 1);
  return { from: calendarDate(start), to: calendarDate(end) };
};
const labels = { 'named-campaign': ['Campanha nomeada', 'Named campaign'], 'correlated-story': ['Evento correlacionado', 'Correlated event'], publication: ['Publicação sem vínculo confirmado', 'Publication without confirmed links'] };
const safeUrl = (value: string) => /^https?:\/\//i.test(value);

function Publication({ row, pt }: { row: PhishingReport; pt: boolean }) {
  const l = (a: string, b: string) => pt ? a : b;
  const unknown = l('Não identificado', 'Not identified');
  const metadata = [
    [l('Vetor', 'Vector'), row.vectors], [l('Setor-alvo', 'Target sector'), row.sectors],
    [l('Região-alvo', 'Target region'), row.regions], [l('Marca imitada', 'Impersonated brand'), row.brands],
    [l('Ator citado', 'Mentioned actor'), row.actorNames], ['Malware / Kit', row.software],
  ] as const;
  return <article className="space-y-3 border-t border-border py-4 first:border-t-0">
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      <time dateTime={row.pubDate}>{row.pubDate.slice(0, 10) || unknown}</time><span>{row.source}</span><span>{row.sourceType}</span>
      {safeUrl(row.link) && <a href={row.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">{l('Abrir fonte', 'Open source')}<ExternalLink className="h-3 w-3" /></a>}
    </div>
    <h4 className="break-words text-sm font-semibold">{row.title}</h4>
    <p className="line-clamp-3 break-words text-sm text-muted-foreground">{row.description}</p>
    <dl className="grid gap-x-5 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">{metadata.map(([label, values]) => <div key={label}><dt className="text-muted-foreground">{label}</dt><dd className="mt-0.5 break-words">{values.join(', ') || unknown}</dd></div>)}</dl>
    {row.ttps.length > 0 && <div className="flex flex-wrap gap-2 text-xs">{row.ttps.map(ttp => <a key={ttp.id} href={`https://attack.mitre.org/techniques/${ttp.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer" className="rounded border border-border px-2 py-1" title={`${ttp.name}: ${ttp.reason}`}>{ttp.id} · {ttp.basis === 'reported' ? l('citado', 'reported') : l('inferido', 'inferred')}</a>)}</div>}
    {row.profileMatches.length > 0 && <p className="text-xs text-muted-foreground">{row.profileMatches.map(match => `${match.profileName}: ${match.reasons.join(', ')}`).join(' · ')}</p>}
    <details className="text-xs"><summary className="cursor-pointer py-1 font-medium">{l('Evidências do matching', 'Matching evidence')} · {row.evidence.length}</summary>
      <div className="mt-2 space-y-3 border-l-2 border-primary/40 pl-3">{row.evidence.map((e, i) => <div key={i}><p className="font-medium">{e.label} · {e.field === 'title' ? l('título', 'title') : e.field === 'body' ? l('corpo', 'body') : l('resumo', 'summary')} · “{e.term}”</p><p className="mt-1 break-words text-muted-foreground">{e.snippet}</p></div>)}</div>
    </details>
  </article>;
}

export function PhishingTrends() {
  const { language } = useLanguage();
  const pt = language === 'pt';
  const l = (a: string, b: string) => pt ? a : b;
  const [query, setQuery] = useState<Query>(() => preset(90));
  const [draft, setDraft] = useState<Query>(query);
  const [data, setData] = useState<PhishingDataset | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [retry, setRetry] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [view, setView] = useState<'campaigns' | 'reports'>('campaigns');
  const [page, setPage] = useState(1);
  const [facets, setFacets] = useState<PhishingDataset['facets']>({ techniques: [], sectors: [], regions: [], brands: [], profiles: [] });

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(false); setData(null); setPage(1);
    fetchPhishingReports({ ...query, limit: 20000 })
      .then(result => { if (!cancelled) { setData(result); setFacets(result.facets); } })
      .catch(() => { if (!cancelled) setError(true); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [query, retry]);

  const reportsByGroup = useMemo(() => {
    const groups = new Map<string, PhishingReport[]>();
    for (const row of data?.reports || []) groups.set(row.groupId, [...(groups.get(row.groupId) || []), row]);
    return groups;
  }, [data]);
  const apply = (event: FormEvent) => {
    event.preventDefault();
    if (draft.from && draft.to && draft.from > draft.to) { toast.error(l('A data inicial deve preceder a final', 'Start date must precede end date')); return; }
    setQuery({ ...draft });
  };
  const choosePeriod = (days?: number) => { const value = { ...draft, from: undefined, to: undefined, ...(days ? preset(days) : {}) }; setDraft(value); setQuery(value); };
  const exportData = async () => {
    if (!data) return;
    setExporting(true);
    try { await exportPhishingTrendsExcel(data); } catch { toast.error(l('Falha ao exportar', 'Export failed')); } finally { setExporting(false); }
  };
  const field = (key: keyof Query, value: string) => setDraft(previous => ({ ...previous, [key]: value }));
  const select = (key: keyof Query, label: string, values: { value: string; label: string }[]) => <label className="space-y-1 text-xs text-muted-foreground"><span>{label}</span><select className={inputStyle} value={draft[key] || ''} onChange={event => field(key, event.target.value)}><option value="">{l('Todos', 'All')}</option>{values.map(value => <option key={value.value} value={value.value}>{value.label}</option>)}</select></label>;
  const options = (values: string[]) => values.map(value => ({ value, label: value }));
  const count = view === 'campaigns' ? data?.campaigns.length || 0 : data?.reports.length || 0;
  const pages = Math.max(1, Math.ceil(count / 20));
  return <section className="space-y-5" aria-label={l('Inteligência de campanhas de phishing', 'Phishing campaign intelligence')}>
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-lg font-semibold">{l('Campanhas de phishing', 'Phishing campaigns')}</h2><p className="mt-1 text-sm text-muted-foreground">{l('Publicações, vínculos e técnicas com evidências das fontes.', 'Publications, relationships and techniques with source evidence.')}</p></div>
      <Button size="sm" variant="outline" onClick={exportData} disabled={loading || !data?.reports.length || exporting} className="gap-2">{exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}{l('Exportar Excel', 'Export Excel')}</Button>
    </div>
    <form onSubmit={apply} className="space-y-3 rounded border border-border p-4">
      <div className="flex flex-wrap items-center gap-2">{[30, 90].map(days => <Button key={days} type="button" size="sm" variant="outline" onClick={() => choosePeriod(days)}>{days} {l('dias', 'days')}</Button>)}<Button type="button" size="sm" variant="outline" onClick={() => choosePeriod()}>{l('Todo o arquivo', 'Entire archive')}</Button><span className="text-xs text-muted-foreground">{l('Ou defina o período abaixo', 'Or set the date range below')}</span></div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <label className="space-y-1 text-xs text-muted-foreground">{l('De', 'From')}<input type="date" aria-label={l('Data inicial', 'Start date')} className={inputStyle} value={draft.from || ''} onInput={event => field('from', event.currentTarget.value)} onChange={event => field('from', event.target.value)} /></label>
        <label className="space-y-1 text-xs text-muted-foreground">{l('Até', 'To')}<input type="date" aria-label={l('Data final', 'End date')} className={inputStyle} value={draft.to || ''} onInput={event => field('to', event.currentTarget.value)} onChange={event => field('to', event.target.value)} /></label>
        {select('technique', l('Técnica', 'Technique'), options(facets.techniques))}
        {select('region', l('Região-alvo', 'Target region'), options([...new Set(['Brazil', 'LATAM', ...facets.regions])]))}
        {select('sector', l('Setor-alvo', 'Target sector'), options(facets.sectors))}
        {select('brand', l('Marca imitada', 'Impersonated brand'), options(facets.brands))}
        {select('profileId', l('Perfil da organização', 'Organization profile'), facets.profiles.map(profile => ({ value: profile.id, label: profile.name })))}
        {select('nationState', 'Nation-state', [{ value: 'reported', label: l('Citado na fonte', 'Reported in source') }, { value: 'unknown', label: l('Não identificado', 'Not identified') }])}
      </div>
      <div className="flex flex-col gap-2 sm:flex-row"><input className={inputStyle} aria-label={l('Buscar publicações', 'Search publications')} placeholder={l('Buscar título, campanha, ator ou kit', 'Search title, campaign, actor or kit')} value={draft.search || ''} onChange={event => field('search', event.target.value)} maxLength={200} /><Button type="submit" size="sm" className="gap-2"><Search className="h-4 w-4" />{l('Aplicar filtros', 'Apply filters')}</Button></div>
    </form>
    <p className="text-xs text-muted-foreground">{l('Recorte aplicado', 'Applied selection')}: {query.from || l('início do arquivo', 'archive start')} → {query.to || l('última publicação', 'latest publication')}{[query.search, query.technique, query.region, query.sector, query.brand, query.profileId ? facets.profiles.find(profile => profile.id === query.profileId)?.name : '', query.nationState === 'reported' ? 'Nation-state' : ''].filter(Boolean).map(value => ` · ${value}`).join('')}</p>
    {loading ? <p role="status" className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />{l('Analisando arquivo…', 'Analyzing archive…')}</p> : error ? <div role="alert" className="rounded border border-destructive/40 p-4 text-sm"><p>{l('Não foi possível carregar as campanhas.', 'Could not load campaigns.')}</p><Button className="mt-3" size="sm" variant="outline" onClick={() => setRetry(value => value + 1)}>{l('Tentar novamente', 'Retry')}</Button></div> : data && <>
      <div className="grid grid-cols-2 divide-x divide-border rounded border border-border lg:grid-cols-4">{[
        [data.summary.publications, l('Publicações', 'Publications')], [data.summary.groups, l('Grupos de campanha / evento', 'Campaign / event groups')],
        [data.summary.correlatedGroups, l('Grupos com várias publicações', 'Groups with multiple publications')], [data.summary.distinctTtps, l('TTPs identificados', 'Identified TTPs')],
      ].map(([value, label]) => <div key={label} className="p-4"><p className="font-mono text-2xl font-semibold">{value}</p><p className="mt-1 text-xs text-muted-foreground">{label}</p></div>)}</div>
      <p className="text-xs text-muted-foreground">{l(`${data.summary.withTechnique} de ${data.summary.publications} publicações com técnica identificada. Campos sem evidência ficam como não identificados.`, `${data.summary.withTechnique} of ${data.summary.publications} publications have an identified technique. Fields without evidence remain unidentified.`)}</p>
      {data.truncated && <p role="alert" className="text-sm text-primary">{l(`Limite atingido: ${data.reports.length} de ${data.total} publicações. Reduza o período para uma exportação completa.`, `Limit reached: ${data.reports.length} of ${data.total} publications. Narrow the range for a complete export.`)}</p>}
      {data.summary.techniques.length > 0 && <div className="rounded border border-border p-4"><h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{l('Técnicas no recorte', 'Techniques in selection')}</h3><div className="flex flex-wrap gap-2">{data.summary.techniques.slice(0, 12).map(item => <button type="button" key={item.label} className="rounded border border-border px-2.5 py-1.5 text-xs hover:border-primary" onClick={() => { const value = { ...query, technique: item.label }; setDraft(value); setQuery(value); }}>{item.label}<span className="ml-2 font-mono text-primary">{item.count}</span></button>)}</div></div>}
      <div className="flex flex-wrap gap-2">{(['campaigns', 'reports'] as const).map(value => <Button key={value} size="sm" variant={view === value ? 'default' : 'outline'} aria-pressed={view === value} onClick={() => { setView(value); setPage(1); }}>{value === 'campaigns' ? l('Campanhas e eventos', 'Campaigns and events') : l('Publicações', 'Publications')} · {value === 'campaigns' ? data.campaigns.length : data.reports.length}</Button>)}</div>
      {count === 0 ? <p className="rounded border border-dashed border-border p-8 text-center text-sm text-muted-foreground">{l('Nenhuma publicação de phishing neste recorte. Ajuste os filtros ou aguarde novas coletas.', 'No phishing publications in this selection. Adjust filters or wait for new collections.')}</p> : <div className="rounded border border-border">
        {view === 'reports' ? <div className="px-4">{data.reports.slice((page - 1) * 20, page * 20).map(row => <Publication key={row.id} row={row} pt={pt} />)}</div> : data.campaigns.slice((page - 1) * 20, page * 20).map(group => <details key={group.id} className="group border-b border-border last:border-0"><summary className="cursor-pointer list-none p-4 hover:bg-muted/20"><div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground"><span>{labels[group.basis][pt ? 0 : 1]}</span><span>{group.firstPublished.slice(0, 10)} → {group.lastPublished.slice(0, 10)}</span><span className="font-mono text-primary">{group.reportCount} {l('publicações', 'publications')} · {group.sources.length} {l('fontes', 'sources')}</span><span className="ml-auto">{l('Ver fontes +', 'View sources +')}</span></div><h3 className="mt-2 break-words text-base font-semibold">{group.name}</h3><p className="mt-2 text-xs text-muted-foreground">{group.techniques.join(' · ') || l('Técnica não identificada', 'Technique not identified')}</p><p className="mt-1 text-xs text-muted-foreground">{group.sources.join(' · ')}</p></summary><div className="border-t border-border bg-muted/10 px-4">{(reportsByGroup.get(group.id) || []).map(row => <Publication key={row.id} row={row} pt={pt} />)}</div></details>)}
      </div>}
      {pages > 1 && <div className="flex items-center justify-between gap-2"><Button size="sm" variant="outline" disabled={page === 1} onClick={() => setPage(value => value - 1)}>{l('Anterior', 'Previous')}</Button><span className="text-xs text-muted-foreground">{page} / {pages}</span><Button size="sm" variant="outline" disabled={page === pages} onClick={() => setPage(value => value + 1)}>{l('Próxima', 'Next')}</Button></div>}
      <p className="text-xs leading-relaxed text-muted-foreground">{l('MITRE citado e inferido são separados. Recortes por organização indicam relevância ao perfil, sem afirmar que ela foi vítima. Grupos sem vínculo confirmado representam publicações individuais.', 'Reported and inferred MITRE mappings are separate. Organization cuts indicate profile relevance without asserting victim status. Unlinked groups represent individual publications.')}</p>
    </>}
  </section>;
}
