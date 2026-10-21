import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { ChevronDown, ChevronRight, Crosshair, Globe2, Search, Target, UsersRound, X } from 'lucide-react';
import { PageLayout } from '@/components/PageLayout';
import { LoadingRows } from '@/components/LoadingState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DataPager } from '@/components/workbench/DataPager';
import { SourceIdentity } from '@/components/SourceIdentity';
import { useLanguage } from '@/contexts/LanguageContext';
import { actorPageCopy, sortActors } from './actorsView';
import { actorSourceLabel, type ActorListItem } from './actorsTypes';
const ActorProfile = lazy(() => import('./ActorProfile').then(module => ({ default: module.ActorProfile })));
const ThreatModelTab = lazy(() => import('./ActorThreatModel').then(module => ({ default: module.ThreatModelTab })));
import { ActorsOverview, ActorsGlobal } from './ActorsOverview';
import { ActorAvatar } from '@/components/ActorAvatar';
import { useAuth } from '@/contexts/AuthContext';
import { fetchActorActivity } from '@/services/actorEvidence';
import { actorOrigin } from './actorOverview';

type Catalog = { actors: ActorListItem[]; countries: string[]; sectors: string[]; targets: string[] };
const emptyCatalog: Catalog = { actors: [], countries: [], sectors: [], targets: [] };
const ALL = '__all__';
type Sort = 'techniques' | 'name' | 'country';

function ActorSource({ source = '' }: { source?: string }) {
  const entries = [
    { match: 'attack', name: 'MITRE ATT&CK', url: 'https://attack.mitre.org' },
    { match: 'misp', name: 'MISP', url: 'https://www.misp-project.org' },
    { match: 'ransomware.live', name: 'Ransomware.live', url: 'https://www.ransomware.live' },
  ].filter(entry => source.includes(entry.match));
  return <span className="inline-flex flex-col gap-1.5 align-middle text-xs text-muted-foreground">
    {entries.length ? entries.map(entry => <SourceIdentity key={entry.match} name={entry.name} url={entry.url} />)
      : <SourceIdentity name={actorSourceLabel(source)} />}
  </span>;
}

function ActorFilter({ label, value, onChange, options, icon: Icon }: {
  label: string; value: string; onChange: (value: string) => void;
  options: { value: string; label: string }[]; icon: typeof Globe2;
}) {
  return <label className="actor-filter relative flex min-w-0 items-center gap-2 focus-within:ring-2 focus-within:ring-ring">
    <Icon className="pointer-events-none h-4 w-4 shrink-0 text-muted-foreground" />
    <select aria-label={label} title={options.find(option => option.value === value)?.label || label} value={value} onChange={event => onChange(event.target.value)} className="w-full min-w-0 appearance-none truncate bg-transparent py-2 pr-5 text-xs font-medium outline-none">
      <option value={ALL}>{label}</option>{options.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
    </select>
    <ChevronDown className="pointer-events-none absolute right-3 h-3.5 w-3.5 text-muted-foreground" />
  </label>;
}

export default function Actors() {
  const { language } = useLanguage(); const pt = language === 'pt';
  const [params, setParams] = useSearchParams(); const actorId = params.get('actor');
  const listScroll = useRef(0);
  const { auth } = useAuth();
  const view = ['overview', 'catalog', 'global', 'model'].includes(params.get('view') || '') ? params.get('view')! : 'overview';
  const setView = (value: string) => setParams(previous => { const next = new URLSearchParams(previous); next.set('view', value); next.delete('actor'); return next; });
  const activity = useQuery({ queryKey: ['actor-activity', auth.login || ''], queryFn: ({ signal }) => fetchActorActivity(signal), enabled: auth.authenticated && !actorId && ['overview', 'catalog'].includes(view), staleTime: 60_000, retry: false });
  const [query, setQuery] = useState(''); const [country, setCountry] = useState(ALL);
  const [sector, setSector] = useState(ALL); const [target, setTarget] = useState(ALL);
  const [motivation, setMotivation] = useState(ALL);
  const [sort, setSort] = useState<Sort>('name');
  const [page, setPage] = useState(1); const [pageSize, setPageSize] = useState(25);
  const baseCatalog = useQuery({ queryKey: ['actor-base-catalog'], queryFn: async ({ signal }) => {
    const response = await fetch('/api/actors?catalogOnly=1', { signal });
    if (!response.ok) throw new Error(String(response.status));
    return await response.json() as Catalog;
  }, enabled: !actorId, staleTime: 30 * 60_000, retry: 1 });
  const fullCatalog = useQuery({ queryKey: ['actor-catalog', auth.login || ''], queryFn: async ({ signal }) => {
    const response = await fetch('/api/actors', { signal, cache: 'no-cache' });
    if (!response.ok) throw new Error(String(response.status));
    return await response.json() as Catalog;
  }, enabled: !actorId && Boolean(baseCatalog.data), staleTime: 60_000, retry: 1 });
  const catalog = { data: fullCatalog.data || baseCatalog.data, isLoading: baseCatalog.isLoading && !fullCatalog.data,
    isError: !fullCatalog.data && !baseCatalog.data && (baseCatalog.isError || fullCatalog.isError),
    refetch: () => { void baseCatalog.refetch(); void fullCatalog.refetch(); } };
  const { actors, countries, sectors, targets } = catalog.data || emptyCatalog;
  const openActor = (id: string, section?: string) => { listScroll.current = window.scrollY; setParams(previous => { const next = new URLSearchParams(previous); next.set('actor', id); if (section) next.set('section', section); else next.delete('section'); return next; }); };
  const closeActor = () => setParams(previous => { const next = new URLSearchParams(previous); next.delete('actor'); next.delete('section'); return next; }, { replace: true });
  useEffect(() => { window.scrollTo({ top: actorId ? 0 : listScroll.current }); }, [actorId]);
  useEffect(() => { setPage(1); }, [query, country, sector, target, motivation, sort]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return sortActors(actors.filter(actor => {
      if (country !== ALL && actorOrigin(actor.country) !== country) return false;
      if (sector !== ALL && !actor.sectors?.includes(sector)) return false;
      if (target !== ALL && !actor.targets?.includes(target)) return false;
      if (motivation !== ALL && actor.motivation !== motivation) return false;
      return !needle || [actor.name, ...(actor.aliases || []), actor.country, actor.motivation, ...(actor.sectors || []), ...(actor.targets || []), actorSourceLabel(actor.source)].join(' ').toLocaleLowerCase().includes(needle);
    }), sort);
  }, [actors, country, sector, target, motivation, query, sort]);
  const current = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)));
  const shown = filtered.slice((current - 1) * pageSize, current * pageSize);
  const active = Boolean(query || [country, sector, target, motivation].some(value => value !== ALL));
  const clear = () => { setQuery(''); setCountry(ALL); setSector(ALL); setTarget(ALL); setMotivation(ALL); };
  const choices = (values: string[]) => values.filter(Boolean).map(value => ({ value, label: value }));
  const facetFilter = (type: 'country' | 'sector' | 'motivation', value: string) => { clear(); ({ country: setCountry, sector: setSector, motivation: setMotivation })[type](value); setView('catalog'); };
  const pager = <DataPager pt={pt} total={filtered.length} page={current} pageSize={pageSize} pageSizes={[25, 50, 100]} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1); }} />;

  return <PageLayout width="max-w-[1600px]" className="actor-workspace" breadcrumbItems={actorId
    ? [{ label: actors.find(actor => actor.id === actorId)?.name || (pt ? 'Perfil do ator' : 'Actor profile') }]
    : [{ label: view === 'catalog' ? (pt ? 'Lista' : 'Listing') : view === 'global' ? 'Global' : view === 'model' ? (pt ? 'Modelagem de ameaças' : 'Threat modelling') : (pt ? 'Visão geral' : 'Overview') }]}>
    {actorId ? <Suspense fallback={<LoadingRows rows={6} />}><ActorProfile key={actorId} id={actorId} initialTab={params.get('section') || undefined} summary={actors.find(actor => actor.id === actorId)} pt={pt} onBack={closeActor} /></Suspense> : <>
      {baseCatalog.data && !fullCatalog.data && <p role="status" className="mb-3 text-xs text-muted-foreground">{fullCatalog.isError ? <>{pt ? 'Não foi possível carregar os perfis das suas fontes.' : 'Could not load profiles from your sources.'} <button className="underline" onClick={() => void fullCatalog.refetch()}>{pt ? 'Tentar novamente' : 'Retry'}</button></> : (pt ? 'Carregando os perfis das suas fontes…' : 'Loading profiles from your sources…')}</p>}
      <Tabs value={view} onValueChange={setView}>
        <TabsList variant="underline" className="mb-6 gap-4" aria-label={pt ? 'Visões de atores' : 'Actor views'}>
          <TabsTrigger value="overview">{pt ? 'Visão geral' : 'Overview'}</TabsTrigger>
          <TabsTrigger value="catalog">{pt ? 'Listagem' : 'Listing'}</TabsTrigger>
          <TabsTrigger value="global">Global</TabsTrigger>
          <TabsTrigger value="model">{pt ? 'Modelagem de ameaças' : 'Threat modelling'}</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">{catalog.isLoading ? <LoadingRows rows={6} /> : catalog.isError ? <p role="alert">{pt ? 'Catálogo indisponível.' : 'Catalog unavailable.'}</p> : <ActorsOverview actors={actors} activity={activity.data} pt={pt} onOpen={openActor} onView={setView} onFilter={facetFilter} />}</TabsContent>
        <TabsContent value="global">{catalog.isLoading ? <LoadingRows rows={6} /> : catalog.isError ? <p role="alert">{pt ? 'Catálogo indisponível.' : 'Catalog unavailable.'}</p> : <ActorsGlobal actors={actors} pt={pt} onFilter={facetFilter} />}</TabsContent>
        <TabsContent value="catalog">
          <section className="actor-surface actor-catalog overflow-hidden">
            <header className="px-5 pt-6 sm:px-7 sm:pt-7"><h1 className="text-xl font-semibold tracking-tight">{actorPageCopy(language).title}</h1><p className="mt-1 text-sm text-muted-foreground">{pt ? 'Explore os atores e filtre por origem, alvos e metadados.' : 'Browse actors and filter by origin, targets and metadata.'}</p></header>
            <div className="actor-filters px-5 pb-4 pt-4 sm:px-7">
              <div className="actor-filter-search relative min-w-0"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><Input aria-label={pt ? 'Buscar ator' : 'Search actor'} value={query} onChange={event => setQuery(event.target.value)} placeholder={pt ? 'Buscar ator ou alias' : 'Search actor or alias'} className="h-9 rounded-lg bg-muted/30 pl-9 text-xs" /></div>
              <ActorFilter label={pt ? 'Origem' : 'Origin'} value={country} onChange={setCountry} options={choices([...new Set(countries.map(actorOrigin))].sort())} icon={Globe2} />
              <ActorFilter label={pt ? 'Países alvo' : 'Target countries'} value={target} onChange={setTarget} options={choices(targets)} icon={UsersRound} />
              <ActorFilter label={pt ? 'Setores alvo' : 'Target sectors'} value={sector} onChange={setSector} options={choices(sectors)} icon={Target} />
              <ActorFilter label={pt ? 'Motivação' : 'Motivation'} value={motivation} onChange={setMotivation} options={choices([...new Set(actors.map(actor => actor.motivation))].sort())} icon={Crosshair} />
            </div>
            <div className="mx-5 flex items-center justify-end gap-3 border-t pt-3 sm:mx-7">{active && <Button variant="ghost" size="sm" className="mr-auto h-8 px-2 text-xs" onClick={clear}><X className="mr-1 h-3.5 w-3.5" />{pt ? 'Limpar filtros' : 'Clear filters'}</Button>}<select aria-label={pt ? 'Ordenar atores' : 'Sort actors'} value={sort} onChange={event => setSort(event.target.value as Sort)} className="rounded-md border bg-background px-2 py-1.5 text-xs text-muted-foreground"><option value="name">{pt ? 'Nome A–Z' : 'Name A–Z'}</option><option value="techniques">{pt ? 'Mais TTPs' : 'Most TTPs'}</option><option value="country">{pt ? 'Origem A–Z' : 'Origin A–Z'}</option></select></div>
            {catalog.isLoading ? <div className="p-6"><LoadingRows rows={7} /></div> : catalog.isError ? <div className="m-5 rounded-xl border border-destructive/30 bg-destructive/5 p-5 text-sm" role="alert"><p>{pt ? 'Não foi possível carregar os atores.' : 'Could not load actors.'}</p><Button variant="outline" size="sm" className="mt-3" onClick={() => void catalog.refetch()}>{pt ? 'Tentar novamente' : 'Retry'}</Button></div> : <>
              {pager}
              <div className="overflow-x-auto"><table className="actor-table w-full min-w-[1050px] text-left text-[13px]">
                <thead><tr>{[pt ? 'Ator de ameaça' : 'Threat actor', pt ? 'Origem' : 'Origin', 'IPs', 'Hosts', 'SHA256', pt ? 'Publicações' : 'Posts', 'TTPs', pt ? 'Setores alvo' : 'Target sectors', pt ? 'Países alvo' : 'Target countries', pt ? 'Motivação' : 'Motivation', pt ? 'Fonte' : 'Source'].map(label => <th key={label}>{label}</th>)}</tr></thead>
                <tbody>{shown.map(actor => <tr key={actor.id}>
                  <td className="w-72"><div className="flex items-center gap-3"><ActorAvatar name={actor.name} logo={actor.logo} /><div className="min-w-0"><button type="button" aria-label={`${pt ? 'Abrir' : 'Open'} ${actor.name}`} className="text-left font-semibold hover:text-primary focus-visible:ring-2 focus-visible:ring-ring" onClick={() => openActor(actor.id)}>{actor.name}</button><p className="mt-1 line-clamp-1 max-w-60 text-xs text-muted-foreground" title={actor.aliases.join(', ')}>{actor.aliases.join(', ') || '—'}</p></div></div></td>
                  <td>{actorOrigin(actor.country) || '—'}</td>{(['ips', 'domains', 'hashes', 'posts'] as const).map(kind => <td key={kind}><button className="rounded-full bg-muted px-2.5 py-1 text-xs text-primary hover:bg-primary/10" aria-label={`${actor.name} ${kind}`} onClick={() => openActor(actor.id, kind)}>{activity.data ? activity.data[actor.id]?.[kind] || 0 : '—'}</button></td>)}<td className="font-mono tabular-nums">{actor.technique_count || 0}</td><td className="max-w-48"><span className="line-clamp-2" title={actor.sectors.join(', ')}>{actor.sectors.join(', ') || '—'}</span></td><td className="max-w-48"><span className="line-clamp-2" title={actor.targets.join(', ')}>{actor.targets.join(', ') || '—'}</span></td><td className="max-w-44">{actor.motivation || '—'}</td><td><ActorSource source={actor.source} /><button type="button" aria-label={`${pt ? 'Ver perfil de' : 'View profile of'} ${actor.name}`} onClick={() => openActor(actor.id)} className="ml-2 rounded p-1 text-muted-foreground hover:text-primary focus-visible:ring-2 focus-visible:ring-ring"><ChevronRight className="h-3.5 w-3.5" /></button></td>
                </tr>)}</tbody>
              </table></div>
              {!shown.length && <div className="px-5 py-12 text-center"><p className="text-sm text-muted-foreground">{pt ? 'Nenhum ator com estes filtros.' : 'No actors match these filters.'}</p>{active && <Button variant="outline" size="sm" className="mt-3" onClick={clear}>{pt ? 'Limpar filtros' : 'Clear filters'}</Button>}</div>}
              {pager}
            </>}
          </section>
        </TabsContent>
        <TabsContent value="model"><header className="mb-5"><h1 className="text-xl font-semibold">{pt ? 'Modelagem de ameaças' : 'Threat modelling'}</h1><p className="mt-1 text-sm text-muted-foreground">{pt ? 'Relacione o catálogo aos setores e regiões da organização.' : 'Match the catalog to organization sectors and regions.'}</p></header>{catalog.isLoading ? <LoadingRows rows={5} /> : catalog.isError ? <p role="alert">{pt ? 'Catálogo indisponível.' : 'Catalog unavailable.'}</p> : <Suspense fallback={<LoadingRows rows={5} />}><ThreatModelTab actors={actors} sectors={sectors} targets={targets} pt={pt} onOpen={openActor} /></Suspense>}</TabsContent>
      </Tabs>
    </>}
  </PageLayout>;
}
