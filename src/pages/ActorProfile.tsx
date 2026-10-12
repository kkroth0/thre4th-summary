import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, BookOpen, Bug, Crosshair, ExternalLink, Globe2, Layers3 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { LoadingRows } from '@/components/LoadingState';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DataPager } from '@/components/workbench/DataPager';
import { SourceIdentity, SourceList } from '@/components/SourceIdentity';
import { actorLink, actorSourceLabel, type ActorDetail, type ActorListItem, type ActorStory } from './actorsTypes';

function EntityTable({ items, pt, software = false }: { items: { id: string; name: string; url: string }[]; pt: boolean; software?: boolean }) {
  const [page, setPage] = useState(1); const [size, setSize] = useState(25);
  const current = Math.min(page, Math.max(1, Math.ceil(items.length / size)));
  const pager = <DataPager pt={pt} total={items.length} page={current} pageSize={size} pageSizes={[25, 50, 100]} onPage={setPage} onPageSize={value => { setSize(value); setPage(1); }} />;
  return <>{pager}<div className="overflow-x-auto"><table className="actor-table w-full min-w-[520px] text-left text-[13px]">
    <thead><tr><th>ID</th><th>{software ? (pt ? 'Malware / ferramenta' : 'Malware / tool') : (pt ? 'Técnica' : 'Technique')}</th><th>{pt ? 'Referência' : 'Reference'}</th></tr></thead>
    <tbody>{items.slice((current - 1) * size, current * size).map((item, index) => <tr key={`${item.id}-${index}`}><td className="w-44 font-mono text-primary">{item.id || '—'}</td><td>{item.name}</td><td>{actorLink(item.url) ? <a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-xs text-muted-foreground hover:text-primary">MITRE ATT&CK<ExternalLink className="h-3 w-3" /></a> : '—'}</td></tr>)}</tbody>
  </table></div>{!items.length && <p className="p-8 text-center text-sm text-muted-foreground">{pt ? 'Sem registros disponibilizados pela fonte.' : 'No records provided by the source.'}</p>}{pager}</>;
}

function ActorTags({ title, items, pt }: { title: string; items: string[]; pt: boolean }) {
  return <section><h3 className="text-sm font-semibold">{title}</h3><div className="mt-3 flex flex-wrap gap-2">{items.length ? items.map(value => <span key={value} className="rounded-md border bg-muted/20 px-2.5 py-1 text-xs">{value}</span>) : <p className="text-xs text-muted-foreground">{pt ? 'Sem metadados na fonte.' : 'No source metadata.'}</p>}</div></section>;
}

export function ActorProfile({ id, summary, pt, onBack }: { id: string; summary?: ActorListItem; pt: boolean; onBack: () => void }) {
  const [tab, setTab] = useState('techniques'); const [allAliases, setAllAliases] = useState(false);
  const detail = useQuery({ queryKey: ['actor-detail', id], queryFn: async ({ signal }) => {
    const response = await fetch(`/api/actors/${encodeURIComponent(id)}`, { signal });
    if (!response.ok) throw new Error(String(response.status));
    return await response.json() as ActorDetail;
  }, staleTime: 30 * 60_000, retry: 1 });
  const news = useQuery({ queryKey: ['actor-stories', id], queryFn: async ({ signal }) => {
    const response = await fetch(`/api/news/stories?actor=${encodeURIComponent(id)}&limit=5`, { signal });
    if (!response.ok) throw new Error(String(response.status));
    const data = await response.json(); return (Array.isArray(data) ? data : []) as ActorStory[];
  }, staleTime: 60_000, retry: 1 });
  const actor = detail.data; const stories = news.data || [];
  const aliases = actor?.aliases || summary?.aliases || [];
  const techniques = actor?.techniques || []; const software = actor?.software || []; const refs = actor?.refs || [];
  const metrics = [
    { label: 'MITRE ATT&CK', value: techniques.length, note: pt ? 'Técnicas mapeadas' : 'Mapped techniques', icon: Crosshair, tab: 'techniques' },
    { label: pt ? 'Malware e ferramentas' : 'Malware and tools', value: software.length, note: pt ? 'Software associado' : 'Associated software', icon: Bug, tab: 'software' },
    { label: pt ? 'Referências' : 'References', value: refs.length, note: pt ? 'Fontes do perfil' : 'Profile sources', icon: BookOpen, tab: 'references' },
    { label: 'Aliases', value: aliases.length, note: pt ? 'Nomes conhecidos' : 'Known names', icon: Layers3, tab: 'details' },
  ];
  return <div className="space-y-6">
    <Button variant="ghost" size="sm" className="-ml-2 gap-2 text-muted-foreground" onClick={onBack}><ArrowLeft className="h-4 w-4" />{pt ? 'Voltar aos atores' : 'Back to threat actors'}</Button>
    <header>
      <div className="flex flex-wrap items-start justify-between gap-4"><div><div className="flex flex-wrap items-center gap-3"><h1 className="text-3xl font-semibold tracking-tight">{actor?.name || summary?.name || (pt ? 'Perfil do ator' : 'Actor profile')}</h1>{(actor?.country || summary?.country) && <span className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs text-muted-foreground"><Globe2 className="h-3 w-3" />{actor?.country || summary?.country}</span>}</div><p className="mt-2 text-sm text-muted-foreground">{actor?.motivation || summary?.motivation || '—'} · {actorSourceLabel(actor?.source || summary?.source)}</p></div>{actorLink(actor?.attack_url) && <Button asChild variant="outline" size="sm" className="rounded-lg"><a href={actor!.attack_url} target="_blank" rel="noopener noreferrer">{actor!.attack_id || 'MITRE ATT&CK'}<ExternalLink className="ml-2 h-3.5 w-3.5" /></a></Button>}</div>
      {aliases.length > 0 && <div className="mt-5 flex flex-wrap items-center gap-2"><span className="mr-1 text-xs text-muted-foreground">{pt ? 'Também conhecido como' : 'Aka'}</span>{(allAliases ? aliases : aliases.slice(0, 8)).map(alias => <span key={alias} className="rounded-md border bg-muted/25 px-2.5 py-1 text-xs">{alias}</span>)}{aliases.length > 8 && <button type="button" className="rounded-md border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground" aria-expanded={allAliases} onClick={() => setAllAliases(value => !value)}>{allAliases ? (pt ? 'Mostrar menos' : 'Show less') : `+${aliases.length - 8}`}</button>}</div>}
    </header>
    {detail.isLoading ? <LoadingRows rows={6} /> : detail.isError || !actor ? <div className="actor-surface p-6" role="alert"><h2 className="font-semibold">{pt ? 'Não foi possível carregar o perfil.' : 'Could not load this profile.'}</h2><Button variant="outline" size="sm" className="mt-4" onClick={() => void detail.refetch()}>{pt ? 'Tentar novamente' : 'Retry'}</Button></div> : <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{metrics.map(metric => <button key={metric.label} type="button" onClick={() => setTab(metric.tab)} className="actor-surface flex min-w-0 items-start justify-between gap-3 p-5 text-left transition-colors hover:border-primary/50 focus-visible:ring-2 focus-visible:ring-ring"><div className="min-w-0"><p className="text-sm font-medium">{metric.label}</p><p className="mt-1 text-[11px] text-muted-foreground">{metric.note}</p><p className="mt-5 font-mono text-3xl font-medium tabular-nums">{metric.value}</p></div><metric.icon className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" /></button>)}</div>
      <section className="actor-surface p-5 sm:p-7"><h2 className="text-base font-semibold">{pt ? 'Visão geral' : 'Overview'}</h2><p className="mt-3 whitespace-pre-wrap break-words text-sm leading-7 text-muted-foreground">{actor.description || (pt ? 'A fonte não forneceu uma descrição para este ator.' : 'The source did not provide a description for this actor.')}</p></section>
      <section className="actor-surface overflow-hidden">
        <div className="px-5 pt-6 sm:px-7"><h2 className="text-base font-semibold">{pt ? 'Perfil do ator de ameaça' : 'Threat actor profile'}</h2><p className="mt-1 text-xs text-muted-foreground">{pt ? 'Relações do catálogo e até 5 notícias correlacionadas recentes do feed.' : 'Catalog relationships and up to 5 recent correlated feed stories.'}</p></div>
        <Tabs value={tab} onValueChange={setTab} className="mt-5">
          <div className="overflow-x-auto px-5 sm:px-7"><TabsList variant="underline" className="w-max min-w-full gap-2" aria-label={pt ? 'Seções do perfil' : 'Profile sections'}>{[
            ['techniques', 'MITRE ATT&CK', techniques.length], ['software', pt ? 'Malware e ferramentas' : 'Malware and tools', software.length], ['details', pt ? 'Detalhes' : 'Details', null], ['references', pt ? 'Referências' : 'References', refs.length], ['news', pt ? 'Notícias' : 'News', news.isLoading || news.isError ? null : stories.length],
          ].map(([value, label, count]) => <TabsTrigger key={String(value)} value={String(value)} className="gap-2 px-3 py-3 text-xs">{label}{count !== null && <span className="rounded border px-1.5 py-0.5 text-[10px] tabular-nums text-muted-foreground">{count}</span>}</TabsTrigger>)}</TabsList></div>
          <TabsContent value="techniques" className="mt-0"><EntityTable items={techniques} pt={pt} /></TabsContent>
          <TabsContent value="software" className="mt-0"><EntityTable items={software} software pt={pt} /></TabsContent>
          <TabsContent value="details" className="space-y-6 p-5 sm:p-7">
            <section><h3 className="text-sm font-semibold">{pt ? 'Metadados' : 'Metadata'}</h3><dl className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">{[[pt ? 'Origem' : 'Origin', actor.country], [pt ? 'Motivação' : 'Motivation', actor.motivation], [pt ? 'Fonte' : 'Source', actorSourceLabel(actor.source)], ['MITRE ATT&CK ID', actor.attack_id]].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-words text-sm">{value || '—'}</dd></div>)}</dl><div className="mt-5"><p className="text-xs text-muted-foreground">ID</p><p className="mt-1 break-all font-mono text-xs">{actor.id}</p></div></section>
            <ActorTags title={pt ? 'Setores alvo' : 'Target sectors'} items={actor.sectors || []} pt={pt} />
            <ActorTags title={pt ? 'Países e regiões alvo' : 'Target countries and regions'} items={actor.targets || []} pt={pt} />
            <ActorTags title="Aliases" items={aliases} pt={pt} />
          </TabsContent>
          <TabsContent value="references" className="p-5 sm:p-7"><h3 className="mb-4 text-sm font-semibold">{pt ? 'Fontes e referências' : 'Sources and references'}</h3><div className="divide-y">{refs.map((ref, index) => { const url = typeof ref === 'string' ? ref : ref.url; const label = typeof ref === 'string' ? ref : ref.name || url; return <div key={`${url}-${index}`} className="flex items-center gap-3 py-4">{actorLink(url) ? <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex min-w-0 items-center gap-2 break-all text-sm text-primary hover:underline"><SourceIdentity name={label} url={url} /><ExternalLink className="h-3.5 w-3.5 shrink-0" /></a> : <span className="break-all text-sm text-muted-foreground">{label}</span>}</div>; })}</div>{!refs.length && <p className="py-6 text-sm text-muted-foreground">{pt ? 'Sem referências disponibilizadas pela fonte.' : 'No references provided by the source.'}</p>}</TabsContent>
          <TabsContent value="news" className="mt-0">{news.isLoading ? <div className="p-5"><LoadingRows rows={3} /></div> : news.isError ? <div className="p-6" role="alert"><p className="text-sm text-muted-foreground">{pt ? 'Não foi possível consultar as notícias correlacionadas.' : 'Could not retrieve correlated news.'}</p><Button variant="outline" size="sm" className="mt-3" onClick={() => void news.refetch()}>{pt ? 'Tentar novamente' : 'Retry'}</Button></div> : <>
            <div className="overflow-x-auto"><table className="actor-table w-full min-w-[640px] text-left text-[13px]"><thead><tr><th>{pt ? 'Publicação' : 'Publication'}</th><th>{pt ? 'Fontes' : 'Sources'}</th><th>{pt ? 'Última atualização' : 'Last update'}</th></tr></thead><tbody>{stories.map(story => <tr key={story.id}><td className="max-w-lg">{actorLink(story.sources[0]?.link) ? <a href={story.sources[0].link} target="_blank" rel="noopener noreferrer" className="font-medium hover:text-primary">{story.title}</a> : story.title}</td><td><SourceList sources={story.sources} /></td><td className="whitespace-nowrap text-xs text-muted-foreground">{Number.isFinite(Date.parse(story.lastSeen)) ? new Date(story.lastSeen).toLocaleDateString(pt ? 'pt-BR' : 'en-US') : '—'}</td></tr>)}</tbody></table></div>{!stories.length && <p className="p-8 text-center text-sm text-muted-foreground">{pt ? 'Nenhuma notícia correlacionada disponível no feed.' : 'No correlated news available in the feed.'}</p>}
          </>}</TabsContent>
        </Tabs>
      </section>
    </>}
  </div>;
}
