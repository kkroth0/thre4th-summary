import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, BookOpen, Bug, Crosshair, ExternalLink, Globe2, Layers3 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { LoadingRows } from '@/components/LoadingState';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DataPager } from '@/components/workbench/DataPager';
import { SourceIdentity, SourceList } from '@/components/SourceIdentity';
import { actorLink, actorSourceLabel, type ActorDetail, type ActorListItem, type ActorStory } from './actorsTypes';
import { ActorInfrastructureTable, ActorNameSources } from '@/components/ActorSourceEvidence';
import { useAuth } from '@/contexts/AuthContext';
import { ActorAvatar } from '@/components/ActorAvatar';
import { ActorEvidenceTable } from './ActorEvidenceTable';
import { fetchActorEvidence } from '@/services/actorEvidence';

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

export function ActorProfile({ id, summary, pt, onBack, initialTab = 'ips' }: { id: string; summary?: ActorListItem; pt: boolean; onBack: () => void; initialTab?: string }) {
  const [tab, setTab] = useState(['ips', 'domains', 'hashes', 'posts'].includes(initialTab) ? initialTab : 'ips'); const [allAliases, setAllAliases] = useState(false);
  const [days, setDays] = useState(180); const { auth } = useAuth();
  const evidence = useQuery({ queryKey: ['actor-evidence', auth.login || '', id, days], queryFn: ({ signal }) => fetchActorEvidence(id, days, signal), staleTime: 300_000, retry: false });
  const detail = useQuery({ queryKey: ['actor-detail', id], queryFn: async ({ signal }) => {
    const response = await fetch(`/api/actors/${encodeURIComponent(id)}`, { signal, cache: 'no-cache' });
    if (!response.ok) throw new Error(String(response.status));
    return await response.json() as ActorDetail;
  }, staleTime: 30 * 60_000, retry: 1 });
  const actor = detail.data;
  const aliases = actor?.aliases || summary?.aliases || [];
  const techniques = actor?.techniques || []; const software = actor?.software || []; const refs = actor?.refs || [];
  const metrics = [
    { label: 'IPs', value: evidence.data?.counts.ips ?? '—', note: pt ? 'Indicadores nas publicações' : 'Publication indicators', icon: Crosshair, tab: 'ips' },
    { label: 'Hosts', value: evidence.data?.counts.domains ?? '—', note: pt ? 'Domínios nas publicações' : 'Publication domains', icon: Globe2, tab: 'domains' },
    { label: 'SHA256', value: evidence.data?.counts.hashes ?? '—', note: pt ? 'Hashes nas publicações' : 'Publication hashes', icon: Layers3, tab: 'hashes' },
    { label: pt ? 'Publicações' : 'Posts', value: evidence.data?.counts.posts ?? '—', note: pt ? 'Fontes que citam o ator' : 'Sources mentioning the actor', icon: BookOpen, tab: 'posts' },
  ];
  return <div className="space-y-6">
    <Button variant="ghost" size="sm" className="-ml-2 gap-2 text-muted-foreground" onClick={onBack}><ArrowLeft className="h-4 w-4" />{pt ? 'Voltar aos atores' : 'Back to threat actors'}</Button>
    <header className="actor-surface p-5 sm:p-7"><div className="flex flex-wrap items-start justify-between gap-5"><div className="flex min-w-0 items-center gap-4"><ActorAvatar name={actor?.name || summary?.name || id} logo={actor?.logo || summary?.logo} large /><div><div className="flex flex-wrap items-center gap-3"><h1 className="text-2xl font-semibold tracking-tight">{actor?.name || summary?.name || id}</h1><span className="rounded-full bg-muted px-2.5 py-1 text-xs text-muted-foreground">{actor?.country || summary?.country || (pt ? 'Origem não informada' : 'Unknown origin')}</span></div><p className="mt-2 text-sm text-muted-foreground">{actor?.motivation || summary?.motivation || actorSourceLabel(actor?.source || summary?.source)}</p></div></div><label className="text-xs text-muted-foreground">{pt ? 'Período' : 'Time range'}<select aria-label={pt ? 'Período dos indicadores' : 'Indicator time range'} className="ml-3 rounded-lg border bg-background px-3 py-2 text-sm" value={days} onChange={event => setDays(Number(event.target.value))}>{[[30, '30d'], [90, '90d'], [180, pt ? 'Últimos 6 meses' : 'Last 6 months'], [365, pt ? 'Último ano' : 'Last year'], [0, pt ? 'Todo o acervo' : 'Entire archive']].map(([value, label]) => <option key={String(value)} value={value}>{label}</option>)}</select></label></div>
      {actor?.logoSource && <a href={actor.logoSource} target="_blank" rel="noopener noreferrer" className="mt-3 inline-block text-[11px] text-muted-foreground hover:text-primary">{pt ? 'Fonte da imagem' : 'Image source'}</a>}
      {aliases.length > 0 && <div className="mt-5 flex flex-wrap items-center gap-2"><span className="mr-1 text-xs text-muted-foreground">AKA</span>{(allAliases ? aliases : aliases.slice(0, 8)).map(alias => <span key={alias} className="rounded-md border bg-muted/25 px-2.5 py-1 text-xs">{alias}</span>)}{aliases.length > 8 && <button type="button" className="rounded-md border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground" aria-expanded={allAliases} onClick={() => setAllAliases(value => !value)}>{allAliases ? (pt ? 'Mostrar menos' : 'Show less') : `+${aliases.length - 8}`}</button>}</div>}
    </header>
    {detail.isLoading ? <LoadingRows rows={6} /> : detail.isError || !actor ? <div className="actor-surface p-6" role="alert"><h2 className="font-semibold">{pt ? 'Não foi possível carregar o perfil.' : 'Could not load this profile.'}</h2><Button variant="outline" size="sm" className="mt-4" onClick={() => void detail.refetch()}>{pt ? 'Tentar novamente' : 'Retry'}</Button></div> : <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{metrics.map(metric => <button key={metric.label} type="button" onClick={() => setTab(metric.tab)} className="actor-surface flex min-w-0 items-start justify-between gap-3 p-5 text-left transition-colors hover:border-primary/50 focus-visible:ring-2 focus-visible:ring-ring"><div className="min-w-0"><p className="text-sm font-medium">{metric.label}</p><p className="mt-1 text-[11px] text-muted-foreground">{metric.note}</p><p className="mt-5 font-mono text-3xl font-medium tabular-nums">{metric.value}</p></div><metric.icon className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" /></button>)}</div>
      <section className="actor-surface p-5 sm:p-7"><h2 className="text-base font-semibold">{pt ? 'Visão geral' : 'Overview'}</h2><p className="mt-3 whitespace-pre-wrap break-words text-sm leading-7 text-muted-foreground">{actor.description || (pt ? 'A fonte não forneceu uma descrição para este ator.' : 'The source did not provide a description for this actor.')}</p></section>
      {actor.ctiFyi && <section className="actor-surface p-5 sm:p-7"><h2 className="text-base font-semibold">Ransomware · CTI.fyi</h2><p className="mt-2 text-sm text-muted-foreground">{pt ? 'Reivindicações registradas pela fonte' : 'Claims recorded by source'}: <strong className="text-foreground">{actor.ctiFyi.claims.toLocaleString()}</strong></p>{actor.ctiFyi.description && <p className="mt-3 whitespace-pre-wrap text-sm leading-7 text-muted-foreground">{actor.ctiFyi.description}</p>}<p className="mt-3 text-xs text-muted-foreground">{pt ? 'Perfil enriquecido automaticamente pela fonte. Reivindicações não confirmam incidentes; domínios das vítimas não são tratados como infraestrutura maliciosa.' : 'Profile automatically enriched by the source. Claims do not confirm incidents; victim domains are not treated as malicious infrastructure.'}</p></section>}
      <section className="actor-surface overflow-hidden">
        <div className="px-5 pt-6 sm:px-7"><h2 className="text-base font-semibold">{pt ? 'Perfil do ator de ameaça' : 'Threat actor profile'}</h2><p className="mt-1 text-xs text-muted-foreground">{pt ? 'Indicadores em publicações que citam este ator. A coocorrência não confirma propriedade da infraestrutura.' : 'Indicators in publications mentioning this actor. Co-occurrence does not confirm infrastructure ownership.'}</p></div>
        <Tabs value={tab} onValueChange={setTab} className="mt-5">
          <div className="overflow-x-auto px-5 sm:px-7"><TabsList variant="underline" className="w-max min-w-full gap-2" aria-label={pt ? 'Seções do perfil' : 'Profile sections'}>{[
            ['ips', 'IP IOCs', evidence.data?.counts.ips ?? null], ['domains', 'Host IOCs', evidence.data?.counts.domains ?? null], ['infrastructure', 'Onion', actor.infrastructure?.length || 0], ['hashes', 'SHA256 IOCs', evidence.data?.counts.hashes ?? null], ['posts', pt ? 'Publicações' : 'Posts', evidence.data?.counts.posts ?? null], ['techniques', 'MITRE ATT&CK', techniques.length], ['software', pt ? 'Malware e ferramentas' : 'Malware and tools', software.length], ['details', pt ? 'Detalhes' : 'Details', null], ['references', pt ? 'Referências' : 'References', refs.length],
          ].map(([value, label, count]) => <TabsTrigger key={String(value)} value={String(value)} className="gap-2 px-3 py-3 text-xs">{label}{count !== null && <span className="rounded border px-1.5 py-0.5 text-[10px] tabular-nums text-muted-foreground">{count}</span>}</TabsTrigger>)}</TabsList></div>
          {(['ips', 'domains', 'hashes', 'posts'] as const).map(kind => <TabsContent key={kind} value={kind} className="mt-0">{evidence.isPending ? <div className="p-5"><LoadingRows rows={4} /></div> : evidence.isError ? <div role="alert" className="p-5"><p className="text-sm text-muted-foreground">{pt ? 'Não foi possível carregar os indicadores do acervo.' : 'Could not load archive indicators.'}</p><Button size="sm" variant="outline" className="mt-3" onClick={() => void evidence.refetch()}>{pt ? 'Tentar novamente' : 'Retry'}</Button></div> : <ActorEvidenceTable key={`${days}-${kind}`} data={evidence.data} kind={kind} pt={pt} />}</TabsContent>)}
          <TabsContent value="techniques" className="mt-0"><EntityTable items={techniques} pt={pt} /></TabsContent>
          <TabsContent value="software" className="mt-0"><EntityTable items={software} software pt={pt} /></TabsContent>
          <TabsContent value="infrastructure" className="p-5 sm:p-7"><ActorInfrastructureTable rows={actor.infrastructure || []} pt={pt} /></TabsContent>
          <TabsContent value="details" className="space-y-6 p-5 sm:p-7">
            <section><h3 className="text-sm font-semibold">{pt ? 'Metadados' : 'Metadata'}</h3><dl className="mt-4 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">{[[pt ? 'Origem' : 'Origin', actor.country], [pt ? 'Motivação' : 'Motivation', actor.motivation], [pt ? 'Fonte' : 'Source', actorSourceLabel(actor.source)], ['MITRE ATT&CK ID', actor.attack_id]].map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-words text-sm">{value || '—'}</dd></div>)}</dl><div className="mt-5"><p className="text-xs text-muted-foreground">ID</p><p className="mt-1 break-all font-mono text-xs">{actor.id}</p></div></section>
            <ActorTags title={pt ? 'Setores alvo' : 'Target sectors'} items={actor.sectors || []} pt={pt} />
            <ActorTags title={pt ? 'Países e regiões alvo' : 'Target countries and regions'} items={actor.targets || []} pt={pt} />
            <ActorTags title="Aliases" items={aliases} pt={pt} />
            <ActorNameSources rows={actor.aliasEvidence || []} pt={pt} />
          </TabsContent>
          <TabsContent value="references" className="p-5 sm:p-7"><h3 className="mb-4 text-sm font-semibold">{pt ? 'Fontes e referências' : 'Sources and references'}</h3><div className="divide-y">{refs.map((ref, index) => { const url = typeof ref === 'string' ? ref : ref.url; const label = typeof ref === 'string' ? ref : ref.name || url; return <div key={`${url}-${index}`} className="flex items-center gap-3 py-4">{actorLink(url) ? <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex min-w-0 items-center gap-2 break-all text-sm text-primary hover:underline"><SourceIdentity name={label} url={url} /><ExternalLink className="h-3.5 w-3.5 shrink-0" /></a> : <span className="break-all text-sm text-muted-foreground">{label}</span>}</div>; })}</div>{!refs.length && <p className="py-6 text-sm text-muted-foreground">{pt ? 'Sem referências disponibilizadas pela fonte.' : 'No references provided by the source.'}</p>}</TabsContent>

        </Tabs>
      </section>
    </>}
  </div>;
}
