import { useState } from 'react';
import { Search, SlidersHorizontal, Newspaper } from 'lucide-react';
import type { WeeklyNews } from '@/types/weekly-report';
import { NewsTimestamp } from './NewsTimestamp';

export function WeeklyNewsChoices({ items, selected, limit, onToggle, disabled, pt, hasProfile=false }: {
  items: WeeklyNews[]; selected: string[]; limit: number; onToggle: (id: string) => void; disabled: boolean; pt: boolean; hasProfile?:boolean;
}) {
  const [kind,setKind]=useState('');
  const [minimum,setMinimum]=useState(0);
  const [contextOnly,setContextOnly]=useState(false);
  const [readOnly,setReadOnly]=useState(false);
  const [search,setSearch]=useState('');
  const normalize=(value:string)=>value.normalize('NFD').replace(/\p{M}/gu,'').toLowerCase();
  const query=normalize(search.trim());
  const visible=items.filter(item=>selected.includes(item.id)||((!query||normalize([item.title,item.summary,...item.sources.map(source=>source.source)].join(' ')).includes(query))&&(!kind||(kind==='primary'?item.sourceRole==='primary':item.sourceKind===kind))&&(minimum===0||!!item.scoreBreakdown&&item.score>=minimum)&&(!contextOnly||!hasProfile||item.contextMatched)&&(!readOnly||item.bodyStatus==='read')));
  const labels=pt?{context:'Cliente',impact:'Impacto potencial',evidence:'Evidências',quality:'Fonte e originalidade',novelty:'Atualidade'}:{context:'Client',impact:'Potential impact',evidence:'Evidence',quality:'Source and originality',novelty:'Recency'};
  const caps=hasProfile?{context:35,impact:25,evidence:20,quality:15,novelty:5}:{context:0,impact:40,evidence:30,quality:23,novelty:7};
  const activeFilters=Number(!!kind)+Number(!!minimum)+Number(readOnly)+Number(hasProfile&&contextOnly);
  function reset(){setKind('');setMinimum(0);setReadOnly(false);setContextOnly(false);setSearch('');}

  if(!items.length)return <div className="py-12 text-center"><Newspaper className="mx-auto h-7 w-7 text-muted-foreground/60" /><h3 className="mt-4 text-sm font-medium">{pt?'Ainda não há sugestões nesta seção':'No suggestions in this section yet'}</h3><p className="mt-2 text-xs text-muted-foreground">{pt?'Consulte outra seção ou escolha um período com publicações.':'Check another section or choose a period with publications.'}</p></div>;

  return <section aria-label={pt?'Notícias sugeridas para a semana':'Suggested weekly news'}>
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-sm font-semibold">{pt?`Selecione até ${limit} notícias`:`Select up to ${limit} stories`}</h2><p className="mt-1 text-xs text-muted-foreground">{pt?'Ordenadas por impacto, evidências e qualidade das fontes.':'Ranked by impact, evidence and source quality.'}</p></div><span className="text-xs tabular-nums text-muted-foreground">{visible.length} {pt?'sugestões':'suggestions'}</span></div>
    <div className="mb-4 space-y-3">
      <div className="relative"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><input type="search" aria-label={pt?'Buscar sugestões':'Search suggestions'} placeholder={pt?'Buscar por notícia, assunto ou fonte…':'Search stories, topics or sources…'} value={search} onChange={event=>setSearch(event.target.value)} className="h-9 w-full rounded-lg border bg-background pl-9 pr-3 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" /></div>
      <details className="group text-xs"><summary className="flex w-fit cursor-pointer list-none items-center gap-2 rounded-md py-1 font-medium text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden"><SlidersHorizontal className="h-3.5 w-3.5" />{pt?'Filtrar sugestões':'Filter suggestions'}{activeFilters>0&&<span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] text-primary">{activeFilters}</span>}<span className="ml-1 text-[10px] group-open:rotate-180">⌄</span></summary>
        <div className="mt-3 flex flex-wrap items-center gap-3 rounded-lg bg-muted/40 p-3">
          <select aria-label={pt?'Tipo de fonte':'Source type'} value={kind} onChange={event=>setKind(event.target.value)} className="h-8 max-w-full rounded-md border bg-background px-2"><option value="">{pt?'Todas as fontes':'All sources'}</option>{[['primary',pt?'Fonte primária':'Primary source'],['research',pt?'Pesquisa especializada':'Specialist research'],['official',pt?'Órgãos oficiais':'Official agencies'],['vendor',pt?'Fabricantes':'Vendors'],['press',pt?'Imprensa especializada':'Security press'],['complementary',pt?'Complementares':'Complementary'],['other',pt?'Outras fontes':'Other sources']].map(([value,label])=><option key={value} value={value}>{label}</option>)}</select>
          <select aria-label={pt?'Prioridade editorial':'Editorial priority'} value={minimum} onChange={event=>setMinimum(Number(event.target.value))} className="h-8 max-w-full rounded-md border bg-background px-2"><option value={0}>{pt?'Todas as prioridades':'All priorities'}</option><option value={80}>{pt?'Destaques · 80+':'Highlights · 80+'}</option><option value={60}>{pt?'Prioridade · 60+':'Priority · 60+'}</option></select>
          {hasProfile&&<label className="flex items-center gap-2"><input type="checkbox" checked={contextOnly} onChange={event=>setContextOnly(event.target.checked)} />{pt?'Só contexto do cliente':'Client context only'}</label>}
          <label className="flex items-center gap-2"><input type="checkbox" checked={readOnly} onChange={event=>setReadOnly(event.target.checked)} />{pt?'Conteúdo analisado':'Content analyzed'}</label>
          {activeFilters>0&&<button onClick={reset} className="font-medium text-primary hover:underline">{pt?'Limpar filtros':'Clear filters'}</button>}
        </div>
      </details>
      {(query||activeFilters>0)&&<p className="text-[11px] text-muted-foreground">{pt?'As notícias selecionadas permanecem visíveis.':'Selected stories remain visible.'}</p>}
    </div>
    <div className="divide-y">{visible.map(item=>{
      const checked=selected.includes(item.id);
      return <article key={item.id} className={`-mx-2 rounded-lg px-2 py-4 transition-colors ${checked?'bg-primary/[0.04]':'hover:bg-muted/30'}`}>
        <div className="flex items-start gap-3">
          <label className="flex min-w-0 flex-1 cursor-pointer items-start gap-3"><input type="checkbox" aria-label={`${pt?'Selecionar':'Select'} ${item.title}`} className="mt-1 h-4 w-4 shrink-0 accent-primary" checked={checked} disabled={disabled||(!checked&&selected.length>=limit)} onChange={()=>onToggle(item.id)} /><span className="min-w-0"><span className="block text-sm font-semibold leading-6">{item.title}</span><span className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground"><NewsTimestamp item={{...item,pubDate:item.published}} pt={pt} /><span>{item.sources.length} {pt?(item.sources.length===1?'fonte':'fontes'):(item.sources.length===1?'source':'sources')}</span>{item.sourceRole==='primary'&&<span className="text-primary">{pt?'Fonte primária':'Primary source'}</span>}</span></span></label>
          <span title={pt?'Prioridade editorial; não indica probabilidade de ataque.':'Editorial priority; does not indicate attack probability.'} className="mt-0.5 shrink-0 rounded-md border px-2 py-1 text-xs font-medium tabular-nums text-muted-foreground">{item.scoreBreakdown?Math.round(item.score):'—'}<span className="ml-0.5 text-[10px]">/100</span></span>
        </div>
        <details className="ml-7 mt-2.5 text-xs"><summary className="w-fit cursor-pointer text-muted-foreground hover:text-primary">{pt?'Resumo e fontes':'Summary and sources'}</summary>
          <p className="mt-3 leading-6 text-muted-foreground">{item.summary}</p>
          {item.scoreBreakdown&&<dl className="mt-3 grid gap-2 rounded-lg bg-muted/40 p-3 sm:grid-cols-2">{(Object.keys(caps).filter(key=>hasProfile||key!=='context') as (keyof typeof caps)[]).map(key=><div key={key} className="flex justify-between gap-2"><dt className="text-muted-foreground">{labels[key]}</dt><dd className="tabular-nums">{item.scoreBreakdown?.[key]}/{caps[key]}</dd></div>)}</dl>}
          {!!item.selectionReasons?.length&&<p className="mt-3 text-[11px] leading-5 text-muted-foreground">{item.selectionReasons.join(' · ')}</p>}
          <div className="mt-3 space-y-2">{item.sources.map(source=><a key={source.link} href={source.link} target="_blank" rel="noreferrer" className="block break-words text-primary hover:underline">{source.source}: {source.title}</a>)}</div>
        </details>
      </article>;
    })}{!visible.length&&<div className="py-10 text-center"><p className="text-sm text-muted-foreground">{pt?'Nenhuma sugestão corresponde à busca e aos filtros.':'No suggestions match your search and filters.'}</p><button className="mt-3 text-xs font-medium text-primary hover:underline" onClick={reset}>{pt?'Mostrar todas as sugestões':'Show all suggestions'}</button></div>}</div>
    {selected.length>=limit&&<p role="status" className="mt-4 rounded-lg bg-muted/50 p-3 text-xs text-muted-foreground">{pt?'Limite de seleção atingido. Para incluir outra notícia, desmarque uma das selecionadas.':'Selection limit reached. Deselect a story to add another.'}</p>}
  </section>;
}
