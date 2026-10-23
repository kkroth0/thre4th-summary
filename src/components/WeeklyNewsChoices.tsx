import { useState } from 'react';
import type { WeeklyNews } from '@/types/weekly-report';
import { NewsTimestamp } from './NewsTimestamp';

export function WeeklyNewsChoices({ items, selected, limit, onToggle, disabled, pt, hasProfile=false }: {
  items: WeeklyNews[]; selected: string[]; limit: number; onToggle: (id: string) => void; disabled: boolean; pt: boolean; hasProfile?:boolean;
}) {
  const [kind,setKind]=useState('');
  const [minimum,setMinimum]=useState(0);
  const [contextOnly,setContextOnly]=useState(false);
  const [readOnly,setReadOnly]=useState(false);
  const visible=items.filter(item=>selected.includes(item.id)||((!kind||(kind==='primary'?item.sourceRole==='primary':item.sourceKind===kind))&&(minimum===0||!!item.scoreBreakdown&&item.score>=minimum)&&(!contextOnly||!hasProfile||item.contextMatched)&&(!readOnly||item.bodyStatus==='read')));
  const labels=pt?{context:'Cliente',impact:'Impacto potencial',evidence:'Evidências',quality:'Fonte e originalidade',novelty:'Atualidade'}:{context:'Client',impact:'Potential impact',evidence:'Evidence',quality:'Source and originality',novelty:'Recency'};
  const caps={context:35,impact:25,evidence:20,quality:15,novelty:5};
  return <section aria-label={pt ? 'Notícias sugeridas para a semana' : 'Suggested weekly news'}>
    <p className="mb-3 text-sm text-muted-foreground">{pt ? `Até 25 sugestões, priorizando ativos monitorados, fontes oficiais e veículos reconhecidos. Escolha no máximo ${limit}; suas escolhas ficam salvas durante as atualizações.` : `Up to 25 suggestions prioritizing monitored assets, official sources and recognized publications. Choose at most ${limit}; updates preserve your selections.`}</p>
    <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
      <select aria-label={pt?'Tipo de fonte':'Source type'} value={kind} onChange={event=>setKind(event.target.value)} className="h-8 rounded-md border bg-background px-2"><option value="">{pt?'Todas as fontes':'All sources'}</option>{[['primary',pt?'Fonte primária':'Primary source'],['research',pt?'Pesquisa especializada':'Specialist research'],['official',pt?'Órgãos oficiais':'Official agencies'],['vendor',pt?'Fabricantes':'Vendors'],['press',pt?'Imprensa especializada':'Security press'],['complementary',pt?'Complementares':'Complementary'],['other',pt?'Outras fontes':'Other sources']].map(([value,label])=><option key={value} value={value}>{label}</option>)}</select>
      <select aria-label={pt?'Prioridade editorial':'Editorial priority'} value={minimum} onChange={event=>setMinimum(Number(event.target.value))} className="h-8 rounded-md border bg-background px-2"><option value={0}>{pt?'Todas as prioridades':'All priorities'}</option><option value={80}>{pt?'Destaques · 80+':'Highlights · 80+'}</option><option value={60}>{pt?'Prioridade · 60+':'Priority · 60+'}</option></select>
      {hasProfile&&<label className="flex items-center gap-2 px-1"><input type="checkbox" checked={contextOnly} onChange={event=>setContextOnly(event.target.checked)} />{pt?'Só contexto do cliente':'Client context only'}</label>}
      <label className="flex items-center gap-2 px-1"><input type="checkbox" checked={readOnly} onChange={event=>setReadOnly(event.target.checked)} />{pt?'Conteúdo analisado':'Content analyzed'}</label>
      <span className="ml-auto text-muted-foreground">{visible.length}/{items.length} · {pt?'selecionadas permanecem visíveis':'selected stories stay visible'}</span>
    </div>
    <p className="mb-3 text-xs text-muted-foreground">{pt?'A nota mede prioridade editorial, não o risco de ataque ao cliente.':'The score measures editorial priority, not the client’s risk of an attack.'}</p>
    <div className="divide-y overflow-hidden rounded-lg border">{visible.map((item, index) => {
      const checked = selected.includes(item.id);
      return <article key={item.id} className={checked ? 'bg-primary/5 p-4' : 'p-4'}>
        <label className="flex cursor-pointer items-start gap-3"><input type="checkbox" className="mt-1 h-4 w-4 accent-primary" checked={checked} disabled={disabled || (!checked && selected.length >= limit)} onChange={() => onToggle(item.id)} /><span className="min-w-0"><span className="font-mono text-xs text-muted-foreground">{String(index + 1).padStart(2, '0')} · {item.scoreBreakdown?(pt?'Prioridade editorial':'Editorial priority'):(pt?'Pontuação anterior':'Previous score')} {item.score}{item.scoreBreakdown?'/100':''}</span><span className="mt-1 block text-sm font-semibold leading-6">{item.title}</span><NewsTimestamp item={{ ...item, pubDate: item.published }} pt={pt} className="mt-1 block text-xs text-muted-foreground" /></span></label>
        <div className="ml-7 mt-2 flex flex-wrap gap-2">{item.selectionReasons?.map(reason => <span key={reason} className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground">{reason}</span>)}</div>
        <details className="ml-7 mt-2 text-xs"><summary className="cursor-pointer text-primary">{pt ? 'Resumo e fontes' : 'Summary and sources'} · {item.sources.length}</summary>{item.scoreBreakdown&&<dl className="mt-3 grid gap-1 sm:grid-cols-2">{(Object.keys(caps) as (keyof typeof caps)[]).map(key=><div key={key} className="flex gap-2"><dt className="text-muted-foreground">{labels[key]}</dt><dd>{item.scoreBreakdown?.[key]}/{caps[key]}</dd></div>)}</dl>}<p className="mt-2 leading-6 text-muted-foreground">{item.summary}</p><div className="mt-2 space-y-1">{item.sources.map(source => <a key={source.link} href={source.link} target="_blank" rel="noreferrer" className="block text-primary hover:underline">{source.source}: {source.title}{source.sourceRole==='primary'?(pt?' · Referência técnica priorizada':' · Preferred technical reference'):''}</a>)}</div></details>
      </article>;
    })}{!visible.length && <p className="p-6 text-sm text-muted-foreground">{pt ? 'Nenhuma notícia corresponde aos filtros neste período.' : 'No news matches the filters in this period.'}</p>}</div>
  </section>;
}
