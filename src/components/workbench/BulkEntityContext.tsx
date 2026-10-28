import {useMemo,useState} from 'react';
import type {BulkEvidence} from '@/services/bulkContext';
import {summarizeEntityEvidence,evidenceHttpLink,type EntityEvidenceGroup,type EntityRelation} from '@/utils/bulkEntityContext';

const kindLabel={actor:'Ator',malware:'Malware',cve:'CVE'};
const relationLabel=(relation:EntityRelation,pt:boolean)=>relation==='attributed'?(pt?'Vínculo informado pela fonte':'Source attribution'):relation==='reported'?(pt?'Informado pela fonte':'Source report'):(pt?'Menção em publicação':'Publication mention');
const date=(value:string,pt:boolean)=>new Date(value).toLocaleDateString(pt?'pt-BR':'en-US',{timeZone:/^\d{4}-\d{2}-\d{2}$/.test(value)?'UTC':'America/Fortaleza'});
function EntityGroup({group,pt,full}:{group:EntityEvidenceGroup;pt:boolean;full:boolean}){
  const [open,setOpen]=useState(false),refs=full?group.references:group.references.slice(0,5);
  return <div className="space-y-1.5 rounded-md border border-border/70 p-2.5">
    <div className="flex flex-wrap items-center gap-1.5"><span className="font-medium text-foreground">{group.name}</span><span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{pt?kindLabel[group.kind]:group.kind}</span></div>
    <p className={group.relation==='mentioned'?'text-muted-foreground':'text-primary'}>{group.provider} · {relationLabel(group.relation,pt)}</p>
    {group.latestPublished&&<p className="text-[10px] text-muted-foreground">{pt?'Última referência: ':'Latest reference: '}{date(group.latestPublished,pt)}</p>}
    <details onToggle={event=>setOpen(event.currentTarget.open)}>
      <summary className="cursor-pointer text-primary" aria-label={`${pt?'Ver referências de':'View references for'} ${group.name} · ${group.provider}`}>{group.references.length} {group.provider==='OTX'?(group.references.length===1?'pulse':'pulses'):(pt?(group.references.length===1?'referência':'referências'):(group.references.length===1?'reference':'references'))}</summary>
      {open&&<div className="mt-2 max-h-64 space-y-2 overflow-y-auto">{refs.map(ref=><div key={ref.key} className="border-t border-border/50 pt-2">{ref.link?<a href={ref.link} target="_blank" rel="noreferrer" className="block break-words text-primary hover:underline">{ref.title}</a>:<p>{ref.title}</p>}<p className="mt-1 text-[10px] text-muted-foreground">{ref.published?date(ref.published,pt):(pt?'Data da publicação não informada':'Publication date unavailable')}</p></div>)}{group.references.length>refs.length&&<p className="text-muted-foreground">+{group.references.length-refs.length} {pt?'no detalhamento do indicador':'in indicator details'}</p>}</div>}
    </details>
  </div>;
}
export function BulkEntityContext({evidence,pt,onDetails,full=false,loading=false}:{evidence:BulkEvidence[];pt:boolean;onDetails?:()=>void;full?:boolean;loading?:boolean}){
  const summary=useMemo(()=>summarizeEntityEvidence(evidence),[evidence]),groups=full?summary.groups:summary.groups.slice(0,3);
  return <div className="space-y-2 text-xs">
    {groups.map(group=><EntityGroup key={group.key} group={group} pt={pt} full={full}/>)}
    {!groups.length&&<p className="text-muted-foreground">{loading?(pt?'Aguardando correlação':'Waiting for correlation'):(pt?'Sem entidades citadas nas evidências recebidas':'No entities mentioned in received evidence')}</p>}
    {groups.some(group=>group.relation==='mentioned')&&<p className="text-[10px] leading-relaxed text-muted-foreground">{pt?'Menções são contexto da publicação e não confirmam autoria ou uso atual do indicador.':'Mentions are publication context and do not confirm attribution or current use of the indicator.'}</p>}
    {onDetails&&summary.recordCount>0&&<button type="button" className="text-primary hover:underline" onClick={onDetails}>{pt?'Ver histórico completo':'View full history'} ({summary.recordCount} {pt?'registros':'records'}){summary.groups.length>groups.length?` · +${summary.groups.length-groups.length} ${pt?'entidades':'entities'}`:''}</button>}
  </div>;
}
export function BulkEvidenceHistory({evidence,pt}:{evidence:BulkEvidence[];pt:boolean}){
  const [open,setOpen]=useState(false);
  return <details className="border-t pt-4" onToggle={event=>setOpen(event.currentTarget.open)}><summary className="cursor-pointer text-sm text-primary">{pt?'Histórico completo':'Full history'} · {evidence.length} {pt?'registros originais':'original records'}</summary>{open&&<div className="mt-4 space-y-4">{evidence.map((item,index)=><article key={index} className="border-t pt-4 text-sm"><p className="text-xs text-muted-foreground">{item.provider} · {item.published?date(item.published,pt):(pt?'Sem data da publicação':'No publication date')}</p>{evidenceHttpLink(item.link)?<a href={item.link} target="_blank" rel="noreferrer" className="mt-1 block text-primary hover:underline">{item.title}</a>:<p>{item.title}</p>}<p className="mt-2 text-xs text-muted-foreground">{item.entities.map(entity=>`${entity.name} (${entity.relation})`).join(' · ')}</p></article>)}</div>}</details>;
}
