import type { BulkEvidence } from '../services/bulkContext';

export type EntityRelation = 'attributed' | 'reported' | 'mentioned';
export interface EntityReference { key: string; title: string; link: string; published: string }
export interface EntityEvidenceGroup {
  key: string; provider: string; kind: 'actor' | 'malware' | 'cve'; name: string;
  relation: EntityRelation; references: EntityReference[]; latestPublished: string;
}
const normalized=(value:string)=>value.normalize('NFKC').trim().replace(/\s+/g,' ').toLowerCase();
export const entityRelation=(value:string):EntityRelation=>value==='attributed-by-source'?'attributed':value==='reported-by-source'?'reported':'mentioned';
const time=(value:string)=>Date.parse(value)||0;
export function evidenceHttpLink(value:string){try{const url=new URL(value);return ['http:','https:'].includes(url.protocol)?value:null;}catch{return null;}}
function referenceKey(provider:string,evidence:BulkEvidence,index:number){
  const link=evidenceHttpLink(evidence.link||'');
  if(link){const url=new URL(link);url.hash='';for(const key of [...url.searchParams.keys()])if(/^utm_/i.test(key)||key==='fbclid')url.searchParams.delete(key);return JSON.stringify([provider,url.href]);}
  // Without a source ID/link we cannot prove that two records are the same publication.
  return JSON.stringify([provider,'unlinked',index]);
}

/** Group repeated labels for display; leave every original observation intact. */
export function summarizeEntityEvidence(evidence:BulkEvidence[]){
  const groups=new Map<string,EntityEvidenceGroup>(),references=new Map<string,Map<string,EntityReference>>();
  evidence.forEach((item,index)=>{
    const source=String(item.provider||item.source||'Fonte').trim(),provider=/^(?:otx|alienvault otx)$/i.test(source)?'OTX':source;
    const publicationKey=referenceKey(normalized(provider),item,index);
    for(const entity of Array.isArray(item.entities)?item.entities:[]){
      if(typeof entity?.name!=='string'||!entity.name.trim()||!['actor','malware','cve'].includes(entity.kind))continue;
      const relation=entityRelation(entity.relation),key=JSON.stringify([normalized(provider),entity.kind,normalized(String(entity.id||entity.name)),relation]);
      if(!groups.has(key)){groups.set(key,{key,provider,kind:entity.kind,name:entity.name.trim(),relation,references:[],latestPublished:''});references.set(key,new Map());}
      const refs=references.get(key)!,existing=refs.get(publicationKey),published=Number.isFinite(Date.parse(item.published))?item.published:'';
      if(!existing)refs.set(publicationKey,{key:publicationKey,title:item.title||item.link||provider,link:evidenceHttpLink(item.link||'')||'',published});
      else if(time(published)>time(existing.published))refs.set(publicationKey,{...existing,published});
    }
  });
  const result=[...groups.values()];
  for(const group of result){group.references=[...references.get(group.key)!.values()].sort((a,b)=>time(b.published)-time(a.published)||a.key.localeCompare(b.key));group.latestPublished=group.references[0]?.published||'';}
  result.sort((a,b)=>(a.relation==='mentioned'?1:0)-(b.relation==='mentioned'?1:0)||b.references.length-a.references.length||a.name.localeCompare(b.name)||a.provider.localeCompare(b.provider));
  return {groups:result,recordCount:evidence.length,referenceCount:new Set(result.flatMap(group=>group.references.map(ref=>ref.key))).size};
}
