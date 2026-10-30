import type {BulkContext, BulkEvidence} from '../services/bulkContext';
import type {BulkRow} from './bulkEnrichment';
export type BulkEntityResolution=NonNullable<BulkContext['entityResolutions']>[number];
const key=(kind:string,label:string,id='')=>JSON.stringify([kind,label.normalize('NFKC').toLowerCase().replace(/\s+/g,' ').trim(),id]);
export function bulkEntityLookup(context?:BulkContext) {
  const exact=new Map<string,BulkEntityResolution>(),named=new Map<string,BulkEntityResolution[]>();
  for(const resolution of context?.entityResolutions||[]){
    exact.set(key(resolution.sourceKind,resolution.sourceLabel,resolution.sourceId||''),resolution);
    const nameKey=key(resolution.sourceKind,resolution.sourceLabel),rows=named.get(nameKey)||[];rows.push(resolution);named.set(nameKey,rows);
  }
  return (sourceKind:string,label:string,sourceId=''):BulkEntityResolution=>{
    const match=exact.get(key(sourceKind,label,sourceId));if(match)return match;
    const candidates=named.get(key(sourceKind,label))||[];
    if(candidates.length&&new Set(candidates.map(row=>JSON.stringify([row.kind,row.id,row.name]))).size===1)return candidates[0];
    return {sourceKind,sourceLabel:label,sourceId,kind:sourceKind==='malware'?'software':sourceKind==='cve'?'cve':'unclassified',name:label,id:sourceKind==='cve'?label:'',verification:sourceKind==='malware'?'source-reported':sourceKind==='cve'?'identifier':'unresolved',catalogSource:''};
  };
}
export function bulkEntityRelation(row:BulkRow,entity:BulkEvidence['entities'][number]) {
  const identity=bulkEntityLookup(row.context)(entity.kind,entity.name,entity.id);
  const kind=identity.kind==='actor'?'Ator do catálogo':identity.kind==='software'?(identity.verification==='catalog'?'Malware/ferramenta do catálogo':'Malware/ferramenta informado'):identity.kind==='cve'?'CVE':identity.kind==='ambiguous'?'Nome ambíguo':'Rótulo sem validação';
  return {...entity,kind,name:identity.name,sourceKind:entity.kind,sourceName:entity.name,catalogId:identity.id,identityStatus:identity.verification==='catalog'?'Correspondência no catálogo':identity.verification==='source-reported'?'Informado pela fonte; fora do catálogo':identity.verification==='identifier'?'Identificador':'Sem correspondência unívoca no catálogo'};
}
