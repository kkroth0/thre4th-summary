import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildActorIdentityIndex} from './actorIdentity.js';
import {enrichActorCatalog} from './actorSources.js';
import {mergeCtiActors} from './ctiFyi.js';
import {buildMalwareIndex,matchMalware} from './malwareMatch.js';

export const BULK_ENTITY_VERSION='2026-10-30-v1';
const labelKey=value=>String(value||'').normalize('NFKC').toLowerCase().replace(/\s+/g,' ').trim();
const strings=value=>Array.isArray(value)?value.flatMap(strings):typeof value==='string'&&value.trim()?[value.trim()]:[];

/** A provider's adversary field never creates a catalog identity. */
export function createBulkEntityResolver({actors=[],malware=[]}={}) {
  const identities=buildActorIdentityIndex(actors),software=buildMalwareIndex(malware),softwareIds=new Map(malware.map(row=>[row.id,row])),cache=new Map();
  function resolve(sourceKind,label,sourceId='') {
    label=String(label||'').trim();const key=JSON.stringify([sourceKind,labelKey(label),sourceId]);
    if(cache.has(key))return cache.get(key);
    let result={sourceKind,sourceLabel:label,sourceId,kind:'unclassified',name:label,id:'',verification:'unresolved',catalogSource:''};
    if(sourceKind==='cve')result={...result,kind:'cve',id:label.toUpperCase(),name:label.toUpperCase(),verification:'identifier'};
    else {
      const actorId=sourceId&&identities.ids.get(sourceId),actor=actorId||identities.resolve(label);
      const matches=softwareIds.has(sourceId)?[softwareIds.get(sourceId)]:matchMalware(label,software,{structured:true});
      const family=matches.length===1?matches[0]:null;
      const knownSoftware=family&&softwareIds.get(family.id);
      const namedActor=identities.resolve(label),conflictingId=actorId&&((namedActor&&namedActor.id!==actorId.id)||(family&&!namedActor));
      const softwareResult=family?{...result,kind:'software',id:knownSoftware?family.id:'',name:family.name,verification:knownSoftware?'catalog':'source-reported',catalogSource:knownSoftware?.source||''}:null;
      if(conflictingId&&sourceKind==='actor')result={...result,kind:'ambiguous',verification:'ambiguous'};
      else if(actorId&&sourceKind==='actor')result={...result,kind:'actor',id:actorId.id,name:actorId.name,verification:'catalog',catalogSource:actorId.source||'actor-catalog'};
      else if(sourceKind==='malware'&&family)result=softwareResult;
      else if(actor&&family)result={...result,kind:'ambiguous',verification:'ambiguous'};
      else if(actor&&sourceKind==='actor')result={...result,kind:'actor',id:actor.id,name:actor.name,verification:'catalog',catalogSource:identities.ids.get(actor.id)?.source||'actor-catalog'};
      else if(family)result=softwareResult;
      else if(sourceKind==='malware'&&!actor)result={...result,kind:'software',verification:'source-reported'};
    }
    if(cache.size>=10000)cache.delete(cache.keys().next().value);cache.set(key,result);return result;
  }
  function normalizeRow(row) {
    const labels=[];
    for(const item of row.context?.evidence||[])for(const entity of item.entities||[])labels.push([entity.kind,entity.name,entity.id]);
    for(const vendor of row.result?.vendorData||[]){
      if(vendor.error||vendor.isLoading||vendor.unsupported)continue;
      if(vendor.name==='AlienVault OTX')for(const pulse of Array.isArray(vendor.data?.['Pulse Details'])?vendor.data['Pulse Details']:[]){
        for(const label of strings(pulse.adversary))labels.push(['actor',label]);
        for(const label of strings(pulse.malwareFamilies))labels.push(['malware',label]);
      }
      for(const field of vendor.name==='ThreatFox'?['All Malware','Malware']:vendor.name==='MalwareBazaar'?['Malware','Signature']:vendor.name==='URLhaus'?['All Malware']:[])
        for(const label of strings(vendor.data?.[field]))for(const part of label.split(/,\s*/))labels.push(['malware',part]);
    }
    const resolutions=new Map();for(const [kind,label,id]of labels){const resolved=resolve(kind,label,id);resolutions.set(JSON.stringify([kind,labelKey(label),id||'']),resolved);}
    return {...row,context:{publications:[],evidence:[],errors:[],...row.context,entityResolutionVersion:BULK_ENTITY_VERSION,entityResolutions:[...resolutions.values()]}};
  }
  return {resolve,normalizeRow,actorCount:identities.actors.length,softwareCount:malware.length};
}

let cached;
export function loadBulkEntityResolver(serverDir=path.dirname(fileURLToPath(import.meta.url))) {
  const files=['data/actors.json','data/actor-sources.json','.cti-fyi.json','data/malware.json'];
  const revision=files.map(name=>{try{const stat=fs.statSync(path.join(serverDir,name));return name+':'+stat.size+':'+stat.mtimeMs;}catch{return name+':missing';}}).join('|');
  if(cached?.dir===serverDir&&cached.revision===revision)return cached.resolver;
  const read=(name,fallback)=>{try{return JSON.parse(fs.readFileSync(path.join(serverDir,name),'utf8'));}catch(error){if(error.code==='ENOENT')return fallback;throw error;}};
  const actorData=read(files[0],{}),sources=read(files[1],{}),cti=read(files[2],{}),malware=read(files[3],{});
  const actors=mergeCtiActors(enrichActorCatalog(actorData.actors||[],sources),cti.groups||[]);
  const resolver=createBulkEntityResolver({actors,malware:Array.isArray(malware)?malware:malware.malware||[]});
  cached={dir:serverDir,revision,resolver};return resolver;
}
export const normalizeBulkEntityRow=row=>loadBulkEntityResolver().normalizeRow(row);
