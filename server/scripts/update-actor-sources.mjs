import fs from 'node:fs';
import { ACTOR_SOURCES, actorNameKey, enrichActorCatalog, parseEtda, parseIcic, parseRapid7, parseRansomwareDomains } from '../actorSources.js';

const output=new URL('../data/actor-sources.json',import.meta.url);
const previous=fs.existsSync(output)?JSON.parse(fs.readFileSync(output,'utf8')):{};
async function text(url) {
  const response=await fetch(url,{headers:{'User-Agent':'ThreatSumm4ry-actor-catalog/1.0'},signal:AbortSignal.timeout(60000)});
  if(!response.ok)throw new Error(`Source HTTP ${response.status}: ${new URL(url).hostname}`);
  return response.text();
}
async function icicProfiles() {
  const page=await text(ACTOR_SOURCES.icic);
  const entry=/src="(\/assets\/index-[A-Za-z0-9_-]+\.js)"/.exec(page)?.[1];
  if(!entry)throw new Error('ICIC entry unavailable');
  const bundle=await text(new URL(entry,ACTOR_SOURCES.icic));
  const profile=/assets\/(APTProfiles-[A-Za-z0-9_-]+\.js)/.exec(bundle)?.[1];
  if(!profile)throw new Error('ICIC public profile asset unavailable');
  return parseIcic(await text(new URL(`/assets/${profile}`,ACTOR_SOURCES.icic)));
}
const collectedAt=new Date().toISOString();
const [bundle,etda,rapid7,icic,repository]=await Promise.all([
  text('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json').then(JSON.parse),
  text(ACTOR_SOURCES.etda).then(JSON.parse),text(ACTOR_SOURCES.rapid7).then(parseRapid7),icicProfiles(),
  text('https://api.github.com/repos/marktsec/Ransomware_Official_Domains/commits/main').then(JSON.parse),
]);
// Authorization was explicitly declared by the product owner on 2026-10-20.
// Keep that decision visible across refreshes; never silently drop attribution.
const etdaAuthorization=previous.etdaAuthorization || {declaredBy:'product-owner',declaredAt:'2026-10-20',basis:'Permission for product use confirmed by owner'};
const mitre=(bundle.objects || []).filter(row=>row.type==='intrusion-set'&&!row.revoked&&!row.x_mitre_deprecated).map(row=>{
  const reference=(row.external_references || []).find(ref=>ref.source_name==='mitre-attack');
  return {name:row.name,actorIds:reference?.external_id?[reference.external_id]:[],aliases:(row.aliases || []).map(name=>({name})),
    source:'MITRE ATT&CK',url:reference?.url || ACTOR_SOURCES.mitre,sourceUpdatedAt:row.modified,relation:'source-declared-name'};
});
if(!/^[a-f0-9]{40}$/.test(repository.sha))throw new Error('Repository commit unavailable');
const readme=await text(`https://raw.githubusercontent.com/marktsec/Ransomware_Official_Domains/${repository.sha}/README.md`);
const snapshot={version:1,collectedAt,etdaAuthorization,sources:[
  {name:'MITRE ATT&CK',url:ACTOR_SOURCES.mitre,records:mitre.length},
  {name:'ETDA',url:ACTOR_SOURCES.etda,records:etda.values.length,license:etda.license,sourceUpdatedAt:etda['last-db-change']},
  {name:'Rapid7',url:ACTOR_SOURCES.rapid7,records:rapid7.length},
  {name:'ICIC',url:ACTOR_SOURCES.icic,records:icic.length,mode:'context-only'},
  {name:'Ransomware Official Domains',url:ACTOR_SOURCES.domains,commit:repository.sha,sourceUpdatedAt:repository.commit?.committer?.date},
],records:[...mitre,...parseEtda(etda),...rapid7,...icic],domains:parseRansomwareDomains(readme,{commit:repository.sha,collectedAt})};
const base=JSON.parse(fs.readFileSync(new URL('../data/actors.json',import.meta.url),'utf8')).actors;
const software=JSON.parse(fs.readFileSync(new URL('../data/malware.json',import.meta.url),'utf8')).malware;
const aliasKeys=new Set(snapshot.records.flatMap(row=>row.aliases || []).map(row=>actorNameKey(row.name)));
snapshot.nonActorNames=[...new Set(software.flatMap(row=>[row.name,...(row.aliases || [])]).filter(name=>aliasKeys.has(actorNameKey(name))))];
const merged=enrichActorCatalog(base,snapshot);
const stats={actors:base.length,enriched:merged.filter(row=>row.aliasEvidence.length||row.infrastructure.length).length,
  newAliases:merged.reduce((sum,row,index)=>sum+row.aliases.length-base[index].aliases.length,0),
  associations:merged.reduce((sum,row)=>sum+row.relatedNames.length,0),
  sites:merged.reduce((sum,row)=>sum+row.infrastructure.length,0),actorsWithSites:merged.filter(row=>row.infrastructure.length).length,
  unresolvedRecords:snapshot.records.filter(row=>!merged.some(actor=>actor.aliasEvidence.some(evidence=>evidence.url===row.url))).length,
  sourceDomains:snapshot.domains.length};
if(mitre.length<100||etda.values.length<400||rapid7.length<10||icic.length<5||snapshot.domains.length<50||stats.enriched<100)throw new Error('Unexpected source coverage; keeping previous snapshot');
snapshot.stats=stats;
fs.writeFileSync(new URL('../data/actor-sources.json.tmp',import.meta.url),JSON.stringify(snapshot,null,2));
fs.renameSync(new URL('../data/actor-sources.json.tmp',import.meta.url),output);
console.log(JSON.stringify({sources:snapshot.sources,stats},null,2));
