import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { enrichActorCatalog, parseEtda, parseRapid7, parseIcic, parseRansomwareDomains } from '../actorSources.js';
import { buildActorIndex, matchActors } from '../actorMatch.js';
import { buildActorNameIndex } from '../actorSoftware.js';
import { createIocIntelligence } from '../iocIntelligence.js';

const actors=[{id:'G0016',name:'APT29',aliases:['Cozy Bear'],refs:[]},{id:'G0032',name:'Lazarus Group',aliases:['Hidden Cobra'],refs:[]},{id:'G0082',name:'APT38',aliases:['Bluenoroff'],refs:[]}];
const record=(name,aliases,extra={})=>({name,aliases:aliases.map(name=>({name})),source:'ETDA',url:'https://apt.etda.or.th/example',relation:'source-declared-name',...extra});

test('ETDA keeps explicit MITRE identifiers, naming organizations, dates and references; not operations or software',()=>{
  const rows=parseEtda({values:[{actor:'APT 29, Cozy Bear',uuid:'uuid',names:[{name:'APT 29','name-giver':'Mandiant'},{name:'G0016','name-giver':'MITRE'}],'mitre-attack':['https://attack.mitre.org/groups/G0016/'],tools:['SeaDuke'],operations:['Office Monkeys'],'last-card-change':'2025-08-16'}]});
  assert.equal(rows[0].name,'APT 29');assert.deepEqual(rows[0].actorIds,['G0016']);assert.equal(rows[0].aliases[0].declaredBy,'Mandiant');
  assert.equal(rows[0].sourceUpdatedAt,'2025-08-16');assert.match(rows[0].url,/showcard.cgi\?g=APT%2029/);assert.equal(rows[0].aliases.length,1);
});

test('Rapid7 parses explicit alias lists only; skips detection rules, technique and mitigation lists',()=>{
  const rows=parseRapid7('<h3 id="apt29">APT29<a>copy</a></h3><p>Other names for this group include:</p><ul><li>Blue Kitsune</li></ul><h3>Detection Rules</h3><p>Techniques</p><ul><li>T1059</li></ul>');
  assert.equal(rows.length,1);assert.deepEqual(rows[0].aliases,[{name:'Blue Kitsune'}]);assert.ok(rows[0].url.endsWith('#apt29'));
  assert.throws(()=>parseRapid7('<p>WAF challenge</p>'));
});

test('ICIC profiles are read as string literals and remain contextual associations',()=>{
  const data=parseIcic('const f=[{name:"Lazarus Group",aliases:"APT38, Hidden Cobra",origin:"North Korea"}]; throw new Error("must not execute")');
  assert.equal(data.length,1);assert.equal(data[0].relation,'source-association');
  const merged=enrichActorCatalog(actors,{records:data});assert.ok(!merged[1].aliases.includes('APT38'));assert.equal(merged[1].relatedNames[0].name,'APT38');assert.equal(merged[2].id,'G0082');
});

test('aliases resolve to existing IDs, deduplicate and work in news matching and provider name indexes',()=>{
  const snapshot={records:[record('APT 29',['APT 29','Blue Kitsune','blue kitsune'],{actorIds:['G0016']})]};
  const merged=enrichActorCatalog(actors,snapshot);assert.equal(merged.length,3);assert.deepEqual(merged[0].aliases,['Cozy Bear','Blue Kitsune']);
  assert.equal(matchActors('Blue Kitsune group targets government',buildActorIndex(merged))[0].id,'G0016');
  assert.equal(buildActorNameIndex(merged).bluekitsune,'APT29');assert.equal(actors[0].aliases.length,1);
  assert.deepEqual(enrichActorCatalog(actors,snapshot),merged);
});

test('shared names, unknown explicit IDs, software labels and broad group names never create new alias attributions',()=>{
  const data={records:[record('APT29',['Shared Fox','SeaDuke']),record('Lazarus Group',['Shared Fox','APT38']),record('Unresolved Source Group',['New Shared Name']),record('APT29',['New Shared Name']),record('APT29',['Must Not Add'],{actorIds:['G9999']})],nonActorNames:['SeaDuke']};
  const merged=enrichActorCatalog(actors,data);
  for(const actor of merged)for(const alias of ['Shared Fox','SeaDuke','Must Not Add','New Shared Name'])assert.ok(!actor.aliases.includes(alias));
  assert.ok(!merged[1].aliases.includes('APT38'));assert.ok(merged[1].relatedNames.some(row=>row.name==='APT38'&&row.relatedActorIds.includes('G0082')));
  assert.ok(!matchActors('Shared Fox targets networks',buildActorIndex(merged)).length);
});

test('onion parser preserves offline, seized, historical and defanged records, and discards secrets and clearnet links',()=>{
  const a='a'.repeat(56)+'.onion',b='b'.repeat(56)+'.onion',c='c'.repeat(56)+'.onion';
  const rows=parseRansomwareDomains(`## Qilin\n## NEW\nhxxp[:]//${a.replace('.','[.]')}/path?key=secret\nEmail: private@example.com\nThe blog access key: never-store-this\nhttps://www.cisa.gov/advisory\n## OLD\nhttp://${b}/\n## Akira\nhttp://${c}/ - Seized\nhttp://${c}/ - Offline`,{commit:'test',collectedAt:'2026-10-20'});
  assert.equal(rows.length,4);assert.equal(rows[0].name,'Qilin');assert.equal(rows[0].host,a);assert.equal(rows[0].url,`http://${a}/`);assert.equal(rows[1].reportedStatus,'historical');assert.equal(rows[2].reportedStatus,'reported-seized');
  assert.ok(!JSON.stringify(rows).includes('secret'));assert.ok(!JSON.stringify(rows).includes('private@example.com'));
});

test('infrastructure binds only to one existing actor, keeps unavailable status and never becomes a C2 inference',()=>{
  const host='a'.repeat(56)+'.onion';const base=[{id:'rl-qilin',name:'Qilin',aliases:[],refs:[]}];
  const domains=parseRansomwareDomains(`## Qilin\nhttp://${host}/ - Offline\nhttp://${host}/`);
  const merged=enrichActorCatalog(base,{domains});assert.equal(merged[0].infrastructure.length,1);assert.equal(merged[0].infrastructure[0].reportedStatus,'reported-offline');assert.equal(merged[0].infrastructure[0].relation,'listed-in-source');
  const ambiguous=enrichActorCatalog([...base,{id:'other',name:'Other',aliases:['Qilin'],refs:[]}],{domains});assert.ok(ambiguous.every(row=>row.infrastructure.length===0));
});

test('real snapshot expands aliases without merging Lazarus/APT38 and includes provenance and ransomware sites',()=>{
  const base=JSON.parse(fs.readFileSync(new URL('../data/actors.json',import.meta.url),'utf8')).actors;
  const snapshot=JSON.parse(fs.readFileSync(new URL('../data/actor-sources.json',import.meta.url),'utf8'));
  const merged=enrichActorCatalog(base,snapshot);
  assert.equal(merged.length,base.length);assert.equal(new Set(merged.map(row=>row.id)).size,base.length);
  assert.ok(merged.find(row=>row.id==='G0016').aliases.includes('Blue Kitsune'));
  assert.ok(!merged.find(row=>row.id==='G0032').aliases.includes('APT38'));
  assert.ok(merged.some(row=>/akira/i.test(row.name)&&row.infrastructure.length));
  assert.ok(merged.filter(row=>row.infrastructure.length).length>80);
  assert.ok(snapshot.etdaAuthorization.declaredAt);
  assert.ok(merged.flatMap(row=>row.aliasEvidence).every(row=>row.source&&row.url.startsWith('https://')));
});

test('saved source identities reconcile into one canonical actor while preserving scope, provenance and relation',async t=>{
  const store=createIocIntelligence();t.after(()=>store.close());
  await store.ingest([{value:'8.8.8.8',scope:'owner',provider:'Axur',externalId:'one',actors:[{id:'axur:actor:blue',name:'Blue Kitsune'}],relation:'mentioned-with',payload:{original:'preserved'}},
    {value:'9.9.9.9',scope:'other',provider:'OTX',externalId:'two',actors:[{id:'otx:blue',name:'Blue Kitsune'}],relation:'mentioned-by-source'}]);
  const catalog=enrichActorCatalog(actors,{records:[record('APT29',['Blue Kitsune'])]});
  assert.equal((await store.reconcileActorAliases(catalog)).changed,2);
  assert.deepEqual(store.detail('8.8.8.8','owner').evidence[0].entities,[{kind:'actor',id:'G0016',name:'APT29',relation:'mentioned-with'}]);
  assert.equal(store.detail('8.8.8.8','owner').evidence[0].payload.original,'preserved');assert.equal(store.detail('8.8.8.8','other'),null);
  assert.equal(store.detail('9.9.9.9','other').evidence[0].entities[0].relation,'mentioned-by-source');
  assert.equal((await store.reconcileActorAliases(catalog)).changed,0);assert.equal(store.status('owner').indicators,1);
});

test('reconciliation preserves known subgroup IDs and refuses aliases shared between catalog actors',async t=>{
  const store=createIocIntelligence();t.after(()=>store.close());
  await store.ingest([{value:'8.8.8.8',provider:'Axur',actors:[{id:'G0082',name:'APT38'},{id:'source-shared',name:'Shared Fox'}]}]);
  await store.reconcileActorAliases(actors.map(actor=>({...actor,aliases:[...actor.aliases,'Shared Fox']})));
  assert.deepEqual(store.detail('8.8.8.8').evidence[0].entities.map(row=>row.id).sort(),['G0082','source-shared']);
});
