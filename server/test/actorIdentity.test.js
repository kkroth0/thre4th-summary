import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonicalizeActors, buildActorIdentityIndex, canonicalActorReferences, actorNameKey } from '../actorIdentity.js';
import { buildActorIndex, matchActors } from '../actorMatch.js';
import { enrichActorCatalog } from '../actorSources.js';
import { mergeCtiActors } from '../ctiFyi.js';
import { axurObservations } from '../axurIntelligence.js';
import { createIocIntelligence } from '../iocIntelligence.js';

test('source duplicates redirect to an authoritative identity without losing names, references or actor subgroups',()=>{
  const rows=[{id:'G1034',name:'Daggerfly',aliases:['Evasive Panda','BRONZE HIGHLAND'],source:'attack'},
    {id:'misp-evasive',name:'Evasive Panda',aliases:['Bronze Highland'],source:'misp',refs:['https://source.example/report']},
    {id:'G0032',name:'Lazarus Group',aliases:['APT38'],source:'attack'},
    {id:'G0082',name:'APT38',aliases:[],source:'attack'}];
  const canonical=canonicalizeActors(rows),index=buildActorIdentityIndex(canonical);
  assert.equal(canonical.length,3);assert.equal(index.ids.get('misp-evasive').id,'G1034');
  assert.equal(index.resolve('Evasive Panda').id,'G1034');
  assert.ok(index.ids.get('G1034').refs.includes('https://source.example/report'));
  assert.equal(index.resolve('APT38').id,'G0082');assert.equal(index.ids.get('G0032').id,'G0032');
  assert.deepEqual(canonicalizeActors(canonical),canonical);
  assert.equal(rows[0].redirectIds,undefined);
});

test('ambiguous aliases are associations, never first-row-wins matches, in either catalog order',()=>{
  const rows=[{id:'G0001',name:'Actor One',aliases:['Shared Fox']},{id:'G0002',name:'Actor Two',aliases:['Shared Fox']}];
  for(const ordered of [rows,rows.slice().reverse()]){
    const index=buildActorIndex(ordered);
    assert.deepEqual(matchActors('Shared Fox group',index),[]);
    assert.deepEqual(matchActors('Shared Fox',index,{structured:true}),[]);
    assert.equal(index.exact.get(actorNameKey('Actor One')).id,'G0001');
    assert.ok(structuredClone(index).exact instanceof Map);
  }
});

test('structured Axur names use the same current catalog as visible CTI aliases, including punctuation',()=>{
  const catalog=mergeCtiActors([{id:'rl-alphv',name:'ALPHV',aliases:[],source:'ransomware.live'},
    {id:'misp-chaya',name:'Chaya_004',aliases:[],source:'misp'}],
    [{name:'ALPHV',aliases:['Noberus','ALPHV'],description:'',techniques:[],refs:[],postCount:0}]);
  const index=buildActorIndex(catalog);
  for(const [label,id]of [['Noberus','rl-alphv'],['Chaya_004','misp-chaya'],['Chaya 004','misp-chaya']]){
    const rows=axurObservations([{id:'fixture',value:'8.8.8.8',relatedInsights:['report']}],
      [{id:'report',threatActors:[label]}],{scope:'owner',matchActors:(text,options)=>matchActors(text,index,options)});
    assert.equal(rows[1].actors[0].id,id);
  }
  assert.deepEqual(catalog[0].aliases,['Noberus']);
});

test('private source-only identities and archived references resolve through canonical IDs, with no cross-actor aliases',()=>{
  const catalog=canonicalizeActors([{id:'rl-alphv',name:'ALPHV',aliases:['Noberus'],source:'ransomware.live'},
    {id:'axur:actor:old',name:'Noberus',aliases:[],verification:'source-reported'}]);
  assert.equal(catalog.length,1);assert.ok(catalog[0].redirectIds.includes('axur:actor:old'));
  const [row]=canonicalActorReferences([{actors:[{id:'axur:actor:old',name:'Noberus'},{id:'rl-alphv',name:'ALPHV'}]}],buildActorIdentityIndex(catalog));
  assert.deepEqual(row.actors,[{id:'rl-alphv',name:'ALPHV'}]);
});

test('real catalog canonicalizes the audited duplicates, retains every old ID, and cleans every AKA list',()=>{
  const original=JSON.parse(fs.readFileSync(new URL('../data/actors.json',import.meta.url),'utf8')).actors;
  const snapshot=JSON.parse(fs.readFileSync(new URL('../data/actor-sources.json',import.meta.url),'utf8'));
  const catalog=enrichActorCatalog(original,snapshot),index=buildActorIdentityIndex(catalog);
  assert.equal(index.ids.get('misp-171d0590').id,'G1034');
  assert.equal(index.ids.get('misp-2ee5ed7a').id,'G0016');
  assert.equal(index.ids.get('G0032').id,'G0032');assert.equal(index.ids.get('G0082').id,'G0082');
  for(const actor of original)assert.ok(index.ids.has(actor.id),actor.id);
  for(const actor of catalog){const keys=[actor.name,...actor.aliases].map(actorNameKey);assert.equal(new Set(keys).size,keys.length,actor.name);}
});

test('old catalog IDs are reconciled without losing evidence, scope or the original alias registry',async t=>{
  const store=createIocIntelligence();t.after(()=>store.close());
  await store.ingest([{value:'8.8.8.8',scope:'owner',provider:'Axur',externalId:'one',actors:[{id:'misp-evasive',name:'Evasive Panda'}],payload:{original:true}}]);
  const catalog=[{id:'G1034',name:'Daggerfly',aliases:['Evasive Panda'],source:'attack'},
    {id:'misp-evasive',name:'Evasive Panda',aliases:[],source:'misp'}];
  assert.equal((await store.reconcileActorAliases(catalog)).changed,1);
  const data=store.detail('8.8.8.8','owner');assert.equal(data.evidence[0].entities[0].id,'G1034');
  assert.equal(data.evidence[0].payload.original,true);assert.equal(store.detail('8.8.8.8','other'),null);
  assert.equal(store.status('owner').indicators,1);
  const names=store.news.entities({owner:'owner',kind:'actor',query:'Evasive Panda'});
  assert.ok(names.length>0);assert.ok(names.every(row=>row.id==='G1034'));
});
