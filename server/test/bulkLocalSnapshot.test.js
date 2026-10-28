import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createIocIntelligence } from '../iocIntelligence.js';
import { createBulkLocalSnapshot } from '../bulkLocalSnapshot.js';
import { analyzeBulkRow } from '../bulkShared.generated.mjs';

const query='94.154.43.158';
function fixture(t, importStatus='complete') {
 const dir=fs.mkdtempSync(path.join(tmpdir(),'bulk-local-')),filePath=path.join(dir,'inventory.sqlite'),store=createIocIntelligence({filePath});
 store.setState('axur-import-v1:owner',{status:importStatus,processed:4341526,lastSuccessfulAt:'2026-10-28T12:00:00.000Z'});
 const snapshots=[];t.after(()=>{for(const snapshot of snapshots)try{snapshot.close();}catch{}store.close();assert.ok(path.resolve(dir).startsWith(path.resolve(tmpdir())+path.sep+'bulk-local-'));fs.rmSync(dir,{recursive:true,force:true});});
 return {dir,store,open(){const snapshot=createBulkLocalSnapshot({filePath,spoolPath:path.join(dir,'contexts'),owner:'owner',now:()=>Date.parse('2026-10-28T18:00:00Z')});snapshots.push(snapshot);return snapshot;}};
}
const row=(value=query,ordinal=0)=>({serverOrdinal:ordinal,query:value,state:'running',contextLoading:true,context:{evidence:[],publications:[],errors:[]},result:{query:value,overallScore:0,threatLevel:'unknown',totalVendors:1,detections:0,vendorData:[{name:'Axur',data:{},isLoading:true}]}});

test('all imported IOC relations are available before remote API tasks finish, with private scope and dates preserved',async t=>{
 const f=fixture(t);await f.store.ingest([
  {value:query,provider:'Axur',scope:'owner',externalId:'own-report',title:'Private source report',link:'https://cti.axur.com/insight/own-report',published:'2023-09-18',actors:[{id:'APT28',name:'APT28'}],malwares:[{id:'Mirai',name:'Mirai'}],relation:'mentioned-with'},
  {value:query,provider:'Axur',scope:'other',externalId:'other-report',title:'Must stay private',actors:[{id:'OtherActor',name:'OtherActor'}]},
  {value:query,provider:'news',scope:'global',externalId:'article',title:'Article with IOC',link:'https://example.org/article',published:'2026-10-27'},
 ]);
 const snapshot=f.open(),input=row(),output=snapshot.enrich(input),a=analyzeBulkRow(output);
 assert.equal(input.context.evidence.length,0);assert.equal(output.state,'running');assert.equal(output.result.vendorData[0].isLoading,true);assert.equal(output.contextLoading,false);
 assert.equal(output.context.evidence.length,2);assert.equal(output.context.publications.length,2);assert.ok(!JSON.stringify(output).includes('OtherActor'));
 assert.equal(output.context.evidence.find(e=>e.provider==='Axur').published,'2023-09-18T00:00:00.000Z');assert.equal(a.record.axActors,'APT28');assert.equal(a.record.axMalware,'Mirai');assert.equal(a.record['status:Axur'],'Consultando');assert.equal(a.record.axLocalStatus,'1 evidência na base importada');assert.equal(a.actors.length,0);assert.equal(snapshot.stats().checked,1);assert.equal(snapshot.stats().axurMatches,1);
 snapshot.enrich(input);assert.equal(snapshot.stats().checked,1,'later worksheets reuse the same context instead of rereading the inventory');
});
test('a local absence is distinguished from a remote absence and partial imports stay identified',t=>{
 const f=fixture(t,'running'),snapshot=f.open(),output=snapshot.enrich(row());assert.equal(output.context.localSnapshot.axurEvidence,0);assert.equal(output.result.vendorData[0].isLoading,true);assert.equal(analyzeBulkRow(output).record.axLocalStatus,'Sem registro na parcela importada');assert.equal(snapshot.stats().axurMatches,0);
});
test('the source snapshot stays stable when new evidence arrives during worksheet generation',async t=>{
 const f=fixture(t),snapshot=f.open();await f.store.ingest([{value:query,provider:'Axur',scope:'owner',externalId:'new',title:'Arrived after the snapshot'}]);assert.equal(snapshot.enrich(row()).context.evidence.length,0);assert.equal(f.store.detail(query,'owner').total,1);
});
test('an unavailable configured inventory fails visibly rather than exporting false negative matches',()=>{
 assert.throws(()=>createBulkLocalSnapshot({filePath:path.join(tmpdir(),'missing-'+Date.now()+'.sqlite'),spoolPath:path.join(tmpdir(),'uncreated'),owner:'owner'}));assert.throws(()=>createBulkLocalSnapshot({filePath:'ignored',owner:'global'}));const legacy=createBulkLocalSnapshot();const input=row();assert.equal(legacy.enrich(input),input);
});
