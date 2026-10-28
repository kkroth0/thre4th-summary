import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,rmSync,readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createBulkStore,BULK_CONTEXT,createBulkRunner } from '../bulkJobs.js';
import { eligibleSources,composeBulkRow,prepareBulkInput,normalizeBulkVendor } from '../bulkShared.generated.mjs';
const owner={sub:'one',login:'analyst'},other={sub:'two',login:'other'};
const context={publications:[],evidence:[],errors:[]};
function fixture(){const dir=mkdtempSync(path.join(tmpdir(),'ts-bulk-'));let clock=1000;const file=path.join(dir,'jobs.sqlite');let store=createBulkStore({filePath:file,now:()=>clock,eligibleSources,composeRow:composeBulkRow});return{get store(){return store;},file,dir,advance(n){clock+=n;},reopen(){store.close();store=createBulkStore({filePath:file,now:()=>clock,eligibleSources,composeRow:composeBulkRow});},close(){store.close();assert.ok(path.resolve(dir).startsWith(path.resolve(tmpdir())+path.sep+'ts-bulk-'));rmSync(dir,{recursive:true,force:true});}};}
function finish(store){let t,n=0;while((t=store.claim())){store.settle(t,t.provider===BULK_CONTEXT?context:{name:t.provider,data:{Status:'Clean'},rawPayload:{value:t.query}});if(++n>100000)throw Error('Unexpected loop');}return n;}
test('jobs are idempotent, account isolated and filtered/paginated before full payloads are read',()=>{
 const f=fixture();try{const id=crypto.randomUUID(),j=f.store.create(owner,['8.8.8.8','example.org','https://example.org/A'],['VirusTotal'],{},id);assert.equal(f.store.create(owner,['8.8.8.8','example.org','https://example.org/A'],['VirusTotal'],{},id).id,j.id);assert.throws(()=>f.store.summary(other.sub,j.id),e=>e.status===404);assert.throws(()=>f.store.action(other.sub,j.id,'pause',other),e=>e.status===404);assert.equal(f.store.list(other.sub).length,0);assert.equal(f.store.page(owner.sub,j.id,{type:'url'}).total,1);assert.equal(f.store.page(owner.sub,j.id,{size:1}).load().length,1);assert.equal(f.store.page(owner.sub,j.id,{query:'%'}).total,0);}finally{f.close();}
});
test('restart retains successful results and only recovers an expired in-flight lease',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8'],['VirusTotal','AbuseIPDB']);const first=f.store.claim();f.store.settle(first,{name:first.provider,data:{Status:'Clean'},rawPayload:{preserved:'answer'}});const interrupted=f.store.claim();f.reopen();assert.equal(f.store.claim(),null);f.advance(120001);const recovered=f.store.claim();assert.equal(recovered.provider,interrupted.provider);assert.notEqual(recovered.lease,interrupted.lease);f.store.settle(interrupted,{name:'stale',data:{}});f.store.settle(recovered,{name:recovered.provider,data:{Status:'Clean'}});finish(f.store);const result=f.store.page(owner.sub,j.id,{}).load()[0];assert.equal(result.state,'complete');assert.ok(result.result.vendorData.every(v=>v.rawPayload===undefined));assert.ok(f.store.completeRow(owner.sub,j.id,0).result.vendorData.some(v=>v.rawPayload?.preserved==='answer'));assert.equal(f.store.summary(owner.sub,j.id).completed,1);}finally{f.close();}
});
test('quota cooldown persists and other providers continue without thousands of failed requests',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8','9.9.9.9'],['VirusTotal','AbuseIPDB']);const first=f.store.claim();f.store.settle(first,null,{status:429,retryAt:61000,message:'Quota'});const blocked=first.provider;let t,n=0;while((t=f.store.claim())){assert.notEqual(t.provider,blocked);f.store.settle(t,t.provider===BULK_CONTEXT?context:{name:t.provider,data:{}});n++;}assert.ok(n>0);f.reopen();assert.equal(f.store.claim(),null);f.advance(60001);const probe=f.store.claim();assert.equal(probe.provider,blocked);assert.equal(probe.ordinal,first.ordinal,'retry the blocked request before releasing the rest of the provider backlog');f.store.settle(probe,{name:blocked,data:{}});finish(f.store);assert.equal(f.store.summary(owner.sub,j.id).completed,2);}finally{f.close();}
});
test('HTTP 500 is retried with a provider circuit breaker; completed sources are retained',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8'],['URLhaus']);const t=f.store.claim();f.store.settle(t,null,{status:500,message:'Temporary error'});assert.equal(f.store.claim(),null);f.advance(15001);const retry=f.store.claim();assert.equal(retry.provider,'URLhaus');f.store.settle(retry,{name:'URLhaus',data:{Status:'No data'},rawPayload:{query_status:'no_results'}});finish(f.store);assert.equal(f.store.summary(owner.sub,j.id).partial,0);}finally{f.close();}
});
test('pausing survives restart and resuming preserves the completed provider response',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8','9.9.9.9'],['VirusTotal']);const t=f.store.claim();f.store.settle(t,{name:t.provider,data:{Status:'Clean'}});f.store.action(owner.sub,j.id,'pause',owner);f.reopen();assert.equal(f.store.summary(owner.sub,j.id).state,'paused');assert.equal(f.store.claim(),null);f.store.action(owner.sub,j.id,'resume',owner);finish(f.store);assert.equal(f.store.summary(owner.sub,j.id).completed,2);}finally{f.close();}
});
test('authentication needs attention and is never treated as a quota renewal',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8','9.9.9.9'],['VirusTotal']);const t=f.store.claim();f.store.settle(t,null,{status:403,code:'PROVIDER_AUTH_FAILED',message:'Revise a conexão'});finish(f.store);assert.equal(f.store.summary(owner.sub,j.id).state,'needs_attention');assert.equal(f.store.claim(),null);f.store.action(owner.sub,j.id,'retry',owner);finish(f.store);assert.equal(f.store.summary(owner.sub,j.id).completed,2);}finally{f.close();}
});
test('shared normalization preserves a source absence and independent malicious findings',()=>{
 const vt=normalizeBulkVendor('8.8.8.8','VirusTotal',{error:'Resource not found'},404);assert.equal(vt.data.Status,'No data');assert.equal(vt.rawPayload.httpStatus,404);const q=prepareBulkInput('8.8.8.8\n10.0.0.1\nexample.org');assert.equal(q.indicators.length,2);assert.equal(q.excluded.nonPublicIps,1);
});
test('runner limits concurrency, checks context after provider persistence and stops cleanly',async()=>{
 const f=fixture();let current=0,peak=0;const seen=new Set();try{
  const job=f.store.create(owner,['8.8.8.8','9.9.9.9','example.org'],['VirusTotal','ThreatFox']);
  const runner=createBulkRunner({store:f.store,concurrency:2,canRun:()=>true,lookup:async task=>{assert.ok(!seen.has(task.provider));seen.add(task.provider);peak=Math.max(peak,++current);await new Promise(r=>setTimeout(r,5));current--;seen.delete(task.provider);return{name:task.provider,data:{Status:'No data'},rawPayload:{indicator:task.query}};},readContext:async task=>{const pending=f.store.prepare("SELECT COUNT(*) n FROM bulk_tasks WHERE job=? AND ordinal=? AND provider!=? AND state!='done'").get(task.job,task.ordinal,BULK_CONTEXT).n;assert.equal(pending,0);return context;}});
  runner.start();try{const deadline=Date.now()+3000;while(f.store.summary(owner.sub,job.id).completed<3&&Date.now()<deadline)await new Promise(r=>setTimeout(r,10));assert.equal(f.store.summary(owner.sub,job.id).completed,3);assert.equal(peak,2);}finally{await runner.stop();}assert.equal(runner.active(),0);
 }finally{f.close();}
});
test('numeric account identifiers survive SQLite serialization',()=>{const f=fixture();try{const principal={sub:42,login:'numeric'},id=crypto.randomUUID();f.store.create(principal,['8.8.8.8'],['VirusTotal'],{},id);assert.equal(f.store.summary(42,id).total,1);assert.equal(f.store.create(principal,['8.8.8.8'],['VirusTotal'],{},id).id,id);}finally{f.close();}});
test('completed snapshots are reusable only by their owner and a refresh request reaches the provider task',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8'],['VirusTotal'],{},undefined,true),task=f.store.claim();assert.equal(task.fresh,1);f.store.settle(task,{name:'VirusTotal',data:{Status:'Clean'},rawPayload:{data:{data:{attributes:{last_analysis_stats:{malicious:0}}}}}});assert.equal(f.store.savedProvider(other.sub,'VirusTotal','8.8.8.8'),null);assert.equal(f.store.savedProvider(owner.sub,'AbuseIPDB','8.8.8.8'),null);assert.equal(f.store.savedProvider(owner.sub,'VirusTotal','9.9.9.9'),null);assert.equal(f.store.savedProvider(owner.sub,'VirusTotal','8.8.8.8').vendor.rawPayload.data.data.attributes.last_analysis_stats.malicious,0);assert.equal(f.store.summary(owner.sub,j.id).refreshSources,true);}finally{f.close();}
});

test('adding Axur backfills the active batch without redoing or deleting completed provider results',()=>{
 const f=fixture();try{
  const j=f.store.create(owner,['8.8.8.8','9.9.9.9'],['VirusTotal']);finish(f.store);
  // Completed batches retain their original scope; only ongoing work migrates.
  assert.equal(f.store.ensureSources(owner.sub,j.id,['Axur']),false);
  f.store.prepare("UPDATE bulk_jobs SET state='active' WHERE id=?").run(j.id);
  assert.throws(()=>f.store.ensureSources(other.sub,j.id,['Axur']),e=>e.status===404);
  assert.equal(f.store.ensureSources(owner.sub,j.id,['Axur']),true);
  assert.equal(f.store.ensureSources(owner.sub,j.id,['Axur']),false);
  const before=f.store.completeRow(owner.sub,j.id,0);assert.ok(before.result.vendorData.find(v=>v.name==='VirusTotal').rawPayload);
  assert.equal(before.contextLoading,true);assert.equal(before.result.vendorData.find(v=>v.name==='Axur').isLoading,true);
  const providers=[];let t;while((t=f.store.claim())){providers.push(t.provider);f.store.settle(t,t.provider===BULK_CONTEXT?context:{name:t.provider,data:{'Registros Axur':0}});}
  assert.deepEqual(providers.sort(),['@context','@context','Axur','Axur']);assert.equal(f.store.summary(owner.sub,j.id).completed,2);assert.deepEqual(f.store.summary(owner.sub,j.id).sources,['VirusTotal','Axur']);
 }finally{f.close();}
});

test('an Axur request has a longer lease and is not duplicated by the normal two-minute recovery',()=>{
 const f=fixture();try{const j=f.store.create(owner,['8.8.8.8'],['Axur']);const task=f.store.claim();assert.equal(task.provider,'Axur');f.advance(120001);assert.equal(f.store.claim(),null);f.advance(480001);assert.equal(f.store.claim().provider,'Axur');assert.equal(f.store.summary(owner.sub,j.id).sources[0],'Axur');}finally{f.close();}
});
