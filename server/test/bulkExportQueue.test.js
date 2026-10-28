import test from 'node:test';
import assert from 'node:assert/strict';
import {createBulkStore,BULK_CONTEXT} from '../bulkJobs.js';
import {releaseCompletedBulkExports} from '../bulkExportQueue.js';
import {eligibleSources,composeBulkRow} from '../bulkShared.generated.mjs';

test('a requested full export stays queued through quota waits and partial results, then uses the final revision',()=>{
 const store=createBulkStore({filePath:':memory:',eligibleSources,composeRow:composeBulkRow}),owner={sub:'owner',login:'analyst'};
 try{
  const job=store.create(owner,['8.8.8.8'],['VirusTotal']);
  store.prepare("INSERT INTO bulk_exports(id,job,owner,state,created,updated,revision,filters) VALUES(?,?,?,'awaiting_completion',1,1,1,?)").run('full',job.id,owner.sub,JSON.stringify({waitForComplete:true}));
  assert.equal(releaseCompletedBulkExports(store,10),0);
  let task=store.claim();store.settle(task,null,{status:429,retryAt:Date.now()+100000,message:'Quota'});
  assert.equal(releaseCompletedBulkExports(store,20),0);
  store.prepare("UPDATE bulk_jobs SET state='partial' WHERE id=?").run(job.id);
  assert.equal(releaseCompletedBulkExports(store,30),0);
  store.prepare("UPDATE bulk_jobs SET state='active' WHERE id=?").run(job.id);store.prepare('DELETE FROM bulk_blocks').run();store.prepare('UPDATE bulk_tasks SET next_at=0').run();
  while((task=store.claim()))store.settle(task,task.provider===BULK_CONTEXT?{errors:[],publications:[],evidence:[]}:{name:task.provider,data:{Status:'No data'}});
  assert.equal(store.summary(owner.sub,job.id).state,'complete');assert.equal(releaseCompletedBulkExports(store,40),1);
  const queued=store.prepare('SELECT * FROM bulk_exports WHERE id=?').get('full');assert.equal(queued.state,'pending');assert.equal(queued.revision,store.owned(owner.sub,job.id).revision);assert.equal(queued.updated,40);assert.equal(releaseCompletedBulkExports(store,50),0);
 }finally{store.close();}
});
