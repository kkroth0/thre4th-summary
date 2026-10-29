// Repairs only this account's saved application job. No upstream writes or quota resets.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
if(!fs.existsSync(path.join(root,'server/bulkExportQueue.js'))||!fs.readFileSync(path.join(root,'server/index.js'),'utf8').includes('completedInventory:true'))throw Error('Wait for the complete-enrichment deployment');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {createBulkStore}=await import(pathToFileURL(path.join(root,'server/bulkJobs.js'))),{eligibleSources,composeBulkRow,THREAT_VERDICT_VERSION}=await import(pathToFileURL(path.join(root,'server/bulkShared.generated.mjs')));
const store=createBulkStore({filePath:env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),eligibleSources,composeRow:composeBulkRow}),jobId='59aa9475-3acd-4b38-9fc4-a2d9d91e29cb';
try{
 const before=store.summary(owner,jobId),quotaBefore=store.prepare("SELECT provider,until_at FROM bulk_blocks WHERE owner=? AND reason='quota' ORDER BY provider").all(owner),principal={sub:owner,login:users[owner].login};
 const after=store.action(owner,jobId,'retry',principal);
 if(after.refreshSources)throw Error('This job still requests live refresh; review the requested Axur inventory mode');
 const quotaAfter=store.prepare("SELECT provider,until_at FROM bulk_blocks WHERE owner=? AND reason='quota' ORDER BY provider").all(owner);
 if(JSON.stringify(quotaBefore)!==JSON.stringify(quotaAfter))throw Error('Unexpected quota change');
 if(before.sourceCounts.some(source=>(after.sourceCounts.find(row=>row.provider===source.provider)?.completed||0)<source.completed))throw Error('Saved response count decreased');
 const filters=JSON.stringify({query:'',type:'all',state:'all',verdictVersion:THREAT_VERDICT_VERSION,localSnapshotVersion:'2026-10-28-v1',waitForComplete:true}),existing=store.prepare("SELECT id,state FROM bulk_exports WHERE owner=? AND job=? AND filters=? AND state IN ('awaiting_completion','pending','running','complete') ORDER BY created DESC LIMIT 1").get(owner,jobId,filters);
 let workbook=existing;
 if(!workbook){const id=crypto.randomUUID(),at=Date.now(),state=after.state==='complete'?'pending':'awaiting_completion';store.prepare('INSERT INTO bulk_exports(id,job,owner,state,created,updated,revision,filters) VALUES(?,?,?,?,?,?,?,?)').run(id,jobId,owner,state,at,at,after.revision,filters);workbook={id,state};}
 console.log(JSON.stringify({at:new Date().toISOString(),applicationJobUpdated:true,upstreamWrites:false,quotaWaitingPreserved:true,savedResponsesPreserved:true,jobState:after.state,liveRefresh:after.refreshSources,completeWorkbook:workbook,sources:after.sourceCounts},null,2));
}finally{store.close();}
