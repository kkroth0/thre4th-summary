// Repairs only this account's saved application job. No upstream calls, writes, quota resets or duplicate exports.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
if(!fs.existsSync(path.join(root,'server/upstreamErrors.js'))||!fs.readFileSync(path.join(root,'server/index.js'),'utf8').includes('PROVIDER_QUERY_UNSUPPORTED'))throw Error('Wait for the complete-enrichment deployment');
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
 const workbook=store.prepare("SELECT id,state FROM bulk_exports WHERE owner=? AND job=? AND id=?").get(owner,jobId,'fadfbdc6-61b9-4396-8d53-6dbc0c79ff52');if(!workbook)throw Error('Previously queued complete export missing');
 console.log(JSON.stringify({at:new Date().toISOString(),applicationJobUpdated:true,upstreamWrites:false,quotaWaitingPreserved:true,savedResponsesPreserved:true,jobState:after.state,liveRefresh:after.refreshSources,completeWorkbook:workbook,sources:after.sourceCounts},null,2));
}finally{store.close();}
