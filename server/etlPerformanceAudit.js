// Read-only progress and final snapshot integrity. No API calls or IOC values.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {gunzipSync} from 'node:zlib';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);
if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');
const job='59aa9475-3acd-4b38-9fc4-a2d9d91e29cb',provider='AlienVault OTX';
if(!db.prepare('SELECT 1 FROM bulk_jobs WHERE id=? AND owner=?').get(job,owner))throw Error('Batch unavailable');
const counts=db.prepare("SELECT COUNT(*) total,SUM(state='done') completed,SUM(state IN ('pending','waiting','running')) pending,SUM(state='error') errors,SUM(state='blocked') blocked,SUM(state='unsupported') unsupported,SUM(state='running') active FROM bulk_tasks WHERE job=? AND provider=?");
const kinds=db.prepare("SELECT i.kind,t.state,COUNT(*) count FROM bulk_tasks t JOIN bulk_items i ON i.job=t.job AND i.ordinal=t.ordinal WHERE t.job=? AND t.provider=? GROUP BY i.kind,t.state");
const snapshots=[];
const samples=process.argv[4]==='checkpoint'?1:8;
for(let i=0;i<samples;i++){
 const started=performance.now(),values=counts.get(job,provider),snapshot={at:new Date().toISOString(),readOnly:true,...values,progressQueryMs:Math.round(performance.now()-started)};snapshots.push(snapshot);console.log(JSON.stringify(snapshot));
 if(!snapshot.pending||i===samples-1)break;
 await new Promise(resolve=>setTimeout(resolve,15000));
}
const final=counts.get(job,provider),summary={at:new Date().toISOString(),readOnly:true,source:provider,...final,byKind:kinds.all(job,provider),unavailableIPs:db.prepare("SELECT COUNT(*) count FROM bulk_items i WHERE i.job=? AND i.kind='ip' AND NOT EXISTS(SELECT 1 FROM bulk_tasks t WHERE t.job=i.job AND t.ordinal=i.ordinal AND t.provider=?)").get(job,provider).count,savedResponsesPreserved:final.completed>=snapshots[0].completed};
summary.queryPlan=db.prepare("EXPLAIN QUERY PLAN SELECT COUNT(*),SUM(state='done') FROM bulk_tasks WHERE job=? AND provider=?").all(job,provider).map(v=>v.detail);
if(final.completed===final.total&&!final.pending&&!final.errors&&!final.blocked){
 let responses=0,raw=0,dated=0,withPulses=0,pulses=0,invalid=0;
 for(const row of db.prepare("SELECT value FROM bulk_tasks WHERE job=? AND provider=? AND state='done'").iterate(job,provider)){
  const v=JSON.parse(gunzipSync(row.value,{maxOutputLength:64*1024*1024}).toString());responses++;
  if(v.rawPayload&&typeof v.rawPayload==='object')raw++;
  if(v.collectedAt&&Number.isFinite(Date.parse(v.collectedAt)))dated++;
  const n=parseInt(String(v.data?.['Pulse Count']||''),10);if(n>0){withPulses++;pulses+=n;}
  if(v.name!==provider||v.error||v.isLoading||!v.data)invalid++;
 }
 summary.integrity={responses,raw,dated,withPulses,pulseReferences:pulses,invalid};
}
console.log(JSON.stringify(summary));db.close();
