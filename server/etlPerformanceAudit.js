// Bounded, read-only operational audit. Emit counts/timings/plans only;
// never indicator values, report content, credentials or encrypted user data.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
const root=path.resolve(process.argv[2] || process.cwd()),login=String(process.argv[3] || '').toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw new Error('Expected GitHub login');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8'));
const owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw new Error('Account not found');
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const file=path.join(root,'server/.ioc-intelligence.sqlite'),db=new Database(file,{readonly:true,fileMustExist:true});
db.pragma('query_only = ON');db.pragma('busy_timeout = 1000');
const measurements=[];
const measure=(name,fn)=>{const start=performance.now();const value=fn();measurements.push({name,ms:Math.round((performance.now()-start)*100)/100});return value;};
const state=key=>{const row=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(key);return row?JSON.parse(row.value):null;};
// Frequent import checks must not scan hundreds of thousands of observations.
if(process.argv[4]==='checkpoint'){
  const processes=[];
  if(process.platform==='linux')for(const pid of fs.readdirSync('/proc').filter(name=>/^\d+$/.test(name))){
    try{
      if(!fs.readFileSync(`/proc/${pid}/cmdline`,'utf8').includes('index.js')||fs.realpathSync(`/proc/${pid}/cwd`)!==path.join(root,'server'))continue;
      const threads=fs.readdirSync(`/proc/${pid}/task`).map(tid=>{
        try{const raw=fs.readFileSync(`/proc/${pid}/task/${tid}/stat`,'utf8'),fields=raw.slice(raw.lastIndexOf(')')+2).split(' ');
          return {tid:Number(tid),name:fs.readFileSync(`/proc/${pid}/task/${tid}/comm`,'utf8').trim(),state:fields[0],cpuTicks:Number(fields[11])+Number(fields[12]),majorFaults:Number(fields[9]),wait:fs.readFileSync(`/proc/${pid}/task/${tid}/wchan`,'utf8').trim()};}catch{return null;}
      }).filter(Boolean);
      const status=fs.readFileSync(`/proc/${pid}/status`,'utf8');
      const memory=Object.fromEntries(status.split('\n').filter(line=>/^(VmRSS|VmSwap|VmSize):/.test(line)).map(line=>line.split(/:\s*/)));
      const group=fs.readFileSync(`/proc/${pid}/cgroup`,'utf8').split('\n').find(line=>line.startsWith('0::'))?.slice(3);
      const limits={};
      if(group)for(const name of ['memory.current','memory.max','memory.high','memory.swap.current','memory.swap.max','memory.events','io.stat']){
        try{limits[name]=fs.readFileSync(path.join('/sys/fs/cgroup',group,name),'utf8').trim();}catch{/* optional kernel controller */}
      }
      processes.push({pid:Number(pid),memory,limits,threads});
    }catch{/* process may exit during inspection */}
  }
  console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,indexReady:Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE name='observations_inventory'").get()),processes,axur:state(`axur-import-v1:${owner}`)},null,2));
  db.close();process.exit(0);
}
if(process.argv[4]==='ui'){
  const indexReady=Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='index' AND name='observations_inventory'").get());
  const checkpoint=state(`axur-import-v1:${owner}`);
  db.close();
  const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js')));
  const env=parse(fs.readFileSync(path.join(root,'.env')));
  if(!env.SESSION_SECRET)throw Error('Session configuration unavailable');
  // Short-lived signature for this existing account, retained only in memory.
  // No credentials, response content or signed token are emitted by the audit.
  const body=Buffer.from(JSON.stringify({sub:owner,login,exp:Math.floor(Date.now()/1000)+240})).toString('base64url');
  const signature=crypto.createHmac('sha256',env.SESSION_SECRET).update(body).digest('base64url');
  const headers={Cookie:`ts_session=${body}.${signature}`};
  const http=[];
  async function probe(endpoint,extra={}){
    const start=performance.now();
    try{
      const response=await fetch(`http://127.0.0.1:3001${endpoint}`,{headers:{...headers,...extra},signal:AbortSignal.timeout(20000)});
      const payload=await response.arrayBuffer();
      http.push({endpoint,conditional:Boolean(extra['If-None-Match']),status:response.status,ms:Math.round(performance.now()-start),bytes:payload.byteLength});
      return response.headers.get('etag');
    }catch{http.push({endpoint,status:'timeout-or-unavailable',ms:Math.round(performance.now()-start)});}
  }
  await probe('/api/actors?catalogOnly=1');
  await probe('/api/actors');
  await probe('/api/actors');
  await probe('/api/actors/G1024');
  const etag=await probe('/api/newsletter');
  if(etag)await probe('/api/newsletter',{'If-None-Match':etag});
  // The health probe should remain responsive while a heavier aggregation runs.
  await Promise.all([probe('/api/actors/activity'),probe('/api/auth/me')]);
  await probe('/api/intelligence/iocs?size=20');
  await probe('/api/intelligence/iocs?size=20');
  console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,indexReady,host:{cpus:os.cpus().length,loadAverage:os.loadavg(),memoryBytes:os.totalmem(),freeMemoryBytes:os.freemem()},axur:checkpoint,http},null,2));
  process.exit(0);
}
const providers=measure('provider-counts',()=>db.prepare('SELECT provider,COUNT(*) observations FROM observations WHERE scope IN (?,?) GROUP BY provider').all('global',owner));
const schema=db.prepare("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name IN ('observations','entity_links','indicators') AND sql IS NOT NULL").all();
const predicate="o.scope IN (?,?) AND o.provider<>'news'",args=['global',owner,'actor','G1024'];
const oldSql=`SELECT COUNT(*) count FROM observations o WHERE ${predicate} AND EXISTS(SELECT 1 FROM entity_links e WHERE e.observation=o.id AND e.kind=? AND e.entity=?)`;
const newSql=`SELECT COUNT(*) count FROM observations o WHERE ${predicate} AND o.id IN (SELECT observation FROM entity_links WHERE kind=? AND entity=?)`;
const forcedSql=newSql.replace('observations o WHERE','observations o INDEXED BY sqlite_autoindex_observations_1 WHERE');
const plans={before:db.prepare('EXPLAIN QUERY PLAN '+oldSql).all(...args).map(row=>row.detail),filtered:db.prepare('EXPLAIN QUERY PLAN '+newSql).all(...args).map(row=>row.detail),after:db.prepare('EXPLAIN QUERY PLAN '+forcedSql).all(...args).map(row=>row.detail)};
const actorMatches=measure('primary-key-actor-observation-count',()=>db.prepare(forcedSql).get(...args).count);
const stat=file=>{try{return fs.statSync(file).size;}catch{return 0;}};
const disk=fs.statfsSync(path.dirname(file));
const axur=state(`axur-import-v1:${owner}`);
const news=state('news-current-cycle'),sync=state('news-sync');
const aliasRevisions=measure('actor-alias-revision-count',()=>db.prepare("SELECT COUNT(*) count FROM intelligence_state WHERE id LIKE 'actor-aliases-v1:%'").get().count);
const reportCaches=measure('axur-insight-cache-count',()=>db.prepare('SELECT COUNT(*) count FROM intelligence_state WHERE id LIKE ?').get(`axur-report-v1:${owner}:%`).count);
db.close();
const http=[];
for(const endpoint of ['/api/vendors/status','/api/actors/G1024']){
  const start=performance.now();
  try{const response=await fetch(`http://127.0.0.1:3001${endpoint}`,{signal:AbortSignal.timeout(20000)});const body=await response.arrayBuffer();http.push({endpoint,status:response.status,ms:Math.round(performance.now()-start),bytes:body.byteLength});}
  catch{http.push({endpoint,status:'timeout-or-unavailable',ms:Math.round(performance.now()-start)});}
}
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,host:{cpus:os.cpus().length,loadAverage:os.loadavg(),memoryBytes:os.totalmem(),freeMemoryBytes:os.freemem(),freeDiskBytes:disk.bavail*disk.bsize},
  storage:{databaseBytes:stat(file),walBytes:stat(file+'-wal'),shmBytes:stat(file+'-shm')},providers,measurements,plans,actorMatches,aliasRevisions,reportCaches,
  axur,news:news?{phase:news.phase,startedAt:news.startedAt,updatedAt:news.updatedAt,stages:news.stages,memory:news.memory}:null,newsSync:sync,http,schema},null,2));
