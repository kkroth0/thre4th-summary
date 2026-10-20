// Bounded, read-only operational audit. Emit counts/timings/plans only;
// never indicator values, report content, credentials or encrypted user data.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
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
const providers=measure('provider-counts',()=>db.prepare('SELECT provider,COUNT(*) observations FROM observations WHERE scope IN (?,?) GROUP BY provider').all('global',owner));
const schema=db.prepare("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name IN ('observations','entity_links','indicators') AND sql IS NOT NULL").all();
const predicate="o.scope IN (?,?) AND o.provider<>'news'",args=['global',owner,'actor','G1024'];
const oldSql=`SELECT COUNT(*) count FROM observations o WHERE ${predicate} AND EXISTS(SELECT 1 FROM entity_links e WHERE e.observation=o.id AND e.kind=? AND e.entity=?)`;
const newSql=`SELECT COUNT(*) count FROM observations o WHERE ${predicate} AND o.id IN (SELECT observation FROM entity_links WHERE kind=? AND entity=?)`;
const plans={before:db.prepare('EXPLAIN QUERY PLAN '+oldSql).all(...args).map(row=>row.detail),after:db.prepare('EXPLAIN QUERY PLAN '+newSql).all(...args).map(row=>row.detail)};
const actorMatches=measure('indexed-actor-observation-count',()=>db.prepare(newSql).get(...args).count);
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
