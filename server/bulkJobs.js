import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { detectQueryType } from './iocValidation.js';

const pack=value=>value==null?null:gzipSync(Buffer.from(JSON.stringify(value)),{level:3});
const unpack=value=>value?JSON.parse(gunzipSync(value,{maxOutputLength:64*1024*1024}).toString()):null;
const fail=(message,status=400)=>Object.assign(Error(message),{status});
const terminal=new Set(['done','error','blocked']);
export const BULK_CONTEXT='@context';

/** Account-scoped operation ledger. No session cookies or API keys are stored here. */
export function createBulkStore({filePath,now=Date.now,eligibleSources,composeRow,readOnly=false}={}){
 if(filePath!==':memory:')fs.mkdirSync(path.dirname(filePath),{recursive:true});
 const db=new Database(filePath,readOnly?{readonly:true,fileMustExist:true}:{});if(!readOnly)db.pragma('journal_mode=WAL');db.pragma('busy_timeout=5000');db.pragma('cache_size=-4000');
 if(!readOnly)db.exec(`CREATE TABLE IF NOT EXISTS bulk_jobs(id TEXT PRIMARY KEY,owner TEXT NOT NULL,login TEXT NOT NULL,org_until INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,total INTEGER NOT NULL,sources TEXT NOT NULL,excluded TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,fingerprint TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS bulk_owner ON bulk_jobs(owner,created DESC);
 CREATE TABLE IF NOT EXISTS bulk_items(job TEXT NOT NULL,ordinal INTEGER NOT NULL,query TEXT NOT NULL,kind TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',context BLOB,context_error TEXT,completed INTEGER,version INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(job,ordinal),UNIQUE(job,query));
 CREATE INDEX IF NOT EXISTS bulk_item_page ON bulk_items(job,state,ordinal);
 CREATE TABLE IF NOT EXISTS bulk_tasks(job TEXT NOT NULL,ordinal INTEGER NOT NULL,provider TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_at INTEGER NOT NULL DEFAULT 0,lease_until INTEGER NOT NULL DEFAULT 0,lease TEXT,value BLOB,error TEXT,http_status INTEGER,error_code TEXT,updated INTEGER NOT NULL,PRIMARY KEY(job,ordinal,provider));
 CREATE INDEX IF NOT EXISTS bulk_due ON bulk_tasks(state,next_at,lease_until);
 CREATE INDEX IF NOT EXISTS bulk_dispatch ON bulk_tasks(state,next_at,updated,job,ordinal,provider);
 CREATE TABLE IF NOT EXISTS bulk_blocks(owner TEXT NOT NULL,provider TEXT NOT NULL,until_at INTEGER NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(owner,provider));
 CREATE TABLE IF NOT EXISTS bulk_exports(id TEXT PRIMARY KEY,job TEXT NOT NULL,owner TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',created INTEGER NOT NULL,updated INTEGER NOT NULL,file TEXT,error TEXT,revision INTEGER NOT NULL,filters TEXT NOT NULL DEFAULT '{}');
 CREATE INDEX IF NOT EXISTS bulk_export_owner ON bulk_exports(owner,job,created DESC);`);
 const statements=new Map(),nativePrepare=db.prepare.bind(db);
 const sql=text=>{let statement=statements.get(text);if(!statement){statement=nativePrepare(text);statements.set(text,statement);}return statement;};
 const getJob=id=>sql('SELECT * FROM bulk_jobs WHERE id=?').get(id);
 function owned(owner,id){const j=getJob(id);if(!j||j.owner!==String(owner))throw fail('Lote não encontrado.',404);return j;}
 const touch=id=>sql('UPDATE bulk_jobs SET updated=?,revision=revision+1 WHERE id=?').run(now(),id);
 function selection(id,{query='',type='all',state='all'}={}){const clauses=['job=?'],params=[id];if(query){clauses.push("query LIKE ? ESCAPE '\\'");params.push('%'+String(query).replace(/[\\%_]/g,'\\$&')+'%');}if(type!=='all'){clauses.push('kind=?');params.push(type);}if(state!=='all'){clauses.push('state=?');params.push(state);}return{where:clauses.join(' AND '),params};}
 const items=(id,filters={})=>{const {where,params}=selection(id,filters);return sql('SELECT * FROM bulk_items WHERE '+where+' ORDER BY ordinal').iterate(...params);};
 function publicSummary(j){
  const counts=Object.fromEntries(sql('SELECT state,COUNT(*) n FROM bulk_items WHERE job=? GROUP BY state').all(j.id).map(r=>[r.state,r.n]));
  const sourceCounts=sql(`SELECT provider,SUM(state='done') completed,SUM(state='error') errors,SUM(state='blocked') blocked,SUM(state IN ('pending','waiting','running')) pending,COUNT(*) total FROM bulk_tasks WHERE job=? AND provider!=? GROUP BY provider`).all(j.id,BULK_CONTEXT);
  const waiting=sql(`SELECT MIN(MAX(t.next_at,COALESCE(b.until_at,0))) next FROM bulk_tasks t JOIN bulk_jobs j ON j.id=t.job LEFT JOIN bulk_blocks b ON b.owner=j.owner AND b.provider=t.provider WHERE t.job=? AND t.state IN ('pending','waiting')`).get(j.id).next;
  const active=sql("SELECT COUNT(*) n FROM bulk_tasks t JOIN bulk_jobs j ON j.id=t.job LEFT JOIN bulk_blocks b ON b.owner=j.owner AND b.provider=t.provider WHERE t.job=? AND (t.state='running' OR (t.state IN ('pending','waiting') AND t.next_at<=? AND COALESCE(b.until_at,0)<=?))").get(j.id,now(),now()).n;
  return{id:j.id,state:j.state==='active'?(!active&&sourceCounts.some(s=>s.blocked)?'needs_attention':waiting>now()&&!active?'waiting':'running'):j.state,total:j.total,processed:(counts.complete||0)+(counts.partial||0)+(counts.error||0)+(counts.unsupported||0),completed:counts.complete||0,partial:counts.partial||0,failed:counts.error||0,pending:(counts.queued||0)+(counts.running||0),sources:JSON.parse(j.sources),sourceCounts,excluded:JSON.parse(j.excluded),createdAt:new Date(j.created).toISOString(),updatedAt:new Date(j.updated).toISOString(),revision:j.revision,retryAt:waiting>now()&&waiting<Number.MAX_SAFE_INTEGER?waiting:null,exports:sql('SELECT id,state,created,updated,error,revision FROM bulk_exports WHERE job=? AND owner=? ORDER BY created DESC LIMIT 5').all(j.id,j.owner)};
 }
 function row(j,item,compact=false){
  const tasks=sql('SELECT * FROM bulk_tasks WHERE job=? AND ordinal=? ORDER BY provider').all(j.id,item.ordinal);
  const data=tasks.filter(t=>t.provider!==BULK_CONTEXT).map(t=>t.state==='done'?unpack(t.value):({name:t.provider,data:{...(t.next_at>now()?{'Próxima tentativa':new Date(t.next_at).toISOString()}:{})},...(t.error?{error:t.error,httpStatus:t.http_status,errorCode:t.error_code,retryAt:t.next_at||undefined}:{isLoading:true})}));
  let context=unpack(item.context)||{publications:[],evidence:[],errors:item.context_error?[item.context_error]:[]};
  if(compact){for(const v of data){delete v.rawPayload;v.rawDeferred=true;}context={...context,evidence:context.evidence.map(({payload,reputation,...e})=>e)};}
  return {...composeRow(item.query,data,context,item.state,item.completed?new Date(item.completed).toISOString():undefined),contextLoading:!terminal.has(tasks.find(t=>t.provider===BULK_CONTEXT)?.state),serverOrdinal:item.ordinal,serverVersion:item.version};
 }
 function refreshItem(job,ordinal){
  const ts=sql('SELECT provider,state FROM bulk_tasks WHERE job=? AND ordinal=?').all(job,ordinal),sources=ts.filter(t=>t.provider!==BULK_CONTEXT),ctx=ts.find(t=>t.provider===BULK_CONTEXT);
  const allSources=sources.every(t=>terminal.has(t.state));
  if(allSources&&ctx?.state==='held')sql("UPDATE bulk_tasks SET state='pending',next_at=0 WHERE job=? AND ordinal=? AND provider=?").run(job,ordinal,BULK_CONTEXT);
  const finished=allSources&&terminal.has(ctx?.state),good=sources.filter(t=>t.state==='done').length;
  const state=finished?(!sources.length?'unsupported':good===sources.length&&ctx.state==='done'?'complete':good?'partial':'error'):sources.some(t=>t.state!=='pending')?'running':'queued';
  sql('UPDATE bulk_items SET state=?,completed=?,version=version+1 WHERE job=? AND ordinal=?').run(state,finished?now():null,job,ordinal);touch(job);
  const pending=sql("SELECT COUNT(*) n FROM bulk_items WHERE job=? AND state IN ('queued','running')").get(job).n;
  if(!pending)sql("UPDATE bulk_jobs SET state=CASE WHEN EXISTS(SELECT 1 FROM bulk_items WHERE job=? AND state!='complete') THEN 'partial' ELSE 'complete' END WHERE id=? AND state='active'").run(job,job);
 }
 const create=db.transaction((principal,queries,sources,excluded={},requestId)=>{
  const fingerprint=crypto.createHash('sha256').update(JSON.stringify([queries,sources])).digest('hex');
  if(requestId){if(!/^[0-9a-f-]{36}$/i.test(requestId))throw fail('Identificador de solicitação inválido.');const existing=getJob(requestId);if(existing){if(existing.owner!==String(principal.sub)||existing.fingerprint!==fingerprint)throw fail('Solicitação já utilizada.',409);return publicSummary(existing);}}
  if(sql("SELECT COUNT(*) n FROM bulk_jobs WHERE owner=? AND state IN ('active','paused')").get(String(principal.sub)).n>=2)throw fail('Já há dois lotes em andamento. Conclua ou encerre um deles antes de criar outro.',409);
  if(!Array.isArray(queries)||queries.length<1||queries.length>10000)throw fail('Use entre 1 e 10.000 indicadores únicos.');
  const id=requestId||crypto.randomUUID(),at=now();
  sql('INSERT INTO bulk_jobs(id,owner,login,org_until,state,created,updated,total,sources,excluded,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(id,String(principal.sub),principal.login,principal.premiumViaOrg?principal.exp*1000:0,'active',at,at,queries.length,JSON.stringify(sources),JSON.stringify(excluded),fingerprint);
  const putItem=sql('INSERT INTO bulk_items(job,ordinal,query,kind) VALUES(?,?,?,?)'),putTask=sql('INSERT INTO bulk_tasks(job,ordinal,provider,state,updated) VALUES(?,?,?,?,?)');
  for(const [i,query]of queries.entries()){
   const eligible=eligibleSources(query,sources);putItem.run(id,i,query,detectQueryType(query));
   for(const provider of eligible)putTask.run(id,i,provider,'pending',at);
   putTask.run(id,i,BULK_CONTEXT,eligible.length?'held':'pending',at);
  }
  return publicSummary(getJob(id));
 });
 function page(owner,id,{page=1,size=20,query='',type='all',state='all'}={}){
  const j=owned(owner,id);page=Math.max(1,Number(page)||1);size=Math.min(100,Math.max(1,Number(size)||20));
  const {where,params}=selection(id,{query,type,state}),total=sql('SELECT COUNT(*) n FROM bulk_items WHERE '+where).get(...params).n;
  page=Math.min(page,Math.max(1,Math.ceil(total/size)));const selected=sql(`SELECT * FROM bulk_items WHERE ${where} ORDER BY ordinal LIMIT ? OFFSET ?`).all(...params,size,(page-1)*size);
  return{total,page,size,revision:selected.map(x=>x.ordinal+':'+x.version).join(','),load:()=>selected.map(item=>row(j,item,true))};
 }
 const dispatchStatements=new Map();
 const claim=db.transaction((excludedProviders=[])=>{
  sql("UPDATE bulk_tasks SET state='waiting',lease=NULL,lease_until=0,next_at=? WHERE state='running' AND lease_until<=?").run(now(),now());
  const clause=excludedProviders.length?` AND t.provider NOT IN (${excludedProviders.map(()=>'?').join(',')})`:'';
  const key=excludedProviders.join('|');let select=dispatchStatements.get(key);if(!select){select=sql(`SELECT t.*,j.owner,j.login,j.org_until,i.query FROM bulk_tasks t INDEXED BY bulk_dispatch JOIN bulk_jobs j ON j.id=t.job JOIN bulk_items i ON i.job=t.job AND i.ordinal=t.ordinal LEFT JOIN bulk_blocks b ON b.owner=j.owner AND b.provider=t.provider WHERE t.state=? AND j.state='active' AND t.next_at<=? AND COALESCE(b.until_at,0)<=? ${clause} ORDER BY t.next_at,t.updated,t.job,t.ordinal,t.provider LIMIT 1`);dispatchStatements.set(key,select);}
  const t=select.get('waiting',now(),now(),...excludedProviders)||select.get('pending',now(),now(),...excludedProviders);
  if(!t)return null;const lease=crypto.randomUUID();
  sql("UPDATE bulk_tasks SET state='running',lease=?,lease_until=?,attempts=attempts+1,updated=? WHERE job=? AND ordinal=? AND provider=?").run(lease,now()+120000,now(),t.job,t.ordinal,t.provider);
  sql("UPDATE bulk_items SET state='running',version=version+1 WHERE job=? AND ordinal=?").run(t.job,t.ordinal);touch(t.job);return{...t,lease,attempts:t.attempts+1};
 });
 const settle=db.transaction((t,value,error)=>{
  if(!sql("SELECT 1 FROM bulk_tasks WHERE job=? AND ordinal=? AND provider=? AND lease=? AND state='running'").get(t.job,t.ordinal,t.provider,t.lease))return;
  let state='done',next=0,message=null,status=null,code=null;
  if(error){status=Number(error.status||error.httpStatus||0);code=error.code||null;message=String(error.message||'Consulta temporariamente indisponível.').slice(0,350);
   const auth=code==='PROVIDER_AUTH_FAILED'||[401,403].includes(status),transient=[0,408,429,500,502,503,504].includes(status);
   state=auth?'blocked':status===429||transient&&t.attempts<5?'waiting':'error';next=state==='waiting'?Math.max(now()+1000,Number(error.retryAt)||now()+Math.min(15*60000,15000*2**Math.min(t.attempts-1,6))):0;
   if(status===429||auth||state==='waiting'&&transient&&t.provider!==BULK_CONTEXT)sql('INSERT OR REPLACE INTO bulk_blocks VALUES(?,?,?,?)').run(t.owner,t.provider,auth?Number.MAX_SAFE_INTEGER:next,auth?'authentication':status===429?'quota':'temporary');
  }
  sql('UPDATE bulk_tasks SET state=?,next_at=?,lease=NULL,lease_until=0,value=?,error=?,http_status=?,error_code=?,updated=? WHERE job=? AND ordinal=? AND provider=?').run(state,next,error?null:pack(value),message,status,code,now(),t.job,t.ordinal,t.provider);
  if(t.provider===BULK_CONTEXT)sql('UPDATE bulk_items SET context=?,context_error=? WHERE job=? AND ordinal=?').run(error?null:pack(value),error?message:null,t.job,t.ordinal);
  refreshItem(t.job,t.ordinal);
 });
 return{db,prepare:sql,create,claim,settle,page,owned,row,items,
  summary:(owner,id)=>publicSummary(owned(owner,id)),list:owner=>sql('SELECT * FROM bulk_jobs WHERE owner=? ORDER BY created DESC LIMIT 20').all(owner).map(publicSummary),
  action(owner,id,action,principal){const j=owned(owner,id);if(!['pause','resume','retry','cancel'].includes(action))throw fail('Ação inválida.');
   if(action==='pause'||action==='cancel'){sql('UPDATE bulk_jobs SET state=? WHERE id=?').run(action==='pause'?'paused':'canceled',id);touch(id);return publicSummary(getJob(id));}
   db.transaction(()=>{sql("UPDATE bulk_jobs SET state='active',login=?,org_until=? WHERE id=?").run(principal.login,principal.premiumViaOrg?principal.exp*1000:0,id);
    sql("DELETE FROM bulk_blocks WHERE owner=? AND reason='authentication'").run(owner);
    if(action==='retry')sql("UPDATE bulk_tasks SET state='pending',attempts=0,next_at=0,error=NULL,http_status=NULL,error_code=NULL WHERE job=? AND state IN ('error','blocked')").run(id);
    else sql("UPDATE bulk_tasks SET state='pending',attempts=0,next_at=0 WHERE job=? AND state='blocked'").run(id);
    sql(`UPDATE bulk_tasks AS c SET state='held',value=NULL,attempts=0,next_at=0 WHERE c.job=? AND c.provider=? AND EXISTS(SELECT 1 FROM bulk_tasks t WHERE t.job=c.job AND t.ordinal=c.ordinal AND t.provider!=? AND t.state IN ('pending','waiting','running'))`).run(id,BULK_CONTEXT,BULK_CONTEXT);
    sql(`UPDATE bulk_items AS i SET state='queued',completed=NULL,version=version+1 WHERE i.job=? AND EXISTS(SELECT 1 FROM bulk_tasks t WHERE t.job=i.job AND t.ordinal=i.ordinal AND t.state IN ('pending','waiting','running','held'))`).run(id);
    if(!sql("SELECT COUNT(*) n FROM bulk_items WHERE job=? AND state IN ('queued','running')").get(id).n)sql("UPDATE bulk_jobs SET state=CASE WHEN EXISTS(SELECT 1 FROM bulk_items WHERE job=? AND state!='complete') THEN 'partial' ELSE 'complete' END WHERE id=?").run(id,id);
    touch(id);
   })();return publicSummary(getJob(id));
  },
  completeRow:(owner,id,ordinal)=>row(owned(owner,id),sql('SELECT * FROM bulk_items WHERE job=? AND ordinal=?').get(id,ordinal)),
  close:()=>db.close(),
 };
}

/** Bounded scheduling continues independently of browsers and observes provider cooldowns. */
export function createBulkRunner({store,lookup,readContext,canRun,concurrency=3,onError=()=>{},canSchedule=()=>true}){
 let stopped=true,timer;const active=new Map();
 async function run(t){try{
   if(!canRun({sub:t.owner,login:t.login,premiumViaOrg:t.org_until>Date.now(),exp:Math.floor(t.org_until/1000)}))throw Object.assign(Error('Acesso ao lote precisa ser renovado.'),{status:403,code:'PROVIDER_AUTH_FAILED'});
   const value=t.provider===BULK_CONTEXT?await readContext(t):await lookup(t);store.settle(t,value);
  }catch(e){store.settle(t,null,e);}finally{active.delete(t.lease);if(!stopped)queueMicrotask(tick);}}
 function tick(){if(stopped||!canSchedule())return;try{while(active.size<concurrency){const task=store.claim([...active.values()].map(t=>t.provider));if(!task)break;active.set(task.lease,task);void run(task);}}catch(e){onError(e);}}
 return{start(){if(!stopped)return;stopped=false;timer=setInterval(tick,1000);timer.unref();tick();},wake:tick,async stop(){stopped=true;clearInterval(timer);while(active.size)await new Promise(r=>setTimeout(r,20));},active:()=>active.size};
}
