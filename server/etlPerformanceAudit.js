// Saved server state only: no provider requests, writes, secrets or IOC values.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
const root=path.resolve(process.argv[2]), login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8'));
const owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);
if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js')));
const env=parse(fs.readFileSync(path.join(root,'.env')));
let service={};
try{
 const output=execFileSync('systemctl',['show','bdppt-site','-p','MainPID','-p','ActiveState','-p','SubState','-p','NRestarts'],{encoding:'utf8',timeout:5000});
 service=Object.fromEntries(output.trim().split('\n').map(line=>line.split('=')));
 const pid=service.MainPID;delete service.MainPID;
 if(/^\d+$/.test(pid)&&pid!=='0')for(const pair of fs.readFileSync(`/proc/${pid}/environ`,'utf8').split('\0')){
  const split=pair.indexOf('='),name=pair.slice(0,split);
  if(/^(?:SECRETS_ENCRYPTION_KEY|VIRUSTOTAL(?:\d+)?_API_KEY|VIRUSTOTAL_REQUESTS_PER_(?:MINUTE|DAY)|BULK_JOBS_PATH|IOC_INTELLIGENCE_PATH)$/.test(name))env[name]=pair.slice(split+1);
 }
}catch{service.inspection='unavailable';}
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const open=file=>{const db=new Database(file,{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');return db;};
const db=open(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'));
const intel=open(env.IOC_INTELLIGENCE_PATH||path.join(root,'server/.ioc-intelligence.sqlite'));
const id='59aa9475-3acd-4b38-9fc4-a2d9d91e29cb';
const job=db.prepare('SELECT id,state,total,created,updated,revision FROM bulk_jobs WHERE id=? AND owner=?').get(id,owner);
if(!job)throw Error('Batch unavailable');
const iso=n=>n&&n<Number.MAX_SAFE_INTEGER?new Date(n).toISOString():null;
const now=Date.now();
const sources=db.prepare("SELECT provider,state,http_status,error_code,COUNT(*) count,MIN(updated) firstUpdated,MAX(updated) lastUpdated,MIN(next_at) firstRetryAt,MAX(next_at) lastRetryAt,MIN(attempts) minAttempts,MAX(attempts) maxAttempts FROM bulk_tasks WHERE job=? GROUP BY provider,state,http_status,error_code").all(id).map(r=>({...r,firstUpdated:iso(r.firstUpdated),lastUpdated:iso(r.lastUpdated),firstRetryAt:iso(r.firstRetryAt),lastRetryAt:iso(r.lastRetryAt)}));
const kinds=db.prepare("SELECT i.kind,t.state,COUNT(*) count FROM bulk_tasks t JOIN bulk_items i ON i.job=t.job AND i.ordinal=t.ordinal WHERE t.job=? AND t.provider='VirusTotal' GROUP BY i.kind,t.state").all(id);
const blocks=db.prepare('SELECT provider,reason,until_at FROM bulk_blocks WHERE owner=?').all(owner).map(r=>({provider:r.provider,reason:r.reason,until:iso(r.until_at),stillActive:r.until_at>now}));
const due=db.prepare("SELECT t.provider,t.state,COUNT(*) count FROM bulk_tasks t LEFT JOIN bulk_blocks b ON b.owner=? AND b.provider=t.provider WHERE t.job=? AND t.state IN ('pending','waiting') AND t.next_at<=? AND COALESCE(b.until_at,0)<=? GROUP BY t.provider,t.state").all(owner,id,now,now);
const leases=db.prepare("SELECT provider,COUNT(*) count,SUM(lease_until<=?) expired,MAX(lease_until) latest FROM bulk_tasks WHERE job=? AND state='running' GROUP BY provider").all(now,id).map(r=>({...r,latest:iso(r.latest)}));
const recentVT=db.prepare("SELECT state,http_status,error_code,updated,next_at,attempts FROM bulk_tasks WHERE job=? AND provider='VirusTotal' ORDER BY updated DESC LIMIT 10").all(id).map(r=>({...r,updated:iso(r.updated),next_at:iso(r.next_at)}));
const exports=db.prepare('SELECT id,state,updated,error FROM bulk_exports WHERE job=? AND owner=? ORDER BY created DESC LIMIT 3').all(id,owner).map(r=>({...r,updated:iso(r.updated)}));
const state=name=>{const r=intel.prepare('SELECT value FROM intelligence_state WHERE id=?').get(name);return r?JSON.parse(r.value):null;};
const {decodeCredentials,credentialId}=await import(pathToFileURL(path.join(root,'server/credentialPool.js')));
const raw=String(env.SECRETS_ENCRYPTION_KEY||'').trim(),decoded=Buffer.from(raw,'base64');
const enc=/^[0-9a-f]{64}$/i.test(raw)?Buffer.from(raw,'hex'):decoded.length===32?decoded:crypto.createHash('sha256').update(raw).digest();
let keys=[],configured='personal';
const encrypted=users[owner].apiKeysEnc?.virustotal;
if(encrypted){const blob=Buffer.from(encrypted,'base64'),cipher=crypto.createDecipheriv('aes-256-gcm',enc,blob.subarray(0,12));cipher.setAuthTag(blob.subarray(12,28));keys=decodeCredentials(Buffer.concat([cipher.update(blob.subarray(28)),cipher.final()]).toString());}
if(!keys.length){configured='platform';for(let i=1;i<=50;i++)keys.push(...String(env[i===1?'VIRUSTOTAL_API_KEY':`VIRUSTOTAL${i}_API_KEY`]||'').split(',').map(s=>s.trim()).filter(Boolean));}
keys=[...new Set(keys)];
const {providerCredentialLimits}=await import(pathToFileURL(path.join(root,'server/providerLimits.js')));
const limits=providerCredentialLimits('virustotal','VIRUSTOTAL',env),day=new Date(now).toISOString().slice(0,10);
const credentials=keys.map((key,index)=>{const s=state('credential-pool:v1:virustotal:'+credentialId(key))||{};const until=Math.max(s.blockedUntil||0,s.nextAt||0,s.invalidUntil||0,limits.perDay>0&&s.day===day&&s.used>=limits.perDay?Date.parse(day+'T00:00:00Z')+86400000:0);return{slot:index+1,day:s.day,localAttempts:s.used||0,todayLocalAttempts:s.day===day?s.used||0:0,lastStatus:s.lastStatus||null,blockedUntil:iso(s.blockedUntil),nextAt:iso(s.nextAt),invalidUntil:iso(s.invalidUntil),available:until<=now,retryAt:until>now?iso(until):null};});
console.log(JSON.stringify({at:new Date(now).toISOString(),readOnly:true,providerRequests:0,service,job:{...job,created:iso(job.created),updated:iso(job.updated)},items:db.prepare('SELECT state,COUNT(*) count FROM bulk_items WHERE job=? GROUP BY state').all(id),sources,kinds,blocks,due,leases,recentVT,credentials:{selected:configured,count:keys.length,limits,sharedUntil:iso(state('credential-pool:shared:virustotal')),slots:credentials},exports},null,2));
db.close();intel.close();
