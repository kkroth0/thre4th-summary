// Read-only diagnostic: never print credentials, token fingerprints or raw responses.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);
if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js')));
const env=parse(fs.readFileSync(path.join(root,'.env'))),raw=(env.SECRETS_ENCRYPTION_KEY||'').trim();
if(!raw)throw Error('Configuration unavailable');
const decoded=Buffer.from(raw,'base64'),enc=/^[0-9a-f]{64}$/i.test(raw)?Buffer.from(raw,'hex'):decoded.length===32?decoded:crypto.createHash('sha256').update(raw).digest();
const blob=Buffer.from(users[owner].apiKeysEnc?.virustotal||'','base64');
const decipher=crypto.createDecipheriv('aes-256-gcm',enc,blob.subarray(0,12));decipher.setAuthTag(blob.subarray(12,28));
const plain=Buffer.concat([decipher.update(blob.subarray(28)),decipher.final()]).toString();
let keys;try{const data=JSON.parse(plain);keys=data.version===1?data.keys:[plain];}catch{keys=[plain];}
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const db=new Database(path.join(root,'server/.ioc-intelligence.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');
const get=id=>{const row=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(id);return row?JSON.parse(row.value):null;};
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,keyCount:keys.length,configuredLimits:{perMinute:Number(env.VIRUSTOTAL_REQUESTS_PER_MINUTE)||0,perDay:Number(env.VIRUSTOTAL_REQUESTS_PER_DAY)||0},sharedGate:get('credential-pool:shared:virustotal')}));
for(let i=0;i<keys.length;i++){
 const key=keys[i],saved=get('credential-pool:v1:virustotal:'+crypto.createHash('sha256').update(key).digest('hex').slice(0,24));
 const output={keyNumber:i+1,saved};
 try{
  const r=await fetch('https://www.virustotal.com/api/v3/users/'+encodeURIComponent(key)+'/overall_quotas',{headers:{Accept:'application/json','x-apikey':key},signal:AbortSignal.timeout(10000)});
  output.httpStatus=r.status;output.rateHeaders=Object.fromEntries(['retry-after','x-ratelimit-reset','x-ratelimit-remaining','x-daily-requests-left'].flatMap(name=>r.headers.has(name)?[[name,r.headers.get(name)]]:[]));
  const body=await r.json();
  if(r.ok)output.windows=Object.fromEntries(['api_requests_daily','api_requests_monthly','api_requests_per_minute'].flatMap(name=>body.data?.[name]?.user?[[name,body.data[name].user]]:[]));
  else{output.errorCode=/^[A-Za-z0-9_]+$/.test(body.error?.code||'')?body.error.code:'upstream_error';output.reportedWindow=['minute','daily','monthly','day','month'].filter(value=>String(body.error?.message||'').toLowerCase().includes(value));}
 }catch{output.error='quota_probe_unavailable';}
 console.log(JSON.stringify(output));
 await new Promise(resolve=>setTimeout(resolve,300));
}
db.close();
