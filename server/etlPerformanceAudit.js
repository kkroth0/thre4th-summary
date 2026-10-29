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
const {providerCredentialLimits}=await import(pathToFileURL(path.join(root,'server/providerLimits.js')));
const db=new Database(path.join(root,'server/.ioc-intelligence.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');
const get=id=>{const row=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(id);return row?JSON.parse(row.value):null;};
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,keyCount:keys.length,configuredLimits:providerCredentialLimits('virustotal','VIRUSTOTAL',env),sharedGate:get('credential-pool:shared:virustotal')}));

const key=keys[0],output={readOnly:true,endpoint:'user_api_usage',keyNumber:1,range:['2026-10-28','2026-10-29']};
try{
 const response=await fetch('https://www.virustotal.com/api/v3/users/'+encodeURIComponent(key)+'/api_usage?start_date=20261028&end_date=20261029',{headers:{Accept:'application/json','x-apikey':key},signal:AbortSignal.timeout(10000),redirect:'error'});
 const body=await response.json();output.httpStatus=response.status;output.retryAfter=response.headers.get('retry-after');
 if(response.ok){const data=body.data||body;output.daily=Object.fromEntries(Object.entries(data.daily||{}).map(([day,values])=>[day,Object.fromEntries(Object.entries(values).filter(([endpoint,count])=>/^\/api\/v3\/[A-Za-z0-9_()/.-]+$/.test(endpoint)&&typeof count==='number'))]));output.total=Object.fromEntries(Object.entries(data.total||{}).filter(([endpoint,count])=>/^\/api\/v3\/[A-Za-z0-9_()/.-]+$/.test(endpoint)&&typeof count==='number'));}
 else{output.errorCode=/^[A-Za-z0-9_]+$/.test(body.error?.code||'')?body.error.code:'upstream_error';let message=String(body.error?.message||'');for(const secret of keys)message=message.replaceAll(secret,'[credential]');output.message=message.replace(/[a-f0-9]{24,}/gi,'[id]').slice(0,180);}
}catch{output.state='probe_unavailable';}
console.log(JSON.stringify(output));db.close();
