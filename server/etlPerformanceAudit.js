// Inspect effective routing and test ThreatFox using the production HTTP client.
// No IOC payloads, credentials, process environment or token fingerprints are logged.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';import {execFileSync} from 'node:child_process';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env'))),envDifferences=[];
try{const pid=execFileSync('systemctl',['show','bdppt-site','-p','MainPID','--value'],{encoding:'utf8',timeout:5000}).trim();if(/^\d+$/.test(pid)&&pid!=='0')for(const pair of fs.readFileSync(`/proc/${pid}/environ`,'utf8').split('\0')){const p=pair.indexOf('='),name=pair.slice(0,p);if(!/^(?:(?:VIRUSTOTAL|ALIENVAULT|ABUSE_CH|THREATFOX|URLHAUS|MALWAREBAZAAR)\d*_API_KEY|SECRETS_ENCRYPTION_KEY|HTTPS?_PROXY|https?_proxy|NO_PROXY|no_proxy)$/.test(name))continue;const value=pair.slice(p+1);if(env[name]!==undefined&&env[name]!==value)envDifferences.push(name);env[name]=value;}}catch{}
const raw=String(env.SECRETS_ENCRYPTION_KEY||'').trim(),decoded=Buffer.from(raw,'base64'),enc=/^[0-9a-f]{64}$/i.test(raw)?Buffer.from(raw,'hex'):decoded.length===32?decoded:crypto.createHash('sha256').update(raw).digest();
const {decodeCredentials,credentialId}=await import(pathToFileURL(path.join(root,'server/credentialPool.js'))),{personalProviderCredentials,platformProviderCredentials}=await import(pathToFileURL(path.join(root,'server/providerCredentials.js')));
function personal(name){const encrypted=users[owner].apiKeysEnc?.[name];if(!encrypted)return [];const blob=Buffer.from(encrypted,'base64'),cipher=crypto.createDecipheriv('aes-256-gcm',enc,blob.subarray(0,12));cipher.setAuthTag(blob.subarray(12,28));return decodeCredentials(Buffer.concat([cipher.update(blob.subarray(28)),cipher.final()]).toString());}
function configured(name){const out=String(env[name]||'').split(',').map(s=>s.trim()).filter(Boolean),match=name.match(/^(.*?)(_API_KEY)$/);if(match)for(let n=2;env[match[1]+n+match[2]]!==undefined;n++)out.push(...String(env[match[1]+n+match[2]]).split(',').map(s=>s.trim()).filter(Boolean));return [...new Set(out)];}
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js'))),db=new Database(env.IOC_INTELLIGENCE_PATH||path.join(root,'server/.ioc-intelligence.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');
const mapping={virustotal:'VIRUSTOTAL_API_KEY',otx:'ALIENVAULT_API_KEY',threatfox:'THREATFOX_API_KEY'},effective={};
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,environmentOverrides:envDifferences,proxyConfigured:!!(env.HTTPS_PROXY||env.HTTP_PROXY||env.https_proxy||env.http_proxy)}));
for(const [provider,variable]of Object.entries(mapping)){
 const own=personalProviderCredentials(provider,personal),platform=platformProviderCredentials(provider,variable,configured),keys=own.length?own:platform;effective[provider]=keys;
 console.log(JSON.stringify({provider,personal:own.length,platform:platform.length,effective:keys.length,selected:own.length?'personal':'platform',platformOverlap:keys.filter(k=>platform.includes(k)).length,slots:keys.map((key,i)=>{const record=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get('credential-pool:v1:'+provider+':'+credentialId(key)),state=record?JSON.parse(record.value):{};return{slot:i+1,day:state.day,used:state.used,lastStatus:state.lastStatus,blockedUntil:state.blockedUntil||null,invalidUntil:state.invalidUntil||null};})}));
}

const bulk=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});bulk.pragma('query_only=ON');
const task=bulk.prepare("SELECT i.query,t.error_code FROM bulk_tasks t JOIN bulk_items i ON i.job=t.job AND i.ordinal=t.ordinal JOIN bulk_jobs j ON j.id=t.job WHERE j.owner=? AND t.job=? AND t.provider='ThreatFox' AND t.state='blocked' LIMIT 1").get(owner,'59aa9475-3acd-4b38-9fc4-a2d9d91e29cb');bulk.close();
if(!task){console.log(JSON.stringify({provider:'ThreatFox',blocked:false}));db.close();process.exit(0);}
if(!env.SESSION_SECRET)throw Error('Session configuration unavailable');
const payload=Buffer.from(JSON.stringify({sub:owner,login,exp:Math.floor(Date.now()/1000)+180})).toString('base64url'),signature=crypto.createHmac('sha256',env.SESSION_SECRET).update(payload).digest('base64url');
try{
 const response=await fetch('http://127.0.0.1:3001/api/threatfox',{method:'POST',headers:{Cookie:`ts_session=${payload}.${signature}`,Origin:'https://threatsumm4ry.app','Content-Type':'application/json'},body:JSON.stringify({query:task.query,fresh:true}),signal:AbortSignal.timeout(65000)});
 let body;try{body=await response.json();}catch{}
 console.log(JSON.stringify({provider:'ThreatFox',throughApplication:true,existingQueuedIndicator:true,httpStatus:response.status,errorCode:/^[A-Za-z0-9_]+$/.test(body?.code||'')?body.code:null,queryStatus:/^[a-z_]+$/i.test(body?.query_status||'')?body.query_status:null,cache:response.headers.get('x-lookup-cache'),message:typeof body?.error==='string'?body.error.slice(0,120):null}));
}catch{console.log(JSON.stringify({provider:'ThreatFox',throughApplication:true,state:'request_unavailable'}));}
db.close();
