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
const mapping={abuseipdb:'ABUSEIPDB_API_KEY'},effective={};
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,environmentOverrides:envDifferences,proxyConfigured:!!(env.HTTPS_PROXY||env.HTTP_PROXY||env.https_proxy||env.http_proxy)}));
for(const [provider,variable]of Object.entries(mapping)){
 const own=personalProviderCredentials(provider,personal),platform=platformProviderCredentials(provider,variable,configured),keys=own.length?own:platform;effective[provider]=keys;
 console.log(JSON.stringify({provider,personal:own.length,platform:platform.length,effective:keys.length,selected:own.length?'personal':'platform',slots:keys.map((key,i)=>{
 const record=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get('credential-pool:v1:'+provider+':'+credentialId(key)),state=record?JSON.parse(record.value):{};
 const qid='quota:'+crypto.createHash('sha256').update(JSON.stringify(['AbuseIPDB',key,'check'])).digest('hex'),qrow=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(qid),q=qrow?JSON.parse(qrow.value):null;
 return{slot:i+1,usedToday:state.day===new Date().toISOString().slice(0,10)?state.used||0:0,lastStatus:state.lastStatus||null,quotaWaitActive:state.blockedUntil>Date.now(),authWaitActive:state.invalidUntil>Date.now(),pacingActive:state.nextAt>Date.now(),lastRecordedQuota:q?{observedAt:q.at,limit:q.item?.limit,remaining:q.item?.remaining,resetAt:q.item?.resetAt,expired:q.item?.resetAt?Date.parse(q.item.resetAt)<=Date.now():q.at?.slice(0,10)!==new Date().toISOString().slice(0,10)}:null};
 })}));
}

const jobs=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});jobs.pragma('query_only=ON');
const jobId='59aa9475-3acd-4b38-9fc4-a2d9d91e29cb';
console.log(JSON.stringify({jobSource:jobs.prepare("SELECT t.provider,t.state,t.http_status,t.error_code,COUNT(*) count FROM bulk_tasks t JOIN bulk_jobs j ON j.id=t.job WHERE j.owner=? AND t.job=? AND t.provider='AbuseIPDB' GROUP BY t.provider,t.state,t.http_status,t.error_code").all(owner,jobId),blocks:jobs.prepare("SELECT provider,reason,until_at FROM bulk_blocks WHERE owner=? AND provider='AbuseIPDB'").all(owner).map(b=>({...b,active:b.until_at>Date.now()}))}));
jobs.close();db.close();
