// Read-only upstream probes. No credentials, IOC payloads or actor reports in logs.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env'))),raw=(env.SECRETS_ENCRYPTION_KEY||'').trim(),decoded=Buffer.from(raw,'base64'),enc=/^[0-9a-f]{64}$/i.test(raw)?Buffer.from(raw,'hex'):decoded.length===32?decoded:crypto.createHash('sha256').update(raw).digest();
const {decodeCredentials}=await import(pathToFileURL(path.join(root,'server/credentialPool.js')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js'))),db=new Database(path.join(root,'server/.ioc-intelligence.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');
function keys(provider,envName){const encrypted=users[owner].apiKeysEnc?.[provider];if(encrypted){const blob=Buffer.from(encrypted,'base64'),cipher=crypto.createDecipheriv('aes-256-gcm',enc,blob.subarray(0,12));cipher.setAuthTag(blob.subarray(12,28));return decodeCredentials(Buffer.concat([cipher.update(blob.subarray(28)),cipher.final()]).toString());}return String(env[envName]||'').split(',').map(s=>s.trim()).filter(Boolean);}

const provider='threatfox', personal=[...new Set(['threatfox','abuse_ch','urlhaus','malwarebazaar'].flatMap(name=>keys(name,'UNUSED')))], candidates=personal.length?personal:[...new Set(['THREATFOX_API_KEY','ABUSE_CH_API_KEY','URLHAUS_API_KEY','MALWAREBAZAAR_API_KEY'].flatMap(name=>String(env[name]||'').split(',').map(s=>s.trim()).filter(Boolean)))];
console.log(JSON.stringify({provider,readOnly:true,candidates:candidates.length,at:new Date().toISOString()}));
for(const [index,key]of candidates.entries()){
 const id='credential-pool:v1:'+provider+':'+crypto.createHash('sha256').update(key).digest('hex').slice(0,24),saved=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(id),state=saved?JSON.parse(saved.value):{};
 if(Math.max(state.blockedUntil||0,state.invalidUntil||0)>Date.now()){console.log(JSON.stringify({slot:index+1,state:'cooldown_preserved',lastStatus:state.lastStatus}));continue;}
 try{
  const response=await fetch('https://threatfox-api.abuse.ch/api/v1/',{method:'POST',headers:{'Auth-Key':key,'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({query:'search_ioc',search_term:'116.179.37.176'}),signal:AbortSignal.timeout(25000),redirect:'error'});
  let data;try{data=await response.json();}catch{}
  console.log(JSON.stringify({slot:index+1,httpStatus:response.status,contentType:response.headers.get('content-type'),queryStatus:/^[a-z_]+$/i.test(data?.query_status||'')?data.query_status:null,readOnly:true}));
  if(response.status!==401&&response.status!==403)break;
 }catch{console.log(JSON.stringify({slot:index+1,state:'probe_unavailable'}));break;}
}
db.close();
