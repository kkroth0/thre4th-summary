// Read-only upstream probes. No credentials, IOC payloads or actor reports in logs.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env'))),raw=(env.SECRETS_ENCRYPTION_KEY||'').trim(),decoded=Buffer.from(raw,'base64'),enc=/^[0-9a-f]{64}$/i.test(raw)?Buffer.from(raw,'hex'):decoded.length===32?decoded:crypto.createHash('sha256').update(raw).digest();
const {decodeCredentials}=await import(pathToFileURL(path.join(root,'server/credentialPool.js')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js'))),db=new Database(path.join(root,'server/.ioc-intelligence.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');
function keys(provider,envName){const encrypted=users[owner].apiKeysEnc?.[provider];if(encrypted){const blob=Buffer.from(encrypted,'base64'),cipher=crypto.createDecipheriv('aes-256-gcm',enc,blob.subarray(0,12));cipher.setAuthTag(blob.subarray(12,28));return decodeCredentials(Buffer.concat([cipher.update(blob.subarray(28)),cipher.final()]).toString());}return String(env[envName]||'').split(',').map(s=>s.trim()).filter(Boolean);}
for(const provider of ['otx','threatfox']){
 const configured=keys(provider,provider==='otx'?'ALIENVAULT_API_KEY':'THREATFOX_API_KEY'),values=configured.length?configured:keys('abuse_ch','ABUSE_CH_API_KEY'),key=values[0],output={provider,readOnly:true,keyCount:values.length,at:new Date().toISOString()};
 if(!key){console.log(JSON.stringify({...output,state:'unconfigured'}));continue;}
 const id='credential-pool:v1:'+provider+':'+crypto.createHash('sha256').update(key).digest('hex').slice(0,24),saved=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(id),state=saved?JSON.parse(saved.value):{};
 output.savedLastStatus=state.lastStatus;output.waitUntil=state.blockedUntil||null;
 if(Math.max(state.blockedUntil||0,state.invalidUntil||0)>Date.now()){console.log(JSON.stringify({...output,state:'cooldown_preserved'}));continue;}
 try{const response=await fetch(provider==='otx'?'https://otx.alienvault.com/api/v1/indicators/IPv4/116.179.37.176/general':'https://threatfox-api.abuse.ch/api/v1/',{method:provider==='otx'?'GET':'POST',headers:provider==='otx'?{'X-OTX-API-KEY':key,Accept:'application/json'}:{'Auth-Key':key,'Content-Type':'application/json',Accept:'application/json'},...(provider==='otx'?{}:{body:JSON.stringify({query:'search_ioc',search_term:'116.179.37.176'})}),signal:AbortSignal.timeout(25000),redirect:'error'});
  const text=await response.text();let body;try{body=JSON.parse(text);}catch{}
  Object.assign(output,{httpStatus:response.status,contentType:response.headers.get('content-type'),retryAfter:response.headers.get('retry-after'),cfMitigated:response.headers.get('cf-mitigated'),html:/^\s*(?:<!doctype|<html)/i.test(text),json:!!body,authMessage:/invalid.{0,20}(?:key|token)|authentication|unauthorized/i.test(String(body?.detail||body?.error||body?.message||'')),queryStatus:/^[a-z_]+$/i.test(body?.query_status||'')?body.query_status:null,recordCount:Array.isArray(body?.data)?body.data.length:typeof body?.pulse_info?.count==='number'?body.pulse_info.count:null});
 }catch{output.state='probe_unavailable';}console.log(JSON.stringify(output));
}
db.close();
