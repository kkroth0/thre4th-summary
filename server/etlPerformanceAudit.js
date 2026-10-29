// Read-only comparison of already saved responses. No vendor API requests,
// no indicator values, source titles, private links or credentials in output.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {gunzipSync} from 'node:zlib';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);
if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');db.pragma('cache_size=-4000');
const job='59aa9475-3acd-4b38-9fc4-a2d9d91e29cb';
if(!db.prepare('SELECT 1 FROM bulk_jobs WHERE id=? AND owner=?').get(job,owner))throw Error('Batch unavailable');
const unpack=bytes=>JSON.parse(gunzipSync(bytes,{maxOutputLength:64*1024*1024}).toString());
const unwrap=(v,field)=>{let body=v.rawPayload;for(let i=0;i<3&&body&&!body[field]&&body.data;i++)body=body.data;return body;};
const n=value=>Number.parseFloat(String(value??''));
const pulseIds=new Set(),vtPulses=new Set(),vtReferences=new Set(),comparison={paired:0,otxPulsesAndVtMalicious:0,otxPulsesWithoutVtMalicious:0,vtMaliciousWithoutOtxPulses:0,neitherCriterion:0,missingComparableFields:0};
let otxResponses=0,otxWithPulses=0,otxWithVtReference=0,otxWithAnalysisStats=0,otxWithAnalysisResults=0;
for(const row of db.prepare("SELECT value FROM bulk_tasks WHERE job=? AND provider='AlienVault OTX' AND state='done'").iterate(job)){
 const v=unpack(row.value),body=unwrap(v,'pulse_info');otxResponses++;
 if(body?.last_analysis_stats)otxWithAnalysisStats++;
 if(body?.last_analysis_results)otxWithAnalysisResults++;
 if(n(v.data?.['Pulse Count'])>0)otxWithPulses++;
 let refersToVt=false;
 for(const pulse of body?.pulse_info?.pulses||[]){
  if(pulse.id)pulseIds.add(pulse.id);
  for(const ref of Array.isArray(pulse.references)?pulse.references:[]){
   const candidate=typeof ref==='string'?ref:ref?.url;
   if(typeof candidate!=='string')continue;
   try{const url=new URL(candidate),host=url.hostname.toLowerCase();if(host==='virustotal.com'||host.endsWith('.virustotal.com')){refersToVt=true;vtReferences.add(url.href);if(pulse.id)vtPulses.add(pulse.id);}}catch{}
  }
 }
 if(refersToVt)otxWithVtReference++;
}
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,noUpstreamCalls:true,otxResponses,otxWithPulses,uniquePulses:pulseIds.size,otxWithVtReference,uniquePulsesReferencingVt:vtPulses.size,uniqueVtReferenceLinks:vtReferences.size,otxWithAnalysisStats,otxWithAnalysisResults}));
for(const row of db.prepare("SELECT v.value vt,o.value otx FROM bulk_tasks v JOIN bulk_tasks o ON o.job=v.job AND o.ordinal=v.ordinal AND o.provider='AlienVault OTX' AND o.state='done' WHERE v.job=? AND v.provider='VirusTotal' AND v.state='done'").iterate(job)){
 const vt=unpack(row.vt),otx=unpack(row.otx),malicious=n(vt.data?.Malicious),pulses=n(otx.data?.['Pulse Count']);comparison.paired++;
 if(!Number.isFinite(malicious)||!Number.isFinite(pulses)){comparison.missingComparableFields++;continue;}
 if(pulses>0&&malicious>0)comparison.otxPulsesAndVtMalicious++;
 else if(pulses>0)comparison.otxPulsesWithoutVtMalicious++;
 else if(malicious>0)comparison.vtMaliciousWithoutOtxPulses++;
 else comparison.neitherCriterion++;
}
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,noUpstreamCalls:true,comparison,criteria:{otx:'At least one pulse in the saved response',virustotal:'At least one malicious analysis result in the saved response'},notAnAccuracyMeasure:true}));db.close();
