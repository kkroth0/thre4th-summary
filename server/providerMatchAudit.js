// One-off live metadata checks. Never downloads payloads or changes production
// data; persistence/profile checks use an isolated in-memory database.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export async function auditProviderMatches(root){
  const load=name=>import(pathToFileURL(path.join(root,'server',name)));
  const {default:dotenv}=await load('node_modules/dotenv/lib/main.js');
  dotenv.config({path:path.join(root,'.env'),quiet:true});
  const {default:http}=await load('node_modules/axios/index.js');
  const {default:Database}=await load('node_modules/better-sqlite3/lib/index.js');
  const {buildMalwareIndex,matchMalware}=await load('malwareMatch.js');
  const {buildActorIndex,matchActors}=await load('actorMatch.js');
  const {sourceObservations}=await load('intelligenceSources.js');
  const {createIocIntelligence}=await load('iocIntelligence.js');
  const {correlateMalware,normalizeFamilies,malwareNameKey}=await load('malwareCatalog.js');
  const read=name=>JSON.parse(fs.readFileSync(path.join(root,'server/data',name),'utf8'));
  const raw=read('malware.json'),families=(Array.isArray(raw)?raw:raw.malware).map(row=>({...row,aliases:row.aliases||[],references:row.references||[]}));
  const malwareIndex=buildMalwareIndex(families),actorData=read('actors.json');
  let catalog=families;
  try{catalog=normalizeFamilies(JSON.parse(fs.readFileSync(path.join(root,'server/.malpedia-cache.json'),'utf8')).data);}catch{/* static catalogue fallback */}
  const actorIndex=buildActorIndex(Array.isArray(actorData)?actorData:actorData.actors);
  const options={matchActors:text=>matchActors(text,actorIndex),matchMalware:(text,settings)=>matchMalware(text,malwareIndex,settings)};
  const db=new Database(path.join(root,'server/.ioc-intelligence.sqlite'),{readonly:true,fileMustExist:true});
  db.pragma('query_only = ON');
  const stored=db.prepare(`SELECT o.provider,COUNT(DISTINCT o.id) observations,COUNT(DISTINCT CASE WHEN e.kind='malware' THEN e.entity END) families,COUNT(DISTINCT CASE WHEN e.kind='actor' THEN e.entity END) actors
    FROM observations o LEFT JOIN entity_links e ON e.observation=o.id WHERE o.provider IN ('OTX','ThreatFox','URLhaus','MalwareBazaar') GROUP BY o.provider`).all();
  const replay=db.prepare("SELECT value FROM intelligence_state WHERE id='provider-matches-v11'").get();
  const key=String(process.env.ABUSE_CH_API_KEY||process.env.THREATFOX_API_KEY||process.env.MALWAREBAZAAR_API_KEY||'').split(',')[0].trim();
  const otxKey=String(process.env.ALIENVAULT_API_KEY||'').split(',')[0].trim();
  const cfg=headers=>({headers,timeout:15000,maxContentLength:8000000,maxRedirects:0,family:4});
  const form=(url,body)=>http.post(url,new URLSearchParams(body).toString(),cfg({'Auth-Key':key,'Content-Type':'application/x-www-form-urlencoded'}));
  const checks=[];
  async function check(provider,configured,get){
    if(!configured){checks.push({provider,status:'unconfigured'});return;}
    const start=performance.now();let memory;
    try{
      const {payload,query}=await get();
      const observations=sourceObservations(provider,payload,{...options,query});
      memory=createIocIntelligence();await memory.ingest(observations);
      const found=memory.families(),known=new Set(catalog.flatMap(row=>[row.name,...row.aliases].map(malwareNameKey)));
      const records=correlateMalware([...catalog,...found.filter(row=>!known.has(malwareNameKey(row.name))).map(row=>({...row,aliases:[],references:[]}))],memory.publications());
      const linked=observations.some(row=>row.malwares?.length||row.actors?.length);
      checks.push({provider,status:linked?'matched':observations.length?'observed_without_family':'no_results',observations:observations.length,
        malwareMatches:[...new Set(observations.flatMap(row=>row.malwares||[]).map(row=>row.name))].slice(0,10),
        actorMatches:[...new Set(observations.flatMap(row=>row.actors||[]).map(row=>row.name))].slice(0,10),
        persistedIndicators:memory.list().total,profilesWithEvidence:[...records.values()].filter(row=>row.posts.length).length,
        reference:observations[0]?.link||'',exampleIndicator:observations[0]?.value||'',elapsedMs:Math.round(performance.now()-start),isolatedPersistence:true});
    }catch(error){checks.push({provider,status:'error',httpStatus:error.response?.status||null,code:error.code||error.name});}
    finally{memory?.close();}
  }
  await check('ThreatFox',key,async()=>{
    const row=db.prepare("SELECT i.value FROM observations o JOIN indicators i ON i.id=o.indicator JOIN entity_links e ON e.observation=o.id WHERE o.scope='global' AND o.provider='ThreatFox' AND e.kind='malware' ORDER BY o.published DESC LIMIT 1").get();
    if(!row)throw Error('No stored ThreatFox control');
    const response=await http.post('https://threatfox-api.abuse.ch/api/v1/',{query:'search_ioc',search_term:row.value,exact_match:true},cfg({'Auth-Key':key}));return {payload:response.data,query:row.value};
  });
  await check('MalwareBazaar',key,async()=>({payload:(await form('https://mb-api.abuse.ch/api/v1/',{query:'get_recent',selector:'100'})).data}));
  await check('OTX',otxKey,async()=>{
    const row=db.prepare("SELECT o.external_id FROM observations o JOIN entity_links e ON e.observation=o.id WHERE o.scope='global' AND o.provider='OTX' AND e.kind='malware' ORDER BY o.published DESC LIMIT 1").get();
    if(!row)throw Error('No stored OTX control');
    const response=await http.get('https://otx.alienvault.com/api/v1/pulses/'+encodeURIComponent(row.external_id),cfg({'X-OTX-API-KEY':otxKey}));return {payload:{results:[response.data]}};
  });
  await check('URLhaus',key,async()=>{
    const recent=await http.get('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/10/',cfg({'Auth-Key':key}));
    const row=recent.data.urls?.find(row=>row.tags?.some(tag=>options.matchMalware(tag,{structured:true}).length))||recent.data.urls?.[0];
    if(!row?.url)throw Error('No URLhaus control');
    const response=await form('https://urlhaus-api.abuse.ch/v1/url/',{url:row.url});return {payload:response.data,query:row.url};
  });
  db.close();return {stored,replay:replay?JSON.parse(replay.value):null,live:checks};
}
