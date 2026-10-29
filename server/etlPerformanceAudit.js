// Account-scoped read-only correlation audit. No API requests or IOC values.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);
if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const open=file=>{const db=new Database(file,{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');db.pragma('cache_size=-4000');return db;};
const bulk=open(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite')),intel=open(env.IOC_INTELLIGENCE_PATH||path.join(root,'server/.ioc-intelligence.sqlite'));
const job='59aa9475-3acd-4b38-9fc4-a2d9d91e29cb';if(!bulk.prepare('SELECT 1 FROM bulk_jobs WHERE id=? AND owner=?').get(job,owner))throw Error('Batch unavailable');
const {enrichActorCatalog}=await import(pathToFileURL(path.join(root,'server/actorSources.js'))),{mergeCtiActors}=await import(pathToFileURL(path.join(root,'server/ctiFyi.js'))),{buildActorIdentityIndex}=await import(pathToFileURL(path.join(root,'server/actorIdentity.js')));
const read=(file,fallback)=>{try{return JSON.parse(fs.readFileSync(path.join(root,'server',file),'utf8'));}catch{return fallback;}};
const catalog=mergeCtiActors(enrichActorCatalog(read('data/actors.json',{}).actors||[],read('data/actor-sources.json',{})),read('.cti-fyi.json',{}).groups||[]),identities=buildActorIdentityIndex(catalog);
const links=intel.prepare("SELECT e.entity,e.name,e.relation,o.provider,o.published,a.observation projection,a.link profileLink FROM indicators i CROSS JOIN observations o INDEXED BY observations_indicator ON o.indicator=i.id CROSS JOIN entity_links e ON e.observation=o.id AND e.kind='actor' LEFT JOIN actor_observations a ON a.observation=o.id WHERE i.value=? AND o.scope IN ('global',?)");
const matchedIocs=new Set(),cataloguedIocs=new Set(),sourceOnlyIocs=new Set(),unknown=new Set(),actors=new Map(),providers=new Map(),relations=new Map();
let evidenceLinks=0,canonicalLinks=0,profileProjectionMissing=0,sourceOnlyLinks=0,withReference=0;
for(const item of bulk.prepare('SELECT ordinal,query FROM bulk_items WHERE job=? ORDER BY ordinal').iterate(job)){
 for(const row of links.all(item.query,owner)){
  evidenceLinks++;matchedIocs.add(item.ordinal);if(!row.projection)profileProjectionMissing++;if(row.profileLink)withReference++;
  const actor=identities.ids.get(row.entity)||identities.resolve(row.name),ps=providers.get(row.provider)||new Set(),rs=relations.get(row.relation)||new Set();ps.add(item.ordinal);rs.add(item.ordinal);providers.set(row.provider,ps);relations.set(row.relation,rs);
  if(actor){canonicalLinks++;cataloguedIocs.add(item.ordinal);const seen=actors.get(actor.id)||{name:actor.name,iocs:new Set(),relations:new Set(),sources:new Set()};seen.iocs.add(item.ordinal);seen.relations.add(row.relation);seen.sources.add(row.provider);actors.set(actor.id,seen);}
  else{sourceOnlyLinks++;sourceOnlyIocs.add(item.ordinal);unknown.add(row.entity);}
 }
}
const summary={at:new Date().toISOString(),readOnly:true,noApiCalls:true,batchTotal:bulk.prepare('SELECT total FROM bulk_jobs WHERE id=?').get(job).total,internalActorCatalogSize:identities.actors.length,iocsWithActorEvidence:matchedIocs.size,iocsLinkedToCataloguedActor:cataloguedIocs.size,cataloguedActorsMatched:actors.size,iocsWithSourceOnlyActorLabels:sourceOnlyIocs.size,distinctSourceOnlyLabels:unknown.size,evidenceLinks,canonicalLinks,sourceOnlyLinks,linksAvailableInActorProfile:withReference,profileProjectionMissing,providers:[...providers].map(([provider,items])=>({provider,iocs:items.size})),relations:[...relations].map(([relation,items])=>({relation,iocs:items.size})),topCataloguedActors:[...actors].sort((a,b)=>b[1].iocs.size-a[1].iocs.size).slice(0,5).map(([id,a])=>({id,name:a.name,indicators:a.iocs.size,sources:[...a.sources],relations:[...a.relations]})),batchContext:bulk.prepare("SELECT state,COUNT(*) count FROM bulk_tasks WHERE job=? AND provider='@context' GROUP BY state").all(job)};
console.log(JSON.stringify(summary));bulk.close();intel.close();
