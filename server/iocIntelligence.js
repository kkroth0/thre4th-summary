import Database from 'better-sqlite3';
import { createObservationWriter } from './observationWriter.js';
import { createIntelligenceWriter } from './intelligenceWriter.js';
import { createIocIntelligenceReads } from './iocIntelligenceReads.js';
import crypto from 'node:crypto';
import { normalizeIndicator } from './indicatorIdentity.js';
export { normalizeIndicator } from './indicatorIdentity.js';
import { setImmediate as yieldLoop } from 'node:timers/promises';
import { declaredRepositoryMalware } from './repositorySources.js';
import { sanitizeStoredMalware } from './malwareMatch.js';
import { createPhishingEvolution } from './phishingEvolution.js';
import { createNewsPersistence } from './newsPersistence.js';
import { createWatchSuggestions } from './watchSuggestions.js';
import { canonicalJsonEvidence } from './jsonEvidence.js';
import { actorNameKey } from './actorSources.js';

const idFor = value => crypto.createHash('sha256').update(value).digest('hex');
const iocValues = row => ['ips','domains','hashes','urls'].flatMap(type => (row.iocs?.[type] || []).map(value=>({value})));

export function createIocIntelligence({filePath=':memory:',now=()=>Date.now(),isolatedWrites=false}={}) {
  const db=new Database(filePath); db.pragma('journal_mode = WAL');db.pragma('busy_timeout = 5000');db.pragma('cache_size = -8000');
  db.exec(`CREATE TABLE IF NOT EXISTS indicators(id TEXT PRIMARY KEY,type TEXT NOT NULL,value TEXT NOT NULL UNIQUE);
    CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,indicator TEXT NOT NULL,scope TEXT NOT NULL,provider TEXT NOT NULL,external_id TEXT NOT NULL,published TEXT NOT NULL,collected TEXT NOT NULL,details TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS observations_indicator ON observations(indicator,scope,published DESC);
    CREATE INDEX IF NOT EXISTS observations_scope ON observations(scope,provider,published DESC);
    CREATE TABLE IF NOT EXISTS entity_links(observation TEXT NOT NULL,kind TEXT NOT NULL,entity TEXT NOT NULL,name TEXT NOT NULL,relation TEXT NOT NULL,PRIMARY KEY(observation,kind,entity));
    CREATE INDEX IF NOT EXISTS entity_lookup ON entity_links(kind,entity,observation);
    CREATE TABLE IF NOT EXISTS observation_revisions(id INTEGER PRIMARY KEY,observation TEXT NOT NULL,at TEXT NOT NULL,payload TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS intelligence_state(id TEXT PRIMARY KEY,value TEXT NOT NULL);`);
  const news = createNewsPersistence(db, { now });
  // Existing provider/news links predate the name registry. Backfill their
  // own scopes and IDs once, without changing links or promoting reputation.
  if (!db.prepare("SELECT 1 FROM intelligence_state WHERE id='entity-name-backfill-v1'").get()) db.transaction(() => {
    const names = db.prepare('SELECT DISTINCT o.scope,e.kind,e.entity id,e.name,o.provider source FROM entity_links e JOIN observations o ON o.id=e.observation').all();
    for (const entity of names) news.registerEntities([entity], entity.scope, entity.source);
    db.prepare('INSERT INTO intelligence_state VALUES(?,?)').run('entity-name-backfill-v1', JSON.stringify({ at: new Date(now()).toISOString(), names: names.length }));
  })();
  const chunk = createObservationWriter(db, news, now);
  const clearLinks=db.prepare('DELETE FROM entity_links WHERE observation=?');
  const putState=db.prepare('INSERT OR REPLACE INTO intelligence_state VALUES(?,?)');
  const writer = isolatedWrites && filePath !== ':memory:' ? createIntelligenceWriter(filePath) : null;
  let flight=Promise.resolve(), writeBarrier=Promise.resolve();
  const ingest = rows => {
    const work=flight.then(async()=>{
      if (writer) return writer.ingest(rows);
      let size = 25;
      for(let i=0;i<rows.length;){
        const batch=rows.slice(i,i+size),start=performance.now();
        chunk(batch); i+=batch.length;
        size=Math.min(200,Math.max(5,Math.floor(size*30/Math.max(1,performance.now()-start))));
        await yieldLoop();
      }
      return rows.length;
    });
    flight=work.catch(()=>{});return work;
  };
  const scopes=owner=>owner?['global',String(owner)]:['global'];
  const scopeSql=owner=>({sql:owner?'o.scope IN (?,?)':'o.scope=?',args:scopes(owner)});
  const { list, detail, publications, entities, status } = createIocIntelligenceReads(db, normalizeIndicator);
  async function ingestNews(rows) {
    await writeBarrier;
    rows=rows.map(row=>row.repository?{...row,malware:[...new Map([...declaredRepositoryMalware({...row,repositoryReport:true}),...(row.malware||[])].map(family=>[family.name.toLowerCase(),family])).values()]}:row);
    const changed=rows.map(row=>({row,key:'news:'+idFor(row.link),hash:idFor(canonicalJsonEvidence(['evidence-v9',row.title,row.pubDate,row.iocs,row.actors,row.malware,row.cves,row.storyId]))}))
      .filter(entry=>db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(entry.key)?.value!==JSON.stringify(entry.hash));
    const replace=db.transaction(entry=>{
      const {row}=entry;
      const existing=db.prepare("SELECT * FROM observations WHERE provider='news' AND scope='global' AND external_id=?").all(row.link);
      const values=new Set(iocValues(row).map(ioc=>normalizeIndicator(ioc.value)?.value).filter(Boolean));
      for(const old of existing){
        const links=db.prepare('SELECT * FROM entity_links WHERE observation=?').all(old.id);
        db.prepare('INSERT INTO observation_revisions(observation,at,payload) VALUES(?,?,?)').run(old.id,new Date(now()).toISOString(),JSON.stringify({...old,entities:links}));
        const value=db.prepare('SELECT value FROM indicators WHERE id=?').get(old.indicator)?.value;
        if(!values.has(value)){clearLinks.run(old.id);db.prepare('DELETE FROM observations WHERE id=?').run(old.id);}
      }
      chunk(iocValues(row).map(ioc=>({...ioc,provider:'news',source:row.source,externalId:row.link,title:row.title,link:row.link,published:row.pubDate,actors:row.actors,malwares:row.malware,cves:(row.cves||[]).map(id=>({id,name:id})),storyId:row.storyId,relation:'mentioned-with'})));
      putState.run(entry.key,JSON.stringify(entry.hash));
    });
    const work=flight.then(async()=>{for(let i=0;i<changed.length;i++){replace(changed[i]);if(i%50===0)await yieldLoop();}});
    flight=work.catch(()=>{});await work;
    putState.run('news-sync',JSON.stringify({lastSuccessfulAt:new Date(now()).toISOString(),publications:rows.length,changed:changed.length}));
  }
  async function replayProviderPayloads(convert) {
    const revision='provider-matches-v12';
    if(db.prepare('SELECT 1 FROM intelligence_state WHERE id=?').get(revision))return 0;
    db.transaction(()=>{
      const stale=db.prepare(`SELECT e.* FROM entity_links e JOIN observations o ON o.id=e.observation WHERE o.provider='MalwareBazaar' AND e.kind='actor'
        AND EXISTS(SELECT 1 FROM entity_links m WHERE m.observation=e.observation AND m.kind='malware' AND lower(m.name)=lower(e.name))`).all();
      for(const link of stale){
        db.prepare('INSERT INTO observation_revisions(observation,at,payload) VALUES(?,?,?)').run(link.observation,new Date(now()).toISOString(),JSON.stringify({retiredSignatureActor:link}));
        db.prepare('DELETE FROM entity_links WHERE observation=? AND kind=? AND entity=?').run(link.observation,link.kind,link.entity);
      }
    })();
    let count=0;
    // Snapshot IDs only; load one saved JSON at a time, with no API calls.
    const ids=db.prepare(`SELECT id FROM observations WHERE provider IN ('OTX','ThreatFox','URLhaus','MalwareBazaar') AND json_type(details,'$.payload')='object'`).all();
    for(const {id} of ids){
      const row=db.prepare('SELECT o.*,i.value FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.id=?').get(id);
      if(!row)continue;
      const payload=JSON.parse(row.details).payload;
      const replacements=convert(row.provider,payload,{scope:row.scope,query:row.value}).map((observation,index)=>({...observation,...(index===0?{payload}:{})}));
      // Atomically replace this provider response; keep revisions and all
      // independent news/provider evidence on the same indicators.
      const work=flight.then(()=>db.transaction(()=>{
        const previous=db.prepare('SELECT * FROM observations WHERE scope=? AND provider=? AND external_id=?').all(row.scope,row.provider,row.external_id);
        for(const old of previous){
          const entities=db.prepare('SELECT * FROM entity_links WHERE observation=?').all(old.id);
          db.prepare('INSERT INTO observation_revisions(observation,at,payload) VALUES(?,?,?)').run(old.id,new Date(now()).toISOString(),JSON.stringify({...old,entities}));
          clearLinks.run(old.id);db.prepare('DELETE FROM observations WHERE id=?').run(old.id);
        }
        chunk(replacements);
      })());
      flight=work.catch(()=>{});await work;count++;await yieldLoop();
    }
    putState.run(revision,JSON.stringify({at:new Date(now()).toISOString(),count}));return count;
  }
  // Correct previously inferred command/protocol labels without discarding
  // provider observations or explicit family attribution.
  function reviewSoftwareLinks(){
    if(db.prepare("SELECT 1 FROM intelligence_state WHERE id='software-links-v10'").get())return;
    db.transaction(()=>{
      for(const link of db.prepare("SELECT * FROM entity_links WHERE kind='malware' AND relation='mentioned-by-source'").all()){
        if(!sanitizeStoredMalware([{name:link.name}],link.name).length){
          db.prepare('INSERT INTO observation_revisions(observation,at,payload) VALUES(?,?,?)').run(link.observation,new Date(now()).toISOString(),JSON.stringify({retiredLink:link}));
          db.prepare('DELETE FROM entity_links WHERE observation=? AND kind=? AND entity=?').run(link.observation,link.kind,link.entity);
        }
      }
      putState.run('software-links-v10',JSON.stringify(true));
    })();
  }
  async function reconcileActorAliases(catalog) {
    const revision='actor-aliases-v1:'+idFor(JSON.stringify(catalog.map(actor=>[actor.id,actor.name,actor.aliases || []])));
    if(db.prepare('SELECT 1 FROM intelligence_state WHERE id=?').get(revision))return {changed:0};
    const owners=new Map(),known=new Set(catalog.map(actor=>actor.id));
    for(const actor of catalog)for(const name of [actor.name,...(actor.aliases || [])]){
      const key=actorNameKey(name),bucket=owners.get(key)||new Map();bucket.set(actor.id,actor);owners.set(key,bucket);
    }
    const work=flight.then(async()=>{
      let changed=0;
      const candidates=db.prepare("SELECT DISTINCT entity,name FROM entity_links WHERE kind='actor'").all();
      const read=db.prepare("SELECT e.*,o.scope,o.provider FROM entity_links e JOIN observations o ON o.id=e.observation WHERE e.kind='actor' AND e.entity=? AND e.name=? LIMIT 200");
      const retire=db.prepare("DELETE FROM entity_links WHERE observation=? AND kind='actor' AND entity=?");
      const revise=db.prepare('INSERT INTO observation_revisions(observation,at,payload) VALUES(?,?,?)');
      const registered=new Set();
      const update=db.transaction((rows,actor)=>{
        for(const row of rows){
          revise.run(row.observation,new Date(now()).toISOString(),JSON.stringify({reason:'actor-alias-reconciliation',previousLink:{kind:row.kind,entity:row.entity,name:row.name,relation:row.relation},canonicalActor:actor.id}));
          db.prepare('INSERT OR IGNORE INTO entity_links VALUES(?,?,?,?,?)').run(row.observation,'actor',actor.id,actor.name,row.relation);
          retire.run(row.observation,row.entity);
          const registryKey=JSON.stringify([row.scope,row.provider,actor.id]);
          if(!registered.has(registryKey)){news.registerEntities([{...actor,kind:'actor'}],row.scope,row.provider);registered.add(registryKey);}
          changed++;
        }
      });
      for(const candidate of candidates){
        // Catalog actors retain their identities, including subgroups. Only
        // source-created identities with one exact alias owner are canonicalized.
        if(known.has(candidate.entity))continue;
        const matches=owners.get(actorNameKey(candidate.name));if(matches?.size!==1)continue;
        const actor=[...matches.values()][0];
        for(let rows=read.all(candidate.entity,candidate.name);rows.length;rows=read.all(candidate.entity,candidate.name)){
          update(rows,actor);await yieldLoop();
        }
      }
      putState.run(revision,JSON.stringify({at:new Date(now()).toISOString(),changed}));return {changed};
    });
    flight=work.catch(()=>{});return work;
  }
  return {ingest,list,detail,publications,replayProviderPayloads,news,watchSuggestions:createWatchSuggestions(db),phishing:createPhishingEvolution(db,{now}),
    deferWritesUntil: promise => { writeBarrier=Promise.resolve(promise); flight=flight.then(()=>writeBarrier); },
    exportRows:({owner='',from,to})=>{
      const scope=scopeSql(owner);
      return db.prepare(`SELECT o.*,i.value,i.type,(SELECT json_group_array(json_object('kind',e.kind,'id',e.entity,'name',e.name)) FROM entity_links e WHERE e.observation=o.id) entities FROM observations o JOIN indicators i ON i.id=o.indicator WHERE ${scope.sql} AND o.published>=? AND o.published<=? ORDER BY o.published DESC,o.id`).all(...scope.args,from,to).map(row=>{
        const details=JSON.parse(row.details),entities=JSON.parse(row.entities);
        return {type:row.type,indicator:row.value,title:details.title,source:row.provider,url:details.link,date:row.published,dateBasis:'source-observation',storyId:details.storyId||'',categories:[],
          actors:entities.filter(entity=>entity.kind==='actor').map(entity=>entity.name),malware:entities.filter(entity=>entity.kind==='malware').map(entity=>entity.name),cves:entities.filter(entity=>entity.kind==='cve').map(entity=>entity.id)};
      });
    },
    ingestNews,reviewSoftwareLinks,reconcileActorAliases,
    families:owner=>entities('malware',owner),entities,
    state:key=>{const row=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(key);return row?JSON.parse(row.value):null;},
    setState:(key,value)=>putState.run(key,JSON.stringify(value)),
    status,
    close:async()=>{ if (writer) await writer.close(); db.close(); }};
}
