import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { createIocIntelligence } from '../iocIntelligence.js';
import { createIocIntelligenceReads } from '../iocIntelligenceReads.js';
import { backfillActorObservationIndex } from '../actorObservationIndex.js';
import { normalizeIndicator } from '../indicatorIdentity.js';

test('legacy actor projection is lossless, scoped and independent of large IOC payloads',()=>{
  const db=new Database(':memory:');
  db.exec(`CREATE TABLE indicators(id TEXT PRIMARY KEY,type TEXT,value TEXT);
    CREATE TABLE observations(id TEXT PRIMARY KEY,indicator TEXT,scope TEXT,provider TEXT,external_id TEXT,published TEXT,collected TEXT,details TEXT);
    CREATE TABLE entity_links(observation TEXT,kind TEXT,entity TEXT,name TEXT,relation TEXT,PRIMARY KEY(observation,kind,entity));
    CREATE INDEX entity_lookup ON entity_links(kind,entity,observation);
    CREATE TABLE intelligence_state(id TEXT PRIMARY KEY,value TEXT);`);
  db.prepare('INSERT INTO indicators VALUES(?,?,?)').run('ip','ip','8.8.8.8');
  const put=db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)');
  db.transaction(()=>{for(let i=0;i<15000;i++)put.run(String(i),'ip','owner','Axur','ioc:'+i,'2026-10-01','2026-10-01',JSON.stringify({payload:'x'.repeat(1024)}));})();
  put.run('actor-one','ip','owner','Axur','insight:1','2026-10-02','2026-10-02',JSON.stringify({link:'https://source.example/one',title:'Private report',source:'Axur'}));
  put.run('actor-two','ip','other','Axur','insight:2','2026-10-02','2026-10-02',JSON.stringify({link:'https://source.example/two',title:'Other report',source:'Axur'}));
  const link=db.prepare('INSERT INTO entity_links VALUES(?,?,?,?,?)');link.run('actor-one','actor','G0007','APT28','mentioned-with');link.run('actor-two','actor','G0007','APT28','mentioned-with');
  const reads=createIocIntelligenceReads(db,normalizeIndicator),before=reads.publications({owner:'owner',kind:'actor'});
  backfillActorObservationIndex(db);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM observations').get().n,15002);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM actor_observations').get().n,2);
  // The fast path must never deserialize provider payload JSON, regardless of inventory size.
  db.function('json_extract',{varargs:true},()=>{throw Error('Actor read touched a provider payload');});
  assert.deepEqual(reads.publications({owner:'owner',kind:'actor'}),before);
  assert.equal(reads.entities('actor','owner').length,1);
  assert.deepEqual([...reads.actorActivityRows('owner')].map(row=>row.link),['https://source.example/one']);
  assert.equal(reads.entities('actor','outsider').length,0);
  db.close();
});

test('replaying or revising an observation updates projection atomically and does not lend another IOC an actor',async t=>{
  const store=createIocIntelligence();t.after(()=>store.close());
  const row={value:'8.8.8.8',provider:'Axur',externalId:'report',link:'https://source.example/report',actors:[{id:'G0007',name:'APT28'}]};
  await store.ingest([row,row,{...row,value:'9.9.9.9',actors:[],malwares:[{id:'malware',name:'Malware'}]}]);
  assert.equal(store.publications({kind:'actor',id:'G0007'})[0].iocs.ips.length,1);
  assert.equal([...store.actorActivityRows()].length,1);
  await store.ingest([{...row,actors:[]}]);
  assert.deepEqual(store.publications({kind:'actor',id:'G0007'}),[]);
  assert.deepEqual(store.entities('actor'),[]);
  assert.equal(store.status('').indicators,2);
});
