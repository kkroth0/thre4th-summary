import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { createNewsPersistence, durableArticleCache } from '../newsPersistence.js';
import { createIocIntelligence } from '../iocIntelligence.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const publication = { link: 'https://research.example/report', title: 'Report', contentHash: 'original', phishingIntel: { detected: true, evidence: [{ field: 'body', snippet: 'original evidence' }] }, actors: [{ id: 'G1', name: 'One', aliases: ['Alias'] }], iocs: { hashes: ['a'.repeat(64)] } };
const story = { id: 'ST1', aliases: ['ST0'], sources: [{ link: publication.link, iocs: publication.iocs }] };

test('shadow migration retains exact identities, aliases, body evidence and immutable revisions', () => {
  const db = new Database(':memory:'), store = createNewsPersistence(db);
  const snapshot = { archive: [publication], stories: [story] };
  assert.equal(store.reconcile(snapshot).readyForReadPilot, true);
  assert.deepEqual(store.rows('archive'), [publication]); assert.deepEqual(store.rows('stories'), [story]);
  assert.equal(store.reconcile(snapshot).changed, 0); assert.equal(store.status().revisions, 0);
  store.reconcile({ archive: [{ ...publication, contentHash: 'corrected' }], stories: [{ ...story, aliases: ['ST0', 'ST2'] }] });
  assert.equal(store.status().revisions, 2);
  assert.equal(JSON.parse(db.prepare("SELECT payload FROM news_document_revisions WHERE kind='archive'").get().payload).phishingIntel.evidence[0].snippet, 'original evidence');
  assert.equal(store.compare(snapshot.archive, snapshot.stories).equal, false); db.close();
});

test('a failed story write rolls back the publication and all revisions in the same transaction', () => {
  const db = new Database(':memory:'), store = createNewsPersistence(db);
  store.reconcile({ archive: [publication], stories: [story] });
  db.exec("CREATE TRIGGER fail_story BEFORE INSERT ON news_documents WHEN NEW.kind='stories' BEGIN SELECT RAISE(ABORT,'disk simulation'); END");
  assert.throws(() => store.reconcile({ archive: [{ ...publication, title: 'changed' }], stories: [{ ...story, aliases: [] }] }), /disk simulation/);
  assert.equal(store.rows('archive')[0].title, 'Report'); assert.equal(store.status().revisions, 0); db.close();
});

test('retention removes only current story copies and duplicate identities are rejected before writes', () => {
  const db = new Database(':memory:'), store = createNewsPersistence(db);
  store.reconcile({ archive: [publication], stories: [story] });
  store.reconcile({ archive: [publication], stories: [] });
  assert.equal(store.rows('archive').length, 1); assert.equal(store.rows('stories').length, 0); assert.equal(store.status().revisions, 1);
  assert.throws(() => store.reconcile({ archive: [publication, publication], stories: [] }), /duplicate/);
  assert.equal(store.rows('archive').length, 1); db.close();
});

test('orphan sources and colliding event aliases prevent a read pilot even when copies are identical', () => {
  const db = new Database(':memory:'), store = createNewsPersistence(db);
  const result = store.reconcile({ archive: [publication], stories: [story, { id: 'ST3', aliases: ['ST0'], sources: [{link:'https://missing.example/'}] }] });
  assert.equal(result.equal, true); assert.equal(result.readyForReadPilot, false); assert.equal(result.orphanSources, 1); assert.equal(result.conflictingAliases, 1); db.close();
});

test('body revisions survive cache eviction while failed fingerprints never reuse unrelated retained text', () => {
  const db = new Database(':memory:'), store = createNewsPersistence(db), entries = new Map();
  const cache = durableArticleCache({get: key => entries.get(key), set: (key,value) => entries.set(key,value)}, store);
  cache.set(publication.link, { text: 'body one', fingerprint:'one', collectedAt:'2026-10-14T10:00:00Z' });
  cache.set(publication.link, { text: 'body two', fingerprint:'two', collectedAt:'2026-10-15T10:00:00Z' });
  entries.clear(); assert.equal(cache.get(publication.link).text, 'body two'); assert.equal(store.status().bodies, 2);
  cache.set(publication.link, {fingerprint:'changed',error:'failed'}); assert.equal(cache.get(publication.link).text, undefined);
  assert.equal(store.body(publication.link).text, 'body two'); db.close();
});

test('entity aliases preserve ambiguity and private provider names never cross owners', async () => {
  const store = createIocIntelligence();
  store.news.registerEntities([{kind:'actor',id:'G1',name:'One',aliases:['Shared']},{kind:'actor',id:'G2',name:'Two',aliases:['Shared']}]);
  await store.ingest([{value:'9.9.9.9',scope:'owner-one',provider:'OTX',actors:[{id:'private',name:'Hidden actor',aliases:['Private alias']}]}]);
  assert.equal(store.news.entities({owner:'owner-one',query:'shared'}).length,2);
  assert.equal(store.news.entities({owner:'owner-one',query:'private alias'}).length,1);
  assert.equal(store.news.entities({owner:'owner-two',query:'private alias'}).length,0);
  store.close();
});

test('legacy provider links backfill into the name registry after restart with their original private scope', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(),'news-entity-backfill-')), filePath = path.join(directory,'inventory.sqlite');
  let store = createIocIntelligence({filePath});
  try {
    await store.ingest([{value:'9.9.9.9',scope:'private-owner',provider:'OTX',malwares:[{id:'private-family',name:'PrivateFamily'}]}]);
    store.close(); store = null;
    const legacy = new Database(filePath);
    legacy.exec("DELETE FROM intelligence_entity_names; DELETE FROM intelligence_state WHERE id='entity-name-backfill-v1'"); legacy.close();
    store = createIocIntelligence({filePath});
    assert.equal(store.news.entities({owner:'private-owner',query:'PrivateFamily'}).length,1);
    assert.equal(store.news.entities({owner:'another-owner',query:'PrivateFamily'}).length,0);
    assert.equal(store.state('entity-name-backfill-v1').names,1);
    assert.equal(store.detail('9.9.9.9','private-owner').evidence[0].entities[0].id,'private-family');
  } finally {
    store?.close();
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(filePath+suffix,{force:true});
    fs.rmdirSync(directory);
  }
});
