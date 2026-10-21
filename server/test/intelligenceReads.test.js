import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { createIocIntelligence } from '../iocIntelligence.js';
import { createIntelligenceReads, optimizeIntelligenceReads } from '../intelligenceReads.js';
import { buildActorActivity, actorPublications } from '../actorEvidence.js';

async function fixture(t, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intelligence-read-'));
  const filePath = path.join(dir, 'inventory.sqlite');
  const store = createIocIntelligence({ filePath });
  const reader = createIntelligenceReads({ filePath, ...options });
  t.after(async () => { await reader.close(); store.close(); fs.rmSync(filePath, { force: true }); });
  const rows = [
    { value: '8.8.8.8', provider: 'OTX', externalId: 'pulse', link: 'https://otx.alienvault.com/pulse/one', actors: [{ id: 'actor', name: 'Actor' }] },
    { value: '9.9.9.9', provider: 'OTX', externalId: 'pulse', link: 'https://otx.alienvault.com/pulse/one', malwares: [{ id: 'family', name: 'Family' }] },
    { value: '1.1.1.1', provider: 'Axur', externalId: 'private', scope: 'one', link: 'https://source.example/report', actors: [{ id: 'private-one', name: 'Private One' }] },
    { value: '4.4.4.4', provider: 'Axur', externalId: 'other', scope: 'two', link: 'https://source.example/other', actors: [{ id: 'private-two', name: 'Private Two' }] },
  ];
  await store.ingest(rows);
  return { store, reader, filePath };
}

test('isolated provider writes preserve all evidence, aliases and scopes across news revisions and independent connections', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intelligence-write-'));
  const filePath = path.join(dir, 'inventory.sqlite');
  const store = createIocIntelligence({ filePath, isolatedWrites: true });
  t.after(async () => { await store.close(); fs.rmSync(filePath, { force: true }); });
  const rows = Array.from({ length: 350 }, (_, i) => ({ value: `8.8.${Math.floor(i/250)}.${i%250+1}`, provider: 'OTX', scope: 'one',
    externalId: String(i), link: 'https://source.example/report', actors: [{ id: 'actor', name: 'Actor', aliases: ['Alias One'] }] }));
  let served = false; setImmediate(() => { served = true; });
  await store.ingest(rows);
  assert.equal(served, true);
  assert.equal(store.status('one').evidence, 350);
  assert.equal(store.status('two').evidence, 0);
  await store.ingestNews([{ link: 'https://news.example/post', title: 'News', pubDate: new Date().toISOString(), source: 'News', iocs: { ips: ['8.8.8.8'] }, actors: [{ id: 'actor', name: 'Actor' }] }]);
  assert.equal(store.status('one').evidence, 351);
  const independent = new Database(filePath, { readonly: true });
  assert.equal(independent.prepare('SELECT COUNT(*) n FROM observations').get().n, 351);
  assert.ok(independent.prepare("SELECT 1 FROM intelligence_entity_names WHERE scope='one' AND alias='alias one'").get());
  independent.close();
});

test('isolated reads retain the exact scoped evidence and keep the main event loop available', async t => {
  const { store, reader } = await fixture(t, { ttl: 0 });
  let served = false;
  setImmediate(() => { served = true; });
  assert.deepEqual(await reader.query('entities', { kind: 'actor', owner: 'one' }), store.entities('actor', 'one'));
  assert.equal(served, true);
  for (const owner of ['', 'one', 'two']) {
    assert.deepEqual(await reader.query('status', { owner }), store.status(owner));
    assert.deepEqual(await reader.query('publications', { owner }), store.publications({ owner }));
    assert.deepEqual(await reader.query('list', { owner, size: 2 }), store.list({ owner, size: 2 }));
    assert.deepEqual(await reader.query('detail', { owner, value: '1.1.1.1' }), store.detail('1.1.1.1', owner));
    const sources = store.publications({ owner });
    const activity = await reader.query('actorActivity', { owner, archive: [], stories: [] });
    assert.deepEqual(activity, buildActorActivity(actorPublications(sources, [])));
  }
  // Grouping a shared pulse must retain its co-mentioned infrastructure too.
  assert.equal((await reader.query('actorActivity', { owner: 'one', archive: [], stories: [] })).actor.ips, 2);
});

test('read cache coalesces identical calls, isolates accounts, and observes new commits after invalidation', async t => {
  const { store, reader } = await fixture(t);
  const first = reader.query('entities', { owner: 'one', kind: 'actor' });
  assert.equal(reader.query('entities', { owner: 'one', kind: 'actor' }), first);
  const data = await first;
  assert.equal(await reader.query('entities', { owner: 'one', kind: 'actor' }), data);
  const other = await reader.query('entities', { owner: 'two', kind: 'actor' });
  assert.equal(other.some(row => row.id === 'private-one'), false);
  await store.ingest([{ value: '8.8.4.4', scope: 'one', actors: [{ id: 'new', name: 'New Actor' }] }]);
  const fresh = await reader.query('entities', { owner: 'one', kind: 'actor' }, { revision: 'changed' });
  assert.equal(fresh.some(row => row.id === 'new'), true);
});

test('additive covering index preserves counts and page contents across private/shared duplicates', async t => {
  const { store, reader, filePath } = await fixture(t, { ttl: 0 });
  await store.ingest([{ value: '8.8.8.8', provider: 'Axur', scope: 'one', externalId: 'overlap' }]);
  const previous = store.list({ owner: 'one' }), status = store.status('one');
  await optimizeIntelligenceReads(filePath);
  const canonical = data => ({ ...data, items: data.items.map(row => ({ ...row, providers: row.providers.slice().sort(), entities: row.entities.slice().sort((a,b) => a.id.localeCompare(b.id)) })) });
  assert.deepEqual(canonical(await reader.query('list', { owner: 'one' })), canonical(previous));
  assert.deepEqual(await reader.query('status', { owner: 'one' }), status);
  assert.deepEqual(await reader.query('list', { owner: 'one', page: 2, size: 1 }), store.list({ owner: 'one', page: 2, size: 1 }));
  await optimizeIntelligenceReads(filePath);
  const db = new Database(filePath, { readonly: true });
  const plan = db.prepare("EXPLAIN QUERY PLAN SELECT COUNT(DISTINCT indicator) FROM observations INDEXED BY observations_inventory WHERE scope=?").all('one');
  assert.ok(plan.some(row => /COVERING INDEX observations_inventory/.test(row.detail)));
  db.close();
});

test('write preparation barrier queues evidence without losing aliases or overlapping sources', async t => {
  const { store } = await fixture(t);
  let release;
  store.deferWritesUntil(new Promise(resolve => { release = resolve; }));
  const pending = store.ingest(Array.from({ length: 350 }, (_, i) => ({ value: '8.8.4.4', provider: i % 2 ? 'OTX' : 'Axur', externalId: String(i),
    scope: 'one', actors: [{ id: 'new', name: 'New Actor', aliases: i % 2 ? ['Alias One'] : ['Alias Two'] }] })));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(store.detail('8.8.4.4', 'one'), null);
  release(); await pending;
  assert.equal(store.detail('8.8.4.4', 'one').total, 350);
  assert.equal(store.detail('8.8.4.4', 'two'), null);
  const aliases = store.news.entities({ owner: 'one', kind: 'actor', id: 'new' })[0].aliases;
  assert.ok(aliases.includes('alias one') && aliases.includes('alias two'));
});
