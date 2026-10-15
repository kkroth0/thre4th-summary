import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createNewsPersistence } from '../newsPersistence.js';
import { createSqliteNewsStores } from '../sqliteNewsStores.js';
import { createNewsArchiveStore } from '../newsArchiveStore.js';
import { createStoryStore } from '../newsStoryStore.js';
import { publishNewsSnapshot } from '../publishNewsSnapshot.js';
import { createIocIntelligence } from '../iocIntelligence.js';

const now = new Date('2026-10-15T12:00:00Z');
const row = (id = 'one') => ({ link: `https://research.example/${id}`, title: `Unique ${id} investigation`, pubDate: now.toISOString(),
  actors: [{ id: 'G1', name: 'APT42', aliases: ['Alias42'] }], iocs: { ips: ['9.9.9.10'], hashes: ['a'.repeat(64)] }, cves: [], malware: [], campaigns: [] });
const legacy = (archive = [], stories = []) => ({
  archive: createNewsArchiveStore({ initialRows: archive, writeJsonAtomic: () => {} }),
  stories: createStoryStore({ initialRows: stories, writeJsonAtomic: () => {} }),
});

test('cutover requires three valid shadow checks and preserves event ordering and aliases', () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  const archive = [row()], stories = [{ id: 'Z', aliases: ['OLD'], sources: [{ link: row().link }] }, { id: 'A', sources: [] }];
  persistence.reconcile({ archive, stories });
  assert.equal(persistence.activate({ archive, stories }), false);
  persistence.reconcile({ archive, stories }); persistence.reconcile({ archive, stories });
  assert.equal(persistence.activate({ archive, stories }), true);
  const stores = createSqliteNewsStores({ persistence, ...legacy() });
  assert.deepEqual(stores.stories.all(), stories);
  assert.equal(stores.stories.get('OLD').id, 'Z');
  assert.equal(stores.archive.all()[0].iocs.hashes.length, 1);
  assert.equal(persistence.status().mode, 'sqlite');
  assert.throws(() => persistence.reconcile({ archive: [], stories: [] }), /cannot overwrite/);
  db.close();
});

test('publication failure rolls back both stores, revisions and generation, then the queue recovers', async () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  const stores = createSqliteNewsStores({ persistence, ...legacy() });
  await publishNewsSnapshot([row()], { ...stores, now });
  const before = persistence.readSnapshot(), revisions = persistence.status().revisions;
  db.exec("CREATE TRIGGER reject_news BEFORE INSERT ON news_documents WHEN NEW.kind='stories' BEGIN SELECT RAISE(ABORT,'simulated failure'); END");
  await assert.rejects(publishNewsSnapshot([row('two')], { ...stores, now }), /simulated failure/);
  assert.deepEqual(persistence.readSnapshot(), before);
  assert.equal(stores.archive.size(), 1); assert.equal(persistence.status().revisions, revisions);
  db.exec('DROP TRIGGER reject_news');
  await publishNewsSnapshot([row('two')], { ...stores, now });
  assert.equal(stores.archive.size(), 2); db.close();
});

test('concurrent publications are serialized without losing per-source evidence', async () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  const stores = createSqliteNewsStores({ persistence, ...legacy() });
  await Promise.all(['one', 'two', 'three'].map(id => publishNewsSnapshot([row(id)], { ...stores, now })));
  assert.equal(stores.archive.size(), 3);
  assert.equal(new Set(stores.stories.all().flatMap(story => story.sources.map(source => source.link))).size, 3);
  assert.equal(persistence.compare(stores.archive.all(), stores.stories.all()).readyForReadPilot, true);
  assert.equal(persistence.generation(), 4); db.close();
});

test('failed JSON backup cannot erase committed SQLite data, including after a disk restart', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sqlite-news-restart-')), file = path.join(directory, 'news.sqlite');
  let db = new Database(file);
  try {
    let persistence = createNewsPersistence(db);
    const stores = createSqliteNewsStores({ persistence, ...legacy(), writeBackup: () => { throw Error('disk full'); } });
    await publishNewsSnapshot([row()], { ...stores, now });
    assert.equal(persistence.status().backup.ok, false);
    db.close(); db = new Database(file); persistence = createNewsPersistence(db);
    let recovered;
    const restarted = createSqliteNewsStores({ persistence, ...legacy(), writeBackup: snapshot => { recovered = snapshot; } });
    assert.equal(restarted.archive.size(), 1); assert.equal(recovered.archive[0].link, row().link);
    assert.equal(persistence.status().backup.ok, true);
    assert.equal(restarted.stories.all()[0].sources[0].iocs.hashes[0], 'a'.repeat(64));
  } finally { db.close(); for (const suffix of ['', '-wal', '-shm']) fs.rmSync(file + suffix, { force: true }); fs.rmdirSync(directory); }
});

test('corrupt SQLite payload or manifest fails closed instead of reimporting empty JSON', () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  createSqliteNewsStores({ persistence, ...legacy([row()]) });
  db.exec("UPDATE news_documents SET payload='{}' WHERE kind='archive'");
  assert.throws(() => createSqliteNewsStores({ persistence, ...legacy() }), /integrity/);
  assert.equal(persistence.rows('archive').length, 1); db.close();
});

test('a missing manifest entry is detected even when document payloads remain valid', () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  createSqliteNewsStores({ persistence, ...legacy([row()]) });
  db.prepare("UPDATE news_storage_state SET payload=? WHERE id='order'").run(JSON.stringify({ archive: [], stories: [] }));
  assert.throws(() => createSqliteNewsStores({ persistence, ...legacy() }), /manifest integrity/);
  db.close();
});

test('a publication cannot be owned by two events and the rejection keeps its original snapshot', () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  createSqliteNewsStores({ persistence, ...legacy([row()]) });
  const before = persistence.readSnapshot();
  assert.throws(() => persistence.commit({ ...before, stories: ['A', 'B'].map(id => ({ id, sources: [{ link: row().link }] })) }, before.generation), /conflicting identities/);
  assert.deepEqual(persistence.readSnapshot(), before); db.close();
});

test('relationship rejection and stale generation leave the previous complete snapshot intact', () => {
  const db = new Database(':memory:'), persistence = createNewsPersistence(db);
  createSqliteNewsStores({ persistence, ...legacy([row()]) });
  const before = persistence.readSnapshot();
  assert.throws(() => persistence.commit({ archive: [], stories: [{ id: 'orphan', sources: [{ link: row().link }] }] }, before.generation), /orphan/);
  assert.deepEqual(persistence.readSnapshot(), before);
  persistence.commit(before, before.generation);
  assert.throws(() => persistence.commit(before, before.generation), /retry required/);
  assert.equal(persistence.readSnapshot().generation, before.generation + 1); db.close();
});

test('published news enters the IOC inventory with actor evidence and survives read cutover', async () => {
  const inventory = createIocIntelligence();
  const stores = createSqliteNewsStores({ persistence: inventory.news, ...legacy() });
  await publishNewsSnapshot([row()], { ...stores, now });
  await inventory.ingestNews(stores.archive.all());
  const detail = inventory.detail('9.9.9.10', 'owner');
  assert.ok(detail.evidence.some(source => source.entities.some(entity => entity.id === 'G1')));
  assert.equal(inventory.news.entities({ query: 'Alias42' })[0].id, 'G1');
  const restarted = createSqliteNewsStores({ persistence: inventory.news, ...legacy() });
  assert.equal(restarted.archive.all()[0].storyId, stores.stories.all()[0].id);
  inventory.close();
});
