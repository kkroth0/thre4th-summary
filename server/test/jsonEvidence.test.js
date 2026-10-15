import test from 'node:test';
import assert from 'node:assert/strict';
import { equalJsonEvidence, canonicalJsonEvidence } from '../jsonEvidence.js';
import { mergeIntoStories } from '../newsStories.js';
import { createNewsArchiveStore } from '../newsArchiveStore.js';
import { createIocIntelligence } from '../iocIntelligence.js';

const now = new Date('2026-10-15T12:00:00Z');
const article = () => ({ link: 'https://research.example/paper', title: 'APT42 Gateway research', source: 'Research', pubDate: now.toISOString(),
  contentHash: 'body-hash', extractionVersion: 'feed-v13', actors: [{ id: 'G1', name: 'APT42', matched: 'APT42', via: 'name' }],
  vendors: [{ id: 'vendor', name: 'Vendor', matched: 'Gateway' }], cves: [], malware: [], campaigns: [], iocs: { ips: ['9.9.9.10'], domains: ['attacker.example'], hashes: ['a'.repeat(64)], urls: [] },
  score: 60, severity: 'High', newsCategories: ['Malware'], primaryCategory: 'Malware' });
const stored = value => JSON.parse(canonicalJsonEvidence(value));

test('JSON evidence ignores object key order and omitted properties but preserves array order and actual changes', () => {
  assert.equal(equalJsonEvidence({ a: [{ id: 'one', name: 'Actor', optional: undefined }], b: 0 }, { b: 0, a: [{ name: 'Actor', id: 'one' }] }), true);
  for (const [left, right] of [[{ a: null }, {}], [[1, 2], [2, 1]], [{ a: '1' }, { a: 1 }], [[,], [7]], [{ a: [] }, { a: null }]]) assert.equal(equalJsonEvidence(left, right), false);
  assert.equal(equalJsonEvidence([undefined], [null]), true);
  assert.equal(canonicalJsonEvidence({ b: 0, a: [{ name: 'Actor', id: 'one' }] }), canonicalJsonEvidence({ a: [{ id: 'one', name: 'Actor' }], b: 0 }));
});

test('a SQLite-shaped event reuses the same story and source when extraction only changes object key order', () => {
  const input = article(), events = stored(mergeIntoStories([], [input], now));
  const replay = mergeIntoStories(events, [input], now);
  assert.equal(replay[0], events[0], 'must not remove, split, compare or rebuild identical evidence after SQLite reload');
  assert.equal(replay[0].sources[0], events[0].sources[0]);
  const changed = mergeIntoStories(events, [{ ...input, iocs: { ...input.iocs, hashes: ['b'.repeat(64)] } }], now);
  assert.deepEqual(changed[0].sources[0].iocs.hashes, ['b'.repeat(64)]);
});

test('a canonical archive does not rewrite unchanged rows, and still persists a real evidence revision', () => {
  const input = article(), original = createNewsArchiveStore({ initialRows: [], writeJsonAtomic: () => {} }); original.add([input]);
  let writes = 0;
  const archive = createNewsArchiveStore({ initialRows: stored(original.all()), writeJsonAtomic: () => writes++ });
  const before = archive.all(); archive.add([input]); assert.equal(writes, 0); assert.equal(archive.all(), before);
  archive.add([{ ...input, actors: [{ ...input.actors[0], name: 'New attribution' }] }]);
  assert.equal(writes, 1); assert.equal(archive.all()[0].actors[0].name, 'New attribution');
});

test('inventory fingerprints do not re-ingest equal canonical evidence or create redundant observation revisions', async () => {
  const inventory = createIocIntelligence();
  try {
    const input = article(); await inventory.ingestNews([input]);
    await inventory.ingestNews([stored(input)]);
    assert.equal(inventory.state('news-sync').changed, 0);
    await inventory.ingestNews([{ ...stored(input), iocs: { ...input.iocs, hashes: ['b'.repeat(64)] } }]);
    assert.equal(inventory.state('news-sync').changed, 1);
    assert.ok(inventory.detail('b'.repeat(64), 'owner').evidence.length);
  } finally { inventory.close(); }
});
