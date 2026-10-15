import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { createIocIntelligence } from '../iocIntelligence.js';
import { auditNewsInventory } from '../newsInventoryAudit.js';
const publication = { link: 'https://research.example/report', title: 'Actor A delivers malware', source: 'Research', pubDate: '2026-10-15', actors: [{ id: 'A', name: 'Actor A' }], malware: [{ id: 'M', name: 'Malware M' }], cves: ['CVE-2026-12345'], iocs: { ips: ['8.8.8.8', '8.8.8.8'], domains: ['bad[.]example.org'] } };
async function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'news-inventory-audit-')), filePath = path.join(directory, 'data.sqlite');
  const store = createIocIntelligence({ filePath });
  const archive = [publication, { ...publication, link: 'https://another.example/no-iocs', score: 0, iocs: {}, actors: [{ id: 'B', name: 'Actor B' }] }];
  store.news.reconcile({ archive, stories: [] }); await store.ingestNews(archive);
  const db = new Database(filePath);
  return { store, db, archive, close: () => { db.close(); store.close(); fs.rmSync(directory, { recursive: true, force: true }); } };
}
test('all accepted news feeds inventory and entity names, including low-score news without IOCs', async () => {
  const f = await fixture(); f.db.pragma('query_only=ON');
  const result = auditNewsInventory(f.db, f.archive);
  assert.equal(result.passed, true); assert.equal(result.publications, 2); assert.equal(result.processedPublications, 2);
  assert.equal(result.publicationsWithIocs, 1); assert.equal(result.validIocMentions, 2); assert.equal(result.expectedEntityLinks, 6);
  f.close();
});
test('missing entity links and skipped publications are visible even when snapshots are structurally valid', async () => {
  const f = await fixture();
  f.db.prepare("DELETE FROM entity_links WHERE kind='actor'").run();
  f.db.prepare("DELETE FROM intelligence_state WHERE id LIKE 'news:%'").run();
  const result = auditNewsInventory(f.db, f.archive);
  assert.equal(result.passed, false); assert.equal(result.missingEntityLinks, 2); assert.equal(result.missingPublicationStates, 2); f.close();
});
test('foreign-account evidence cannot mask a missing global news observation', async () => {
  const f = await fixture();
  await f.store.ingest([{ value: '9.9.9.9', provider: 'news', externalId: publication.link, scope: 'other-owner', actors: publication.actors }]);
  const changed = [{ ...publication, iocs: { ips: ['9.9.9.9'] } }];
  const result = auditNewsInventory(f.db, changed);
  assert.equal(result.missingObservations, 1); assert.equal(result.staleObservations, 2); assert.equal(result.passed, false); f.close();
});
