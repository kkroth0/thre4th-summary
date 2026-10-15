import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createIocIntelligence } from '../iocIntelligence.js';
import { createPhishWatchStore } from '../phishingWatch.js';
import { buildPhishingWeeks, summarizePhishingWeeks } from '../phishingEvolution.js';
import { evaluateCtBacktest } from '../phishingCtBacktest.js';
import { PHISHING_VERSION } from '../phishingIntel.js';
import Database from 'better-sqlite3';
import { createPhishingEvolution } from '../phishingEvolution.js';

const at = new Date('2026-10-14T12:00:00Z');
const row = (id, extra = {}) => ({ link: `https://source.example/${id}`, title: 'ClickFix credential phishing campaign', description: 'Attackers targeted victims with phishing',
  pubDate: '2026-10-06T12:00:00Z', storyId: 'event-1', extractionVersion: 'feed-v13', phishingIntel: { version: PHISHING_VERSION, detected: true, techniques: ['ClickFix'], primaryTechnique: 'ClickFix', vectors: [], sectors: [], regions: [], brands: ['Bank'], kits: [], ttps: [], evidence: [] }, ...extra });

test('weekly event identity deduplicates coverage but never collapses different incidents sharing a campaign', () => {
  const weeks = buildPhishingWeeks([row('a'), row('b'), row('c', { storyId: 'event-2', campaigns: [{ id: 'reported:x', name: 'ClickFix' }] }), row('d', { dateInferred: true }), row('future', { pubDate: '2027-01-01' })], { now: at });
  const week = weeks.find(week => week.week === '2026-10-04');
  assert.equal(week.publications, 3); assert.equal(week.events, 2); assert.equal(week.facets.technique[0].count, 2); assert.equal(week.sources, 1);
  assert.equal(week.members.length, 3); assert.equal(week.bodyCoverage.unknown, 3);
});
test('Sunday UTC boundaries, partial week and unavailable history never fabricate baseline or percentages', () => {
  const weeks = buildPhishingWeeks([row('saturday', { pubDate: '2026-10-10T23:59:59Z' }), row('sunday', { pubDate: '2026-10-11T00:00:00Z' })], { now: at });
  assert.equal(weeks.at(-1).closed, false); assert.equal(weeks.at(-1).publications, 1);
  const summary = summarizePhishingWeeks(weeks); assert.equal(summary.baselineReady, false); assert.equal(summary.signals[0].percent, null);
});
test('legacy null campaign entries cannot prevent the production weekly snapshot', () => {
  const weeks = buildPhishingWeeks([row('legacy', { campaigns: [null, { id: 'reported:one', name: 'Named campaign' }] })], { now: at });
  const week = weeks.find(week => week.week === '2026-10-04');
  assert.equal(week.publications, 1); assert.equal(week.facets.campaign.length, 1); assert.equal(week.facets.campaign[0].label, 'Named campaign');
});

test('kit rule changes preserve archived incident classification when only a summary remains', () => {
  const cached = row('body-only', { title: 'Research findings', description: 'Summary without incident details' });
  cached.phishingIntel = { ...cached.phishingIntel, kits: ['AI-powered', 'Australia', 'Blue'], evidence: [{ kind: 'classification', label: 'Phishing', field: 'body', term: 'phishing', snippet: 'Attackers deploy phishing kit called NovelBrand to steal credentials.' }] };
  const week = buildPhishingWeeks([cached], { now: at }).find(week => week.week === '2026-10-04');
  assert.equal(week.events, 1); assert.equal(week.publications, 1);
  assert.deepEqual(week.facets.malware.map(item => item.label), ['NovelBrand']);
  assert.equal(week.rules.phishing, PHISHING_VERSION); assert.equal(week.rules.phishingKits, 'phishing-kits-v2');
});
test('baseline uses eight comparable closed weeks and never a partial current week', () => {
  const rows = Array.from({ length: 9 }, (_, i) => row('week-' + i, { pubDate: new Date(Date.parse('2026-08-09T00:00:00Z') + i * 7 * 86400000).toISOString() }));
  rows.push(row('extra', { storyId: 'second-incident' }));
  const weeks = buildPhishingWeeks(rows, { now: at }), summary = summarizePhishingWeeks(weeks);
  assert.equal(summary.baselineReady, true); assert.equal(summary.baselineWeeks, 8);
  assert.equal(summary.signals.find(signal => signal.kind === 'technique').baseline, 1);
  weeks[0].rules.phishing = 'old'; assert.equal(summarizePhishingWeeks(weeks).baselineReady, false);
  rows[0].extractionVersion = 'feed-v7'; assert.equal(summarizePhishingWeeks(buildPhishingWeeks(rows, { now: at })).baselineReady, false);
});
test('unchanged DNS checks update observation time without generating evidence revisions', () => {
  const db = new Database(':memory:'), evolution = createPhishingEvolution(db);
  const hit = { id: 'p:example.com', ownerId: 'one', profileId: 'p', apexDomain: 'example.com', status: 'new', lastSeen: at.toISOString(), dns: { checkedAt: at.toISOString(), a: ['9.9.9.9'] } };
  evolution.syncCandidates([hit]); evolution.syncCandidates([{ ...hit, lastSeen: '2026-10-14T13:00:00Z', dns: { ...hit.dns, checkedAt: '2026-10-14T13:00:00Z' } }]);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM watch_candidate_revisions').get().n, 0);
  assert.equal(evolution.candidates('one')[0].lastSeen, '2026-10-14T13:00:00Z');
  evolution.syncCandidates([{ ...hit, verdict: 'legitimate' }]); assert.equal(db.prepare('SELECT COUNT(*) n FROM watch_candidate_revisions').get().n, 1); db.close();
});
test('archive backfill alone cannot claim comparable weeks without observed collection coverage', () => {
  const store = createIocIntelligence({ now: () => at.getTime() });
  const rows = Array.from({ length: 9 }, (_, i) => row('old-' + i, { pubDate: new Date(Date.parse('2026-08-09T00:00:00Z') + i * 7 * 86400000).toISOString() }));
  store.phishing.saveWeeks(buildPhishingWeeks(rows, { now: at }));
  const overview = store.phishing.overview(); assert.equal(overview.baselineReady, false); assert.equal(overview.baselineWeeks, 0); assert.ok(overview.signals.every(signal => signal.percent === null));
  store.close();
});

test('collection telemetry persists only aggregate extraction cache counts for production diagnostics', () => {
  const db = new Database(':memory:'), evolution = createPhishingEvolution(db);
  evolution.recordCycle({ at: at.toISOString(), extraction: { reused: 2000, recomputed: 10, entries: 2010, bytes: 100000, evictions: 0, title: 'must not persist', bad: -1 } });
  const cycle = JSON.parse(db.prepare('SELECT payload FROM phishing_collection_cycles').get().payload);
  assert.deepEqual(cycle.extraction, { reused: 2000, recomputed: 10, entries: 2010, bytes: 100000, evictions: 0 });
  db.close();
});
test('SQLite rollups survive restart, retain source members and revise corrected event IDs', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishing-rollup-')), filePath = path.join(dir, 'inventory.sqlite');
  try {
    let store = createIocIntelligence({ filePath }); const weeks = buildPhishingWeeks([row('a')], { now: at });
    store.phishing.saveWeeks(weeks); store.phishing.saveWeeks(weeks);
    store.phishing.recordCycle({ at: at.toISOString(), sources: [['https://source/feed', { status: 'stale' }]] });
    store.phishing.recordCycle({ at: at.toISOString(), sources: [['https://source/feed', { status: 'stale' }]] });
    store.close(); store = createIocIntelligence({ filePath, now: () => at.getTime() });
    assert.equal(store.phishing.weekEvidence('2026-10-04').members[0].event, 'event-1');
    assert.equal(store.phishing.overview().health.cycles24h, 1); assert.equal(store.phishing.overview().health.sources[0].stale, 1);
    store.phishing.saveWeeks(buildPhishingWeeks([row('a', { storyId: 'corrected' })], { now: at }));
    assert.equal(store.phishing.weekEvidence('2026-10-04').members[0].event, 'corrected'); store.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('private candidate verdicts survive operational eviction, do not create malicious IOCs, and never cross owners', () => {
  const db = createIocIntelligence(), hit = { id: 'p:example.com', ownerId: 'one', profileId: 'p', apexDomain: 'example.com', status: 'dismissed', reasons: ['brand-glued'] };
  db.phishing.syncCandidates([hit]); db.phishing.syncCandidates([]);
  assert.equal(db.phishing.metrics('one').precision, null); assert.equal(db.phishing.metrics('two').total, 0); assert.equal(db.status('one').indicators, 0);
  db.phishing.syncCandidates([{ ...hit, verdict: 'legitimate' }, { ...hit, id: 'second', verdict: 'malicious' }]);
  assert.equal(db.phishing.metrics('one').precision, 0.5); assert.equal(db.phishing.metrics('one').byReason[0].precision, 0.5);
  db.phishing.dropProfile('two', 'p'); assert.equal(db.phishing.metrics('one').total, 2);
  db.phishing.dropProfile('one', 'p'); assert.equal(db.phishing.metrics('one').total, 0); db.close();
});
test('verdict validation, ownership, JSON write failure and legacy dismissal remain independent', () => {
  let fail = false; const synced = [];
  const store = createPhishWatchStore({ filePath: 'memory', readFileSync: () => '{"hits":[],"runs":{}}', writeJsonAtomic: () => { if (fail) throw Error('disk'); }, onChange: rows => synced.push(...rows) });
  store.absorb('p', [{ id: 'a', profileId: 'p', ownerId: 'one', apexDomain: 'example.com', status: 'new', lastSeen: at.toISOString() }], at);
  assert.throws(() => store.review('two', 'a', 'malicious', 'analyst-confirmed'), /encontrado/);
  assert.throws(() => store.review('one', 'a', 'legitimate', 'duplicate'), /motivo/);
  store.setStatus('one', 'a', 'dismissed'); assert.equal(store.list('one')[0].verdict, undefined);
  fail = true; assert.throws(() => store.review('one', 'a', 'malicious', 'analyst-confirmed'), /disk/); assert.equal(store.list('one')[0].verdict, undefined);
  fail = false; store.review('one', 'a', 'inconclusive', 'duplicate'); assert.equal(synced.at(-1).verdict, 'inconclusive');
});
test('CT backtest requires exact hostname and observed timestamp, excludes issued-date fallback and reports missing negative sample', () => {
  const sample = { hostname: 'bancoxpto-login.com', firstSeen: '2026-10-10T12:00:00Z', cohort: 'watch', label: 'malicious', certificates: [
    { id: 1, name_value: 'bancoxpto-login.com', not_before: '2020-01-01', entry_timestamp: '2026-10-10T10:00:00' },
    { id: 2, name_value: '*.com', entry_timestamp: '2026-10-10T11:00:00Z' },
    { id: 3, name_value: 'bancoxpto-login.com', not_before: '2026-10-10T11:59:00Z' },
  ] };
  let result = evaluateCtBacktest([sample, sample], { brands: ['bancoxpto'] });
  assert.equal(result.sampleCount, 1); assert.equal(result.results[0].opportunityHours, 2); assert.equal(result.falsePositiveRate, null); assert.equal(result.precision, null);
  result = evaluateCtBacktest([sample, { ...sample, hostname: 'bancoxpto.com', label: 'legitimate', certificates: [] }], { brands: ['bancoxpto'] });
  assert.equal(result.falsePositiveRate, 1); assert.equal(result.results[1].opportunityHours, null);
});
