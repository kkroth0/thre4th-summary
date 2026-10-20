import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseHuntingFile, mergeHuntingQueries, HUNTING_SOURCES, fingerprint, collectHuntingRepository } from '../huntingLibrary.js';
import { buildHuntingCandidates, createHuntingIndex, createHuntingService, huntingWindow } from '../huntingService.js';
import { createHuntingGenerator } from '../huntingAi.js';

const now = Date.parse('2026-10-20T15:00:00Z');
const revision = 'a'.repeat(40);
const q = { id: fingerprint('powershell'), title: 'Encoded PowerShell', description: 'Find PowerShell encoded payload execution', query: 'DeviceProcessEvents\n| where FileName == "powershell.exe"', platform: 'defender', tables: ['DeviceProcessEvents'], techniques: ['T1059.001'], cves: [], provenance: [{ repo: 'example/research', license: 'MIT', revision, url: 'https://github.com/example/research/blob/' + revision + '/test.kql' }] };
const library = { all: () => [q], revision: () => 'v1', status: () => ({ queries: 1, sources: [] }) };
const news = extra => ({ title: 'PowerShell encoded payload execution', description: 'PowerShell encoded execution described in a research report', link: 'https://research.example/report', pubDate: '2026-10-20T12:00:00Z', ttpIds: ['T1059.001'], cves: [], score: 80, ...extra });

test('hunting windows respect Fortaleza midnight and reject arbitrary periods', () => {
  assert.equal(huntingWindow('day', now).from, '2026-10-20T03:00:00.000Z');
  assert.equal(huntingWindow('day', Date.parse('2026-10-20T02:00Z')).from, '2026-10-19T03:00:00.000Z');
  assert.equal(huntingWindow('week', now).from, '2026-10-13T15:00:00.000Z');
  assert.throws(() => huntingWindow('forever'), /inválido/);
});

test('repository import retains immutable attribution, separates platforms and deduplicates exact query copies', () => {
  const text = '# Encoded PowerShell\nMITRE T1059.001\n## Defender XDR\n```kql\nDeviceProcessEvents\n| where FileName == "powershell.exe"\n```\n## Sentinel\n```kusto\nDeviceProcessEvents\n| where FileName == "powershell.exe"\n```';
  const rows = parseHuntingFile(HUNTING_SOURCES[1], 'Defender For Endpoint/test.md', text, revision);
  assert.equal(rows.length, 2); assert.deepEqual(rows.map(x => x.platform), ['defender', 'sentinel']);
  assert.deepEqual(rows[0].techniques, ['T1059.001']); assert.match(rows[0].provenance[0].url, new RegExp(revision));
  assert.equal(mergeHuntingQueries([...rows, rows[0]]).length, 2);
  assert.equal(parseHuntingFile(HUNTING_SOURCES[0], 'Learning/test.md', text, revision).length, 0);
  assert.equal(parseHuntingFile(HUNTING_SOURCES[1], 'README.md', text, revision).length, 0);
  assert.equal(parseHuntingFile(HUNTING_SOURCES[1], 'test.kql', 'DeviceEvents\n| where x == "' + 'a'.repeat(19000) + '"', revision).length, 0);
});

test('unchanged repository revisions do not redownload archives', async () => {
  let calls = 0; const old = { revision, queries: [q] };
  const result = await collectHuntingRepository(HUNTING_SOURCES[0], { get: async () => { calls++; return { data: { sha: revision } }; } }, '', old);
  assert.equal(result, old); assert.equal(calls, 1);
});

test('bundled catalog contains licensed imports from all requested repositories', () => {
  const snapshot = JSON.parse(readFileSync(new URL('../data/hunting-library.json', import.meta.url), 'utf8'));
  assert.equal(snapshot.sources.length, 3); assert.ok(snapshot.queries.length > 1000);
  assert.equal(new Set(snapshot.queries.map(row => row.id)).size, snapshot.queries.length);
  for (const source of HUNTING_SOURCES) { const row = snapshot.sources.find(s => s.repo === source.repo); assert.ok(row.licenseText.length > 500); assert.match(row.revision, /^[a-f0-9]{40}$/); }
  for (const row of snapshot.queries) { assert.ok(row.query.length <= 18000); assert.ok(row.provenance.every(p => /^https:\/\/github\.com\//.test(p.url))); }
});

test('candidate selection excludes undated, future, irrelevant and outside-window publications', () => {
  const rows = [news(), news({ link: 'https://x.example/old', pubDate: '2026-10-19T20:00Z' }), news({ link: 'https://x.example/future', pubDate: '2026-10-21' }), news({ link: 'https://x.example/undated', dateInferred: true }), news({ link: 'https://x.example/unrelated', securityRelevant: false })];
  const result = buildHuntingCandidates({ news: rows, library: [q], now });
  assert.equal(result.publications, 1); assert.equal(result.candidates.length, 1); assert.equal(result.candidates[0].sources.length, 1);
  assert.equal(result.candidates[0].techniques[0].id, 'T1059.001');
  assert.equal(buildHuntingCandidates({ news: rows, library: [q], period: 'week', now }).publications, 2);
});

test('matching query duplicates consolidate provenance, not unrelated story identities', () => {
  const result = buildHuntingCandidates({ news: [news({ storyId: 'one' }), news({ storyId: 'two', link: 'https://other.example/report' })], library: [q], now });
  assert.equal(result.candidates.length, 1); assert.deepEqual(result.candidates[0].sources.map(x => x.storyId), ['one', 'two']);
});

test('behaviour-specific queries outrank unrelated actor-themed variants of the same MITRE technique', () => {
  const decoy = { ...q, id: fingerprint('fin7'), title: 'PowerShell scripts from WindowsApps (FIN7)' };
  const index = createHuntingIndex([decoy, q]);
  assert.equal(index.match(news())[0].query.id, q.id);
});

test('encoded PowerShell reports select encoded behaviour from the real catalog, not an unrelated policy change', () => {
  const snapshot = JSON.parse(readFileSync(new URL('../data/hunting-library.json', import.meta.url), 'utf8'));
  const hit = createHuntingIndex(snapshot.queries).match(news())[0];
  assert.match(hit.query.title, /encoded|encoding/i);
  assert.doesNotMatch(hit.query.title, /execution policy|FIN7/i);
});

test('generic initial-access and file words cannot attach AsyncRAT or guest-sharing hunts to unrelated reports', () => {
  const snapshot = JSON.parse(readFileSync(new URL('../data/hunting-library.json', import.meta.url), 'utf8'));
  const unrelated = snapshot.queries.filter(row => /AsyncRAT Initial Access|MultipleFilesSharedtoGuests/.test(row.title));
  const index = createHuntingIndex(unrelated);
  for (const title of ['Atlassian Arbitrary File Access Vulnerability', 'Microsoft Says AI Agents Could Become Insider Threats']) {
    assert.deepEqual(index.match({ title, description: 'Initial access can allow a user to open files in an environment. Multiple files and access are discussed in this report.', ttpIds: ['T1190'] }), []);
  }
});

test('CVE exposure uses exact escaped IDs and never infers ATT&CK from a vulnerability alone', () => {
  const result = buildHuntingCandidates({ news: [], cves: [{ id: 'CVE-2026-12345', published: '2026-10-20', cvss: 9.8, kev: true }, { id: 'CVE-2026-12345" | take 1', published: '2026-10-20' }], library: [q], now });
  assert.equal(result.candidates.length, 1); assert.deepEqual(result.candidates[0].techniques, []);
  assert.match(result.candidates[0].query.query, /CveId == "CVE-2026-12345"/);
  assert.equal(result.candidates[0].signals.kev, true);
});

test('current RCE advisories cannot recommend old OpenSSL CVEs or unrelated WMIC and PowerShell hunts', () => {
  const snapshot = JSON.parse(readFileSync(new URL('../data/hunting-library.json', import.meta.url), 'utf8'));
  const wrong = snapshot.queries.filter(row => /OpenSSL critical|WMIC Remote|PowerShell spawning|Blocklist.de|Qakbot post|ExtractPhoneNumber/.test(row.title));
  const index = createHuntingIndex(wrong);
  for (const description of ['Critical vulnerability allows remote code execution on devices', 'Customers and servers affected by multiple post compromise commands', 'Your first hours after a database breach may expose a phone number']) {
    assert.deepEqual(index.match({ title: 'Atlassian vulnerability', description, cves: ['CVE-2026-21589'] }), []);
  }
});

test('roundup KEV and EPSS signals are never copied to every mentioned CVE', () => {
  const result = buildHuntingCandidates({ news: [news({ title: 'Two vulnerabilities', description: '', ttpIds: [], cves: ['CVE-2026-11111', 'CVE-2026-22222'], kev: true, kevDetails: { cve: 'CVE-2026-11111' }, epss: 0.95 })], library: [], now });
  const first = result.candidates.find(row => row.cves.includes('CVE-2026-11111'));
  const second = result.candidates.find(row => row.cves.includes('CVE-2026-22222'));
  assert.equal(first.signals.kev, true); assert.equal(second.signals.kev, false); assert.equal(second.signals.epss, null);
});

test('feedback persists per user across restart and invalid feedback is rejected', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hunting-test-')), filePath = path.join(dir, 'feedback.sqlite');
  let service = createHuntingService({ library, filePath, getNews: () => [news()], now: () => now });
  service.feedback('alice', q.id, 'no');
  assert.throws(() => service.feedback('alice', q.id, 'bad'), /inválido/);
  assert.throws(() => service.feedback('alice', 'f'.repeat(64), 'yes'), /não encontrada/);
  service.close(); service = createHuntingService({ library, filePath, getNews: () => [news()], now: () => now });
  assert.equal((await service.overview('alice', 'day')).hypotheses[0].feedback, 'no');
  assert.equal((await service.overview('bob', 'day')).hypotheses[0].feedback, null);
  service.close(); rmSync(dir, { recursive: true, force: true });
});

test('AI generation is single-flight, cached, source-bound and never replaces repository KQL', async () => {
  let calls = 0, release; const gate = new Promise(resolve => { release = resolve; });
  const service = createHuntingService({ library, getNews: () => [news()], now: () => now, generate: async ({ candidates }) => { calls++; await gate; return { hypotheses: [{ id: 'invented', title: 'bad' }, { id: candidates[0].id, title: 'Investigar PowerShell', hypothesis: 'Pode haver execução codificada.', reason: 'Comportamento descrito na fonte.' }] }; } });
  assert.equal((await service.overview('alice', 'day')).aiStatus, 'processing'); await service.overview('alice', 'day'); assert.equal(calls, 1);
  release(); await service.idle(); const result = await service.overview('alice', 'day');
  assert.equal(result.aiStatus, 'ready'); assert.equal(result.hypotheses[0].aiUsed, true); assert.equal(result.hypotheses[0].query.query, q.query); assert.equal(calls, 1);
  service.close();
});

test('unsupported AI identifiers fail safely and failures are cooled down', async () => {
  let calls = 0;
  const service = createHuntingService({ library, getNews: () => [news()], now: () => now, generate: async ({ candidates }) => { calls++; return { hypotheses: [{ id: candidates[0].id, title: 'CVE-2099-12345', hypothesis: 'bad', reason: 'bad' }] }; } });
  await service.overview('alice', 'day'); await service.idle(); const result = await service.overview('alice', 'day');
  assert.equal(result.aiStatus, 'unavailable'); assert.equal(result.hypotheses[0].aiUsed, false); assert.equal(calls, 1); service.close();
});

test('daily AI budget is bounded per user even when publications change', async () => {
  let version = 0, calls = 0;
  const service = createHuntingService({ library, getNews: () => [news({ contentHash: String(version++) })], now: () => now, generate: async () => { calls++; throw Error('provider unavailable'); } });
  for (let index = 0; index < 14; index++) { await service.overview('alice', 'day'); await service.idle(); }
  assert.equal(calls, 9);
  await service.overview('bob', 'day'); await service.idle(); assert.equal(calls, 10); service.close();
});

test('generator sends only bounded candidate metadata, no KQL or feedback from other users', async () => {
  let body;
  const generate = createHuntingGenerator({ http: { post: async (_url, input) => { body = input; return { data: { choices: [{ message: { content: '{"hypotheses":[]}' } }] } }; } }, getKey: () => 'test-only' });
  const base = buildHuntingCandidates({ news: [news()], library: [q], now }).candidates;
  await generate({ period: 'day', candidates: base, feedback: { [q.id]: 'yes', private: 'should-not-be-sent' } });
  assert.equal(body.model, 'deepseek/deepseek-v4.1-flash'); assert.doesNotMatch(body.messages[1].content, /should-not-be-sent|DeviceProcessEvents\\n/);
});
