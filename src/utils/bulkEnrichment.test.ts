import assert from 'node:assert/strict';
import test from 'node:test';
import { bulkCsv, bulkField, bulkResultState, prepareBulkInput, runBulkQueue } from './bulkEnrichment';
import type { ThreatIntelligenceResult } from '../types/threat-intelligence';

test('bulk extraction deduplicates defanged assets and excludes email, CIDR and private IPs', () => {
  const { indicators, excluded } = prepareBulkInput('EXAMPLE[.]COM example.com 1.1.1.1 1.1.1.1\n10.0.0.1 user@example.org 8.8.8.0/24 2001:db8::1 hxxps://8.8.8.8/Login');
  assert.deepEqual(indicators, ['https://8.8.8.8/Login', '1.1.1.1', 'example.com']);
  assert.deepEqual(excluded, { emails: 1, cidrs: 1, nonPublicIps: 2 });
});
test('IPv6 and hash spelling is canonical while URL path case is preserved', () => {
  const { indicators } = prepareBulkInput(`2606:4700:4700:0:0:0:0:1111 2606:4700:4700::1111 ${'A'.repeat(64)} ${'a'.repeat(64)} https://example.com/A https://example.com/a`);
  assert.equal(indicators.length, 4);
  assert.ok(indicators.includes('2606:4700:4700::1111'));
});
test('queue bounds concurrency and stopping prevents queued work from starting', async () => {
  let active = 0; let maximum = 0; let stop = false; const started: number[] = [];
  const gates: (() => void)[] = [];
  const work = runBulkQueue([1, 2, 3, 4, 5], async item => {
    started.push(item); active++; maximum = Math.max(maximum, active);
    await new Promise<void>(resolve => gates.push(resolve)); active--;
  }, () => stop, 2);
  assert.deepEqual(started, [1, 2]); stop = true; gates.forEach(resolve => resolve()); await work;
  assert.equal(maximum, 2); assert.deepEqual(started, [1, 2]);
});
test('failed providers produce partial or error states, never a completed clean result', () => {
  const base: ThreatIntelligenceResult = { query: '1.1.1.1', overallScore: 0, threatLevel: 'unknown', totalVendors: 0, detections: 0, vendorData: [] };
  assert.equal(bulkResultState(base), 'unsupported');
  assert.equal(bulkResultState({ ...base, vendorData: [{ name: 'a', data: {}, error: 'quota' }] }), 'error');
  assert.equal(bulkResultState({ ...base, vendorData: [{ name: 'a', data: {}, error: 'quota' }, { name: 'b', data: { ASN: 1 } }] }), 'partial');
  assert.equal(bulkResultState({ ...base, vendorData: [{ name: 'b', data: { ASN: 1 } }] }), 'complete');
});
test('CSV neutralizes spreadsheet formulas and preserves row completion status', () => {
  const csv = bulkCsv([{ query: '=HYPERLINK("bad")', state: 'stopped' }]);
  assert.ok(csv.includes('"\'=HYPERLINK(""bad"")"')); assert.ok(csv.includes('"stopped"'));
});
test('enrichment fields ignore failed/loading sources and retain provenance', () => {
  const row = { query: '1.1.1.1', state: 'partial' as const, result: { query: '1.1.1.1', overallScore: 0, threatLevel: 'unknown' as const, totalVendors: 3, detections: 0, vendorData: [
    { name: 'failed', error: 'quota', data: { Country: 'wrong' } },
    { name: 'pending', isLoading: true, data: { Country: 'wrong' } },
    { name: 'geo', data: { Country: 'BR', AS: 'AS123' } },
  ] } };
  assert.deepEqual(bulkField(row, ['Country']), { value: 'BR', source: 'geo' });
  assert.deepEqual(bulkField(row, ['ASN', 'AS']), { value: 'AS123', source: 'geo' });
  assert.equal(bulkField(row, ['ISP']).value, '—');
});
test('URL email-like paths and numeric segments remain complete URL assets', () => {
  assert.deepEqual(prepareBulkInput('https://1.1.1.1/24/user@example.com').indicators, ['https://1.1.1.1/24/user@example.com']);
});

test('bulk CSV includes complete provider payloads, all publications, attribution and failures', () => {
  const payload = { data: { reports: Array.from({ length: 12 }, (_, i) => ({ comment: `report-${i}` })) } };
  const row = { query: '46.101.130.1', state: 'partial' as const, result: { query: '46.101.130.1', overallScore: 95, threatLevel: 'malicious' as const, totalVendors: 2, detections: 1, vendorData: [
    { name: 'AbuseIPDB', data: { 'Total Reports': 12 }, rawPayload: payload },
    { name: 'VirusTotal', data: {}, error: 'Quota exceeded' },
  ] }, context: { publications: [{ storyId: 'event', title: 'Report', source: 'Research', link: 'https://lab.example/report', pubDate: '2026-10-12', actors: ['Lazarus'], categories: [] }], evidence: [], errors: ['OTX base unavailable'] } };
  const csv = bulkCsv([row]);
  for (const value of ['report-11', 'https://lab.example/report', 'Lazarus', 'Quota exceeded', 'OTX base unavailable', 'AbuseIPDB_raw_json', 'VirusTotal_status']) assert.ok(csv.includes(value), value);
});
