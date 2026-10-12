import assert from 'node:assert/strict';
import test from 'node:test';
import { cidrTilePage, domainHosts, extractEnrichmentTargets, networkObservations, parsePublicCidr } from './networkInvestigation';
import { formatVendorData, type AttackSurfaceFinding } from '@/services/threatApi';

test('CIDR normalizes host bits and computes the entire address space including /31 and /32', () => {
  const block = parsePublicCidr('46.101.129.42/17')!;
  assert.deepEqual([block.cidr, block.first, block.last, block.size], ['46.101.128.0/17', '46.101.128.0', '46.101.255.255', 32768]);
  assert.equal(parsePublicCidr('8.8.8.9/31')?.size, 2);
  assert.equal(parsePublicCidr('8.8.8.8/32')?.size, 1);
  for (const invalid of ['8.8.8.8/99', '8.8.8.8/', '8.8.8.8/24/1', '999.8.8.8/24', '172.0.0.0/8', '192.0.0.0/8', '0.0.0.0/0', '10.0.0.1/24']) assert.equal(parsePublicCidr(invalid), null, invalid);
});
test('CIDR extraction does not silently query its base IP and URLs do not create implicit host lookups', () => {
  assert.deepEqual(extractEnrichmentTargets('46.101.129.42/17 8.8.8.8 example.com'), ['46.101.128.0/17', '8.8.8.8', 'example.com']);
  assert.deepEqual(extractEnrichmentTargets('https://8.8.8.8/24'), ['https://8.8.8.8/24']);
  assert.deepEqual(extractEnrichmentTargets('46.101.128.0/99'), ['46.101.128.0/99']);
});
test('network observations deduplicate IPs and reject provider records outside the requested block', () => {
  const range = parsePublicCidr('46.101.128.0/17')!;
  const finding = { ip: '46.101.130.1', port: 443, hostnames: ['a.example.com'], cves: ['CVE-2026-10000'], organization: 'Example', asn: 'AS1', country: 'DE', observedAt: '2026-10-01' } as AttackSurfaceFinding;
  const rows = networkObservations(range, [finding, { ...finding, port: 80 }, { ...finding, ip: '8.8.8.8' }], { reportedAddress: [{ ipAddress: finding.ip, numReports: 5, abuseConfidenceScore: 75, mostRecentReport: '2026-10-02' }, { ipAddress: '127.0.0.1' }] });
  assert.equal(rows.length, 1); assert.deepEqual(rows[0].sources, ['Shodan', 'AbuseIPDB']); assert.deepEqual(rows[0].ports, [443, 80]); assert.equal(rows[0].reports, 5);
  const first = cidrTilePage(range, rows, 1, 64, false); const last = cidrTilePage(range, rows, 2, 64, false);
  assert.equal(first.total, 128); assert.equal(last.tiles.length, 64); assert.equal(last.tiles.at(-1)?.cidr, '46.101.255.0/24');
  const filtered = cidrTilePage(range, rows, 1, 64, true); assert.equal(filtered.total, 1); assert.equal(filtered.tiles[0].cidr, '46.101.130.0/24'); assert.equal(filtered.tiles[0].reported, 1);
});
test('Shodan domain records survive the backend wrapper and keep more than 25 hosts', () => {
  const names = Array.from({length: 40}, (_, i) => `host${i}`);
  const data = formatVendorData('Shodan', { data: { subdomains: names, data: [{ subdomain: 'WWW', type: 'A', value: '8.8.8.8', last_seen: '2026-10-01' }] } }, 'example.com');
  assert.equal(data['Subdomain List'].length, 40);
  const hosts = domainHosts('EXAMPLE.COM', [{ name: 'Shodan', data }], { A: ['1.1.1.1'] });
  assert.equal(hosts.length, 42); assert.equal(hosts.find(row => row.hostname === 'www.example.com')?.addresses[0], '8.8.8.8');
});
