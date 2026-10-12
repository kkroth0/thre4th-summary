import test from 'node:test';
import assert from 'node:assert/strict';
import { investigationDomain, mergeDomainHosts, domainDate } from './domainInvestigation';
test('URLs retain their full query while domain investigation scopes to the hostname', () => {
  assert.equal(investigationDomain('https://www.example.com/path?q=1'), 'www.example.com');
  assert.equal(investigationDomain('https://8.8.8.8/path'), null);
  assert.equal(investigationDomain('example.com'), 'example.com');
  assert.equal(investigationDomain('8.8.8.0/24'), null);
});
test('passive host names merge sources and first seen without inventing resolution', () => {
  const rows = mergeDomainHosts('example.com', [{ hostname: 'www.example.com', addresses: ['1.1.1.1'], sources: ['Shodan'], lastSeen: '2026-01-01' }], [{ hostname: 'www.example.com', firstSeen: '2020-01-01', source: 'crt.name' }, { hostname: 'api.example.com', firstSeen: null, source: 'crt.name' }, { hostname: 'example.com.attacker.com', firstSeen: null, source: 'crt.name' }]);
  assert.equal(rows.length, 2); assert.deepEqual(rows[0].addresses, []); assert.deepEqual(rows[1].sources, ['Shodan', 'crt.name']); assert.equal(rows[1].firstSeen, '2020-01-01');
  assert.equal(domainDate('2020-01-01', true), '01/01/2020');
});
