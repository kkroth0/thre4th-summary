import test from 'node:test';
import assert from 'node:assert/strict';
import { providerCredentialLimits } from '../providerLimits.js';
import { createCredentialPool } from '../credentialPool.js';

test('VirusTotal defaults pace public calls and preserve upstream waiting times', async () => {
  let at = Date.parse('2026-10-28T10:00:00Z');
  const stored = new Map(), limits = providerCredentialLimits('virustotal', 'VIRUSTOTAL', {});
  const pool = createCredentialPool({ now: () => at, load: key => stored.get(key), save: (key, value) => stored.set(key, value) });
  await pool.run('virustotal', ['test-credential'], async () => ({status: 200}), limits);
  await assert.rejects(pool.run('virustotal', ['test-credential'], () => assert.fail('minute ceiling ignored'), limits), e => e.response.status === 429 && e.response.headers['retry-after'] === '15');
  at += 15000;
  await assert.rejects(pool.run('virustotal', ['test-credential'], async () => { throw {response: {status: 429, headers: {'retry-after': '3600'}}}; }, limits), e => e.response.status === 429);
  at += 15000;
  await assert.rejects(pool.run('virustotal', ['test-credential'], () => assert.fail('upstream cooldown ignored'), limits), e => e.response.status === 429 && Number(e.response.headers['retry-after']) > 3500);
  assert.equal(limits.perDay, 500);
});

test('configured allowances override defaults; unknown plans have no invented cap', () => {
  assert.deepEqual(providerCredentialLimits('virustotal', 'VIRUSTOTAL', {VIRUSTOTAL_REQUESTS_PER_MINUTE: '60', VIRUSTOTAL_REQUESTS_PER_DAY: '10000'}), {perMinute: 60, perDay: 10000});
  assert.deepEqual(providerCredentialLimits('virustotal', 'VIRUSTOTAL', {VIRUSTOTAL_REQUESTS_PER_MINUTE: '0', VIRUSTOTAL_REQUESTS_PER_DAY: '0'}), {perMinute: 0, perDay: 0});
  assert.deepEqual(providerCredentialLimits('virustotal', 'VIRUSTOTAL', {VIRUSTOTAL_REQUESTS_PER_MINUTE: '-1', VIRUSTOTAL_REQUESTS_PER_DAY: 'invalid'}), {perMinute: 4, perDay: 500});
  assert.deepEqual(providerCredentialLimits('otx', 'OTX', {}), {perMinute: 0, perDay: 0});
});
