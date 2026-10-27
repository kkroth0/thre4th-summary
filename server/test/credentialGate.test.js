import test from 'node:test';
import assert from 'node:assert/strict';
import { createCredentialGate, retryAt } from '../credentialGate.js';
test('quota cooldown persists across instances and does not depend on token count', () => {
  let now = Date.parse('2026-10-23T12:00:00Z');
  const state = new Map(), options = { now: () => now, load: key => state.get(key), save: (key, val) => state.set(key, val) };
  const gate = createCredentialGate(options);
  gate.reserve('vt'); gate.limited('vt', { 'retry-after': '120' });
  assert.throws(() => createCredentialGate(options).reserve('vt'), e => e.response.status === 429);
  gate.reserve('other-account'); now += 120001; gate.reserve('vt');
});
test('daily and minute limits reserve slots atomically and resume at reset', () => {
  let now = Date.parse('2026-10-23T23:59:00Z');
  const gate = createCredentialGate({ now: () => now });
  gate.reserve('abuse', { perMinute: 60, perDay: 2 });
  assert.throws(() => gate.reserve('abuse', { perMinute: 60, perDay: 2 }));
  now += 1001; gate.reserve('abuse', { perMinute: 60, perDay: 2 });
  now += 1001; assert.throws(() => gate.reserve('abuse', { perDay: 2 }));
  now = Date.parse('2026-10-24T00:00:01Z'); gate.reserve('abuse', { perDay: 2 });
});
test('retry headers support seconds, dates, unix reset, and safe fallback', () => {
  const now = Date.parse('2026-10-23T12:00:00Z');
  assert.equal(retryAt({ 'Retry-After': '15', 'retry-after': '15' }, now), now + 15000);
  assert.equal(retryAt({ 'retry-after': 'Fri, 23 Oct 2026 12:02:00 GMT' }, now), now + 120000);
  assert.equal(retryAt({ 'x-ratelimit-reset': (now + 90000) / 1000 }, now), now + 90000);
  assert.equal(retryAt({}, now), now + 60000);
});
