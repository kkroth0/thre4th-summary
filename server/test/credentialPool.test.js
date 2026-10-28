import test from 'node:test';
import assert from 'node:assert/strict';
import { createCredentialPool, decodeCredentials, parseCredentialInput } from '../credentialPool.js';

function fixture() {
  let clock = Date.parse('2026-10-27T12:00:00Z');
  const store = new Map();
  const deps = { now: () => clock, load: key => store.get(key), save: (key, value) => store.set(key, value) };
  return { router: createCredentialPool(deps), deps, advance: ms => { clock += ms; } };
}
const failure = (status, headers = {}) => Object.assign(new Error('upstream failure'), { response: { status, headers } });
const keys = Array.from({ length: 20 }, (_, index) => 'test-credential-' + index);

test('twenty keys receive fair traffic and metadata never contains a secret', async () => {
  const { router } = fixture(), used = [];
  for (let i = 0; i < 40; i++) await router.run('vt', keys, key => { used.push(key); return { status: 200 }; });
  for (const key of keys) assert.equal(used.filter(value => value === key).length, 2);
  const metadata = JSON.stringify(router.describe('vt', keys));
  for (const key of keys) assert.ok(!metadata.includes(key));
});

test('429 skips the limited key until its persisted reset without losing the query', async () => {
  const { router, deps, advance } = fixture(), used = [];
  await router.run('vt', keys.slice(0, 2), key => { used.push(key); if (key === keys[0]) throw failure(429, { 'retry-after': '120' }); return { status: 200 }; });
  assert.deepEqual(used, keys.slice(0, 2));
  assert.equal(createCredentialPool(deps).describe('vt', [keys[0]])[0].status, 'cooldown');
  await assert.rejects(router.run('vt', [keys[0]], () => assert.fail('limited credential called')), error => error.response.status === 429 && error.response.headers['retry-after'] === '120');
  advance(120001);
  await router.run('vt', [keys[0]], () => ({ status: 200 }));
});

test('account owners with different keys are isolated; the same key cannot evade its counter', async () => {
  const { router } = fixture();
  await router.run('vt', [keys[0]], () => ({}), { perDay: 1 });
  await assert.rejects(router.run('vt', [keys[0]], () => assert.fail(), { perDay: 1 }), error => error.response.status === 429);
  await router.run('vt', [keys[1]], () => ({}), { perDay: 1 });
});

test('concurrent queries use distinct credentials and a busy pool returns a short retry', async () => {
  const { router } = fixture();
  const release = [];
  const runs = keys.slice(0, 3).map(() => router.run('vt', keys.slice(0, 3), key => new Promise(resolve => release.push({ key, resolve }))));
  assert.equal(new Set(release.map(item => item.key)).size, 3);
  await assert.rejects(router.run('vt', keys.slice(0, 3), () => assert.fail()), error => error.response.status === 429);
  release.forEach(item => item.resolve({ status: 200 })); await Promise.all(runs);
});

test('minute and daily reservations survive restart and advance across a UTC day', async () => {
  const { router, deps, advance } = fixture();
  await router.run('vt', [keys[0]], () => ({}), { perMinute: 4, perDay: 2 });
  await assert.rejects(createCredentialPool(deps).run('vt', [keys[0]], () => assert.fail(), { perMinute: 4, perDay: 2 }));
  advance(15001); await router.run('vt', [keys[0]], () => ({}), { perMinute: 4, perDay: 2 });
  advance(15001); await assert.rejects(router.run('vt', [keys[0]], () => assert.fail(), { perDay: 2 }));
  advance(86400000); await router.run('vt', [keys[0]], () => ({}), { perDay: 2 });
});

test('reported shared IP limit pauses all keys, including after a restart', async () => {
  const { router, deps } = fixture();
  await assert.rejects(router.run('otx', keys, () => { throw failure(429, { 'retry-after': '30', 'x-ratelimit-scope': 'ip' }); }), error => error.response.status === 429);
  await assert.rejects(createCredentialPool(deps).run('otx', [keys[19]], () => assert.fail()), error => error.response.headers['retry-after'] === '30');
});

test('authentication failures fall back safely, but a genuine 404 does not rotate', async () => {
  const { router } = fixture(), seen = [];
  await router.run('vt', keys, key => { seen.push(key); if (key === keys[0]) throw failure(401); return {}; });
  assert.equal(seen.length, 2);
  assert.equal(router.describe('vt', [keys[0]])[0].status, 'authentication_error');
  let calls = 0;
  await assert.rejects(router.run('urlhaus', keys, () => { calls++; throw failure(404); }));
  assert.equal(calls, 1);
});

test('legacy keys migrate without loss and bulk inputs reject invalid or oversized secrets', () => {
  assert.deepEqual(decodeCredentials('legacy-secret'), ['legacy-secret']);
  assert.deepEqual(decodeCredentials(JSON.stringify({ version: 1, keys: ['legacy-secret', 'legacy-secret', 'second-secret'] })), ['legacy-secret', 'second-secret']);
  assert.deepEqual(parseCredentialInput(' first-secret\nsecond-secret\nfirst-secret '), ['first-secret', 'second-secret']);
  assert.throws(() => parseCredentialInput(['bad key with spaces']));
  assert.throws(() => parseCredentialInput(Array(51).fill('valid-secret')));
});
test('rejected credentials remain authentication failures during cooldown, never a misleading 429',async()=>{
 const {router}=fixture();let calls=0;
 await assert.rejects(router.run('threatfox',[keys[0]],()=>{calls++;throw failure(401);}),e=>e.code==='PROVIDER_AUTH_FAILED'&&e.response.status===502);
 await assert.rejects(router.run('threatfox',[keys[0]],()=>{calls++;return {};}),e=>e.code==='PROVIDER_AUTH_FAILED'&&e.response.status===502);
 assert.equal(calls,1);assert.equal(router.describe('threatfox',[keys[0]])[0].status,'authentication_error');
});
