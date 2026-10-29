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

test('bounded OTX parallelism preserves reservations and the longest concurrent upstream wait',async()=>{
 const {router,deps}=fixture(),key=keys[0],limits={maxConcurrent:2},release=[];
 const first=router.run('otx',[key],()=>new Promise((resolve,reject)=>release.push({resolve,reject})),limits),second=router.run('otx',[key],()=>new Promise((resolve,reject)=>release.push({resolve,reject})),limits);
 assert.equal(release.length,2);assert.equal(router.describe('otx',[key],limits)[0].status,'busy');
 await assert.rejects(router.run('otx',[key],()=>assert.fail('parallel capacity exceeded'),limits));
 const settled=Promise.allSettled([first,second]);release[0].reject(failure(429,{'retry-after':'600'}));release[1].reject(failure(429,{'retry-after':'60'}));await settled;
 const state=router.describe('otx',[key],limits)[0];assert.equal(state.usedToday,2);assert.equal(state.retryAt,deps.now()+600000);
 await assert.rejects(router.run('otx',[key],()=>assert.fail('upstream wait bypassed'),limits));
});

test('5614 simulated IOC calls rotate across twelve independent credentials without hidden shared daily depletion',async()=>{
 const {router,deps,advance}=fixture(),twelve=keys.slice(0,12),used=new Map(twelve.map(k=>[k,0]));
 const request=key=>{used.set(key,used.get(key)+1);return{status:200};},limits={perMinute:4,perDay:500};
 const call=async pool=>{for(;;){try{await pool.run('virustotal',twelve,request,limits);return;}catch(e){assert.equal(e.response?.status,429);advance(e.retryAt-deps.now()+1);}}};
 for(let i=0;i<5614;i++){await call(router);advance(2000);}
 assert.deepEqual([...used.values()].sort((a,b)=>a-b),[467,467,468,468,468,468,468,468,468,468,468,468]);
 const restored=createCredentialPool(deps);
 for(let i=5614;i<6000;i++){await call(restored);advance(2000);}
 assert.ok([...used.values()].every(n=>n===500));
 await assert.rejects(restored.run('virustotal',twelve,()=>assert.fail('depleted key queried'),limits),e=>e.response.status===429);
});

test('query validation and gateway errors record the real HTTP status and never invalidate a credential',async()=>{
 const {router}=fixture();
 for(const status of [422,502]){await assert.rejects(router.run('vt',[keys[0]],()=>{throw failure(status);}));const key=router.describe('vt',[keys[0]])[0];assert.equal(key.lastStatus,status);assert.equal(key.status,'available');}
});

test('availability explains local pacing, local day caps and upstream waits separately',async()=>{
 const {router,advance}=fixture(),limits={perMinute:4,perDay:2};
 await router.run('vt',[keys[0]],()=>({status:200}),limits);assert.equal(router.describe('vt',[keys[0]],limits)[0].waitingReason,'pacing');
 advance(15001);await router.run('vt',[keys[0]],()=>({status:200}),limits);assert.equal(router.describe('vt',[keys[0]],limits)[0].waitingReason,'local_daily_limit');
 await assert.rejects(router.run('vt',[keys[1]],()=>{throw failure(429,{'retry-after':'3600'});},limits));const upstream=router.describe('vt',[keys[1]],limits)[0];assert.equal(upstream.waitingReason,'provider');assert.equal(upstream.lastStatus,429);
 await assert.rejects(router.run('vt',[keys[2]],()=>{throw failure(403);},limits));assert.equal(router.describe('vt',[keys[2]],limits)[0].waitingReason,'authentication');
});

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
