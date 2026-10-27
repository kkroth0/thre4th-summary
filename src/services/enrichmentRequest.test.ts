import test from 'node:test';
import assert from 'node:assert/strict';
import { enrichmentRequest, EnrichmentRequestError } from './enrichmentRequest';
const fixture = (statuses: number[], headers: Record<string,string> = {}) => {
  let clock = 0, calls = 0;
  const waits: number[] = [];
  return { get calls() { return calls; }, waits, options: {
    now: () => clock, sleep: async (ms: number) => { waits.push(ms); clock += ms; },
    fetch: (async () => new Response(statuses[calls++] === 200 ? '{}' : 'gateway html', {status:statuses[calls-1],headers})) as typeof fetch,
  }};
};
test('busy credentials can finish a 15-second lookup before the next IOC retries',async()=>{
  const f=fixture([...Array(15).fill(429),200],{'Retry-After':'1'});
  assert.equal((await enrichmentRequest('/api/otx',{},f.options)).status,200);
  assert.equal(f.calls,16); assert.equal(f.waits.reduce((a,b)=>a+b,0),15000);
});
test('gateway and network failures retry with backoff and never leak gateway HTML',async()=>{
  const f=fixture([502,503,504,200]);
  assert.equal((await enrichmentRequest('/api/urlhaus',{},f.options)).status,200);
  assert.deepEqual(f.waits,[1000,2000,4000]);
  const bad=fixture(Array(30).fill(502));
  await assert.rejects(enrichmentRequest('/api/urlhaus',{},bad.options),e=>e instanceof EnrichmentRequestError&&!e.message.includes('html'));
});
test('daily cooldown does not trigger another request or a wait that blocks the browser',async()=>{
  const f=fixture([429],{'Retry-After':'86400'});
  await assert.rejects(enrichmentRequest('/api/otx',{},f.options),e=>e instanceof EnrichmentRequestError&&e.retryAt===86400000);
  assert.equal(f.calls,1); assert.deepEqual(f.waits,[]);
});
test('authentication and ordinary client errors are never retried',async()=>{
  let calls=0;
  const fetch=(async()=>{calls++;return new Response(JSON.stringify({error:'Upstream authentication or access configuration failed'}),{status:502,headers:{'Content-Type':'application/json'}});}) as typeof globalThis.fetch;
  assert.equal((await enrichmentRequest('/api/otx',{},{fetch})).status,502); assert.equal(calls,1);
  const f=fixture([400]);assert.equal((await enrichmentRequest('/api/otx',{},f.options)).status,400);assert.equal(f.calls,1);
});
test('an aborted lookup does not issue a request',async()=>{
  const f=fixture([200]),controller=new AbortController();controller.abort();
  await assert.rejects(enrichmentRequest('/api/otx',{signal:controller.signal},f.options));assert.equal(f.calls,0);
});
