import test from 'node:test';
import assert from 'node:assert/strict';
import { createNewsEpssLookup } from '../newsEpss.js';
const at = Date.parse('2026-10-15T15:00:00Z');
const id = n => `CVE-2026-${10000 + n}`;

test('local EPSS covers news independently of NVD, preserves zero, and requests only missing CVEs', async () => {
  const calls = [];
  const lookup = createNewsEpssLookup({ now: () => at,
    readLocal: async () => ({ rows: [{ cve: id(0), score: 0, date: '2026-10-15' }, { cve: id(1), score: .8, date: '2026-10-15' }] }),
    fetchBatch: async ids => { calls.push(ids); return [{ cve: id(2), epss: '0.4' }, { cve: id(999), epss: '1' }]; },
  });
  const result = await lookup([id(0).toLowerCase(), id(0), id(1), id(2), 'bad']);
  assert.deepEqual([...result], [[id(0), 0], [id(1), .8], [id(2), .4]]);
  assert.deepEqual(calls, [[id(2)]]);
  await lookup([id(2)]); assert.equal(calls.length, 1);
});

test('failed/empty batches back off without inventing scores; stale evidence survives and recovers', async () => {
  let clock = at, calls = 0;
  const lookup = createNewsEpssLookup({ now: () => clock,
    readLocal: async () => ({ rows: [{ cve: id(0), score: .2, date: '2026-10-01' }] }),
    fetchBatch: async () => { calls++; if (calls === 1) throw Error('offline'); return [{ cve: id(0), epss: '.5' }, { cve: id(1), epss: '' }, { cve: id(2), epss: '2' }]; },
  });
  assert.deepEqual([...await lookup([id(0), id(1), id(2)])], [[id(0), .2]]);
  await lookup([id(0), id(1)]); assert.equal(calls, 1);
  clock += 300001;
  assert.deepEqual([...await lookup([id(0), id(1), id(2)])], [[id(0), .5]]);
  await lookup([id(1), id(2)]); assert.equal(calls, 2);
});

test('bounded remote concurrency aborts real pending requests and does not start more batches', async () => {
  let running = 0, peak = 0, calls = 0, aborts = 0;
  const lookup = createNewsEpssLookup({ budgetMs: 30, readLocal: async () => { throw Error('catalog busy'); },
    fetchBatch: async (_, { signal }) => { calls++; peak = Math.max(peak, ++running); return new Promise((_, reject) => signal.addEventListener('abort', () => { running--; aborts++; reject(Error('aborted')); }, { once: true })); },
  });
  assert.equal((await lookup(Array.from({ length: 501 }, (_, n) => id(n)))).size, 0);
  assert.equal(peak, 2); assert.equal(calls, 2); assert.equal(aborts, 2); assert.equal(running, 0);
});

test('overlapping callers reuse cached missing results and retry after their TTL', async () => {
  let clock = at, calls = 0;
  const lookup = createNewsEpssLookup({ now: () => clock, readLocal: async () => ({ rows: [] }), fetchBatch: async () => { calls++; return []; } });
  await Promise.all([lookup([id(0)]), lookup([id(0)])]); assert.equal(calls, 1);
  clock += 3600001; await lookup([id(0)]); assert.equal(calls, 2);
});
