import test from 'node:test';
import assert from 'node:assert/strict';

process.env.SHODAN_MIN_INTERVAL_MS = '30';
const { shodanThrottled, shodanAxios } = await import('../shodanGate.js');

test('spaces concurrent calls by the minimum interval', async () => {
  const starts = [];
  await Promise.all([1, 2, 3].map((n) => shodanThrottled(async () => {
    starts.push(Date.now());
    return n;
  })));

  assert.equal(starts.length, 3);
  assert.ok(starts[1] - starts[0] >= 25, `gap 1 too small: ${starts[1] - starts[0]}ms`);
  assert.ok(starts[2] - starts[1] >= 25, `gap 2 too small: ${starts[2] - starts[1]}ms`);
});

test('retries once on 429 and returns the second response', async () => {
  let calls = 0;
  const client = shodanAxios({
    get: async () => {
      calls += 1;
      if (calls === 1) {
        const error = new Error('Too many requests');
        error.response = { status: 429, headers: { 'retry-after': '0' } };
        throw error;
      }
      return { data: 'ok' };
    },
  });

  assert.deepEqual(await client.get('https://api.shodan.io/api-info'), { data: 'ok' });
  assert.equal(calls, 2);
});

test('a failing call does not break the chain for the next one', async () => {
  await assert.rejects(shodanThrottled(async () => { throw new Error('boom'); }), /boom/);
  assert.equal(await shodanThrottled(async () => 'still works'), 'still works');
});
