import test from 'node:test';
import assert from 'node:assert/strict';
import { createNewsFeedResponse } from '../newsFeedResponse.js';
const row = (link, score, categories) => ({ link, title: 'Security vulnerability report', layer: 1, score, categories, pubDate: '2026-10-15', iocs: { hashes: ['a'.repeat(64)] }, text: 'retained body' });
const input = () => ({ current: [], archive: [row('one', 80, ['Malware']), row('two', 30, ['AI'])], stories: [], owner: 'a', preferences: { mode: 'all', vendorIds: [] } });

test('cached HTTP projection preserves all evidence and invalidates on archive, live feed and story revisions', () => {
  const read = createNewsFeedResponse(), data = input();
  const first = read(data); assert.equal(read(data), first);
  assert.equal(JSON.parse(first.body)[0].iocs.hashes[0], 'a'.repeat(64));
  assert.equal(JSON.parse(first.body)[0].text, undefined);
  data.archive = [...data.archive, row('three', 95, ['Malware'])];
  assert.equal(JSON.parse(read(data).body).length, 3); assert.notEqual(read(data).etag, first.etag);
  const second = read(data); data.current = [row('four', 10, ['Other'])]; assert.notEqual(read(data), second);
  const third = read(data); data.stories = [...data.stories]; assert.notEqual(read(data), third);
});

test('owner, preferences and query changes cannot reuse an incompatible response', () => {
  const read = createNewsFeedResponse(), data = input();
  const all = read(data);
  assert.notEqual(read({ ...data, owner: 'b' }), all);
  assert.equal(JSON.parse(read({ ...data, preferences: { mode: 'selected', vendorIds: [] } }).body).length, 0);
  assert.deepEqual(JSON.parse(read({ ...data, query: { minScore: '70', category: 'malware', sort: 'relevance' } }).body).map(row => row.link), ['one']);
  assert.equal(read(data), all);
});

test('response cache has bounded entries/bytes and never truncates oversized feeds', () => {
  const data = input(), read = createNewsFeedResponse({ maxEntries: 1 });
  const first = read(data); read({ ...data, owner: 'b' }); assert.notEqual(read(data), first);
  const small = createNewsFeedResponse({ maxBytes: 1 });
  assert.equal(JSON.parse(small(data).body).length, 2); assert.notEqual(small(data), small(data));
});
