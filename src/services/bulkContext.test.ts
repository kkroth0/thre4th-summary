import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchBulkContext } from './bulkContext';

test('bulk context reads every evidence page and includes historical publication mentions', async () => {
  const original = globalThis.fetch; const pages: string[] = [];
  globalThis.fetch = async path => {
    const url = new URL(String(path), 'http://localhost');
    if (url.pathname.includes('/news/')) return new Response(JSON.stringify({ mentions: [] }));
    pages.push(url.searchParams.get('offset') || '0');
    const offset = Number(url.searchParams.get('offset'));
    return new Response(JSON.stringify({ total: 101, evidence: Array.from({ length: offset ? 1 : 100 }, (_, i) => ({ provider: 'news', title: `Report ${offset + i}`, source: 'Research', link: `https://lab.example/${offset + i}`, published: '2026-10-12', entities: [] })) }));
  };
  try {
    const result = await fetchBulkContext('46.101.130.1');
    assert.deepEqual(pages, ['0', '100']); assert.equal(result.evidence.length, 101);
    assert.equal(result.publications.length, 101); assert.deepEqual(result.errors, []);
  } finally { globalThis.fetch = original; }
});

test('missing inventory is empty evidence while failed news retrieval remains explicit', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async path => new Response('{}', { status: String(path).includes('/news/') ? 503 : 404 });
  try { const result = await fetchBulkContext('1.1.1.1'); assert.equal(result.errors.length, 1); assert.deepEqual(result.evidence, []); }
  finally { globalThis.fetch = original; }
});
