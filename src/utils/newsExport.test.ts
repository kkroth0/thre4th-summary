import test from 'node:test';
import assert from 'node:assert/strict';
import { newsExportRange } from './newsExport';

test('local export days include late-night records and reject invalid or reversed dates', () => {
  const before = process.env.TZ;
  process.env.TZ = 'America/Fortaleza';
  try {
    assert.deepEqual(newsExportRange('2026-10-13', '2026-10-13'), { from: '2026-10-13T03:00:00.000Z', to: '2026-10-14T02:59:59.999Z' });
    for (const [from, to] of [['2026-02-30', '2026-10-13'], ['', ''], ['2026-10-14', '2026-10-13']]) assert.throws(() => newsExportRange(from, to));
  } finally { if (before === undefined) delete process.env.TZ; else process.env.TZ = before; }
});
