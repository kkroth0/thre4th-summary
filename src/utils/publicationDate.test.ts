import test from 'node:test';
import assert from 'node:assert/strict';
import { formatPublicationDate } from './publicationDate';

test('publisher time uses Fortaleza and crosses calendar days correctly', () => {
  assert.equal(formatPublicationDate({ pubDate: '2026-10-13T01:25:00Z' }).text, '12/10/2026 · 22:25');
  assert.match(formatPublicationDate({ pubDate: '2026-10-13T15:25:00Z' }).title, /Fortaleza/);
});
test('date-only publishers and repository reports do not invent midnight', () => {
  for (const row of [{ pubDate: '2026-10-13' }, { pubDate: '2026-10-13T00:00:00Z', publicationTimeKnown: false }, { pubDate: '2026-10-13T00:00:00Z', repository: { dateBasis: 'report-date' } }]) {
    assert.equal(formatPublicationDate(row).text, '13/10/2026 · hora não informada');
  }
});
test('missing publication date remains explicitly first collection, not publication', () => {
  const result = formatPublicationDate({ pubDate: '2026-10-14T00:00:00Z', dateInferred: true, firstCollectedAt: '2026-10-13T12:40:00Z' });
  assert.equal(result.label, 'Coleta');
  assert.equal(result.text, '13/10/2026 · 09:40');
});
test('invalid dates stay unavailable', () => assert.equal(formatPublicationDate({ pubDate: 'invalid' }).text, '—'));
test('an Atom update time is identified as an update', () => assert.equal(formatPublicationDate({ pubDate: '2026-10-13T12:00:00Z', publicationDateBasis: 'updated' }).label, 'Atualização'));
