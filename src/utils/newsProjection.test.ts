import test from 'node:test';
import assert from 'node:assert/strict';
import { projectNews, createNewsProjector, type NewsProjectionOptions } from './newsProjection';
import { annotateOrg, type OrgThreatModel } from './orgRelevance';
import { groupAdvisoriesIntoStories, filterNewsletterAdvisories, filterStoryCards, countByCategory } from '../pages/newsletterView';

const rows = Array.from({ length: 125 }, (_, index) => ({
  link: `https://source.example/${index}`, title: `PHP report ${index}`, description: 'Security report', source: 'Source',
  pubDate: '2026-10-21', storyId: `story-${Math.floor(index / 2)}`, newsCategories: index % 3 ? ['Vulnerabilities'] : ['Malware'],
  iocs: { hashes: Array.from({ length: 32 }, (_, i) => `${index}-${i}`) },
}));
const options: NewsProjectionOptions = { model: null, filters: { search: '', severity: 'all', source: 'all', kevOnly: false, sortByRelevance: false, timeRange: 'all' }, category: '', orgOnly: false, pt: true };

test('isolated projection preserves all stories, original indicators and category counts', () => {
  const original = structuredClone(rows);
  const grouped = groupAdvisoriesIntoStories(annotateOrg(filterNewsletterAdvisories(rows, options.filters), null), { pt: true });
  const expected = { cards: filterStoryCards(grouped, options), counts: countByCategory(grouped) };
  const result = projectNews(rows, options);
  assert.deepEqual(result, expected);
  assert.equal(result.cards.length, 63);
  assert.equal(result.cards.flatMap(card => card.sources).reduce((sum,row) => sum + row.iocs.hashes.length, 0), 4000);
  assert.deepEqual(rows, original);
});

test('reused projection responds to category, search, snapshot and organization changes', () => {
  const project = createNewsProjector<typeof rows[number]>();
  const model: OrgThreatModel = { actorIds: [], pinnedIds: [], actors: [], sectors: [], regions: [], assets: [{ vendor: '', product: 'PHP' }], techniques: [], otPresent: false };
  for (const config of [options, { ...options, category: 'Malware' },
    { ...options, filters: { ...options.filters, search: '124' } },
    { ...options, model, orgOnly: true }, { ...options, orgOnly: true }, { ...options, pt: false }]) {
    assert.deepEqual(project(rows, config), projectNews(rows, config));
  }
  const changed = [...rows, { ...rows[0], link: 'https://source.example/new', storyId: 'new' }];
  assert.deepEqual(project(changed, options), projectNews(changed, options));
});
