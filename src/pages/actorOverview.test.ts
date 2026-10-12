import test from 'node:test';
import assert from 'node:assert/strict';
import { actorFacets, countryPaths, actorOrigin } from './actorOverview';
import type { ActorListItem } from './actorsTypes';
test('overview facets count profiles once and do not assign unknown origins', () => {
  const actors = [{ country: 'China', motivation: 'Espionage', sectors: ['Government', 'Government'] }, { country: '', motivation: '', sectors: ['Government'] }] as ActorListItem[];
  const facets = actorFacets(actors); assert.deepEqual(facets.countries, [{ label: 'China', count: 1 }]); assert.deepEqual(facets.sectors, [{ label: 'Government', count: 2 }]); assert.equal(facets.unknown, 1);
});
test('global map decodes reversed topology arcs without mutating the data', () => {
  const world = { transform: { scale: [1, 1], translate: [0, 0] }, arcs: [[[0, 0], [1, 1]]], objects: { countries: { geometries: [{ type: 'Polygon', arcs: [[-1]], properties: { name: 'Test' } }] } } };
  const paths = countryPaths(world); assert.equal(paths[0].name, 'Test'); assert.match(paths[0].path, /^M452.5,222.5/); assert.deepEqual(world.arcs[0], [[0, 0], [1, 1]]);
});

test('origin codes and equivalent country names collapse to one facet', () => { assert.equal(actorOrigin('RU'), 'Russia'); assert.equal(actorOrigin('Russian Federation'), 'Russia'); assert.equal(actorOrigin('Iran (Islamic Republic of)'), 'Iran'); });
