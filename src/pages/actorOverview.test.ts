import test from 'node:test';
import assert from 'node:assert/strict';
import { actorFacets, countryPaths, actorOrigin } from './actorOverview';
import type { ActorListItem } from './actorsTypes';
import { readFileSync } from 'node:fs';
import type { Topology, GeometryCollection } from 'topojson-specification';
test('overview facets count profiles once and do not assign unknown origins', () => {
  const actors = [{ country: 'China', motivation: 'Espionage', sectors: ['Government', 'Government'] }, { country: '', motivation: '', sectors: ['Government'] }] as ActorListItem[];
  const facets = actorFacets(actors); assert.deepEqual(facets.countries, [{ label: 'China', count: 1 }]); assert.deepEqual(facets.sectors, [{ label: 'Government', count: 2 }]); assert.equal(facets.unknown, 1);
});
test('global map decodes reversed topology arcs without mutating the data', () => {
  const world: Topology<{ countries: GeometryCollection<{ name: string }> }> = { type: 'Topology', transform: { scale: [1, 1], translate: [0, 0] }, arcs: [[[0, 0], [4, 0], [0, 4], [-4, 0], [0, -4]]], objects: { countries: { type: 'GeometryCollection', geometries: [{ type: 'Polygon', arcs: [[-1]], properties: { name: 'Test' } }] } } };
  const before = JSON.stringify(world);
  const paths = countryPaths(world); assert.equal(paths[0].name, 'Test'); assert.match(paths[0].path, /^M[\d.,-]+/); assert.equal(JSON.stringify(world), before);
});

test('world map clips dateline countries instead of drawing blue strips across the world', () => {
  const world = JSON.parse(readFileSync('public/data/world-countries-110m.json', 'utf8'));
  const paths = countryPaths(world);
  assert.ok(paths.length > 150);
  assert.ok(!paths.some(country => country.name === 'Antarctica'));
  for (const name of ['Russia', 'Fiji', 'United States of America']) {
    const path = paths.find(country => country.name === name)?.path;
    assert.ok(path, name);
    let lastX = 0;
    for (const [, command, x, y] of path.matchAll(/([ML])(-?[\d.]+),(-?[\d.]+)/g)) {
      assert.ok(Number(x) >= 11 && Number(x) <= 889 && Number(y) >= 13 && Number(y) <= 437, `${name}: coordinates stay inside map`);
      if (command === 'L') assert.ok(Math.abs(Number(x) - lastX) < 600, `${name}: no trans-world segment`);
      lastX = Number(x);
    }
  }
});

test('origin codes and equivalent country names collapse to one facet', () => { assert.equal(actorOrigin('RU'), 'Russia'); assert.equal(actorOrigin('Russian Federation'), 'Russia'); assert.equal(actorOrigin('Iran (Islamic Republic of)'), 'Iran'); });
test('unknown origin labels stay out of geographic facets', () => { const facets = actorFacets([{ country: 'Unknown', sectors: [] }, { country: 'N/A', sectors: [] }, { country: 'China', sectors: [] }] as ActorListItem[]); assert.equal(facets.unknown, 2); assert.deepEqual(facets.countries, [{ label: 'China', count: 1 }]); });
