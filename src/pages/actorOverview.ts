import type { ActorListItem } from './actorsTypes';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import type { Topology, GeometryCollection } from 'topojson-specification';
import type { FeatureCollection } from 'geojson';
export function actorOrigin(value: string) {
  if (!value || /^(unknown(?: origin)?|unspecified|undetermined|n\/?a|none|—)$/i.test(value.trim())) return '';
  const aliases: Record<string, string> = { 'Russian Federation': 'Russia', 'Iran (Islamic Republic of)': 'Iran', "Korea (Democratic People's Republic of)": 'North Korea', 'Korea (Republic of)': 'South Korea', "People's Republic of China": 'China', 'United States of America': 'United States', 'Viet Nam': 'Vietnam' };
  if (aliases[value]) return aliases[value];
  if (/^[A-Z]{2}$/.test(value)) { try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(value) || value; } catch { return value; } }
  return value;
}
export function actorFacets(actors: ActorListItem[]) {
  const count = (values: (actor: ActorListItem) => string[]) => {
    const result = new Map<string, number>();
    for (const actor of actors) for (const value of new Set(values(actor).filter(Boolean))) result.set(value, (result.get(value) || 0) + 1);
    return [...result].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  };
  return { countries: count(actor => [actorOrigin(actor.country)]), sectors: count(actor => actor.sectors || []), motivations: count(actor => [actor.motivation]), unknown: actors.filter(actor => !actorOrigin(actor.country)).length };
}
export function countryPaths(world: Topology<{ countries: GeometryCollection<{ name: string }> }>) {
  const countries = feature(world, world.objects.countries) as FeatureCollection;
  const visible = { ...countries, features: countries.features.filter(country => country.properties?.name !== 'Antarctica') };
  // Geographic clipping splits polygons at ±180°, avoiding Russia/Fiji strips.
  const projection = geoNaturalEarth1().fitExtent([[12, 14], [888, 436]], visible);
  const draw = geoPath(projection);
  return visible.features.map(country => ({ name: String(country.properties?.name || ''), path: draw(country) || '' }));
}
