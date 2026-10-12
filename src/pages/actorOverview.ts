import type { ActorListItem } from './actorsTypes';
export function actorOrigin(value: string) {
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
  return { countries: count(actor => [actorOrigin(actor.country)]), sectors: count(actor => actor.sectors || []), motivations: count(actor => [actor.motivation]), unknown: actors.filter(actor => !actor.country).length };
}
type Topology = { transform: { scale: number[]; translate: number[] }; arcs: number[][][]; objects: { countries: { geometries: { type: string; arcs: number[][] | number[][][]; properties: { name: string } }[] } } };
export function countryPaths(world: Topology) {
  const arcs = world.arcs.map(arc => { let x = 0, y = 0; return arc.map(point => { x += point[0]; y += point[1]; return [(x * world.transform.scale[0] + world.transform.translate[0] + 180) * 2.5, (90 - (y * world.transform.scale[1] + world.transform.translate[1])) * 2.5]; }); });
  const ring = (indexes: number[]) => indexes.flatMap(index => index < 0 ? [...arcs[~index]].reverse() : arcs[index]);
  return world.objects.countries.geometries.filter(country => country.properties.name !== 'Antarctica').map(country => {
    const polygons = country.type === 'Polygon' ? [country.arcs as number[][]] : country.arcs as number[][][];
    return { name: country.properties.name, path: polygons.flatMap(polygon => polygon.map(indexes => ring(indexes).map((point, i) => `${i ? 'L' : 'M'}${point[0].toFixed(1)},${point[1].toFixed(1)}`).join(' ') + ' Z')).join(' ') };
  });
}
