import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { normalizeVictim } from './ransomwareLive.js';

const DAY = 86400000;
const text = value => typeof value === 'string' ? value.trim().slice(0, 6000) : '';
const array = value => Array.isArray(value) ? value : [];
const key = value => text(value).normalize('NFKD').replace(/\p{Mn}/gu, '').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
export function ctiDate(value) {
  const input = text(value).replace(' ', 'T').replace(/(\.\d{3})\d+/, '$1');
  if (!/^\d{4}-\d\d-\d\d(?:T\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)?$/.test(input)) return null;
  const timestamp = Date.parse(input.length === 10 || /(?:Z|[+-]\d\d:\d\d)$/.test(input) ? input : input + 'Z');
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}
const publicUrl = value => { try { const url = new URL(value); return /^https?:$/.test(url.protocol) && !url.username && !url.password ? url.href : ''; } catch { return ''; } };
export function normalizeCtiPost(raw) {
  if (!raw || !text(raw.group_name) || !text(raw.post_title)) return null;
  const meta = raw.enriched_metadata && typeof raw.enriched_metadata === 'object' ? raw.enriched_metadata : {};
  const discovered = ctiDate(raw.discovered); if (!discovered) return null;
  const leakUrl = publicUrl(raw.post_url);
  const id = createHash('sha256').update(text(raw.group_name).toLowerCase() + ':' + (leakUrl || text(raw.id) || `${text(raw.discovered)}:${text(raw.post_title)}`)).digest('hex').slice(0, 32);
  if (meta.is_toxic === true) return { id, removed: true };
  let domain = domainToASCII(text(meta.domain).toLowerCase().replace(/\.$/, ''));
  if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) || domain.endsWith('.onion')) domain = '';
  const country = /^[a-z]{2}$/i.test(text(meta.country_iso)) ? meta.country_iso.toUpperCase() : '';
  return { ...normalizeVictim({ id, name: text(meta.canonical_name) || raw.post_title, website: domain, group: raw.group_name, country,
    sector: text(meta.industry_sector), description: text(meta.summary), published: ctiDate(raw.published), discovered,
    permalink: `https://cti.fyi/api/v1/posts?group=${encodeURIComponent(raw.group_name)}&search=${encodeURIComponent(text(meta.canonical_name) || raw.post_title)}` }, 'CTI.fyi'),
    published: ctiDate(raw.published), discovered, updated: ctiDate(raw.updated), leakUrl,
    publicationTimeKnown: !!raw.published && !/^\d{4}-\d\d-\d\d(?:[ T]00:00:00(?:\.0+)?)?$/.test(text(raw.published)),
    claimStatus: 'unverified', domainRole: 'victim', metadataBasis: 'source-automated', sources: ['CTI.fyi'] };
}
export function normalizeCtiGroups(payload) {
  if (!Array.isArray(payload?.results)) throw Error('Invalid CTI.fyi groups');
  return payload.results.filter(row => text(row?.name)).map(row => {
    const profile = row.profile && !Array.isArray(row.profile) ? row.profile : {};
    return { name: text(row.name), aliases: array(profile.aliases).map(text).filter(Boolean), description: text(profile.description),
      techniques: array(profile.ttps).flatMap(value => { const match = text(value).match(/^(T\d{4}(?:\.\d{3})?)\s*(?::\s*(.*))?$/); return match ? [{ id: match[1], name: match[2] || match[1], url: `https://attack.mitre.org/techniques/${match[1].replace('.', '/')}/`, source: 'CTI.fyi' }] : []; }),
      refs: [...new Set([`https://cti.fyi/api/v1/groups/${encodeURIComponent(row.name)}?include_posts=false`, ...array(Array.isArray(row.profile) ? row.profile : profile.references).map(value => publicUrl(typeof value === 'string' ? value : value?.url)).filter(Boolean)])],
      postCount: Number.isFinite(row.post_count) ? row.post_count : 0 };
  });
}
export function mergeCtiActors(actors, groups) {
  const rows = actors.map(row => ({ ...row })); const names = new Map(), primary = new Map();
  for (const actor of rows) { const ids = primary.get(key(actor.name)) || new Set(); ids.add(actor.id); primary.set(key(actor.name), ids); }
  const index = actor => { for (const name of [actor.name, ...array(actor.aliases)]) { const ids = names.get(key(name)) || new Set(); ids.add(actor.id); names.set(key(name), ids); } };
  rows.forEach(index);
  for (const group of groups) {
    let matches = primary.get(key(group.name)) || names.get(key(group.name));
    if (!matches?.size) matches = new Set(group.aliases.flatMap(alias => [...(names.get(key(alias)) || [])]));
    const existing = matches?.size === 1 ? rows.find(row => row.id === [...matches][0]) : null;
    const ctiFyi = { group: group.name, description: group.description, claims: group.postCount, metadataBasis: 'source-automated', references: group.refs };
    if (existing) {
      existing.aliases = [...new Set([...array(existing.aliases), ...group.aliases, ...(key(existing.name) === key(group.name) ? [] : [group.name])])];
      existing.techniques = [...new Map([...group.techniques, ...array(existing.techniques)].map(row => [row.id, row])).values()];
      existing.refs = [...new Set([...array(existing.refs), ...group.refs])];
      existing.ctiFyi = { ...ctiFyi, groups: [...new Set([...array(existing.ctiFyi?.groups), existing.ctiFyi?.group, group.name].filter(Boolean))] }; index(existing);
    } else {
      const row = { id: `cti-fyi:${encodeURIComponent(group.name.toLowerCase())}`, name: group.name, aliases: group.aliases, description: group.description,
        country: '', motivation: '', sectors: [], targets: [], techniques: group.techniques, software: [], refs: group.refs, source: 'CTI.fyi', verification: 'source-reported', ctiFyi };
      rows.push(row); index(row);
    }
  }
  return rows;
}
export function ctiPublications(victims, actors) {
  const groups = new Map(actors.filter(row => row.ctiFyi).flatMap(row => [...array(row.ctiFyi.groups), row.ctiFyi.group].map(name => [key(name), row])));
  return victims.flatMap(victim => { const actor = groups.get(key(victim.group)); return actor ? [{ title: `${victim.name} · ${victim.group} · reivindicação`, link: `https://cti.fyi/api/v1/posts?search=${encodeURIComponent(victim.name)}&group=${encodeURIComponent(victim.group)}`,
    source: 'CTI.fyi', pubDate: victim.published || victim.discovered, dateInferred: !victim.published, actors: [{ id: actor.id, name: actor.name }], malware: [], iocs: { ips: [], domains: [], hashes: [], urls: [] }, claimId: victim.id, victimDomain: victim.website, claimStatus: 'unverified' }].map(row => ({ ...row, link: `${row.link}#claim-${victim.id}` })) : []; });
}
export function mergeRansomwareVictims(primary, secondary) {
  const result = primary.map(row => ({ ...row, sources: row.sources || [row.source] }));
  const index = new Map();
  const websiteKey = value => { try { return new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`).hostname.toLowerCase().replace(/^www\./, ''); } catch { return key(value); } };
  const keys = row => [row.website && `domain:${websiteKey(row.website)}`, `name:${key(row.name)}`].filter(Boolean).map(value => `${row.actorId || key(row.group)}:${value}`);
  const add = row => { for (const value of keys(row)) { const rows = index.get(value) || []; rows.push(row); index.set(value, rows); } };
  result.forEach(add);
  for (const victim of secondary) {
    const candidates = [...new Set(keys(victim).flatMap(value => index.get(value) || []))];
    const existing = candidates.find(row => !victim.sources.some(source => row.sources.includes(source)) && !(victim.website && row.website && websiteKey(row.website) !== websiteKey(victim.website))
      && Math.abs(Date.parse(row.published || row.discovered) - Date.parse(victim.published || victim.discovered)) <= 2 * DAY);
    if (!existing) { const row = { ...victim }; result.push(row); add(row); continue; }
    existing.sources = [...new Set([...existing.sources, ...victim.sources])]; existing.source = existing.sources.join(' · ');
    for (const field of ['website', 'country', 'countryName', 'sector', 'description']) if (!existing[field] || existing[field] === 'Unknown') existing[field] = victim[field];
    existing.ctiFyi = { id: victim.id, permalink: victim.permalink, discovered: victim.discovered, updated: victim.updated };
  }
  return result;
}
export function attachRansomwareActors(victims, actors) {
  const names = new Map(), primary = new Map(), sourceGroups = new Map();
  for (const actor of actors) {
    const ids = primary.get(key(actor.name)) || new Set(); ids.add(actor.id); primary.set(key(actor.name), ids);
    if (actor.ctiFyi) for (const name of [...array(actor.ctiFyi.groups), actor.ctiFyi.group]) sourceGroups.set(key(name), actor.id);
  }
  for (const actor of actors) for (const name of [actor.name, ...array(actor.aliases), actor.ctiFyi?.group].filter(Boolean)) { const ids = names.get(key(name)) || new Set(); ids.add(actor.id); names.set(key(name), ids); }
  return victims.map(row => { const sourceId = sourceGroups.get(key(row.group)); if (sourceId) return { ...row, actorId: sourceId }; const ids = primary.get(key(row.group)) || names.get(key(row.group)); return ids?.size === 1 ? { ...row, actorId: [...ids][0] } : row; });
}

export function createCtiFyi({ http, read = () => null, save = () => {}, now = () => Date.now() }) {
  let state; try { state = read(); } catch { /* first run */ }
  if (state?.version !== 1 || !Array.isArray(state.posts) || !Array.isArray(state.groups)) state = { version: 1, posts: [], groups: [], nextAt: 0 };
  let flight = null;
  const status = () => ({ id: 'CTI.fyi', configured: true, status: flight ? 'collecting' : state.lastSuccessfulAt ? state.error ? 'stale' : 'ready' : state.error ? 'error' : 'pending',
    lastSuccessfulAt: state.lastSuccessfulAt || null, nextAt: state.nextAt, posts: state.posts.length, groups: state.groups.length, partial: !!state.cursor || !!state.updatedCursor,
    rateLimit: { limit: 60, remaining: state.quota?.resetAt > now() ? state.quota.remaining : null, resetAt: state.quota?.resetAt || null } });
  const persist = () => { try { save(state); } catch { state.error = 'storage_unavailable'; } };
  async function get(path, params) {
    const response = await http.get(`https://cti.fyi/api/v1/${path}`, { params, timeout: 8000, family: 4, maxRedirects: 0, maxContentLength: 8_000_000, headers: { Accept: 'application/json' } });
    const remaining = Number(response.headers?.['x-ratelimit-remaining']); const reset = Number(response.headers?.['x-ratelimit-reset']);
    if (Number.isFinite(remaining) && Number.isFinite(reset)) state.quota = { remaining, resetAt: reset > 1e12 ? reset : reset * 1000 };
    return response.data;
  }
  async function collect() {
    const posts = new Map(state.posts.map(row => [row.id, row]));
    const until = new Date(now() + DAY).toISOString().slice(0, 10);
    const since = new Date(state.lastSuccessfulAt ? Date.parse(state.lastSuccessfulAt) - 2 * DAY : now() - 60 * DAY).toISOString().slice(0, 10);
    try {
      if (!state.groupsAt || now() - Date.parse(state.groupsAt) >= DAY) { state.groups = normalizeCtiGroups(await get('groups')); state.groupsAt = new Date(now()).toISOString(); }
      for (const updated of [false, true]) {
        if (updated && !state.lastSuccessfulAt && !state.updatedCursor) continue;
        const field = updated ? 'updatedCursor' : 'cursor';
        const cursor = state[field] || { since, until, offset: 0 };
        for (let page = 0; page < 4; page++) {
          const data = await get('posts', { [updated ? 'updated_since' : 'since']: cursor.since, [updated ? 'updated_until' : 'until']: cursor.until, sort: updated ? 'updated' : 'discovered', limit: 500, offset: cursor.offset });
          if (!Array.isArray(data?.results) || !Number.isFinite(data.count) || data.results.length > 500) throw Error('Invalid CTI.fyi posts');
          for (const raw of data.results) { const row = normalizeCtiPost(raw); if (row?.removed) posts.delete(row.id); else if (row) posts.set(row.id, row); }
          cursor.offset += data.results.length;
          if (!data.results.length || cursor.offset >= data.count) { state[field] = null; break; }
          state[field] = { ...cursor };
        }
      }
      state.lastSuccessfulAt = new Date(now()).toISOString(); state.error = null;
      state.nextAt = now() + (state.cursor || state.updatedCursor ? 15 * 60000 : 3600000);
    } catch (error) {
      state.error = error.response?.status === 429 ? 'rate_limited' : 'upstream_unavailable';
      const retry = Number(error.response?.headers?.['retry-after']); state.nextAt = now() + Math.max(60000, Math.min(DAY, Number.isFinite(retry) ? retry * 1000 : 5 * 60000));
    }
    state.posts = [...posts.values()].sort((a, b) => b.discovered.localeCompare(a.discovered)).slice(0, 50000); persist(); return status();
  }
  return { status, victims: () => state.posts, groups: () => state.groups, groupsVersion: () => state.groupsAt || '',
    refresh() { if (flight) return flight; if (now() < state.nextAt) return Promise.resolve(status()); flight = collect().finally(() => { flight = null; }); return flight; } };
}
