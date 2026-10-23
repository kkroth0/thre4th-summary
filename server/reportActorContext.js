import fs from 'node:fs';
import * as cheerio from 'cheerio';
import { buildActorIndex, matchActors } from './actorMatch.js';
import { completeReportEvidence } from './reportEvidence.js';

const key = value => String(value || '').normalize('NFKD').toLowerCase().replace(/[^a-z0-9]/g, '');
const publicReference = value => { try { const url = new URL(value); return /^https?:$/.test(url.protocol) && !url.username && !url.password ? url.href : null; } catch { return null; } };
const refs = actor => [...new Map([
  ...(actor.refs || []).map(ref => ({ source: typeof ref === 'object' ? ref.name || actor.source : actor.source, url: typeof ref === 'string' ? ref : ref.url })),
  ...(actor.ctiFyi?.references || []).map(url => ({ source: 'CTI.fyi', url })),
].filter(ref => publicReference(ref.url)).map(ref => [ref.url, { source: ref.source || 'Catálogo CTI', url: ref.url }])).values()].slice(0, 16);

export function parseMalpediaActor(html, url) {
  const $ = cheerio.load(html);
  $('script,style,form').remove();
  const heading = $('h2').first();
  const name = heading.clone().children().remove().end().text().trim();
  if (!name) throw new Error('Malpedia actor unavailable');
  const section = heading.nextUntil('hr');
  const description = section.filter('p').map((_, node) => $(node).text().trim()).get()
    .filter(text => !/^aka\s*:/i.test(text)).join('\n\n').slice(0, 6000);
  const aliases = (section.filter('p').filter((_, node) => /^aka\s*:/i.test($(node).text().trim())).first().text()
    .replace(/^aka\s*:\s*/i, '') || '').split(',').map(text => text.trim()).filter(Boolean);
  const references = [...new Set($('a[href]').map((_, node) => $(node).attr('href')).get()
    .filter(value => /^https?:\/\//i.test(value) && !value.includes('github.com/MISP/')))].slice(0, 12);
  return { name, description, aliases, url, references };
}

/** Bounded cached reads, never a provider call per IOC or a new AI request. */
export function createReportActorContext({ http, cacheFile, now = Date.now, enabled = true } = {}) {
  let cache = {};
  try { cache = JSON.parse(fs.readFileSync(cacheFile, 'utf8')); } catch { /* optional persisted cache */ }
  const pending = new Map();
  let indexedActors, index;
  async function malpedia(actor) {
    if (!enabled || !http) return null;
    const slug = String(actor.name || '').toLowerCase().trim().replace(/\s+/g, '-');
    if (!/^[a-z0-9][a-z0-9._-]{2,100}$/.test(slug)) return null;
    if (cache[slug]?.until > now()) return cache[slug].value;
    if (pending.has(slug)) return pending.get(slug);
    if (pending.size >= 2) return null; // A cold queue must not multiply network waits.
    const task = (async () => {
      let value = null;
      try {
        const url = `https://malpedia.caad.fkie.fraunhofer.de/actor/${slug}`;
        const response = await http.get(url, { timeout: 4500, maxContentLength: 1_000_000, maxRedirects: 0, family: 4 });
        const parsed = parseMalpediaActor(response.data, url);
        if (key(parsed.name) === key(actor.name)) value = parsed;
      } catch { /* catalog context remains available */ }
      cache[slug] = { value, until: now() + (value ? 86400_000 : 3600_000) };
      // Cache contains public source data only; bounded to recent actor lookups.
      cache = Object.fromEntries(Object.entries(cache).filter(([, row]) => row.until > now()).slice(-200));
      if (cacheFile) { try { const tmp = cacheFile + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(cache)); fs.renameSync(tmp, cacheFile); } catch { /* memory cache remains valid */ } }
      return value;
    })().finally(() => pending.delete(slug));
    pending.set(slug, task);
    return task;
  }
  return async function build(job, { actors = [], items = [], documents = [] } = {}) {
    if (indexedActors !== actors) { index = buildActorIndex(actors); indexedActors = actors; }
    const urls = new Set(job.urls || [job.url]);
    const sources = items.filter(row => urls.has(row.link));
    const text = [job.title, job.renderReport?.ator?.threat_actor,
      ...sources.map(row => row.title), ...documents.map(row => `${row.title}\n${String(row.text || '').slice(0, 12000)}`)].filter(Boolean).join('\n');
    const ids = new Set([...sources.flatMap(row => (row.actors || []).map(actor => actor.id)), ...matchActors(text, index).map(actor => actor.id)]);
    const selected = actors.filter(actor => ids.has(actor.id)).slice(0, 3);
    const profiles = await Promise.all(selected.map(async actor => {
      const extra = await malpedia(actor);
      const references = refs(actor);
      if (extra) references.push({ source: 'Malpedia', url: extra.url });
      const description = actor.description || extra?.description || actor.ctiFyi?.description || '';
      const activeSince = description.match(/(?:active since(?: at least)?|ativo desde(?: pelo menos)?)\s+(\d{4})/i)?.[1] || null;
      return { id: actor.id, name: actor.name, aliases: (actor.aliases || []).slice(0, 16),
        country: actor.country || '', activeSince, description: description.slice(0, 6000),
        sectors: (actor.sectors || []).slice(0, 12), targets: (actor.targets || []).slice(0, 12),
        software: (actor.software || []).map(row => typeof row === 'string' ? row : row.name).filter(Boolean).slice(0, 12),
        techniques: (actor.techniques || []).slice(0, 40), references,
        // Provider names are source claims, not extra aliases for identity resolution.
        sourceClaims: extra ? [{ source: 'Malpedia', url: extra.url, aliases: extra.aliases, description: extra.description }] : [],
        basis: 'historical-catalog', collectedAt: new Date(now()).toISOString() };
    }));
    const evidence = completeReportEvidence({ iocs: [] }, { ...job, documents }, { items: sources });
    return { profiles, iocs: evidence.iocs, sourceUrls: [...urls].filter(Boolean) };
  };
}
