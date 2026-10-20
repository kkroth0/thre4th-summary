import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createGunzip } from 'node:zlib';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const require = createRequire(import.meta.url);
const { extract } = require('tar-stream');
export const HUNTING_SOURCES = [
  { repo: 'cyb3rmik3/KQL-threat-hunting-queries', license: 'MIT', prefixes: ['Sentinel/', '01.ThreatHunting/', '02.ThreatDetection/', 'Defender For Endpoint/'] },
  { repo: 'Bert-JanP/Hunting-Queries-Detection-Rules', license: 'BSD-3-Clause', prefixes: [] },
  { repo: 'reprise99/Sentinel-Queries', license: 'MIT', prefixes: [] },
];
export const fingerprint = value => createHash('sha256').update(value).digest('hex');
const clean = (value, limit) => String(value || '').replace(/[\u0000-\u0008\u000b-\u001f]/g, '').trim().slice(0, limit);
const ids = text => [...new Set(String(text).match(/\bT\d{4}(?:\.\d{3})?\b/g) || [])];
const encodedPath = value => value.split('/').map(encodeURIComponent).join('/');
export function parseHuntingFile(source, file, text, revision) {
  if (!/^[a-f0-9]{40}$/.test(revision) || !/\.(md|kql)$/i.test(file) || text.length > 160000 || /(?:^|\/)(?:README|LICENSE|DetectionTemplate|threat-hunting-template)\b/i.test(file)) return [];
  if (source.prefixes.length && !source.prefixes.some(prefix => file.startsWith(prefix))) return [];
  const title = clean(text.match(/^#\s+(.+)$/m)?.[1] || file.split('/').pop().replace(/\.(md|kql)$/i, '').replace(/[_-]/g, ' '), 180);
  const blocks = /\.kql$/i.test(file) ? [{ query: text, before: '' }] : [...text.matchAll(/```([^\r\n]*)\r?\n([\s\S]*?)```/g)].filter(match => /^(?:kql|kusto|kustoquery|query|)$/i.test(match[1].trim())).map(match => ({ query: match[2], before: text.slice(0, match.index) }));
  return blocks.flatMap(({ query, before }) => {
    if (query.length > 18000) return [];
    query = clean(query.replace(/\r\n?/g, '\n'), 18000);
    if (!query || !/\|\s*(?:where|project|summarize|extend|join|take|search|distinct|sort|order|parse|lookup|union)\b/i.test(query)) return [];
    const heading = [...before.matchAll(/^#{1,4}\s+(.+)$/gm)].at(-1)?.[1] || '';
    const platformText = [heading, file].join(' ');
    const platform = /sentinel|log analytics|syslog|cef|azure activity|securityevents?/i.test(platformText) ? 'sentinel' : /defender|endpoint|xdr|m365/i.test(platformText) ? 'defender' : /\bTimeGenerated\b/.test(query) ? 'sentinel' : /\bTimestamp\b|\bDevice\w+Events\b/.test(query) ? 'defender' : 'unknown';
    const tables = [...new Set([...query.matchAll(/(?:^|\n)\s*([A-Z][A-Za-z0-9_]+)\s*(?=\r?\n\s*\||\s*\|)/g)].map(match => match[1]))].slice(0, 15);
    const description = clean(text.replace(/```[\s\S]*?```/g, '').replace(/https?:\/\/\S+/g, '').replace(/[#*|]/g, ' ').replace(/\s+/g, ' '), 800);
    const id = fingerprint(platform + '\n' + query);
    return [{ id, title, description, query, platform, tables, techniques: ids(text), cves: [...new Set(text.match(/\bCVE-\d{4}-\d{4,}\b/gi) || [])].map(x => x.toUpperCase()), provenance: [{ repo: source.repo, license: source.license, revision, path: file, url: `https://github.com/${source.repo}/blob/${revision}/${encodedPath(file)}` }] }];
  });
}
export function mergeHuntingQueries(queries) {
  const merged = new Map();
  for (const query of queries) {
    const old = merged.get(query.id);
    if (!old) merged.set(query.id, { ...query, provenance: [...query.provenance] });
    else { old.provenance = [...new Map([...old.provenance, ...query.provenance].map(row => [row.url, row])).values()]; old.techniques = [...new Set([...old.techniques, ...query.techniques])]; old.cves = [...new Set([...old.cves, ...query.cves])]; }
  }
  return [...merged.values()];
}
function bounded(max) { let bytes = 0; return new Transform({ transform(chunk, _encoding, done) { bytes += chunk.length; done(bytes > max ? Error('Repository size limit') : null, chunk); } }); }
export async function collectHuntingRepository(source, http, token = '', previous) {
  const headers = { Accept: 'application/vnd.github+json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const head = await http.get(`https://api.github.com/repos/${source.repo}/commits/main`, { headers, timeout: 12000, maxContentLength: 1000000, maxRedirects: 0 });
  const revision = head.data?.sha;
  if (!/^[a-f0-9]{40}$/.test(revision)) throw Error('Invalid repository revision');
  if (previous?.revision === revision && previous.queries?.length) return previous;
  const response = await http.get(`https://codeload.github.com/${source.repo}/tar.gz/${revision}`, { responseType: 'stream', timeout: 45000, maxRedirects: 0 });
  const tar = extract(), queries = []; let entries = 0, licenseText = '';
  tar.on('entry', (header, stream, next) => {
    const file = header.name.split('/').slice(1).join('/');
    const permitted = ++entries <= 30000 && header.type === 'file' && header.size <= 160000 && !file.split('/').some(part => !part || part === '.' || part === '..') && !/[\\\u0000-\u001f]/.test(file);
    const wanted = permitted && (/^LICENSE(?:\.\w+)?$/i.test(file) || /\.(md|kql)$/i.test(file));
    if (!wanted) { stream.resume(); stream.on('end', next); return; }
    const chunks = []; stream.on('data', chunk => chunks.push(chunk)); stream.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (/^LICENSE(?:\.\w+)?$/i.test(file)) licenseText = text;
      else queries.push(...parseHuntingFile(source, file, text, revision));
      next();
    });
  });
  await pipeline(response.data, bounded(16 * 1024 * 1024), createGunzip(), bounded(60 * 1024 * 1024), tar);
  if (!queries.length || !licenseText) throw Error('Repository has no licensed KQL');
  return { repo: source.repo, revision, license: source.license, licenseText, queries };
}
export function createHuntingLibrary({ snapshotPath = new URL('./data/hunting-library.json', import.meta.url), cachePath, http, token = '', now = () => Date.now() } = {}) {
  let snapshot = { queries: [], sources: [], updatedAt: null }, flight, checkedAt = 0;
  for (const file of [snapshotPath, cachePath].filter(Boolean)) { try { const value = JSON.parse(readFileSync(file, 'utf8')); if (Array.isArray(value.queries) && value.queries.length && (!snapshot.updatedAt || Date.parse(value.updatedAt) >= Date.parse(snapshot.updatedAt))) snapshot = value; } catch { /* use bundled catalog */ } }
  const revision = () => fingerprint(snapshot.sources.map(s => s.revision).join(':'));
  async function sync() {
    if (!http || now() - checkedAt < 24 * 3600000) return;
    if (flight) return flight;
    checkedAt = now();
    flight = (async () => {
      const sources = [], queries = [];
      for (const source of HUNTING_SOURCES) {
        try { const old = snapshot.sources.find(row => row.repo === source.repo); const previous = old ? { ...old, queries: snapshot.queries.filter(row => row.provenance.some(p => p.repo === source.repo)) } : undefined; const result = await collectHuntingRepository(source, http, token, previous); const { queries: rows, ...meta } = result; sources.push(meta); queries.push(...rows); }
        catch { const old = snapshot.sources.find(row => row.repo === source.repo); if (old) { sources.push(old); queries.push(...snapshot.queries.filter(row => row.provenance.some(p => p.repo === source.repo))); } }
      }
      if (sources.length !== HUNTING_SOURCES.length) return;
      const next = { updatedAt: new Date(now()).toISOString(), sources, queries: mergeHuntingQueries(queries) };
      if (cachePath) { mkdirSync(path.dirname(cachePath), { recursive: true }); const tmp = cachePath + '.tmp'; writeFileSync(tmp, JSON.stringify(next)); renameSync(tmp, cachePath); }
      snapshot = next;
    })().finally(() => { flight = null; });
    return flight;
  }
  return { all: () => snapshot.queries, revision, status: () => ({ updatedAt: snapshot.updatedAt, queries: snapshot.queries.length, sources: snapshot.sources.map(({ licenseText, ...source }) => source) }), sync };
}
