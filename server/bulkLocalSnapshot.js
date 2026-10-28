import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { gzipSync, gunzipSync } from 'node:zlib';
import { normalizeIndicator } from './indicatorIdentity.js';

// A read-only inventory snapshot enriches an export even while its API tasks
// remain pending. Materialize each context once on disk, not in a growing Map.
export function createBulkLocalSnapshot({ filePath, spoolPath, owner, now = Date.now } = {}) {
  if (!filePath) return { enrich: row => row, metadata: null, close() {} };
  if (!owner || owner === 'global') throw Error('Account scope required for the export');
  const db = new Database(filePath, { readonly: true, fileMustExist: true });
  db.pragma('query_only=ON'); db.pragma('busy_timeout=1000'); db.pragma('cache_size=-2000'); db.exec('BEGIN');
  const savedImport = db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(`axur-import-v1:${owner}`);
  const imported = savedImport ? JSON.parse(savedImport.value) : null;
  const metadata = { asOf: new Date(now()).toISOString(), axurImportStatus: imported?.status || 'unavailable', axurImportAt: imported?.lastSuccessfulAt || null, axurRecordsTraversed: imported?.processed || 0, method: 'Exact indicator matches in global and account-private saved evidence; no external API requests.' };
  const cacheFile = spoolPath + '.' + crypto.randomUUID();
  const cache = new Database(cacheFile);
  cache.pragma('journal_mode=MEMORY'); cache.pragma('synchronous=OFF'); cache.pragma('cache_size=-2000');
  cache.exec('CREATE TABLE contexts(ordinal INTEGER PRIMARY KEY, value BLOB NOT NULL)');
  const hit = cache.prepare('SELECT value FROM contexts WHERE ordinal=?'), put = cache.prepare('INSERT INTO contexts VALUES(?,?)');
  // Force exact-IOC probes instead of scanning the account's multi-million-row catalog.
  const observations = db.prepare('SELECT o.* FROM observations o INDEXED BY observations_indicator WHERE o.indicator=? AND o.scope IN (?,?) ORDER BY published DESC,id');
  const entities = db.prepare('SELECT kind,entity id,name,relation FROM entity_links WHERE observation=?');
  let checked = 0, axurMatches = 0;
  return {
    metadata,
    enrich(row) {
      const previous = hit.get(row.serverOrdinal);
      let context;
      if (previous) context = JSON.parse(gunzipSync(previous.value).toString());
      else {
        const normalized = normalizeIndicator(row.query);
        if (!normalized) throw Error('Invalid saved indicator during local correlation');
        const id = crypto.createHash('sha256').update(normalized.type + ':' + normalized.value).digest('hex');
        const evidence = observations.all(id, 'global', String(owner)).map(record => ({ ...JSON.parse(record.details), provider: record.provider, published: record.published, collectedAt: record.collected, entities: entities.all(record.id) }));
        const publications = [...(row.context?.publications || [])], known = new Set(publications.map(item => item.link));
        for (const item of evidence) if (['news', 'Axur'].includes(item.provider) && item.link && !known.has(item.link)) {
          known.add(item.link); publications.push({ storyId: '', title: item.title, source: item.source || item.provider, link: item.link, pubDate: item.published, actors: item.entities.filter(entity => entity.kind === 'actor').map(entity => entity.name), categories: [] });
        }
        const count = evidence.filter(item => item.provider === 'Axur').length;
        checked++; if (count) axurMatches++;
        context = { evidence, publications, errors: [], localSnapshot: { ...metadata, axurEvidence: count } };
        put.run(row.serverOrdinal, gzipSync(Buffer.from(JSON.stringify(context)), { level: 1 }));
      }
      // This completes the local read only. API pending/error states and the
      // original verdict remain intact; no job/task is marked complete here.
      return { ...row, context, contextLoading: false };
    },
    stats: () => ({ ...metadata, checked, axurMatches }),
    close() { try { if (db.inTransaction) db.exec('ROLLBACK'); } finally { db.close(); cache.close(); if (fs.existsSync(cacheFile)) fs.unlinkSync(cacheFile); } },
  };
}
