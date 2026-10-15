import { createHash } from 'node:crypto';

const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const json = value => JSON.stringify(canonical(JSON.parse(JSON.stringify(value))));
const hash = value => createHash('sha256').update(value).digest('hex');
const aliasKey = value => String(value || '').normalize('NFD').replace(/\p{Mn}/gu, '').toLowerCase().trim().replace(/\s+/g, ' ');
const prepared = (rows, field) => {
  const values = new Map();
  for (const row of rows) {
    if (!row?.[field] || values.has(row[field])) throw Error('News snapshot contains missing or duplicate identities');
    const payload = json(row); values.set(row[field], { payload, hash: hash(payload) });
  }
  return values;
};
const pairs = (archive, stories) => [['archive', prepared(archive, 'link')], ['stories', prepared(stories, 'id')]];

export function compareNewsSnapshots(db, archive, stories) {
  const result = {};
  for (const [kind, expected] of pairs(archive, stories)) {
    const stored = new Map(db.prepare('SELECT id,hash,payload FROM news_documents WHERE kind=?').all(kind).map(row => [row.id, hash(row.payload) === row.hash ? row.hash : 'invalid-payload']));
    result[kind] = { source: expected.size, stored: stored.size, missing: 0, changed: 0, extra: 0 };
    for (const [id, row] of expected) { if (!stored.has(id)) result[kind].missing++; else if (stored.get(id) !== row.hash) result[kind].changed++; }
    for (const id of stored.keys()) if (!expected.has(id)) result[kind].extra++;
  }
  const links = new Set(archive.map(row => row.link));
  const identities = stories.flatMap(row => [row.id, ...(row.aliases || [])]);
  result.orphanSources = stories.flatMap(row => row.sources || []).filter(row => !links.has(row.link)).length;
  result.conflictingAliases = identities.length - new Set(identities).size;
  result.equal = ['archive', 'stories'].every(kind => !result[kind].missing && !result[kind].changed && !result[kind].extra);
  result.readyForReadPilot = result.equal && !result.orphanSources && !result.conflictingAliases;
  return result;
}

// Same SQLite connection as IOC evidence. JSON remains authoritative during
// shadow validation; one transaction mirrors both complete source snapshots.
export function createNewsPersistence(db, { now = () => Date.now() } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS news_documents(kind TEXT NOT NULL,id TEXT NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,updated TEXT NOT NULL,PRIMARY KEY(kind,id));
    CREATE TABLE IF NOT EXISTS news_document_revisions(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,document TEXT NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,at TEXT NOT NULL,reason TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS news_revision_lookup ON news_document_revisions(kind,document,id);
    CREATE TABLE IF NOT EXISTS news_body_versions(link TEXT NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,collected TEXT NOT NULL,PRIMARY KEY(link,hash));
    CREATE INDEX IF NOT EXISTS news_body_latest ON news_body_versions(link,collected DESC);
    CREATE TABLE IF NOT EXISTS news_shadow_checks(id INTEGER PRIMARY KEY,at TEXT NOT NULL,payload TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS intelligence_entity_names(scope TEXT NOT NULL,kind TEXT NOT NULL,entity TEXT NOT NULL,name TEXT NOT NULL,alias TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(scope,kind,entity,alias,source));
    CREATE INDEX IF NOT EXISTS intelligence_alias_lookup ON intelligence_entity_names(alias,scope,kind);`);
  const at = () => new Date(now()).toISOString();
  const register = db.prepare('INSERT INTO intelligence_entity_names VALUES(?,?,?,?,?,?) ON CONFLICT(scope,kind,entity,alias,source) DO UPDATE SET name=excluded.name WHERE name<>excluded.name');
  function registerEntities(rows, scope = 'global', source = 'news') {
    for (const row of rows) {
      if (!['actor', 'malware', 'campaign', 'cve'].includes(row.kind) || !row.id || !row.name) continue;
      for (const name of new Set([row.name, ...(Array.isArray(row.aliases) ? row.aliases : [])])) {
        if (typeof name !== 'string' || !name.trim() || name.length > 240) continue;
        register.run(String(scope), row.kind, String(row.id), String(row.name), aliasKey(name), source);
      }
    }
  }
  const put = db.prepare('INSERT OR REPLACE INTO news_documents VALUES(?,?,?,?,?)');
  const revise = db.prepare('INSERT INTO news_document_revisions(kind,document,hash,payload,at,reason) VALUES(?,?,?,?,?,?)');
  const compare = (archive, stories) => compareNewsSnapshots(db, archive, stories);
  const reconcile = db.transaction(({ archive, stories }) => {
    let changed = 0;
    for (const [kind, desired] of pairs(archive, stories)) {
      const previous = new Map(db.prepare('SELECT * FROM news_documents WHERE kind=?').all(kind).map(row => [row.id, row]));
      for (const [id, row] of desired) {
        const old = previous.get(id);
        if (old?.hash === row.hash && old.payload === row.payload) continue;
        if (old) revise.run(kind, id, old.hash, old.payload, at(), 'updated');
        put.run(kind, id, row.hash, row.payload, at()); changed++;
      }
      for (const [id, old] of previous) if (!desired.has(id)) {
        revise.run(kind, id, old.hash, old.payload, at(), 'source-retention');
        db.prepare('DELETE FROM news_documents WHERE kind=? AND id=?').run(kind, id); changed++;
      }
    }
    registerEntities(archive.flatMap(row => [
      ...['actor', 'malware', 'campaign'].flatMap(kind => (row[{ actor: 'actors', malware: 'malware', campaign: 'campaigns' }[kind]] || []).filter(Boolean).map(entity => ({ ...entity, kind }))),
      ...(row.cves || []).map(id => ({ id, name: id, kind: 'cve' })),
    ]));
    const result = { ...compare(archive, stories), changed, at: at(), mode: 'shadow' };
    db.prepare('INSERT INTO news_shadow_checks(at,payload) VALUES(?,?)').run(result.at, JSON.stringify(result));
    db.prepare('DELETE FROM news_shadow_checks WHERE id NOT IN (SELECT id FROM news_shadow_checks ORDER BY id DESC LIMIT 1000)').run();
    return result;
  });
  const saveBody = db.transaction((link, entry) => {
    if (!entry?.text || typeof entry.text !== 'string') return;
    const digest = hash(entry.text), payload = JSON.stringify({ ...entry, link, contentHash: digest });
    db.prepare('INSERT INTO news_body_versions VALUES(?,?,?,?) ON CONFLICT(link,hash) DO UPDATE SET payload=excluded.payload,collected=excluded.collected WHERE payload<>excluded.payload').run(link, digest, payload, entry.collectedAt || at());
  });
  const registerTransaction = db.transaction(registerEntities);
  return { reconcile, compare, saveBody,
    registerEntities: (...args) => db.inTransaction ? registerEntities(...args) : registerTransaction(...args),
    body: link => { const row = db.prepare('SELECT payload FROM news_body_versions WHERE link=? ORDER BY collected DESC,rowid DESC LIMIT 1').get(link); return row ? JSON.parse(row.payload) : null; },
    rows: kind => db.prepare('SELECT payload FROM news_documents WHERE kind=? ORDER BY id').all(kind).map(row => JSON.parse(row.payload)),
    status: () => {
      const row = db.prepare('SELECT payload FROM news_shadow_checks ORDER BY id DESC LIMIT 1').get();
      return { mode: 'shadow', latest: row ? JSON.parse(row.payload) : null,
        bodies: db.prepare('SELECT COUNT(*) n FROM news_body_versions').get().n, revisions: db.prepare('SELECT COUNT(*) n FROM news_document_revisions').get().n };
    },
    entities: ({ owner = '', kind = '', query = '', limit = 50 } = {}) => {
      const scopes = owner ? ['global', String(owner)] : ['global'];
      const clauses = [`scope IN (${scopes.map(() => '?').join(',')})`], args = [...scopes];
      if (kind) { clauses.push('kind=?'); args.push(kind); }
      if (query) { clauses.push("alias LIKE ? ESCAPE '\\'"); args.push('%' + aliasKey(query).slice(0, 180).replace(/[\\%_]/g, '\\$&') + '%'); }
      return db.prepare(`SELECT kind,entity id,name,json_group_array(DISTINCT alias) aliases FROM intelligence_entity_names WHERE ${clauses.join(' AND ')} GROUP BY kind,entity,name ORDER BY name,entity LIMIT ?`).all(...args, Math.min(100, Math.max(1, Number(limit) || 50))).map(row => ({ ...row, aliases: JSON.parse(row.aliases) }));
    },
  };
}

// Capture successful bodies before disk cache eviction. Failed attempts never
// overwrite retained text; the cache's current fingerprint remains authoritative.
export function durableArticleCache(cache, persistence, onError = () => {}) {
  return { ...cache,
    get(key) {
      const disk = cache.get(key);
      if (disk?.text) { try { persistence.saveBody(key, disk); } catch (error) { onError(error); } return disk; }
      if (disk) return disk;
      try { return persistence.body(key); } catch (error) { onError(error); return null; }
    },
    set(key, value) { cache.set(key, value); try { persistence.saveBody(key, value); } catch (error) { onError(error); } },
  };
}
