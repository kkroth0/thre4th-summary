import { createHash } from 'node:crypto';
import { buildPhishingDataset } from './phishingDataset.js';
import { PHISHING_VERSION, PHISHING_KIT_VERSION } from './phishingIntel.js';
import { EXTRACTION_VERSION } from './feedEnrichment.js';

const DAY = 86400000, WEEK = 7 * DAY;
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const unique = values => [...new Set(values.filter(Boolean))];
const sourceHost = row => { try { return new URL(row.link).hostname.replace(/^www\./, ''); } catch { return row.source || 'unknown'; } };
export const weekStart = value => { const at = new Date(value); at.setUTCHours(0, 0, 0, 0); at.setUTCDate(at.getUTCDate() - at.getUTCDay()); return at.toISOString().slice(0, 10); };
const dimensions = { technique: 'phishingTechniques', brand: 'brands', sector: 'sectors', actor: 'actorNames', campaign: 'campaigns', malware: 'software' };

// Count an event once per dimension/week. Named campaigns may span multiple
// incidents, so campaign IDs never replace the correlator's event identity here.
export function buildPhishingWeeks(rows, { now = new Date() } = {}) {
  const current = Date.parse(weekStart(now)), earliest = current - 9 * WEEK;
  const eligible = rows.filter(row => row.securityRelevant !== false && !row.dateInferred && Date.parse(row.pubDate) >= earliest && Date.parse(row.pubDate) <= now.getTime());
  const dataset = buildPhishingDataset(eligible, { limit: 20000 });
  const oldest = Math.min(...rows.filter(row => !row.dateInferred && row.securityRelevant !== false).map(row => Date.parse(row.pubDate)).filter(Number.isFinite), now.getTime());
  return Array.from({ length: 10 }, (_, index) => {
    const start = current - (9 - index) * WEEK, end = start + WEEK;
    const reports = dataset.reports.filter(row => Date.parse(row.pubDate) >= start && Date.parse(row.pubDate) < end);
    const eventOf = row => row.storyId || `publication:${row.link}`;
    const facets = Object.fromEntries(Object.entries(dimensions).map(([kind, field]) => {
      const counts = new Map();
      for (const row of reports) for (const label of unique((Array.isArray(row[field]) ? row[field] : []).map(value => typeof value === 'string' ? value : value?.name))) {
        const entry = counts.get(label) || { label, events: new Set(), sources: new Set() };
        entry.events.add(eventOf(row)); entry.sources.add(sourceHost(row)); counts.set(label, entry);
      }
      return [kind, [...counts.values()].map(entry => ({ label: entry.label, count: entry.events.size, sources: entry.sources.size })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))];
    }));
    const known = reports.filter(row => typeof row.articleTextAvailable === 'boolean');
    return { week: new Date(start).toISOString().slice(0, 10), end: new Date(end).toISOString().slice(0, 10), closed: end <= current,
      hasArchiveHistory: oldest <= start, truncated: dataset.truncated,
      comparable: reports.every(row => row.phishingIntel?.version === PHISHING_VERSION && row.extractionVersion === EXTRACTION_VERSION),
      rules: { phishing: PHISHING_VERSION, phishingKits: PHISHING_KIT_VERSION, extraction: EXTRACTION_VERSION },
      publications: reports.length, events: unique(reports.map(eventOf)).length, sources: unique(reports.map(sourceHost)).length,
      bodyCoverage: { known: known.length, available: known.filter(row => row.articleTextAvailable).length, unknown: reports.length - known.length }, facets,
      historicalMemberships: reports.filter(row => row.evidence.some(e => e.basis === 'retained-week-membership')).length,
      members: reports.map(row => ({ link: row.link, event: eventOf(row), source: sourceHost(row), contentHash: row.contentHash || null,
        phishingVersion: row.phishingIntel?.version || PHISHING_VERSION, extractionVersion: row.extractionVersion || null, articleTextAvailable: row.articleTextAvailable ?? null })) };
  });
}

export function summarizePhishingWeeks(weeks) {
  const closed = weeks.filter(week => week.closed).sort((a, b) => b.week.localeCompare(a.week));
  const target = closed[0], baseline = closed.slice(1, 9).filter(week => week.hasArchiveHistory && !week.truncated && week.comparable);
  const ready = !!target && baseline.length === 8 && !target.truncated && target.hasArchiveHistory && target.comparable && baseline.every(week => JSON.stringify(week.rules) === JSON.stringify(target.rules));
  const signals = Object.keys(dimensions).flatMap(kind => (target?.facets[kind] || []).map(item => {
    const average = baseline.length ? baseline.reduce((sum, week) => sum + (week.facets[kind].find(entry => entry.label === item.label)?.count || 0), 0) / baseline.length : null;
    return { kind, ...item, baseline: ready ? average : null, delta: ready ? item.count - average : null,
      percent: ready && average > 0 ? (item.count / average - 1) * 100 : null, newInArchive: ready && average === 0 };
  }).sort((a, b) => (b.delta ?? b.count) - (a.delta ?? a.count) || b.count - a.count).slice(0, 20));
  return { target: target?.week || null, baselineWeeks: baseline.length, baselineReady: ready, signals,
    basis: 'archive-observations', sourceIndependence: 'hostname-proxy', timezone: 'UTC', weekStartsOn: 'Sunday' };
}

// Uses the inventory connection: no new database/deploy files and no API calls
// in the HTTP read path. Candidates are deliberately separate from indicators.
export function createPhishingEvolution(db, { now = () => Date.now() } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS phishing_weeks(week TEXT PRIMARY KEY,hash TEXT NOT NULL,payload TEXT NOT NULL,updated TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS phishing_week_revisions(id INTEGER PRIMARY KEY,week TEXT NOT NULL,payload TEXT NOT NULL,at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS phishing_collection_cycles(at TEXT PRIMARY KEY,status TEXT NOT NULL,payload TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS phishing_source_days(day TEXT NOT NULL,source TEXT NOT NULL,fresh INTEGER NOT NULL DEFAULT 0,unchanged INTEGER NOT NULL DEFAULT 0,stale INTEGER NOT NULL DEFAULT 0,failed INTEGER NOT NULL DEFAULT 0,last_at TEXT,last_success TEXT,PRIMARY KEY(day,source));
    CREATE TABLE IF NOT EXISTS watch_candidates(scope TEXT NOT NULL,id TEXT NOT NULL,profile TEXT NOT NULL,domain TEXT NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,updated TEXT NOT NULL,PRIMARY KEY(scope,id));
    CREATE INDEX IF NOT EXISTS watch_candidate_profile ON watch_candidates(scope,profile);
    CREATE TABLE IF NOT EXISTS watch_candidate_revisions(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,candidate TEXT NOT NULL,payload TEXT NOT NULL,at TEXT NOT NULL);`);
  const saveWeeks = db.transaction(weeks => {
    for (const week of weeks) {
      const previous = db.prepare('SELECT * FROM phishing_weeks WHERE week=?').get(week.week), revision = hash(week);
      if (previous?.hash === revision) continue;
      if (previous) db.prepare('INSERT INTO phishing_week_revisions(week,payload,at) VALUES(?,?,?)').run(week.week, previous.payload, new Date(now()).toISOString());
      db.prepare('INSERT OR REPLACE INTO phishing_weeks VALUES(?,?,?,?)').run(week.week, revision, JSON.stringify(week), new Date(now()).toISOString());
    }
  });
  const recordCycle = db.transaction(({ at = new Date(now()).toISOString(), status = 'ready', elapsedMs = 0, bodies = {}, sources = [] } = {}) => {
    const inserted = db.prepare('INSERT OR IGNORE INTO phishing_collection_cycles VALUES(?,?,?)').run(at, status, JSON.stringify({ elapsedMs, bodies, sourceCount: sources.length, healthySources: sources.filter(([, health]) => ['fresh', 'unchanged'].includes(health.status)).length }));
    if (!inserted.changes) return;
    for (const [source, health] of sources) {
      const state = ['fresh', 'unchanged', 'stale', 'failed'].includes(health.status) ? health.status : 'failed';
      db.prepare(`INSERT INTO phishing_source_days(day,source,${state},last_at,last_success) VALUES(?,?,1,?,?) ON CONFLICT(day,source) DO UPDATE SET ${state}=${state}+1,last_at=excluded.last_at,last_success=COALESCE(excluded.last_success,last_success)`).run(at.slice(0, 10), source, at, health.lastSuccessfulAt || null);
    }
    const cutoff = new Date(now() - 90 * DAY).toISOString();
    db.prepare('DELETE FROM phishing_collection_cycles WHERE at<?').run(cutoff);
    db.prepare('DELETE FROM phishing_source_days WHERE day<?').run(cutoff.slice(0, 10));
  });
  const syncCandidates = db.transaction(hits => {
    for (const hit of hits) {
      if (!hit.ownerId || !hit.id || !hit.profileId || !hit.apexDomain) continue;
      const payload = { ...hit, verdict: hit.verdict || (hit.status === 'confirmed' ? 'malicious' : 'unknown'), role: 'candidate' };
      const { lastSeen: _lastSeen, dns, ...evidence } = payload;
      const { checkedAt: _checkedAt, ...dnsEvidence } = dns || {};
      const revision = hash({ ...evidence, dns: dnsEvidence }), previous = db.prepare('SELECT * FROM watch_candidates WHERE scope=? AND id=?').get(hit.ownerId, hit.id);
      if (previous?.hash === revision) {
        if (previous.payload !== JSON.stringify(payload)) db.prepare('UPDATE watch_candidates SET payload=?,updated=? WHERE scope=? AND id=?').run(JSON.stringify(payload), new Date(now()).toISOString(), hit.ownerId, hit.id);
        continue;
      }
      if (previous) db.prepare('INSERT INTO watch_candidate_revisions(scope,candidate,payload,at) VALUES(?,?,?,?)').run(hit.ownerId, hit.id, previous.payload, new Date(now()).toISOString());
      db.prepare('INSERT OR REPLACE INTO watch_candidates VALUES(?,?,?,?,?,?,?)').run(hit.ownerId, hit.id, hit.profileId, hit.apexDomain, revision, JSON.stringify(payload), new Date(now()).toISOString());
    }
  });
  const candidates = (owner, profile) => db.prepare(`SELECT payload FROM watch_candidates WHERE scope=?${profile ? ' AND profile=?' : ''} ORDER BY updated DESC`).all(String(owner), ...(profile ? [profile] : [])).map(row => JSON.parse(row.payload));
  function metrics(owner, profile) {
    const rows = candidates(owner, profile), malicious = rows.filter(row => row.verdict === 'malicious').length, legitimate = rows.filter(row => row.verdict === 'legitimate').length;
    const byReason = unique(rows.flatMap(row => row.reasons || [])).map(reason => {
      const selected = rows.filter(row => row.reasons?.includes(reason)), positive = selected.filter(row => row.verdict === 'malicious').length, negative = selected.filter(row => row.verdict === 'legitimate').length;
      return { reason, total: selected.length, malicious: positive, legitimate: negative, precision: positive + negative ? positive / (positive + negative) : null };
    });
    return { total: rows.length, malicious, legitimate, unresolved: rows.length - malicious - legitimate, precision: malicious + legitimate ? malicious / (malicious + legitimate) : null, byReason };
  }
  return { saveWeeks, recordCycle, syncCandidates, candidates, metrics,
    historicalMemberships: () => db.prepare('SELECT payload FROM phishing_week_revisions').all().flatMap(row => {
      const week = JSON.parse(row.payload);
      return week.rules?.phishing === PHISHING_VERSION && !week.rules.phishingKits ? week.members.map(member => ({ ...member, week: week.week })) : [];
    }),
    dropProfile: (owner, profile) => db.transaction(() => {
      db.prepare('DELETE FROM watch_candidate_revisions WHERE scope=? AND candidate IN (SELECT id FROM watch_candidates WHERE scope=? AND profile=?)').run(owner, owner, profile);
      db.prepare('DELETE FROM watch_candidates WHERE scope=? AND profile=?').run(owner, profile);
    })(),
    overview: () => {
      const weeks = db.prepare('SELECT payload,updated FROM phishing_weeks ORDER BY week DESC LIMIT 10').all().reverse();
      const values = weeks.map(row => JSON.parse(row.payload));
      const observedDays = new Set(db.prepare("SELECT substr(at,1,10) day FROM phishing_collection_cycles WHERE status='ready' AND json_extract(payload,'$.healthySources')>0 GROUP BY day").all().map(row => row.day));
      const comparable = values.map(week => {
        const collectionDays = Array.from({ length: 7 }, (_, day) => new Date(Date.parse(week.week) + day * DAY).toISOString().slice(0, 10)).filter(day => observedDays.has(day)).length;
        return { ...week, collectionDays, comparable: week.comparable && collectionDays === 7 };
      });
      const cycles = db.prepare('SELECT * FROM phishing_collection_cycles WHERE at>=? ORDER BY at DESC').all(new Date(now() - DAY).toISOString());
      return { weeks: comparable.map(({ members: _members, ...week }) => week), ...summarizePhishingWeeks(comparable), updatedAt: weeks.at(-1)?.updated || null,
        health: { observedSince: db.prepare('SELECT MIN(at) at FROM phishing_collection_cycles').get().at, cycles24h: cycles.length, failed24h: cycles.filter(row => row.status !== 'ready').length,
          latest: cycles[0] ? { at: cycles[0].at, status: cycles[0].status, ...JSON.parse(cycles[0].payload) } : null,
          sources: db.prepare('SELECT source,SUM(fresh) fresh,SUM(unchanged) unchanged,SUM(stale) stale,SUM(failed) failed,MAX(last_success) lastSuccess FROM phishing_source_days WHERE day>=? GROUP BY source ORDER BY SUM(failed)+SUM(stale) DESC,source LIMIT 15').all(new Date(now() - 7 * DAY).toISOString().slice(0, 10)) } };
    },
    weekEvidence: week => { const row = db.prepare('SELECT payload FROM phishing_weeks WHERE week=?').get(week); return row ? JSON.parse(row.payload) : null; }
  };
}
