import { createHash } from 'node:crypto';
import { buildPhishingDataset } from './phishingDataset.js';
import { normalizeBrandTerm, PHISH_LIMITS, createPhishError } from './phishingWatch.js';

const termFor = brand => normalizeBrandTerm(String(brand).normalize('NFD').replace(/\p{Mn}/gu, '').replace(/\s+/g, ''));

// Suggestions are evidence for an analyst, never an instruction to start
// monitoring another brand or to classify any associated host as malicious.
export function proposeWatchTerms(rows, profile, { now = new Date() } = {}) {
  const cutoff = now.getTime() - 90 * 86400000;
  const watched = new Set((profile.brands || []).map(normalizeBrandTerm));
  const reports = buildPhishingDataset(rows.filter(row => !row.dateInferred && row.securityRelevant !== false && Date.parse(row.pubDate) >= cutoff && Date.parse(row.pubDate) <= now.getTime()), { profiles: [profile] }).reports;
  const groups = new Map();
  for (const report of reports) {
    const match = report.profileMatches.find(item => item.profileId === profile.id);
    if (!match) continue;
    for (const brand of report.brands) {
      const term = termFor(brand);
      if (!term || watched.has(term)) continue;
      const id = createHash('sha256').update(JSON.stringify([profile.ownerId, profile.id, term])).digest('hex').slice(0, 24);
      const entry = groups.get(term) || { id, term, brand, events: new Set(), sources: new Set(), publications: new Map(), reasons: new Set() };
      entry.events.add(report.storyId || report.link);
      try { entry.sources.add(new URL(report.link).hostname.replace(/^www\./, '')); } catch { continue; }
      for (const reason of match.reasons) entry.reasons.add(reason);
      if (entry.publications.size < 5) {
        const patterns = [];
        for (const value of (report.iocs?.urls || []).slice(0, 50)) try {
          const url = new URL(value);
          if (url.hostname.includes(term)) patterns.push({ hostname: url.hostname, path: url.pathname.slice(0, 160) });
        } catch { /* malformed source IOC */ }
        entry.publications.set(report.link, { link: report.link, title: report.title, pubDate: report.pubDate, techniques: report.phishingTechniques, campaign: report.campaignName || '', patterns: patterns.slice(0, 5) });
      }
      groups.set(term, entry);
    }
  }
  return [...groups.values()].map(entry => ({ ...entry, events: entry.events.size, sources: entry.sources.size, publications: [...entry.publications.values()], reasons: [...entry.reasons] }))
    .sort((a, b) => b.events - a.events || b.sources - a.sources || a.term.localeCompare(b.term)).slice(0, 15);
}

export function createWatchSuggestions(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS watch_term_suggestions(scope TEXT NOT NULL,profile TEXT NOT NULL,id TEXT NOT NULL,term TEXT NOT NULL,status TEXT NOT NULL,payload TEXT NOT NULL,updated TEXT NOT NULL,reviewed TEXT,PRIMARY KEY(scope,profile,id));`);
  const refresh = db.transaction((profile, proposals) => {
    for (const item of proposals) db.prepare(`INSERT INTO watch_term_suggestions VALUES(?,?,?,?, 'proposed',?,?,NULL)
      ON CONFLICT(scope,profile,id) DO UPDATE SET payload=excluded.payload,updated=excluded.updated WHERE payload<>excluded.payload`).run(profile.ownerId, profile.id, item.id, item.term, JSON.stringify(item), new Date().toISOString());
  });
  return {
    list(profile, proposals) {
      refresh(profile, proposals);
      const current = new Set(proposals.map(item => item.id));
      return db.prepare("SELECT id,payload FROM watch_term_suggestions WHERE scope=? AND profile=? AND status='proposed'").all(profile.ownerId, profile.id)
        .filter(row => current.has(row.id)).map(row => JSON.parse(row.payload)).sort((a, b) => b.events - a.events || b.sources - a.sources || a.term.localeCompare(b.term));
    },
    review(owner, profile, id, decision, profiles) {
      if (!['accepted', 'dismissed'].includes(decision)) throw createPhishError(400, 'decisão inválida');
      const row = db.prepare('SELECT * FROM watch_term_suggestions WHERE scope=? AND profile=? AND id=?').get(owner, profile.id, id);
      if (!row) throw createPhishError(404, 'sugestão não encontrada');
      if (decision === 'accepted' && !(profile.brands || []).some(brand => normalizeBrandTerm(brand) === row.term)) {
        if ((profile.brands || []).length >= PHISH_LIMITS.brandsPerProfile) throw createPhishError(409, 'limite de marcas atingido; revise as marcas do perfil');
        profiles.update(owner, profile.id, { brands: [...(profile.brands || []), row.term] });
      }
      db.prepare('UPDATE watch_term_suggestions SET status=?,reviewed=? WHERE scope=? AND profile=? AND id=?').run(decision, new Date().toISOString(), owner, profile.id, id);
      return { id, term: row.term, status: decision };
    },
    dropProfile: (owner, profile) => db.prepare('DELETE FROM watch_term_suggestions WHERE scope=? AND profile=?').run(owner, profile),
  };
}
