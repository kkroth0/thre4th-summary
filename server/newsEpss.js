const DAY = 86400000;
const validScore = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
const idsOf = values => [...new Set((Array.isArray(values) ? values : []).filter(value => typeof value === 'string').map(value => value.toUpperCase()).filter(value => /^CVE-\d{4}-\d{4,}$/.test(value)))];

// The daily catalog is authoritative for dated scores. Only missing/stale CVEs
// reach FIRST, with bounded parallelism, an actual abort deadline and a cooldown
// for missing results. Unknown never becomes a fabricated zero.
export function createNewsEpssLookup({ readLocal, fetchBatch, now = () => Date.now(), budgetMs = 20000, concurrency = 2, maxEntries = 20000 }) {
  const cache = new Map();
  let flight = Promise.resolve();
  const remember = (id, value) => {
    cache.delete(id); cache.set(id, value);
    while (cache.size > maxEntries) cache.delete(cache.keys().next().value);
  };
  async function lookup(values) {
    const ids = idsOf(values), scores = new Map(), fresh = new Set(), missing = [];
    if (!ids.length) return scores;
    let local;
    try { local = await readLocal(ids); } catch { /* bounded remote fallback */ }
    const wanted = new Set(ids);
    for (const row of local?.rows || []) {
      if (!wanted.has(row.cve) || !validScore(row.score)) continue;
      scores.set(row.cve, row.score);
      const date = Date.parse(row.date);
      if (Number.isFinite(date) && date <= now() && now() - date < 2 * DAY) fresh.add(row.cve);
    }
    for (const id of ids) {
      const prior = cache.get(id);
      if (!fresh.has(id) && validScore(prior?.score)) scores.set(id, prior.score);
      if (!fresh.has(id) && (!prior || prior.expiresAt <= now())) missing.push(id);
    }
    if (!missing.length) return scores;
    const controller = new AbortController(), deadline = now() + budgetMs;
    const timer = setTimeout(() => controller.abort(), budgetMs);
    let cursor = 0;
    try {
      await Promise.all(Array.from({ length: Math.min(Math.max(1, concurrency), Math.ceil(missing.length / 100)) }, async () => {
        while (cursor < missing.length && !controller.signal.aborted && now() < deadline) {
          const chunk = missing.slice(cursor, cursor += 100), requested = new Set(chunk);
          try {
            const rows = await fetchBatch(chunk, { signal: controller.signal });
            const returned = new Map();
            for (const row of rows || []) {
              const cve = typeof row.cve === 'string' ? row.cve.toUpperCase() : '';
              const score = typeof row.epss === 'string' && row.epss.trim() ? Number(row.epss) : row.epss;
              if (requested.has(cve) && validScore(score)) returned.set(cve, score);
            }
            for (const id of chunk) {
              const score = returned.get(id);
              if (score !== undefined) scores.set(id, score);
              remember(id, { score: score ?? scores.get(id), expiresAt: now() + (score === undefined ? 3600000 : DAY) });
            }
          } catch {
            for (const id of chunk) remember(id, { score: scores.get(id), expiresAt: now() + 300000 });
          }
        }
      }));
    } finally { clearTimeout(timer); }
    return scores;
  }
  return values => {
    // Serialize callers so overlapping refreshes reuse completed cache entries.
    const run = flight.then(() => lookup(values));
    flight = run.catch(() => {});
    return run;
  };
}
