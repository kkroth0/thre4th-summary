// Read-only production audit. Prints aggregate results only; no private domains,
// profile names, API keys, source payloads or candidate content in Actions logs.
import path from 'node:path';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true }); db.pragma('query_only=ON');
db.exec('BEGIN');
const candidateCount = db.prepare('SELECT COUNT(*) n FROM watch_candidates').get().n;
const weekly = db.prepare('SELECT week,payload FROM phishing_weeks ORDER BY week DESC LIMIT 10').all();
const candidatesMisclassified = db.prepare("SELECT COUNT(*) n FROM observations WHERE provider='phishingWatch'").get().n;
const report = { at: new Date().toISOString(), readOnly: true, candidateCount, candidateRecordsInReputationInventory: candidatesMisclassified,
  weeks: weekly.map(row => { const data = JSON.parse(row.payload); return { week: row.week, publications: data.publications, events: data.events, evidenceMembers: data.members.length, closed: data.closed }; }),
  collectionCycles: db.prepare('SELECT COUNT(*) n FROM phishing_collection_cycles').get().n,
  observedSources: db.prepare('SELECT COUNT(DISTINCT source) n FROM phishing_source_days').get().n };
const latestCycle = db.prepare('SELECT at,status,payload FROM phishing_collection_cycles ORDER BY at DESC LIMIT 1').get();
report.collection = {
  successfulCycles: db.prepare("SELECT COUNT(*) n FROM phishing_collection_cycles WHERE status='ready'").get().n,
  failedCycles: db.prepare("SELECT COUNT(*) n FROM phishing_collection_cycles WHERE status<>'ready'").get().n,
  latest: latestCycle ? { at: latestCycle.at, status: latestCycle.status, ...JSON.parse(latestCycle.payload) } : null,
};
try {
  const { buildPhishingWeeks } = await import(pathToFileURL(path.join(root, 'server/phishingEvolution.js')));
  const { readPrimaryNewsSnapshot } = await import(pathToFileURL(path.join(root, 'server/newsPersistence.js')));
  const hasManifest = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='news_storage_state'").get();
  const primary = hasManifest ? readPrimaryNewsSnapshot(db) : null;
  const recalculated = buildPhishingWeeks(primary?.archive || JSON.parse(fs.readFileSync(path.join(root, 'server/.news-archive.json'), 'utf8')));
  report.newsStorage = primary ? 'sqlite' : 'json';
  report.replay = { weeks: recalculated.length, publications: recalculated.reduce((sum, week) => sum + week.publications, 0) };
} catch (error) { report.replay = { error: error.name, message: error.message, stack: String(error.stack).split('\n').slice(0, 5) }; }
const { evaluateCtBacktest, candidateBrandMatch } = await import(pathToFileURL(path.join(root, 'server/phishingCtBacktest.js')));
let watch = { hits: [] }; try { watch = JSON.parse(fs.readFileSync(path.join(root, 'server/.phish-watch.json'), 'utf8')); } catch { /* not populated */ }
const selected = [...(watch.hits || []).filter(hit => hit.verdict === 'malicious' || !hit.verdict && hit.status === 'confirmed').slice(0, 2), ...(watch.hits || []).filter(hit => hit.verdict === 'legitimate').slice(0, 2)]
  .map(hit => ({ hostname: hit.domain || hit.apexDomain, firstSeen: hit.firstSeen, cohort: 'watch', label: hit.verdict === 'legitimate' ? 'legitimate' : 'malicious' }));
const brands = [...new Set((watch.hits || []).map(hit => hit.term).filter(Boolean))];
const watched = new Set((watch.hits || []).flatMap(hit => [hit.domain, hit.apexDomain]));
const independent = db.prepare("SELECT DISTINCT i.value,i.type FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.scope='global' AND o.provider IN ('ThreatFox','URLhaus','OpenPhish') AND i.type IN ('domain','url') ORDER BY i.value LIMIT 2000").all();
for (const row of independent) {
  let hostname; try { hostname = row.type === 'url' ? new URL(row.value).hostname : row.value; } catch { continue; }
  if (selected.length >= 8) break;
  // Provider records are screened by this very filter, so they cannot estimate
  // recall. Their source first-seen is not recoverable from last-collected.
  if (!watched.has(hostname) && !selected.some(sample => sample.hostname === hostname) && candidateBrandMatch(hostname, brands)) selected.push({ hostname, firstSeen: null, cohort: 'provider-screened', label: 'reported-malicious' });
}
const samples = [];
for (const sample of selected) {
  if (!sample.firstSeen) { samples.push({ ...sample, certificates: [] }); continue; }
  let certificates = [], lookupFailed = false;
  try {
    const url = new URL('https://crt.sh/'); url.searchParams.set('q', sample.hostname); url.searchParams.set('output', 'json');
    const response = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!response.ok || Number(response.headers.get('content-length')) > 5000000) throw Error('unavailable');
    const reader = response.body.getReader(); let size = 0; const chunks = [];
    try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > 5000000) throw Error('too large'); chunks.push(Buffer.from(part.value)); } } finally { await reader.cancel(); }
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (!Array.isArray(parsed)) throw Error('invalid'); certificates = parsed;
  } catch { lookupFailed = true; }
  samples.push({ ...sample, certificates, lookupFailed });
}
const backtest = evaluateCtBacktest(samples, { brands });
const { results: _results, ...summary } = backtest;
report.backtest = { ...summary, completedLookups: samples.filter(sample => !sample.lookupFailed).length,
  independentSampleAvailable: false, providerCandidatesAwaitingReview: selected.filter(sample => sample.cohort === 'provider-screened').length, decision: 'independent-samples-and-prospective-validation-required',
  labels: 'analyst-verdicts-and-provider-reports-not-independent-ground-truth',
  note: 'A matched retrospective name is not a detected threat. Independent positive and legitimate samples plus a prospective pilot are required.' };
db.close(); console.log(JSON.stringify(report, null, 2));
if (!weekly.length || report.replay.error || candidatesMisclassified || weekly.some(row => JSON.parse(row.payload).publications !== JSON.parse(row.payload).members.length)) process.exitCode = 1;
