// Read-only production audit. Prints aggregate results only; no private domains,
// profile names, API keys, source payloads or candidate content in Actions logs.
import path from 'node:path';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true }); db.pragma('query_only=ON');
const candidateCount = db.prepare('SELECT COUNT(*) n FROM watch_candidates').get().n;
const weekly = db.prepare('SELECT week,payload FROM phishing_weeks ORDER BY week DESC LIMIT 10').all();
const candidatesMisclassified = db.prepare("SELECT COUNT(*) n FROM observations WHERE provider='phishingWatch'").get().n;
const report = { at: new Date().toISOString(), readOnly: true, candidateCount, candidateRecordsInReputationInventory: candidatesMisclassified,
  weeks: weekly.map(row => { const data = JSON.parse(row.payload); return { week: row.week, publications: data.publications, events: data.events, evidenceMembers: data.members.length, closed: data.closed }; }),
  collectionCycles: db.prepare('SELECT COUNT(*) n FROM phishing_collection_cycles').get().n,
  observedSources: db.prepare('SELECT COUNT(DISTINCT source) n FROM phishing_source_days').get().n };
const { evaluateCtBacktest, candidateBrandMatch } = await import(pathToFileURL(path.join(root, 'server/phishingCtBacktest.js')));
let watch = { hits: [] }; try { watch = JSON.parse(fs.readFileSync(path.join(root, 'server/.phish-watch.json'), 'utf8')); } catch { /* not populated */ }
const selected = (watch.hits || []).filter(hit => ['malicious', 'legitimate'].includes(hit.verdict) || hit.status === 'confirmed').slice(0, 4)
  .map(hit => ({ hostname: hit.domain || hit.apexDomain, firstSeen: hit.firstSeen, cohort: 'watch', label: hit.verdict === 'legitimate' ? 'legitimate' : 'malicious' }));
const brands = [...new Set((watch.hits || []).map(hit => hit.term).filter(Boolean))];
const watched = new Set((watch.hits || []).flatMap(hit => [hit.domain, hit.apexDomain]));
const independent = db.prepare("SELECT i.value,i.type,MIN(o.collected) firstSeen FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.scope='global' AND o.provider IN ('ThreatFox','URLhaus') AND i.type IN ('domain','url') GROUP BY i.id ORDER BY firstSeen DESC LIMIT 2000").all();
for (const row of independent) {
  let hostname; try { hostname = row.type === 'url' ? new URL(row.value).hostname : row.value; } catch { continue; }
  if (selected.length >= 8) break;
  if (!watched.has(hostname) && !selected.some(sample => sample.hostname === hostname) && candidateBrandMatch(hostname, brands)) selected.push({ hostname, firstSeen: row.firstSeen, cohort: 'independent-provider', label: 'malicious' });
}
const samples = [];
for (const sample of selected) {
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
  independentSampleAvailable: selected.some(sample => sample.cohort === 'independent-provider'), decision: 'prospective-validation-required',
  labels: 'analyst-verdicts-and-provider-reports-not-independent-ground-truth',
  note: 'A matched retrospective name is not a detected threat. Independent positive and legitimate samples plus a prospective pilot are required.' };
db.close(); console.log(JSON.stringify(report, null, 2));
if (!weekly.length || candidatesMisclassified || weekly.some(row => JSON.parse(row.payload).publications !== JSON.parse(row.payload).members.length)) process.exitCode = 1;
