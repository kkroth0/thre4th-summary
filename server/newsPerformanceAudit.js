// Read-only measurements: aggregate counts/timings only. Never print source
// payloads, private profiles, cookies, API keys or unfiltered service logs.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd()), service = process.argv[3];
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const { readPrimaryNewsSnapshot } = await import(pathToFileURL(path.join(root, 'server/newsPersistence.js')));
const { completeNewsFeed } = await import(pathToFileURL(path.join(root, 'server/newsQuality.js')));
const report = { readOnly: true, at: new Date().toISOString(), timingsMs: {} };
const measure = (key, task) => { const start = performance.now(); const value = task(); report.timingsMs[key] = Math.round(performance.now() - start); return value; };
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true });
db.pragma('query_only=ON'); db.exec('BEGIN');
const snapshot = measure('readPrimary', () => readPrimaryNewsSnapshot(db));
if (!snapshot) throw Error('Primary news storage is unavailable');
report.generation = snapshot.generation; report.archive = snapshot.archive.length; report.stories = snapshot.stories.length;
const cves = [...new Set(snapshot.archive.flatMap(row => row.cves || []))]; report.distinctCves = cves.length;
const file = path.join(root, 'server/.feed-cache/rss', createHash('sha256').update('newsletter:snapshot').digest('hex') + '.json');
let current = [];
try { report.feedCacheBytes = fs.statSync(file).size; if (report.feedCacheBytes < 128 * 1024 * 1024) current = measure('readFeedCache', () => JSON.parse(fs.readFileSync(file, 'utf8'))).items || []; } catch { report.feedCacheUnavailable = true; }
const rows = measure('completeFeed', () => completeNewsFeed(current, snapshot.archive));
const encoded = measure('serializeFeed', () => JSON.stringify(rows));
report.feed = { publications: rows.length, bytes: Buffer.byteLength(encoded), gzipBytes: measure('compressFeed', () => gzipSync(encoded)).length };
if (fs.existsSync(path.join(root, 'server/newsFeedResponse.js'))) {
  const { createNewsFeedResponse } = await import(pathToFileURL(path.join(root, 'server/newsFeedResponse.js')));
  const respond = createNewsFeedResponse(), args = { current, archive: snapshot.archive, stories: snapshot.stories, owner: 'read-only-audit', preferences: { mode: 'all', vendorIds: [] } };
  const first = measure('feedResponseCold', () => respond(args));
  const warm = measure('feedResponseWarm', () => respond(args));
  report.feedResponse = { equal: first.body === encoded, reused: warm === first, bytes: first.size };
}
report.lastCycles = db.prepare('SELECT at,status,payload FROM phishing_collection_cycles ORDER BY at DESC LIMIT 5').all().map(row => {
  const value = JSON.parse(row.payload); return { at: row.at, status: row.status, elapsedMs: value.elapsedMs, stages: value.stages, bodies: value.bodies, sourceCount: value.sourceCount, healthySources: value.healthySources };
});
const sync = db.prepare("SELECT value FROM intelligence_state WHERE id='news-sync'").get(); report.newsSync = sync ? JSON.parse(sync.value) : null;
db.close();
try {
  const catalog = new Database(path.join(root, 'server/.vulnerability-catalog.sqlite'), { readonly: true, fileMustExist: true }); catalog.pragma('query_only=ON');
  report.localEpss = measure('readLocalEpss', () => {
    const query = catalog.prepare('SELECT score,date FROM epss WHERE cve=?');
    const known = cves.map(cve => query.get(cve)).filter(Boolean);
    const meta = catalog.prepare("SELECT value FROM metadata WHERE key='source:epss'").get();
    return { covered: known.length, missing: cves.length - known.length, status: meta ? JSON.parse(meta.value) : null };
  }); catalog.close();
} catch { report.localEpss = { unavailable: true }; }
if (service) {
  try {
    const state = execFileSync('systemctl', ['show', service, '--property=ActiveState,ExecMainStartTimestamp,SubState,MainPID'], { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] });
    report.serviceState = Object.fromEntries(state.trim().split('\n').map(line => { const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)]; }));
    if (/^\d+$/.test(report.serviceState.MainPID)) report.process = execFileSync('ps', ['-p', report.serviceState.MainPID, '-o', 'etimes=,pcpu=,rss='], { encoding: 'utf8', timeout: 10000 }).trim();
    const text = execFileSync('journalctl', ['-u', service, '--since', '90 minutes ago', '-n', '5000', '-o', 'cat', '--no-pager'], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] });
    const lines = text.split('\n');
    const statuses = pattern => lines.filter(line => pattern.test(line)).reduce((result, line) => { const key = line.match(/(?:status code |HTTP )(\d{3})/)?.[1] || (/timeout/i.test(line) ? 'timeout' : 'other'); result[key] = (result[key] || 0) + 1; return result; }, {});
    const cycles = lines.filter(line => line.includes('[feed] cycle ')).flatMap(line => { try {
      const value = JSON.parse(line.slice(line.indexOf('[feed] cycle ') + 13));
      return [{ elapsedMs: value.elapsedMs, stages: value.stages, correlationMs: value.correlation?.elapsedMs, publications: value.correlation?.publications }];
    } catch { return []; } });
    const diagnosticPatterns = ['Server running on port', 'news evidence review failed:', 'Phishing weekly snapshot unavailable:', 'Unhandled', 'unhandled', 'Article body persistence failed:', 'Saved provider match review failed'];
    const diagnostics = Object.fromEntries(diagnosticPatterns.map(pattern => [pattern, lines.filter(line => line.includes(pattern)).length]));
    const boot = execFileSync('journalctl', ['-u', service, '--since', report.serviceState.ExecMainStartTimestamp.replace(/^[A-Za-z]{3} /, ''), '-n', '5000', '-o', 'cat', '--no-pager'], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] }).split('\n');
    report.boot = { lines: boot.length, diagnostics: Object.fromEntries(diagnosticPatterns.map(pattern => [pattern, boot.filter(line => line.includes(pattern)).length])), bodyFailures: boot.filter(line => line.includes('Article fetch failed for ')).length, completedCycles: boot.filter(line => line.includes('[feed] cycle ')).length };
    report.service = { lines: lines.length, diagnostics, cycles: cycles.slice(-3), epssFailures: statuses(/EPSS fetch failed:/), bodyFailures: statuses(/Article fetch failed for /), newsletterFailures: lines.filter(line => line.includes('Failed to background refresh newsletter feeds:')).length };
  } catch { report.service = { unavailable: true }; }
}
console.log(JSON.stringify(report, null, 2));
