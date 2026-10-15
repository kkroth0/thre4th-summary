// Focused read-only audit: no benchmark, historical recrawl, sample download or database mutation.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const read = name => JSON.parse(fs.readFileSync(path.join(root, 'server', name), 'utf8'));
const archive = read('.news-archive.json'), stories = read('.news-stories.json');
const target = archive.find(row => row.link?.includes('cyble.com/blog/weekly-vulnerability-report-langflow-n8n-ics-flaws'));
const canonical = value => { try { const url = new URL(value); return url.origin + url.pathname.replace(/\/$/, ''); } catch { return value; } };
const events = target ? stories.filter(story => story.sources?.some(row => canonical(row.link) === canonical(target.link))) : [];
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true }); db.pragma('query_only = ON');
const active = target ? db.prepare("SELECT COUNT(*) count FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.provider='news' AND o.external_id=? AND i.value='2.6.0.4'").get(target.link).count : null;
const miraiLinks = db.prepare("SELECT COUNT(*) count FROM entity_links e JOIN observations o ON o.id=e.observation JOIN indicators i ON i.id=o.indicator WHERE e.kind='malware' AND e.name LIKE 'Mirai%' AND i.value='2.6.0.4' AND o.provider='news' AND o.external_id=?").get(target?.link || '').count;
const firmware = { publicationFound: !!target, events: events.length, archivedHasFalseIp: !!target?.iocs?.ips?.includes('2.6.0.4'),
  eventSourceHasFalseIp: events.some(story => story.sources.some(row => canonical(row.link) === canonical(target.link) && row.iocs?.ips?.includes('2.6.0.4'))),
  eventAggregateHasFalseIp: events.some(story => story.iocs?.ips?.includes('2.6.0.4')), currentHistoricalObservations: active, miraiLinks, preservedArticleIps: target?.iocs?.ips?.length || 0 };
db.close();
let cti = { status: 'not_initialized' };
try {
  const snapshot = read('.cti-fyi.json');
  const { mergeCtiActors, ctiPublications } = await import(pathToFileURL(path.join(root, 'server/ctiFyi.js')));
  const actors = mergeCtiActors(read('data/actors.json').actors, snapshot.groups);
  const publications = ctiPublications(snapshot.posts, actors);
  const response = await fetch('http://127.0.0.1:3001/api/intel/threat-map?days=30', { signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw Error('Map HTTP ' + response.status);
  const map = await response.json();
  cti = { status: snapshot.error ? 'stale' : 'ready', collectedAt: snapshot.lastSuccessfulAt, savedClaims: snapshot.posts.length, groups: snapshot.groups.length,
    linkedActorPublications: publications.length, victimDomainsMisclassifiedAsIocs: publications.flatMap(row => row.iocs.domains).length,
    mapSource: map.source, mapVictims: map.victims.length, ctiMapVictims: map.victims.filter(row => row.sources?.includes('CTI.fyi')).length,
    actorPivots: map.victims.filter(row => row.actorId).length, partial: !!snapshot.cursor || !!snapshot.updatedCursor };
} catch (error) { cti = { status: 'error', code: error.code || error.name }; }
console.log(JSON.stringify({ checkedAt: new Date().toISOString(), readOnly: true, firmware, cti }, null, 2));
if (!target || !events.length || firmware.archivedHasFalseIp || firmware.eventSourceHasFalseIp || active || miraiLinks || cti.status === 'error' || !cti.ctiMapVictims || cti.victimDomainsMisclassifiedAsIocs) process.exitCode = 1;
