// Controlled read-only replay of cached public inputs. No HTTP, cache writes,
// provider calls or live inventory/correlation mutations. Output aggregates only.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const load = name => import(pathToFileURL(path.join(root, 'server', name)));
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const { createFeedExtractionCache } = await load('feedExtractionCache.js');
const { enrichFeedItemsAsync } = await load('feedEnrichment.js');
const { collectArticleTexts } = await load('articleCollector.js');
const { buildActorIndex, matchActors } = await load('actorMatch.js');
const { buildMalwareIndex, matchMalware } = await load('malwareMatch.js');
const { buildCampaignIndex, matchCampaigns } = await load('campaignMatch.js');
const { extractSellerHandle } = await load('darkWebHandle.js');
const { categorize } = await load('newsCategories.js');
const { equalJsonEvidence } = await load('jsonEvidence.js');
const digest = value => createHash('sha256').update(value).digest('hex');
const read = file => { try { return fs.statSync(file).size <= 128 * 1024 * 1024 ? JSON.parse(fs.readFileSync(file, 'utf8')) : null; } catch { return null; } };
const catalog = (file, field) => { const data = read(path.join(root, 'server/data', file)); return Array.isArray(data) ? data : data?.[field] || []; };
const actors = buildActorIndex(catalog('actors.json', 'actors'));
const malware = buildMalwareIndex(catalog('malware.json', 'malware'));
const campaigns = buildCampaignIndex(catalog('campaigns.json', 'campaigns'));
const directory = path.join(root, 'server/.feed-cache/rss'), byLink = new Map();
for (const file of fs.readdirSync(directory).filter(file => /^[a-f0-9]{64}\.json$/.test(file) && file !== digest('newsletter:snapshot') + '.json').sort()) {
    for (const item of read(path.join(directory, file))?.items || []) {
        if (typeof item.link === 'string' && !byLink.has(item.link)) byLink.set(item.link, item);
    }
}
// Stable sample across sources rather than a single publisher's first entries.
const items = [...byLink.values()].sort((a, b) => digest(a.link).localeCompare(digest(b.link))).slice(0, 120);
if (!items.length) throw Error('No cached public news inputs available');
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true });
db.pragma('query_only=ON'); db.exec('BEGIN');
const retainedBody = db.prepare('SELECT payload FROM news_body_versions WHERE link=? ORDER BY collected DESC,rowid DESC LIMIT 1');
const bodies = await collectArticleTexts(items, { maxFetches: 0, cache: {
    get: link => read(path.join(root, 'server/.feed-cache/articles', digest(link) + '.json')) || JSON.parse(retainedBody.get(link)?.payload || 'null'),
} });
db.close();
const extractionCache = createFeedExtractionCache();
const options = { texts: bodies.texts, supplementalIocs: bodies.supplementalIocs, extractionCache, catalogRevision: 'read-only-bundled-catalogs',
    actors: text => matchActors(text, actors), malware: text => matchMalware(text, malware, { news: true }),
    campaigns: text => matchCampaigns(text, campaigns), seller: extractSellerHandle, categorize };
const timingsMs = {};
let start = performance.now(); const cold = await enrichFeedItemsAsync(items, options); timingsMs.cold = Math.round(performance.now() - start);
start = performance.now(); const warm = await enrichFeedItemsAsync(items, options); timingsMs.warm = Math.round(performance.now() - start);
const unchanged = equalJsonEvidence(cold, warm);
console.log(JSON.stringify({ readOnly: true, at: new Date().toISOString(), scope: 'cached public inputs, retained bodies and bundled catalogs; no network or writes',
    availableInputs: byLink.size, sampledInputs: items.length, withBody: bodies.texts.size, withAppendixIocs: bodies.supplementalIocs.size,
    timingsMs, evidenceUnchanged: unchanged, publications: cold.length, cache: extractionCache.stats(),
    evidence: Object.fromEntries(['actors', 'malware', 'campaigns', 'cves'].map(field => [field, cold.reduce((sum, item) => sum + (item[field]?.length || 0), 0)])),
    iocs: Object.fromEntries(['ips', 'domains', 'hashes', 'urls'].map(field => [field, cold.reduce((sum, item) => sum + (item.iocs?.[field]?.length || 0), 0)])),
}, null, 2));
if (!unchanged) process.exitCode = 1;
