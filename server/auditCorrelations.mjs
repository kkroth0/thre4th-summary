// Offline replay. Reads public metadata or an exported feed; no production
// state, network requests, credentials or story-store writes.
import fs from 'node:fs';
import { mergeIntoStories, CORRELATION_VERSION } from './newsStories.js';
import { auditCorrelations } from './correlationAudit.js';

const file = process.argv[2] || new URL('./test/fixtures/news-correlation-2026-10-09.json', import.meta.url);
const data = JSON.parse(fs.readFileSync(file, 'utf8'));
const items = Array.isArray(data) ? data : data.items;
if (!Array.isArray(items)) throw new Error('Expected an array of publications or { items, evaluationAt }');
const at = new Date(data.evaluationAt || Math.max(...items.map((item) => Date.parse(item.pubDate))));
if (!Number.isFinite(at.getTime())) throw new Error('A valid evaluationAt or publication date is required');
const start = performance.now();
const stories = mergeIntoStories([], items, at);
const current = auditCorrelations(items, stories);
const baselineItems = items.filter((item) => item.baselineStoryId);
const baseline = new Map();
for (const item of baselineItems) {
    if (!baseline.has(item.baselineStoryId)) baseline.set(item.baselineStoryId, { id: item.baselineStoryId, sources: [] });
    baseline.get(item.baselineStoryId).sources.push(item);
}
const compact = ({ falseMerges, missedPairs, ...report }) => ({ ...report,
    falseMergeExamples: falseMerges.slice(0, 5), missedPairExamples: missedPairs.slice(0, 5) });
console.log(JSON.stringify({ correlationVersion: CORRELATION_VERSION, evaluationAt: at.toISOString(),
    elapsedMs: Math.round(performance.now() - start),
    baseline: baselineItems.length ? compact(auditCorrelations(baselineItems, [...baseline.values()])) : null,
    current: compact(current),
    note: 'Metrics apply only to reviewed labels; the baseline used RSS-only evidence, current evidence may include article bodies.',
}, null, 2));
if (current.falsePositive || current.falseNegative || current.duplicateLinks.length || current.unassigned.length) process.exitCode = 1;
