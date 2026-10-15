import { serialize, deserialize } from 'node:v8';
import { contentHash } from './articleCollector.js';
import { canonicalJsonEvidence } from './jsonEvidence.js';

// Process-local only: deploying new extraction/classification code starts cold.
// All publication inputs participate except collection telemetry, which is
// copied from the current raw item when assembling the result.
const telemetry = new Set(['collectedAt', 'collectionStatus', 'articleCollectionStatus']);
export function createFeedExtractionCache({ maxEntries = 6000, maxBytes = 32 * 1024 * 1024 } = {}) {
    const entries = new Map();
    let bytes = 0;
    const counters = { hits: 0, misses: 0, bypassed: 0, evictions: 0 };
    const remove = key => { const entry = entries.get(key); if (entry) { bytes -= entry.size; entries.delete(key); } };
    return {
        extract(item, { bodyText, supplementalIocs, extractionVersion, catalogRevision }, compute) {
            // Callers must explicitly own catalog revisioning. Callback identity
            // is insufficient: closures are recreated and indexes can be replaced.
            if (!item.link || !catalogRevision) { counters.bypassed++; return compute(); }
            const input = Object.fromEntries(Object.entries(item).filter(([key]) => !telemetry.has(key)));
            const fingerprint = contentHash(canonicalJsonEvidence({ input, bodyText, supplementalIocs, extractionVersion, catalogRevision }));
            const previous = entries.get(item.link);
            if (previous?.fingerprint === fingerprint) {
                counters.hits++; entries.delete(item.link); entries.set(item.link, previous);
                return deserialize(previous.payload);
            }
            counters.misses++;
            const value = compute(); // Never install a partial/failed extraction.
            const payload = serialize(value);
            const size = payload.length + Buffer.byteLength(item.link) + fingerprint.length;
            remove(item.link);
            if (maxEntries > 0 && size <= maxBytes) {
                entries.set(item.link, { fingerprint, payload, size }); bytes += size;
                while (entries.size > maxEntries || bytes > maxBytes) { remove(entries.keys().next().value); counters.evictions++; }
            }
            // Serialized storage prevents KEV boosts, public row cleanup or
            // caller mutations from modifying cached nested evidence.
            return value;
        },
        stats: () => ({ ...counters, entries: entries.size, bytes }),
    };
}
