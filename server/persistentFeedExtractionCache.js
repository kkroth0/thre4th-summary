import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { serialize, deserialize } from 'node:v8';
import { createFeedExtractionCache } from './feedExtractionCache.js';

// Includes code dependencies and installed dependency versions. A release that
// changes an extraction rule invalidates the snapshot without relying on a
// developer remembering to increment EXTRACTION_VERSION.
export function extractionRulesRevision(directory, roots = ['index.js']) {
    const files = new Map();
    const visit = name => {
        if (files.has(name)) return;
        const file = path.resolve(directory, name);
        if (!file.startsWith(path.resolve(directory) + path.sep)) throw Error('Invalid extraction dependency');
        const source = fs.readFileSync(file, 'utf8'); files.set(name, source);
        if (name.endsWith('.js')) for (const match of source.matchAll(/(?:from\s*|import\s*\(\s*)['"](\.\.?\/[^'"]+)['"]/g)) {
            visit(path.normalize(path.join(path.dirname(name), match[1])));
        }
    };
    roots.forEach(visit); visit('package.json'); visit('package-lock.json');
    const hash = createHash('sha256').update('persistent-extraction-v1');
    for (const [name, source] of [...files].sort(([a], [b]) => a.localeCompare(b))) hash.update(name).update('\0').update(source).update('\0');
    return hash.digest('hex');
}

// Index content, including IDs/aliases/tiers, owns reuse; collection timestamps
// alone must not force every article to be extracted again each day.
export const extractionCatalogRevision = (...indexes) => createHash('sha256').update(serialize(indexes)).digest('hex');

export function createPersistentFeedExtractionCache({ directory, file, maxEntries = 6000, maxBytes = 32 * 1024 * 1024, onError = () => {} }) {
    const cache = createFeedExtractionCache({ maxEntries, maxBytes });
    let revision;
    try {
        revision = extractionRulesRevision(directory);
        if (fs.existsSync(file)) {
            if (fs.statSync(file).size > maxBytes + maxEntries * 1024) throw Error('Oversized extraction snapshot');
            const saved = deserialize(fs.readFileSync(file));
            if (saved.revision === revision) cache.restore(saved.payload);
        }
    } catch (error) { onError(error); }
    let savedMisses = cache.stats().misses;
    return { ...cache,
        flush() {
            if (!revision || cache.stats().misses === savedMisses) return;
            const temporary = file + '.' + process.pid + '.tmp';
            try {
                fs.mkdirSync(path.dirname(file), { recursive: true });
                fs.writeFileSync(temporary, serialize({ revision, payload: cache.snapshot() }), { mode: 0o600 });
                fs.renameSync(temporary, file);
                savedMisses = cache.stats().misses;
            } catch (error) {
                try { fs.unlinkSync(temporary); } catch { /* optional disposable cache */ }
                onError(error);
            }
        },
    };
}
