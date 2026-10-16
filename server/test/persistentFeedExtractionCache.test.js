import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createPersistentFeedExtractionCache, extractionCatalogRevision, extractionRulesRevision } from '../persistentFeedExtractionCache.js';

function fixture(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatsumm4ry-extraction-'));
    t.after(() => {
        assert.ok(path.resolve(directory).startsWith(path.resolve(os.tmpdir()) + path.sep + 'threatsumm4ry-extraction-'));
        fs.rmSync(directory, { recursive: true, force: true });
    });
    fs.writeFileSync(path.join(directory, 'index.js'), "import { match } from './matcher.js';");
    fs.writeFileSync(path.join(directory, 'matcher.js'), 'export const match = value => value;');
    fs.writeFileSync(path.join(directory, 'package.json'), '{}');
    fs.writeFileSync(path.join(directory, 'package-lock.json'), '{}');
    return { directory, file: path.join(directory, 'cache', 'extraction.bin') };
}
const item = { link: 'https://lab.example/report', title: 'Research report', text: 'IOC appendix' };
const catalog = () => ({ aliases: new Map([['apt28', { id: 'G0007', name: 'APT28' }]]), maxGram: 4 });
const identity = () => ({ extractionVersion: 'current', catalogRevision: extractionCatalogRevision(catalog()), supplementalIocs: { hashes: Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(64, 'a')) } });

test('restart restores full independent extraction evidence, while catalog/body changes force fresh results', t => {
    const options = fixture(t); let computes = 0;
    let cache = createPersistentFeedExtractionCache(options);
    const config = identity(), expected = { actors: [{ id: 'G0007', name: 'APT28' }], iocs: config.supplementalIocs, cves: ['CVE-2026-12345'], reasons: [] };
    const compute = () => { computes++; return structuredClone(expected); };
    const first = cache.extract(item, config, compute); cache.flush();
    first.iocs.hashes.pop(); first.reasons.push('caller KEV boost');
    cache = createPersistentFeedExtractionCache(options);
    assert.equal(cache.stats().restored, 1);
    assert.deepEqual(cache.extract(item, identity(), compute), expected);
    assert.equal(computes, 1); assert.equal(cache.stats().hits, 1);
    cache.extract(item, { ...config, bodyText: 'New body' }, compute);
    const changed = catalog(); changed.aliases.set('new alias', { id: 'G0007', name: 'APT28' });
    assert.notEqual(extractionCatalogRevision(changed), config.catalogRevision);
    cache.extract(item, { ...config, catalogRevision: extractionCatalogRevision(changed) }, compute);
    assert.equal(computes, 3);
});

test('transitive code, callback wiring and dependency changes invalidate persisted results automatically', t => {
    const options = fixture(t);
    for (const name of ['matcher.js', 'index.js', 'package-lock.json']) {
        const before = extractionRulesRevision(options.directory);
        let cache = createPersistentFeedExtractionCache(options);
        cache.extract(item, identity(), () => ({ old: true })); cache.flush();
        fs.appendFileSync(path.join(options.directory, name), '\nchanged');
        assert.notEqual(extractionRulesRevision(options.directory), before);
        cache = createPersistentFeedExtractionCache(options);
        assert.equal(cache.stats().restored, 0);
        assert.deepEqual(cache.extract(item, identity(), () => ({ new: true })), { new: true });
    }
});

test('damaged/oversized cache and unwritable cache directory never prevent extraction or return stale evidence', t => {
    const options = fixture(t), errors = [];
    let cache = createPersistentFeedExtractionCache(options);
    cache.extract(item, identity(), () => null); cache.flush();
    fs.writeFileSync(options.file, 'damaged');
    cache = createPersistentFeedExtractionCache({ ...options, onError: error => errors.push(error) });
    assert.equal(errors.length, 1); assert.equal(cache.stats().entries, 0);
    assert.deepEqual(cache.extract(item, identity(), () => ({ evidence: 'preserved' })), { evidence: 'preserved' }); cache.flush();
    cache = createPersistentFeedExtractionCache({ ...options, maxEntries: 1, maxBytes: 1, onError: error => errors.push(error) });
    assert.equal(cache.stats().entries, 0);
    assert.equal(cache.extract(item, identity(), () => 'recomputed'), 'recomputed');
    const blocked = path.join(options.directory, 'not-a-directory'); fs.writeFileSync(blocked, 'file');
    cache = createPersistentFeedExtractionCache({ ...options, file: path.join(blocked, 'cache'), onError: error => errors.push(error) });
    cache.extract(item, identity(), () => 'retained in memory'); assert.doesNotThrow(() => cache.flush());
    assert.equal(cache.extract(item, identity(), () => { throw Error('must be cached'); }), 'retained in memory');
});
