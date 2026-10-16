import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildOtProductBase, describeOtProduct, enrichOtVendorCatalog, isOtModelPattern } from '../otProductCatalog.js';
import { normalizeOtCsaf, allowedOtDocument, OT_VENDOR_FEEDS, OT_CATALOG } from '../otPatchDay.js';
import { AI_TOOL_CATALOG } from '../aiToolCatalog.js';

const row = { id: 'VDE-2026-001', source: 'wago', vendors: ['WAGO'], url: 'https://certvde.com/en/advisories/', published: '2026-01-01', updated: '2026-10-01', products: [{ name: 'PFC200 firmware <4.10.0 (FW32)', family: 'PFC200', vendor: 'WAGO', modelNumbers: ['750-821?-????-????', '750-8212'], status: 'affected', affectedCves: ['CVE-2026-12345'] }] };
test('OT product base deduplicates evidence and retains per-product CVE attribution', () => {
    const base = buildOtProductBase([row, { ...row, id: 'VDE-2026-002', products: [{ ...row.products[0], status: 'fixed', fixedCves: ['CVE-2026-67890'] }] }]);
    assert.equal(base.rows.length, 1); const p = base.rows[0];
    assert.equal(p.evidence.length, 2); assert.deepEqual(p.affectedCves, ['CVE-2026-12345']); assert.deepEqual(p.fixedCves, ['CVE-2026-67890']);
    assert.equal(p.version, '<4.10.0 (FW32)'); assert.equal(p.versionType, 'firmware');
    assert.deepEqual(p.modelPatterns, ['750-821?-????-????']);
    const [catalog] = enrichOtVendorCatalog([{ vendor: 'WAGO', models: ['Reference model'] }], base);
    assert.deepEqual(catalog.models, ['Reference model']); assert.deepEqual(catalog.observedModels, ['750-8212']);
    assert.equal(buildOtProductBase([row], { limit: 0 }).truncated, true);
});
test('cached source names enrich versions conservatively without inventing firmware', () => {
    assert.equal(describeOtProduct({ name: 'S7-1500' }).version, '');
    assert.equal(isOtModelPattern('6ES7222-1BF32-0XB0'), false);
    assert.equal(isOtModelPattern('0751-9x01'), true);
    assert.equal(describeOtProduct({ name: 'Library V2.1.0' }).versionType, 'unspecified');
    assert.equal(describeOtProduct({ name: 'Library V2.1.0' }).versionOrigin, 'product_name');
    assert.equal(describeOtProduct({ name: 'Device', version: 'vers:generic/<4.10.0|>=4.0', versionKind: 'range' }).versionLabel, '<4.10.0 >=4.0');
});
test('CSAF relationships join firmware ranges to hardware without losing exact CVE states', () => {
    const input = { document: { title: 'WAGO advisory', tracking: { id: row.id, current_release_date: row.updated } }, product_tree: { branches: [{ category: 'vendor', name: 'WAGO', branches: [{ category: 'product_family', name: 'CC100', product: { product_id: 'hw', name: 'CC100', product_identification_helper: { model_numbers: ['0751-9?01'] } } }, { category: 'product_version_range', name: '<4.10.0 (FW32)', product: { product_id: 'os', name: 'WAGO Linux firmware <4.10.0 (FW32)' } }] }], relationships: [{ product_reference: 'os', relates_to_product_reference: 'hw', full_product_name: { product_id: 'combined', name: 'WAGO Linux installed on CC100' } }] }, vulnerabilities: [{ cve: 'CVE-2026-12345', product_status: { known_affected: ['combined'] } }] };
    const product = normalizeOtCsaf(input, 'wago', row.url).products.find(p => p.id === 'combined');
    assert.equal(product.family, 'CC100'); assert.equal(product.version, '<4.10.0 (FW32)'); assert.equal(product.versionOrigin, 'csaf_tree');
    assert.deepEqual(product.modelNumbers, ['0751-9?01']); assert.deepEqual(product.affectedCves, ['CVE-2026-12345']);
});
test('new industrial feeds accept vendor filenames only on their own official hosts', () => {
    for (const feed of OT_VENDOR_FEEDS) {
        const url = `https://${feed.host}/.well-known/csaf/white/2026/advisory2026-11_vde-2026-094.json`;
        assert.equal(allowedOtDocument(url, feed.id), true);
        assert.equal(allowedOtDocument(url.replace(feed.host, feed.host + '.evil.test'), feed.id), false);
        assert.equal(allowedOtDocument(url + '?other=1', feed.id), false);
        assert.equal(allowedOtDocument(url, 'siemens'), false);
    }
    assert.ok(OT_CATALOG.vendors.find(v => v.vendor === 'Phoenix Contact'));
});
test('every seeded AI tool has its own sourced purpose definition', () => {
    const glossary = JSON.parse(readFileSync(new URL('../aiToolGlossary.json', import.meta.url), 'utf8'));
    for (const tool of AI_TOOL_CATALOG) {
        const entry = glossary.find(g => g.name === tool.name);
        assert.ok(entry, tool.name); assert.ok(entry.description.length > 30, tool.name); assert.match(entry.url, /^https:\/\//);
    }
});
