import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { OT_CATALOG, OT_SOURCES, allowedOtDocument, createOtPatchDay, defaultOtMonth, matchOtAssets, mergeOtAdvisories, normalizeOtCsaf, parseCiscoOtFeed, parseOtRolie, parseRockwellOtIndex, parseSchneiderOtIndex, validOtMonth } from '../otPatchDay.js';
import { identifyOtEquipment, OT_EQUIPMENT_TYPES } from '../otEquipment.js';

const docUrl = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-100-01.json';
function csaf() { return {
    document: { title: 'Schneider Modicon', tracking: { id: 'ICSA-26-100-01', version: '2', initial_release_date: '2026-04-10T00:00:00Z', current_release_date: '2026-10-13T00:00:00Z' }, references: [{ url: 'https://www.se.com/advisory' }], notes: [{ category: 'summary', text: 'Summary' }] },
    product_tree: { branches: [{ category: 'vendor', name: 'Schneider Electric', branches: [{ category: 'product_name', name: 'Modicon M340', branches: [{ category: 'product_version_range', name: '<3.70', product: { name: 'BMXP342020: before 3.70', product_id: 'affected' } }, { category: 'product_version', name: '3.70', product: { name: 'BMXP342020: 3.70', product_id: 'fixed' } }] }] }] },
    vulnerabilities: [{ cve: 'CVE-2026-12345', product_status: { known_affected: ['affected'], fixed: ['fixed'] }, scores: [{ cvss_v3: { baseScore: 8.8 } }], remediations: [{ category: 'vendor_fix', details: 'Upgrade to 3.70', product_ids: ['affected'], url: 'https://www.se.com/fix' }] }],
}; }
const rolie = () => ({ feed: { entry: [{ id: 'ICSA-26-100-01', title: 'Schneider', published: '2026-04-10T00:00:00Z', updated: '2026-10-13T00:00:00Z', content: { src: docUrl } }] } });
const tile = `<div class="content-fragment-list__tile" data-doc-id="SD1801" data-pub-date="2026-10-13 12:35:00" data-updated-date="2026-10-14 12:35:00"><a class="content-fragment-list__tile-title" href="https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1801.html">SD1801 | ControlLogix</a>${Object.entries({ Products: '1756-L61', 'CVE IDs': 'CVE-2026-11111', 'CVSS Scores (v3.1)': '9.1, 7.5', Corrected: 'Yes', Workaround: 'No' }).map(([k, v]) => `<div class="content-fragment-list__tile-information-item"><div class="content-fragment-list__tile-information-label">${k}:</div><div class="content-fragment-list__tile-information-value">${v}</div></div>`).join('')}</div>`;

test('monthly default uses Fortaleza and rejects invalid month values', () => {
    assert.equal(defaultOtMonth(new Date('2026-11-01T01:00:00Z')), '2026-10');
    assert.equal(validOtMonth('2026-13'), false); assert.equal(validOtMonth(['2026-10']), false);
    assert.equal(validOtMonth('2026-01'), true);
});
test('CSAF preserves initial/revision dates, affected/fixed versions and vendor fixes', () => {
    const row = normalizeOtCsaf(csaf(), 'cisa', docUrl);
    assert.equal(row.published, '2026-04-10T00:00:00.000Z'); assert.equal(row.updated, '2026-10-13T00:00:00.000Z');
    assert.equal(row.patch, 'available'); assert.equal(row.cvss, 8.8);
    assert.equal(row.products.find(p => p.id === 'fixed').status, 'fixed');
    assert.equal(row.remediations[0].products[0], 'BMXP342020: before 3.70');
    assert.deepEqual(row.cves, ['CVE-2026-12345']);
    assert.ok(matchOtAssets(row).some(m => m.level === 'model' && m.models.includes('BMXP342020')));
});
test('CISA advisory links target the actual advisory instead of a generic recommended-practices alert', () => {
    const input = csaf();
    input.document.references.unshift({ category: 'external', url: 'https://www.cisa.gov/news-events/ics-alerts/ics-alert-10-301-01' });
    assert.equal(normalizeOtCsaf(input, 'cisa', docUrl).url, 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-100-01');
    input.document.tracking.id = 'ICSMA-26-288-02';
    assert.equal(normalizeOtCsaf(input, 'cisa', docUrl).url, 'https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-288-02');
});
test('mitigation is not a published patch, and manufacturer matching is not model matching', () => {
    const input = csaf(); delete input.vulnerabilities[0].product_status.fixed;
    input.vulnerabilities[0].remediations = [{ category: 'mitigation', details: 'Restrict access' }];
    input.product_tree.branches[0].branches[0].branches[0].product.name = 'Different product';
    input.product_tree.branches[0].branches[0].branches[1].product.name = 'Different product';
    const row = normalizeOtCsaf(input, 'cisa', docUrl);
    assert.equal(row.patch, 'mitigation'); assert.equal(matchOtAssets(row)[0].level, 'vendor');
    row.products = [{ name: 'BMXP3420209' }]; assert.equal(matchOtAssets(row)[0].level, 'vendor');
});
test('Schneider CSAF model_numbers match actual catalog models even when product names omit SKU', () => {
    const input = csaf();
    const product = input.product_tree.branches[0].branches[0].branches[0].product;
    product.name = 'Modbus/TCP Ethernet Modicon M340 FactoryCast module Versions prior to 6.80';
    product.product_identification_helper = { model_numbers: ['BMXNOE0110'] };
    input.product_tree.relationships = [{ full_product_name: { product_id: 'relationship', name: 'Firmware installed on controller' } }];
    const row = normalizeOtCsaf(input, 'schneider', 'https://www.se.com/.well-known/csaf/2026/sevd-2026-286-02.json');
    assert.ok(matchOtAssets(row).some(m => m.models.includes('BMXNOE0110')));
    assert.ok(row.products.some(p => p.id === 'relationship'));
});
test('ROLIe captures revisions of old advisories and excludes arbitrary source URLs', () => {
    const input = rolie(); input.feed.entry.push({ ...input.feed.entry[0], content: { src: 'http://127.0.0.1/secret' } });
    assert.equal(parseOtRolie(input).length, 1);
    for (const url of ['http://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/a.json', 'https://raw.githubusercontent.com/other/repo/a.json', 'https://sec.cloudapps.cisco.com@localhost/file.json', 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/a.json']) assert.equal(allowedOtDocument(url), false);
});
test('Rockwell official fields distinguish corrected from workaround and deduplicate grid/list tiles', () => {
    const rows = parseRockwellOtIndex(tile + tile);
    assert.equal(rows.length, 1); assert.equal(rows[0].patch, 'available'); assert.equal(rows[0].cvss, 9.1);
    assert.equal(rows[0].updated, '2026-10-14T12:35:00.000Z');
    assert.equal(parseRockwellOtIndex(tile.replace('>Yes<', '>No<').replace('>No</div></div></div>', '>Yes</div></div></div>'))[0].patch, 'mitigation');
});
test('Cisco feed upgrades official HTTP links to HTTPS and declares invalid feeds', () => {
    const link = 'http://sec.cloudapps.cisco.com:80/security/center/content/CiscoSecurityAdvisory/cisco-sa-test/csaf/cisco-sa-test.json';
    const rows = parseCiscoOtFeed(`<rss><channel><item><title>cisco-sa-test</title><guid>${link}</guid><pubDate>2026-10-15 19:37:28.0</pubDate></item></channel></rss>`);
    assert.match(rows[0].url, /^https:/); assert.equal(rows[0].updated, '2026-10-15T19:37:28.000Z');
    assert.throws(() => parseCiscoOtFeed('<html>Blocked</html>'));
});
test('Schneider uses official changes.csv instead of blocked portal; cross-year revisions and URL boundaries survive', () => {
    const rows = parseSchneiderOtIndex('"2025/sevd-2025-252-01.json","2026-10-13T07:00:00.000Z"\n"../../private.json","2026-10-13T07:00:00Z"\n"2026/sevd-2026-286-02.json","2026-10-13T07:00:00.000Z"');
    assert.equal(rows.length, 2); assert.equal(rows[0].id, 'SEVD-2025-252-01');
    assert.equal(rows[0].updated, '2026-10-13T07:00:00.000Z');
    assert.match(rows[0].url, /^https:\/\/www.se.com\/\.well-known\/csaf\/2025\//);
    assert.equal(allowedOtDocument('https://www.se.com/.well-known/csaf/2025/sevd-2025-252-01.json'), true);
    assert.equal(allowedOtDocument('https://www.se.com/private.json'), false);
    assert.throws(() => parseSchneiderOtIndex('<html>Access denied</html>'));
});
test('same CVE alone never merges distinct advisories; explicit republication retains both references', () => {
    const original = parseRockwellOtIndex(tile)[0];
    const copy = { ...normalizeOtCsaf(csaf(), 'cisa', docUrl), cves: original.cves };
    assert.equal(mergeOtAdvisories([copy, original]).length, 2);
    copy.references.push(original.url);
    copy.vendors = original.vendors;
    const rows = mergeOtAdvisories([copy, original]);
    assert.equal(rows.length, 1); assert.ok(rows[0].references.includes(docUrl));
    assert.deepEqual(rows[0].alsoReportedBy, ['CISA']);
    assert.equal(rows[0].relatedAdvisories[0].products.length, copy.products.length);
});
test('daily source caching, single flight, persisted restart, stale fallback and local CVE signals', async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ot-patch-test-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    let time = Date.parse('2026-10-16T12:00:00Z'), calls = [], broken = false;
    const http = { get: async url => {
        calls.push(url); if (broken) throw { response: { status: 503 } };
        if (url === OT_SOURCES[0].url) return { status: 200, data: rolie(), headers: { etag: 'a' } };
        if (url === OT_SOURCES[1].url) return { status: 200, data: tile, headers: {} };
        if (url === docUrl) return { status: 200, data: csaf(), headers: {} };
        throw { response: { status: 403 } };
    } };
    const options = { filePath: path.join(dir, 'cache.json'), http, now: () => time, getCve: () => ({ kev: true, epss: 0.92 }) };
    const service = createOtPatchDay(options); service.query({ month: '2026-10' });
    assert.equal(service.sync(), service.sync()); await service.sync();
    let result = service.query({ month: '2026-10' });
    assert.equal(result.rows.length, 2); assert.equal(result.status.pending, 0); assert.equal(result.summary.kev, 2);
    assert.ok(result.rows.every(r => r.cveSignals.every(c => c.epss === 0.92)));
    const initialCalls = calls.length; await service.sync(); assert.equal(calls.length, initialCalls);
    const oldCache = JSON.parse(fs.readFileSync(options.filePath, 'utf8'));
    oldCache.documents['cisa:ICSA-26-100-01'].row.url = 'https://www.cisa.gov/news-events/ics-alerts/ics-alert-10-301-01';
    fs.writeFileSync(options.filePath, JSON.stringify(oldCache));
    const restart = createOtPatchDay(options); assert.equal(restart.query({ month: '2026-10' }).rows.length, 2);
    assert.equal(restart.query({ month: '2026-10' }).rows.find(r => r.source === 'cisa').url, 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-100-01');
    await restart.sync(); assert.equal(calls.length, initialCalls);
    time += 86400001; broken = true; await restart.sync();
    result = restart.query({ month: '2026-10' }); assert.equal(result.rows.length, 2); assert.ok(result.rows.every(r => r.stale));
    assert.ok(result.sources.some(s => s.status === 'stale')); assert.equal(restart.query({ month: '2026-04' }).rows.length, 1);
});
test('catalog contains no installed firmware inventory or site-specific labels', () => {
    assert.equal(OT_CATALOG.vendors.length, 47);
    assert.equal(OT_CATALOG.vendors.filter(v => /rockwell|allen/i.test(v.vendor)).length, 1);
    assert.ok(OT_CATALOG.vendors.some(v => v.vendor === 'ABB' && v.review.some(m => m.includes('fabricante a confirmar'))));
    const data = JSON.stringify(OT_CATALOG);
    assert.doesNotMatch(data, /"firmware"|"client"|"cliente"|do R3|Raytek W[12]/i);
});

const siemensUrl = 'https://cert-portal.siemens.com/productcert/csaf/ssa-580366.json';
const abbUrl = 'https://psirt.abb.com/csaf/2026/7paa025438.json';
const vendorFeed = (source, id, url, updated = '2026-10-15T00:00:00Z') => ({ feed: { entry: [{ id, title: source, published: updated, updated, content: { src: url } }] } });

test('Siemens and ABB ROLIE feeds preserve revisions and restrict documents to the originating manufacturer', () => {
    const feed = vendorFeed('Siemens', 'SSA-580366', siemensUrl);
    feed.feed.entry[0].published = '2025-01-01T00:00:00Z';
    feed.feed.entry.push({ ...feed.feed.entry[0], id: 'bad', content: { src: docUrl } });
    const rows = parseOtRolie(feed, 'siemens');
    assert.equal(rows.length, 1); assert.equal(rows[0].source, 'siemens');
    assert.ok(rows[0].published.startsWith('2025-01')); assert.ok(rows[0].updated.startsWith('2026-10'));
    assert.equal(parseOtRolie(vendorFeed('ABB', '7paa025438', abbUrl), 'abb')[0].source, 'abb');
    for (const url of [siemensUrl + '?download=other', siemensUrl.replace('cert-portal.siemens.com', 'cert-portal.siemens.com.evil.test'), 'https://cert-portal.siemens.com/private.json', 'https://psirt.abb.com/csaf/2026/../../../private.json']) assert.equal(allowedOtDocument(url), false);
    assert.equal(allowedOtDocument(siemensUrl, 'abb'), false);
    assert.throws(() => parseOtRolie({ feed: { entry: [] } }, 'siemens'));
});

test('Siemens product family differs from an exact model and partial product names do not match', () => {
    const family = matchOtAssets({ vendors: ['Siemens AG'], products: [{ name: 'SIMATIC S7-1500 CPU with firmware < V3.1.7' }] })[0];
    assert.equal(family.vendor, 'Siemens'); assert.equal(family.level, 'family'); assert.deepEqual(family.models, []);
    const exact = matchOtAssets({ vendors: ['Siemens'], products: [{ name: 'CPU', modelNumbers: ['6ES7518-4AX00-1AB0'] }] })[0];
    assert.equal(exact.level, 'model'); assert.ok(exact.models.includes('6ES7518-4AX00-1AB0'));
    assert.equal(matchOtAssets({ vendors: ['Siemens'], products: [{ name: '6ES7518-4AX00-1AB09' }] })[0].level, 'vendor');
});

test('CSAF retains comparison operators, expands remediation groups and distinguishes mixed product status', () => {
    const doc = csaf();
    doc.product_tree.product_groups = [{ group_id: 'g', product_ids: ['affected', 'fixed'] }];
    doc.vulnerabilities[0].remediations = [{ category: 'vendor_fix', details: 'Affected >= 1.0 < 2.0; update to >= 2.0', group_ids: ['g'] }];
    doc.vulnerabilities.push({ cve: 'CVE-2026-12346', product_status: { known_affected: ['fixed'] } });
    const row = normalizeOtCsaf(doc, 'cisa', docUrl);
    assert.match(row.remediations[0].details, /< 2.0.*>= 2.0/);
    assert.equal(row.remediations[0].products.length, 2);
    assert.equal(row.products.find(p => p.id === 'fixed').status, 'mixed');
    doc.vulnerabilities.push({ remediations: [{ category: 'none_available', details: 'No fix for this product' }] });
    assert.equal(normalizeOtCsaf(doc, 'cisa', docUrl).partialFix, true);
    doc.vulnerabilities = [{ cve: 'CVE-2026-12345', remediations: [{ category: 'none_available', details: 'Fix expected next week' }, { category: 'mitigation', details: 'Restrict access' }] }];
    assert.equal(normalizeOtCsaf(doc, 'siemens', siemensUrl).patch, 'mitigation');
});

test('all manufacturers make progress, unchanged documents are reused and changed indexes use conditional requests', async () => {
    let time = Date.parse('2026-10-16T12:00:00Z'), revision = '2026-10-15T00:00:00Z'; const calls = [];
    const http = { get: async (url, options) => {
        calls.push({ url, options });
        const source = OT_SOURCES.find(s => s.url === url);
        if (source?.id === 'cisa') return { status: 200, data: rolie(), headers: {} };
        if (source?.id === 'siemens') return { status: 200, data: vendorFeed('Siemens', 'SSA-580366', siemensUrl, revision), headers: {} };
        if (source?.id === 'abb') return { status: 200, data: vendorFeed('ABB', '7paa025438', abbUrl, revision), headers: {} };
        if (source) throw { response: { status: 503 } };
        if (url === siemensUrl && options.headers['If-None-Match']) return { status: 304, headers: {} };
        const doc = csaf(); doc.document.tracking.id = url === siemensUrl ? 'SSA-580366' : url === abbUrl ? '7PAA025438' : 'ICSA-26-100-01';
        doc.product_tree.branches[0].name = url === siemensUrl ? 'Siemens' : url === abbUrl ? 'ABB' : 'Schneider Electric';
        return { status: 200, data: doc, headers: { etag: 'document-v1' } };
    } };
    const service = createOtPatchDay({ http, now: () => time, batchSize: 3 });
    service.query({ month: '2026-10' }); await service.sync();
    const result = service.query({ month: '2026-10' });
    assert.equal(result.rows.length, 3); assert.equal(result.status.pending, 0);
    assert.ok(result.rows.some(r => r.vendors.includes('Siemens'))); assert.ok(result.rows.some(r => r.vendors.includes('ABB')));
    const count = calls.length; await service.sync(); assert.equal(calls.length, count);
    time += 86400001; revision = '2026-10-16T00:00:00Z'; await service.sync();
    assert.equal(calls.filter(c => c.url === siemensUrl).at(-1).options.headers['If-None-Match'], 'document-v1');
    assert.equal(service.query({ month: '2026-10' }).status.pending, 0);
});

test('equipment explanations identify product roles without guessing an unknown model type', () => {
    assert.ok(OT_EQUIPMENT_TYPES.every(t => t.description.length > 40 && t.patchContext.length > 40));
    assert.deepEqual(identifyOtEquipment(['SIMATIC S7-1500']), ['plc']);
    assert.deepEqual(identifyOtEquipment(['PanelView Plus 1000']), ['hmi']);
    assert.deepEqual(identifyOtEquipment(['SCALANCE']), ['network']);
    assert.deepEqual(identifyOtEquipment(['SCADAPack']), ['rtu']);
    assert.deepEqual(identifyOtEquipment(['PCM600']), ['engineering']);
    assert.deepEqual(identifyOtEquipment(['Unknown model 123']), []);
    const data = createOtPatchDay().query({ month: '2026-10' });
    assert.ok(data.catalog.find(v => v.vendor === 'Siemens').equipmentTypes.includes('plc'));
    assert.ok(data.equipmentTypes.some(t => t.id === 'relay'));
});

test('large manufacturer indexes cannot starve other sources within a bounded batch', async () => {
    const fetched = [];
    const http = { get: async url => {
        const source = OT_SOURCES.find(s => s.url === url);
        if (source?.id === 'cisa') return { status: 200, headers: {}, data: { feed: { entry: Array.from({ length: 50 }, (_, i) => ({ id: `ICSA-26-100-${String(i + 1).padStart(2, '0')}`, updated: '2026-10-16T00:00:00Z', content: { src: docUrl.replace('01.json', `${String(i + 1).padStart(2, '0')}.json`) } })) } } };
        if (source?.id === 'siemens') return { status: 200, headers: {}, data: vendorFeed('Siemens', 'SSA-580366', siemensUrl) };
        if (source?.id === 'abb') return { status: 200, headers: {}, data: vendorFeed('ABB', '7paa025438', abbUrl) };
        if (!source) fetched.push(url);
        throw { response: { status: 503 } };
    } };
    const service = createOtPatchDay({ http, batchSize: 3 }); service.query({ month: '2026-10' }); await service.sync();
    assert.equal(fetched.length, 3); assert.ok(fetched.includes(siemensUrl)); assert.ok(fetched.includes(abbUrl));
});

test('transient document failures recover promptly, preserve retry-after and survive restart without a request storm', async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ot-retry-test-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    let time = Date.parse('2026-10-16T12:00:00Z'), requests = 0;
    const filePath = path.join(dir, 'cache.json');
    const http = { get: async url => {
        if (url === OT_SOURCES.find(s => s.id === 'siemens').url) return { status: 200, data: vendorFeed('Siemens', 'SSA-580366', siemensUrl), headers: {} };
        if (url === siemensUrl) {
            requests++;
            if (requests === 1) throw { code: 'ECONNABORTED' };
            if (requests === 2) throw { response: { status: 429, headers: { 'retry-after': '120' } } };
            const doc = csaf(); doc.document.tracking.id = 'SSA-580366'; doc.product_tree.branches[0].name = 'Siemens';
            return { status: 200, data: doc, headers: {} };
        }
        throw { response: { status: 403 } };
    } };
    const options = { filePath, http, now: () => time }; let service = createOtPatchDay(options);
    service.query({ month: '2026-10' }); await service.sync();
    let data = service.query({ month: '2026-10' }); assert.equal(data.status.failedDocuments[0].reason, 'ECONNABORTED');
    assert.equal(Date.parse(data.status.failedDocuments[0].retryAt) - time, 30000);
    service = createOtPatchDay(options); service.query({ month: '2026-10' }); await service.sync(); assert.equal(requests, 1);
    time += 30001; await service.sync(); data = service.query({ month: '2026-10' });
    assert.equal(data.status.failedDocuments[0].reason, 'HTTP 429'); assert.equal(Date.parse(data.status.failedDocuments[0].retryAt) - time, 120000);
    time += 119999; await service.sync(); assert.equal(requests, 2);
    time += 2; await service.sync(); data = service.query({ month: '2026-10' });
    assert.equal(requests, 3); assert.equal(data.status.failed, 0); assert.equal(data.rows.length, 1);
    const legacy = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    legacy.documents['siemens:SSA-580366'] = { error: true, retryAt: time + 3600000 };
    fs.writeFileSync(filePath, JSON.stringify(legacy));
    service = createOtPatchDay(options); service.query({ month: '2026-10' }); await service.sync();
    assert.equal(requests, 4); assert.equal(service.query({ month: '2026-10' }).status.failed, 0);
});
