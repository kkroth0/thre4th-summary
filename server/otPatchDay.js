import fs from 'node:fs';
import path from 'node:path';
import * as cheerio from 'cheerio';
import axios from 'axios';
import { identifyOtEquipment, OT_EQUIPMENT_REFERENCE, OT_EQUIPMENT_TYPES } from './otEquipment.js';
import { buildOtProductBase, describeOtProduct, enrichOtVendorCatalog } from './otProductCatalog.js';

export const OT_VENDOR_FEEDS = [
    ['phoenixcontact', 'Phoenix Contact'], ['wago', 'WAGO'], ['weidmueller', 'Weidmüller'],
    ['festo', 'Festo'], ['pilz', 'Pilz'], ['pepperl-fuchs', 'Pepperl+Fuchs'],
    ['turck', 'Turck'], ['codesys', 'CODESYS'], ['beckhoff', 'Beckhoff'],
].map(([id, vendor]) => ({ id, vendor, host: `${id}.csaf-tp.certvde.com` }));

export const OT_CATALOG = JSON.parse(fs.readFileSync(new URL('./otAssetCatalog.json', import.meta.url), 'utf8'));
export const OT_SOURCES = [
    { id: 'cisa', name: 'CISA OT · CSAF', url: 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json', coverage: 'Arquivo de advisories OT/ICS e suas revisões.' },
    { id: 'rockwell', name: 'Rockwell Automation', url: 'https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html', coverage: 'Portal oficial: produtos, CVEs, correção e workaround.' },
    { id: 'cisco', name: 'Cisco · CSAF', url: 'https://sec.cloudapps.cisco.com/security/center/csaf_20.xml', coverage: 'Feed recente do fabricante; não constitui arquivo histórico completo.' },
    { id: 'schneider', name: 'Schneider Electric · CSAF', url: 'https://www.se.com/.well-known/csaf/changes.csv', metadataUrl: 'https://www.se.com/.well-known/csaf/provider-metadata.json', coverage: 'Distribuição CSAF oficial: índice de revisões e arquivos JSON, independente do portal HTML.' },
    { id: 'siemens', name: 'Siemens ProductCERT · CSAF', url: 'https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json', coverage: 'Arquivo oficial de Security Advisories (SSA): publicações e revisões, produtos e versões, CVEs, correções e medidas compensatórias.' },
    { id: 'abb', name: 'ABB PSIRT · CSAF', url: 'https://psirt.abb.com/csaf/abb-csaf-feed-tlp-white.json', coverage: 'Avisos oficiais ABB e B&R publicados no feed PSIRT: produtos afetados, versões corrigidas e restrições de atualização.' },
    ...OT_VENDOR_FEEDS.map(v => ({ id: v.id, name: `${v.vendor} · CSAF / CERT@VDE`, url: `https://${v.host}/.well-known/csaf/white/csaf-feed-tlp-white.json`, bootstrapDocuments: 5, coverage: 'Avisos oficiais distribuídos pelo CERT@VDE, com produtos, versões e correções. Os cinco avisos mais recentes também alimentam a base acumulada de ativos.' })),
];
const DAY = 86400000;
const DOCUMENT_VERSION = 2;
const clean = value => String(value ?? '').replace(/\s+/g, ' ').trim();
const unique = values => [...new Set(values.filter(Boolean))];
const iso = value => { const time = Date.parse(value); return Number.isFinite(time) ? new Date(time).toISOString() : ''; };
const keyText = value => clean(value).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
export const defaultOtMonth = (date = new Date()) => {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Fortaleza', year: 'numeric', month: '2-digit' }).formatToParts(date);
    return parts.find(p => p.type === 'year').value + '-' + parts.find(p => p.type === 'month').value;
};
export function validOtMonth(month) { return typeof month === 'string' && /^20\d{2}-(0[1-9]|1[0-2])$/.test(month); }
const inMonth = (row, month) => row.published?.startsWith(month) || row.updated?.startsWith(month);
const cisaAdvisoryUrl = id => {
    const value = String(id).toLowerCase();
    return /^icsa-\d{2}-\d{3}-\d{2}$/.test(value) ? `https://www.cisa.gov/news-events/ics-advisories/${value}`
        : /^icsma-\d{2}-\d{3}-\d{2}$/.test(value) ? `https://www.cisa.gov/news-events/ics-medical-advisories/${value}` : '';
};
const vendorFor = name => OT_CATALOG.vendors.find(v => v.aliases.some(alias => keyText(name) === keyText(alias)))?.vendor || clean(name);
function safeUrl(value, base) { try { const u = new URL(value, base); return u.protocol === 'https:' && !u.username && !u.password ? u.href : ''; } catch { return ''; } }
export function allowedOtDocument(value, source) {
    try {
        const u = new URL(value);
        if (u.protocol !== 'https:' || u.username || u.password || u.port || u.search || u.hash) return false;
        return (!source || source === 'cisa') && u.hostname === 'raw.githubusercontent.com' && u.pathname.startsWith('/cisagov/CSAF/develop/csaf_files/OT/') && u.pathname.endsWith('.json')
            || (!source || source === 'cisco') && u.hostname === 'sec.cloudapps.cisco.com' && u.pathname.startsWith('/security/center/content/CiscoSecurityAdvisory/') && u.pathname.endsWith('.json')
            || (!source || source === 'schneider') && u.hostname === 'www.se.com' && /^\/\.well-known\/csaf\/20\d{2}\/(?:sevd|sesb)-20\d{2}-\d{3}-\d{2}\.json$/.test(u.pathname)
            || (!source || source === 'siemens') && u.hostname === 'cert-portal.siemens.com' && /^\/productcert\/csaf\/ssa-\d{6}\.json$/.test(u.pathname)
            || (!source || source === 'abb') && u.hostname === 'psirt.abb.com' && /^\/csaf\/20\d{2}\/[a-z0-9-]{4,40}\.json$/.test(u.pathname)
            || OT_VENDOR_FEEDS.some(v => (!source || source === v.id) && u.hostname === v.host && /^\/\.well-known\/csaf\/white\/20\d{2}\/[a-z0-9_-]{4,100}\.json$/.test(u.pathname));
    } catch { return false; }
}

export function matchOtAssets(row) {
    const vendors = new Set((row.vendors || []).map(vendorFor));
    const haystack = keyText((row.products || []).map(p => [p.name, ...(p.modelNumbers || [])].join(' | ')).join(' | '));
    return OT_CATALOG.vendors.filter(v => vendors.has(v.vendor)).map(v => {
        // A match identifies a product mentioned in the advisory. Installed
        // firmware is deliberately absent: this is not exposure confirmation.
        const models = v.models.filter(model => {
            const tokens = keyText(model).match(/[a-z0-9]+/g) || [];
            return tokens.join('').length >= 6 && new RegExp('(?<![a-z0-9])' + tokens.join('[\\s./-]*') + '(?![a-z0-9])').test(haystack);
        });
        const families = (v.families || []).filter(family => {
            const tokens = keyText(family).match(/[a-z0-9]+/g) || [];
            return tokens.length && new RegExp('(?<![a-z0-9])' + tokens.join('[\\s./-]*') + '(?![a-z0-9])').test(haystack);
        });
        return { vendor: v.vendor, level: models.length ? 'model' : families.length ? 'family' : 'vendor', models, ...(families.length ? { families } : {}) };
    });
}

export function normalizeOtCsaf(input, source, url) {
    const doc = input?.document, tracking = doc?.tracking;
    if (!tracking?.id || !doc.title || !iso(tracking.current_release_date)) throw Error('Invalid CSAF document');
    const products = new Map(), vendors = [];
    function walk(branches, vendor = '', context = {}) {
        for (const b of branches || []) {
            const current = b.category === 'vendor' ? vendorFor(b.name) : vendor;
            if (b.category === 'vendor') vendors.push(current);
            const next = { ...context };
            if (b.category === 'product_family') next.family = clean(b.name);
            if (b.category === 'product_name') next.platform = clean(b.name);
            if (['product_version', 'product_version_range'].includes(b.category)) { next.version = clean(b.name); next.versionKind = b.category === 'product_version_range' ? 'range' : 'exact'; next.versionOrigin = 'csaf_tree'; }
            if (b.product?.product_id) products.set(b.product.product_id, describeOtProduct({ id: b.product.product_id, name: clean(b.product.name || b.name), vendor: current, ...next, cpe: clean(b.product.product_identification_helper?.cpe), modelNumbers: (b.product.product_identification_helper?.model_numbers || []).map(clean) }));
            walk(b.branches, current, next);
        }
    }
    walk(input.product_tree?.branches);
    for (const p of input.product_tree?.full_product_names || []) products.set(p.product_id, describeOtProduct({ id: p.product_id, name: clean(p.name), vendor: '', cpe: clean(p.product_identification_helper?.cpe), modelNumbers: (p.product_identification_helper?.model_numbers || []).map(clean) }));
    for (const r of input.product_tree?.relationships || []) {
        const p = r.full_product_name;
        if (p?.product_id) {
            const software = products.get(r.product_reference), hardware = products.get(r.relates_to_product_reference);
            products.set(p.product_id, describeOtProduct({ ...software, id: p.product_id, name: clean(p.name), vendor: hardware?.vendor || software?.vendor || '', family: hardware?.family || software?.family || '', platform: hardware?.platform || hardware?.name || '', cpe: clean(p.product_identification_helper?.cpe || software?.cpe), modelNumbers: unique([...(p.product_identification_helper?.model_numbers || []), ...(hardware?.modelNumbers || [])]) }));
        }
    }
    const groups = new Map((input.product_tree?.product_groups || []).map(g => [g.group_id, g.product_ids || []]));
    const affected = new Set(), fixed = new Set(), remediations = [], cves = [], scores = [], affectedCves = new Map(), fixedCves = new Map();
    for (const v of input.vulnerabilities || []) {
        if (/^CVE-\d{4}-\d{4,}$/i.test(v.cve || '')) cves.push(v.cve.toUpperCase());
        for (const id of v.product_status?.known_affected || []) { affected.add(id); if (v.cve) affectedCves.set(id, unique([...(affectedCves.get(id) || []), v.cve])); }
        for (const id of v.product_status?.fixed || []) { fixed.add(id); if (v.cve) fixedCves.set(id, unique([...(fixedCves.get(id) || []), v.cve])); }
        for (const s of v.scores || []) {
            // Prefer CVSS v3 for comparison with the local vulnerability catalog.
            const n = s.cvss_v3?.baseScore ?? s.cvss_v4?.baseScore ?? s.cvss_v2?.baseScore;
            if (Number.isFinite(n) && n >= 0 && n <= 10) scores.push(n);
        }
        for (const r of v.remediations || []) remediations.push({ category: clean(r.category), details: clean(r.details), url: safeUrl(r.url), products: unique([...(r.product_ids || []), ...(r.group_ids || []).flatMap(id => groups.get(id) || [])]).map(id => products.get(id)?.name || id), cve: v.cve || '' });
    }
    const dedupRemediations = [...new Map(remediations.map(r => [JSON.stringify(r), r])).values()];
    const references = unique([url, ...(doc.references || []).map(r => safeUrl(r.url))]);
    const cisaWeb = cisaAdvisoryUrl(tracking.id);
    const primaryUrl = source === 'cisa' && cisaWeb ? cisaWeb : references.find(r => !r.endsWith('.json')) || url;
    const fixes = dedupRemediations.some(r => r.category === 'vendor_fix') || fixed.size > 0;
    const mitigation = dedupRemediations.some(r => ['mitigation', 'workaround'].includes(r.category));
    return {
        id: clean(tracking.id), title: clean(doc.title), source, url: primaryUrl,
        references: unique([primaryUrl, ...references]), vendors: unique((vendors.length ? vendors : [({ cisco: 'Cisco', schneider: 'Schneider Electric', siemens: 'Siemens', abb: 'ABB' })[source] || doc.publisher?.name]).map(vendorFor)),
        published: iso(tracking.initial_release_date), updated: iso(tracking.current_release_date), revision: clean(tracking.version),
        summary: clean((doc.notes || []).find(n => n.category === 'summary')?.text), cves: unique(cves), cvss: scores.length ? Math.max(...scores) : null,
        products: [...products.values()].map(p => ({ ...p, affectedCves: affectedCves.get(p.id) || [], fixedCves: fixedCves.get(p.id) || [], status: fixed.has(p.id) && affected.has(p.id) ? 'mixed' : fixed.has(p.id) ? 'fixed' : affected.has(p.id) ? 'affected' : 'mentioned' })),
        remediations: dedupRemediations, patch: fixes ? 'available' : mitigation ? 'mitigation' : 'unconfirmed',
        partialFix: fixes && dedupRemediations.some(r => r.category === 'none_available'),
    };
}

export function parseOtRolie(input, source = 'cisa') {
    if (!Array.isArray(input?.feed?.entry)) throw Error('Invalid OT ROLIE feed');
    const rows = input.feed.entry.map(e => ({ id: clean(e.id), title: clean(e.title), source, published: iso(e.published), updated: iso(e.updated), url: e.content?.src }))
        .filter(e => e.id && e.updated && allowedOtDocument(e.url, source));
    if (!rows.length) throw Error('OT ROLIE feed contains no allowed advisories');
    return [...new Map(rows.map(e => [e.id.toLowerCase(), e])).values()];
}
export function parseCiscoOtFeed(xml) {
    const $ = cheerio.load(xml, { xmlMode: true }); const rows = [];
    $('item').each((_, el) => {
        const item = $(el); let url;
        try { const u = new URL(item.find('guid').text() || item.find('link').text()); u.protocol = 'https:'; u.port = ''; u.search = ''; url = u.href; } catch { return; }
        const date = item.find('pubDate').text().trim();
        if (allowedOtDocument(url)) rows.push({ id: clean(item.find('title').text()), source: 'cisco', title: '', published: '', updated: iso(date.replace(' ', 'T').replace(/\.0$/, '') + 'Z'), url });
    });
    if (!rows.length) throw Error('Cisco feed contains no advisories');
    return rows;
}
export function parseSchneiderOtIndex(csv) {
    const rows = [];
    for (const line of String(csv).split(/\r?\n/)) {
        const columns = line.match(/^"([^"\r\n]+)","([^"\r\n]+)"\s*$/);
        if (!columns) continue;
        const name = columns[1].match(/^(20\d{2})\/((?:sevd|sesb)-(20\d{2})-(\d{3})-\d{2})\.json$/i);
        if (!name || name[1] !== name[3]) continue;
        const updated = iso(columns[2]), url = new URL(columns[1], 'https://www.se.com/.well-known/csaf/').href;
        // Filename date is ONLY a discovery hint. Displayed publication and
        // revision dates always come from the fetched CSAF tracking object.
        const hint = iso(new Date(Date.UTC(Number(name[3]), 0, Number(name[4]))).toISOString());
        if (updated && allowedOtDocument(url)) rows.push({ id: name[2].toUpperCase(), source: 'schneider', title: '', published: hint, updated, url });
    }
    if (!rows.length) throw Error('Schneider index contains no CSAF documents');
    return rows;
}
function htmlText(value) {
    return clean(String(value ?? '').replace(/<[^>]*>/g, ' ')).replace(/&(?:#(x[0-9a-f]+|\d+)|([a-z]+));/gi, (whole, numeric, name) => {
        if (numeric) { const n = numeric[0].toLowerCase() === 'x' ? parseInt(numeric.slice(1), 16) : Number(numeric); return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : whole; }
        return ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', reg: '®', trade: '™', copy: '©' })[name.toLowerCase()] || whole;
    });
}
export function parseRockwellOtIndex(html) {
    const rows = [];
    // The portal is ~9MB. Parse one tile at a time instead of retaining an
    // entire DOM alongside the ETL archive on the 1GB production host.
    const parts = html.split(/<div class="content-fragment-list__tile"/).slice(1);
    for (const part of parts) {
        const tile = part.slice(0, 30000), attr = name => tile.match(new RegExp('\\b' + name + '="([^"]*)"'))?.[1], id = attr('data-doc-id');
        if (!id) continue;
        const fields = {};
        for (const pair of tile.matchAll(/<div[^>]*class="content-fragment-list__tile-information-label"[^>]*>([\s\S]*?)<\/div>\s*<div[^>]*class="content-fragment-list__tile-information-value"[^>]*>([\s\S]*?)<\/div>/g)) fields[htmlText(pair[1]).replace(/:$/, '')] = htmlText(pair[2]);
        const link = tile.match(/<a\b[^>]*\bclass="content-fragment-list__tile-title"[^>]*>([\s\S]*?)<\/a>/), url = safeUrl(link?.[0].match(/\bhref="([^"]+)"/)?.[1]);
        if (!url || new URL(url).hostname !== 'www.rockwellautomation.com') continue;
        const score = (fields['CVSS Scores (v3.1)'] || fields['CVSS Scores (v4.0)'] || '').match(/\d+(?:\.\d+)?/g)?.map(Number).filter(n => n <= 10) || [];
        rows.push({ id, source: 'rockwell', title: htmlText(link[1]), url, references: [url], vendors: ['Rockwell Automation'],
            published: iso(attr('data-pub-date')?.replace(' ', 'T') + 'Z'), updated: iso(attr('data-updated-date')?.replace(' ', 'T') + 'Z'), revision: '', summary: '',
            cves: unique((fields['CVE IDs'] || '').match(/CVE-\d{4}-\d{4,}/g) || []), cvss: score.length ? Math.max(...score) : null,
            products: fields.Products ? [{ id: '', name: fields.Products, vendor: 'Rockwell Automation', status: 'mentioned' }] : [],
            patch: /^yes$/i.test(fields.Corrected || '') ? 'available' : /^yes$/i.test(fields.Workaround || '') ? 'mitigation' : 'unconfirmed',
            remediations: [{ category: 'reference', details: 'Consulte as versões afetadas, versões corrigidas e instruções no aviso oficial.', url, products: [], cve: '' }],
            vendorKev: /^yes$/i.test(fields['Known Exploited Vulnerability (KEV)'] || ''),
        });
    }
    if (!rows.length) throw Error('Rockwell portal contains no advisories');
    return [...new Map(rows.map(r => [r.id, r])).values()];
}

// Deduplicate only a CISA republication with an explicit original reference.
// Sharing a CVE alone does not mean two advisories affect the same products.
export function mergeOtAdvisories(rows) {
    const result = [];
    for (const row of [...rows].sort((a, b) => Number(a.source === 'cisa') - Number(b.source === 'cisa'))) {
        const original = row.source === 'cisa' && result.find(r => r.source !== 'cisa' && row.vendors.some(v => r.vendors.includes(v)) && row.cves.length > 0 && [...row.cves].sort().join(',') === [...r.cves].sort().join(',') && (row.references.includes(r.url) || row.references.some(url => {
            try { const reference = decodeURIComponent(url).replace(/\s/g, '').toLowerCase(); return new RegExp('(?:/|=)' + r.id.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:[./?&#]|$)').test(reference); } catch { return false; }
        })));
        if (original) { original.references = unique([...original.references, ...row.references]); original.alsoReportedBy = unique([...(original.alsoReportedBy || []), 'CISA']); original.relatedAdvisories = [...(original.relatedAdvisories || []), row]; }
        else result.push({ ...row, references: [...row.references] });
    }
    return result;
}

export function createOtPatchDay({ filePath, http = axios, now = () => Date.now(), getCve = () => null, batchSize = 40 } = {}) {
    let state = { version: 1, sources: {}, index: {}, documents: {}, months: [] }, flight = null, cacheError = false, needsSave = false;
    const signals = new Map();
    let productBaseCache = null, bootstrapCache = null;
    const cveSignal = id => {
        const cached = signals.get(id);
        if (cached && cached.until > now()) return cached.value;
        const v = getCve(id), value = { id, kev: v?.kev ?? null, epss: v?.epss ?? null, cvss: v?.cvss ?? null };
        if (signals.size >= 6000) signals.delete(signals.keys().next().value);
        signals.set(id, { value, until: now() + 300000 }); return value;
    };
    if (filePath) try { if (fs.statSync(filePath).size > 24 * 1024 * 1024) throw Error('Oversized OT cache'); const s = JSON.parse(fs.readFileSync(filePath, 'utf8')); if (s.version === 1 && s.documents && s.index && s.sources && Array.isArray(s.months)) state = s; } catch { /* fresh or invalid cache: rebuild */ }
    // Repair links already cached by the initial release without downloading
    // unchanged documents or erasing retained evidence.
    for (const doc of Object.values(state.documents)) {
        const url = doc.row?.source === 'cisa' && cisaAdvisoryUrl(doc.row.id);
        if (url && doc.row.url !== url) { doc.row = { ...doc.row, url, references: unique([url, ...(doc.row.references || [])]) }; needsSave = true; }
        // Upgrade the old one-hour catch-all retry once; subsequent restarts
        // retain the backoff (including provider Retry-After instructions).
        if (doc.error && doc.retryPolicy !== 2) { doc.retryAt = now(); doc.retryPolicy = 2; needsSave = true; }
    }
    const persist = () => {
        if (!filePath) return;
        try {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
            const temp = filePath + '.tmp';
            fs.writeFileSync(temp, JSON.stringify(state), { mode: 0o600 }); fs.renameSync(temp, filePath); cacheError = false; needsSave = false;
        } catch { cacheError = true; }
    };
    const request = async (url, etag) => http.get(url, { timeout: 15000, maxRedirects: 0, maxContentLength: 12 * 1024 * 1024, headers: { 'User-Agent': 'ThreatSumm4ry OT Patch Day (+https://threatsumm4ry.app)', ...(etag ? { 'If-None-Match': etag } : {}) }, validateStatus: s => s === 200 || s === 304, responseType: 'text' });
    const bootstrap = () => {
        if (bootstrapCache) return bootstrapCache;
        const selected = new Set();
        for (const source of OT_SOURCES) for (const entry of [...(state.index[source.id] || [])].sort((a, b) => b.updated.localeCompare(a.updated)).slice(0, source.bootstrapDocuments || 0)) selected.add(entry.source + ':' + entry.id);
        const recent = [...(state.index.cisa || [])].filter(e => Date.parse(e.updated) >= now() - 366 * DAY).sort((a, b) => b.updated.localeCompare(a.updated));
        for (const vendor of OT_CATALOG.vendors) {
            const aliases = vendor.aliases.filter(a => a.length >= 4).map(keyText);
            const entry = recent.find(e => aliases.some(a => new RegExp('(?:^|[^a-z0-9])' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:$|[^a-z0-9])').test(keyText(e.title))));
            if (entry) selected.add('cisa:' + entry.id);
        }
        bootstrapCache = selected; return selected;
    };
    const candidates = () => { const base = bootstrap(); return Object.entries(state.index).filter(([source]) => source !== 'rockwell').flatMap(([, entries]) => entries).filter(e => (state.months.some(m => inMonth(e, m)) || base.has(e.source + ':' + e.id)) && (!state.documents[e.source + ':' + e.id]?.row || state.documents[e.source + ':' + e.id].indexedUpdated !== e.updated || state.documents[e.source + ':' + e.id].version !== DOCUMENT_VERSION)); };
    function sync() {
        if (flight) return flight;
        flight = (async () => {
            let changed = cacheError || needsSave;
            for (const source of OT_SOURCES) {
                const old = state.sources[source.id] || {};
                if ((old.nextAt || 0) > now()) continue;
                changed = true;
                try {
                    const response = await request(source.url, old.etag);
                    if (response.status !== 304) {
                        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                        const parsed = ['cisa', 'siemens', 'abb', ...OT_VENDOR_FEEDS.map(v => v.id)].includes(source.id) ? parseOtRolie(JSON.parse(body), source.id) : source.id === 'cisco' ? parseCiscoOtFeed(body) : source.id === 'rockwell' ? parseRockwellOtIndex(body) : parseSchneiderOtIndex(body);
                        state.index[source.id] = parsed;
                        bootstrapCache = null;
                        productBaseCache = null;
                    }
                    state.sources[source.id] = { status: 'ok', checkedAt: new Date(now()).toISOString(), lastSuccess: new Date(now()).toISOString(), nextAt: now() + DAY, etag: response.headers?.etag || old.etag || '' };
                } catch (error) {
                    state.sources[source.id] = { ...old, status: old.lastSuccess ? 'stale' : 'error', checkedAt: new Date(now()).toISOString(), nextAt: now() + 3600000, error: error.response?.status ? `HTTP ${error.response.status}` : 'Fonte indisponível ou formato não reconhecido' };
                }
                await new Promise(resolve => setImmediate(resolve));
            }
            // Round-robin sources so a large CISA/Siemens revision cannot hold
            // back all other manufacturers. Keep remote requests sequential.
            const ready = candidates().filter(e => (state.documents[e.source + ':' + e.id]?.retryAt || 0) <= now());
            const buckets = OT_SOURCES.map(s => ready.filter(e => e.source === s.id).sort((a, b) => b.updated.localeCompare(a.updated)));
            const queue = [];
            while (queue.length < batchSize && buckets.some(b => b.length)) for (const bucket of buckets) { if (bucket.length && queue.length < batchSize) queue.push(bucket.shift()); }
            for (const e of queue) {
                changed = true;
                const key = e.source + ':' + e.id, old = state.documents[key];
                try {
                    if (!allowedOtDocument(e.url, e.source)) throw Error('Disallowed CSAF URL');
                    const response = await request(e.url, old?.version === DOCUMENT_VERSION ? old.etag : undefined);
                    if (response.status === 304) {
                        if (!old?.row) throw Error('CSAF 304 without cached document');
                        state.documents[key] = { ...old, indexedUpdated: e.updated, fetchedAt: new Date(now()).toISOString(), error: false, retryAt: 0, attempts: 0 };
                        continue;
                    }
                    const row = normalizeOtCsaf(typeof response.data === 'string' ? JSON.parse(response.data) : response.data, e.source, e.url);
                    if (row.id.toLowerCase() !== e.id.toLowerCase()) throw Error('CSAF document ID differs from index');
                    state.documents[key] = { row, version: DOCUMENT_VERSION, etag: response.headers?.etag || '', indexedUpdated: e.updated, fetchedAt: new Date(now()).toISOString() };
                    productBaseCache = null;
                } catch (error) {
                    const status = error.response?.status, attempts = (old?.attempts || 0) + 1;
                    const invalid = error instanceof SyntaxError || /Invalid CSAF|document ID differs|Disallowed CSAF|304 without/.test(error.message || '');
                    const transient = !invalid && (!status || [408, 425, 429, 500, 502, 503, 504].includes(status));
                    const retryAfter = error.response?.headers?.['retry-after'];
                    const instruction = /^\d+$/.test(String(retryAfter)) ? Number(retryAfter) * 1000 : Math.max(0, Date.parse(retryAfter) - now()) || 0;
                    const instructed = Number.isFinite(instruction) ? Math.min(7 * DAY, instruction) : DAY;
                    const delay = transient ? Math.min(3600000, 30000 * 2 ** Math.min(attempts - 1, 7)) : 3600000;
                    const reason = status ? `HTTP ${status}` : ['ECONNABORTED', 'ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND', 'ERR_NETWORK', 'ERR_BAD_RESPONSE'].includes(error.code) ? error.code : 'Documento inválido ou indisponível';
                    state.documents[key] = { ...old, retryAt: now() + Math.max(delay, instructed), retryPolicy: 2, attempts, failureReason: reason, error: true };
                }
                await new Promise(resolve => setImmediate(resolve));
            }
            // Retain compact normalized advisories, never full source DOMs.
            if (!changed) return;
            const entries = Object.entries(state.documents).sort((a, b) => (a[1].fetchedAt || '').localeCompare(b[1].fetchedAt || ''));
            let bytes = entries.reduce((sum, [, value]) => sum + Buffer.byteLength(JSON.stringify(value)), 0), remaining = entries.length;
            for (const [key, value] of entries) {
                if (remaining <= 2000 && bytes <= 16 * 1024 * 1024) break;
                bytes -= Buffer.byteLength(JSON.stringify(value)); remaining--; delete state.documents[key]; changed = true;
                productBaseCache = null;
            }
            if (changed) persist();
        })().catch(() => { /* expose stale data; the next tick retries */ }).finally(() => { flight = null; });
        return flight;
    }
    function query({ month = defaultOtMonth(new Date(now())), vendor = '', scope = 'all' } = {}) {
        if (!validOtMonth(month)) throw Error('Invalid month');
        if (!state.months.includes(month)) { state.months = [...state.months, month].slice(-24); needsSave = true; }
        const native = (state.index.rockwell || []).filter(r => inMonth(r, month));
        const docs = Object.values(state.documents).flatMap(d => d.row && inMonth(d.row, month) ? [{ ...d.row, documentStale: Boolean(d.error) }] : [])
            .filter(row => row.source !== 'cisco' || /\b(?:Catalyst|Industrial|IOS XE)\b/i.test(row.title + ' ' + row.products.map(p => p.name).join(' ')));
        let rows = mergeOtAdvisories([...native, ...docs]).map(row => {
            const cveSignals = row.cves.map(cveSignal);
            return { ...row, matches: matchOtAssets(row), cveSignals, kev: Boolean(row.vendorKev || cveSignals.some(v => v.kev === true)), revised: row.updated.slice(0, 10) !== row.published.slice(0, 10), stale: Boolean(row.documentStale || state.sources[row.source]?.status !== 'ok') };
        });
        if (vendor) rows = rows.filter(r => r.vendors.includes(vendor));
        if (scope === 'baseline') rows = rows.filter(r => r.matches.length);
        if (scope === 'models') rows = rows.filter(r => r.matches.some(m => m.level === 'model'));
        rows.sort((a, b) => Number(b.kev) - Number(a.kev) || (b.cvss ?? -1) - (a.cvss ?? -1) || b.updated.localeCompare(a.updated));
        const allPending = candidates(), pending = allPending.filter(e => inMonth(e, month));
        if (!productBaseCache) productBaseCache = buildOtProductBase([...(state.index.rockwell || []), ...Object.values(state.documents).flatMap(d => d.row ? [d.row] : [])], { canonicalVendor: vendorFor });
        const catalog = enrichOtVendorCatalog(OT_CATALOG.vendors, productBaseCache).map(v => ({ ...v, equipmentTypes: identifyOtEquipment([...(v.models || []), ...(v.families || []), ...v.observedFamilies]) }));
        return {
            month, rows, catalog, productBase: productBaseCache, equipmentTypes: OT_EQUIPMENT_TYPES, equipmentReference: OT_EQUIPMENT_REFERENCE, sources: OT_SOURCES.map(s => ({ ...s, ...state.sources[s.id] })),
            status: { running: Boolean(flight), pending: pending.length, catalogPending: allPending.length, catalogFailed: allPending.filter(e => state.documents[e.source + ':' + e.id]?.error).length, failed: pending.filter(e => state.documents[e.source + ':' + e.id]?.error).length, failedDocuments: pending.filter(e => state.documents[e.source + ':' + e.id]?.error).map(e => { const d = state.documents[e.source + ':' + e.id]; return { id: e.id, source: e.source, reason: d.failureReason || 'Nova tentativa agendada', retryAt: new Date(d.retryAt).toISOString() }; }), initialized: OT_SOURCES.every(s => state.sources[s.id]?.checkedAt), cadenceHours: 24, persistenceError: cacheError },
            summary: { advisories: rows.length, patches: rows.filter(r => r.patch === 'available').length, mitigations: rows.filter(r => r.patch === 'mitigation').length, kev: rows.filter(r => r.kev).length, matched: rows.filter(r => r.matches.some(m => m.level === 'model')).length },
        };
    }
    return { query, sync };
}
