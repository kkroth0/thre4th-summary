import { createHash } from 'node:crypto';
import { identifyOtEquipment } from './otEquipment.js';

const unique = values => [...new Set(values.filter(Boolean))];
const clean = v => String(v ?? '').replace(/\s+/g, ' ').trim();
const key = v => clean(v).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
export const isOtModelPattern = value => /[?*]|\d[xX]+(?=\d|[-_. ]|$)|(?:^|[-_. ])[xX]+(?=\d)/.test(value);

export function describeOtProduct(product) {
    let version = clean(product.version), versionKind = product.versionKind || '', versionOrigin = product.versionOrigin || '';
    if (!version) {
        // Retain the manufacturer's wording, never compare or invent versions.
        // This also enriches older cache entries without downloading them again.
        const tail = clean(product.name).split(/\s+installed on\s+/i)[0];
        const explicit = /\b(?:firmware(?:\s+versions?)?|versions?)\s*:?\s+(.+)$/i.exec(tail);
        const range = /(?:^|\s)((?:>=|<=|>|<)\s*V?\d[^<>]*(?:\s*(?:>=|<=|>|<)\s*V?\d[^<>]*)*)$/i.exec(tail);
        const exact = /\s(V\d+\.\d+(?:[\w.()-]*))$/i.exec(tail);
        version = clean(explicit?.[1] || range?.[1] || exact?.[1]);
        if (version) { versionKind = /[<>]|prior|before|earlier|through|all versions/i.test(version) ? 'range' : 'description'; versionOrigin = 'product_name'; }
    }
    const context = `${product.name || ''} ${version} ${product.platform || ''}`;
    const versionType = /\bfirmware\b|\bFW\s*\d+/i.test(context) ? 'firmware' : String(product.cpe || '').startsWith('cpe:2.3:o:') ? 'os' : String(product.cpe || '').startsWith('cpe:2.3:a:') ? 'software' : 'unspecified';
    return { ...product, version, versionKind, versionOrigin, versionType, versionLabel: version.replace(/^vers:[^/]+\//, '').replace(/\|/g, ' '), equipmentTypes: identifyOtEquipment([product.family, product.platform, product.name].filter(Boolean)) };
}

export function buildOtProductBase(advisories, { limit = 10000, canonicalVendor = clean } = {}) {
    const products = new Map(); let truncated = false;
    for (const row of [...advisories].sort((a, b) => (b.updated || '').localeCompare(a.updated || ''))) {
        for (const input of row.products || []) {
            const p = describeOtProduct(input);
            // Older vendor caches sometimes contain only a version leaf, not
            // an identifiable product. Keep it in the advisory evidence, but
            // do not present it as an equipment model in the asset catalog.
            if (!p.platform && !p.family && (!/[a-z]{2}/i.test(p.name) || /^[<>=~()\sVv]*\d*\.\d/.test(p.name))) continue;
            if ((p.platform || p.family) && /^[<>=~()\sVv]*\d*\.\d/.test(p.name)) p.name = [p.platform || p.family, p.name].join(' ');
            const vendor = canonicalVendor(p.vendor || (row.vendors?.length === 1 ? row.vendors[0] : 'Fabricante não identificado'));
            const modelNumbers = unique(p.modelNumbers || []), identity = [vendor, p.family, p.platform, p.name, p.version, ...modelNumbers.slice().sort()].map(key).join('\u0000');
            let record = products.get(identity);
            if (!record) {
                if (products.size >= limit) { truncated = true; continue; }
                record = { id: createHash('sha256').update(identity).digest('hex').slice(0, 20), vendor, name: clean(p.name), family: p.family || '', platform: p.platform || '', version: p.version, versionLabel: p.versionLabel, versionKind: p.versionKind, versionOrigin: p.versionOrigin, versionType: p.versionType, modelNumbers, modelPatterns: modelNumbers.filter(isOtModelPattern), equipmentTypes: p.equipmentTypes, statuses: [], affectedCves: [], fixedCves: [], evidence: [] };
                products.set(identity, record);
            }
            record.statuses = unique([...record.statuses, p.status || 'mentioned']);
            record.affectedCves = unique([...record.affectedCves, ...(p.affectedCves || [])]); record.fixedCves = unique([...record.fixedCves, ...(p.fixedCves || [])]);
            if (!record.evidence.some(e => e.source === row.source && e.id === row.id)) record.evidence.push({ id: row.id, source: row.source, url: row.url, published: row.published, updated: row.updated, status: p.status || 'mentioned' });
        }
    }
    const rows = [...products.values()].sort((a, b) => a.vendor.localeCompare(b.vendor) || a.name.localeCompare(b.name));
    return { rows, truncated, summary: { products: rows.length, vendors: unique(rows.map(r => r.vendor)).length, versioned: rows.filter(r => r.version).length, firmware: rows.filter(r => ['firmware', 'os'].includes(r.versionType)).length, fixed: rows.filter(r => r.statuses.some(s => ['fixed', 'mixed'].includes(s))).length } };
}

export function enrichOtVendorCatalog(seed, base) {
    const catalog = new Map(seed.map(v => [v.vendor, { ...v, observedModels: [], observedFamilies: [], evidenceProducts: 0 }]));
    for (const product of base.rows) {
        if (product.vendor === 'Fabricante não identificado') continue;
        const vendor = catalog.get(product.vendor) || { vendor: product.vendor, aliases: [product.vendor], models: [], families: [], review: [], observedModels: [], observedFamilies: [], evidenceProducts: 0, discovered: true };
        vendor.evidenceProducts++;
        vendor.observedModels = unique([...vendor.observedModels, ...product.modelNumbers.filter(m => !isOtModelPattern(m))]).slice(0, 1000);
        vendor.observedFamilies = unique([...vendor.observedFamilies, product.family]).slice(0, 200);
        catalog.set(vendor.vendor, vendor);
    }
    return [...catalog.values()].sort((a, b) => a.vendor.localeCompare(b.vendor));
}
