import { VENDOR_CATALOG } from './vendorCatalog.js';
import { matchVendors } from './vendorMatch.js';

const knownIds = new Set(VENDOR_CATALOG.map((vendor) => vendor.id));
const idByName = new Map(VENDOR_CATALOG.map((vendor) => [vendor.name.toLowerCase(), vendor.id]));
const defaults = () => ({ mode: 'all', vendorIds: [], updatedAt: null });
const invalid = (message) => Object.assign(new Error(message), { status: 400 });

export function normalizeNewsMonitoring(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input) || !['all', 'selected'].includes(input.mode)) {
        throw invalid('Escolha todas as notícias ou somente os fornecedores selecionados.');
    }
    if (!Array.isArray(input.vendorIds) || input.vendorIds.length > VENDOR_CATALOG.length * 2 || input.vendorIds.some((id) => typeof id !== 'string' || !knownIds.has(id))) {
        throw invalid('Selecione fornecedores válidos do catálogo.');
    }
    return { mode: input.mode, vendorIds: [...new Set(input.vendorIds)].sort() };
}

export function createNewsMonitoringStore({ filePath, readFileSync, writeJsonAtomic }) {
    const rows = new Map();
    try {
        const saved = JSON.parse(readFileSync(filePath, 'utf8'));
        if (saved && typeof saved === 'object' && !Array.isArray(saved)) {
            for (const [ownerId, value] of Object.entries(saved)) {
                try {
                    const normalized = normalizeNewsMonitoring({ ...value, vendorIds: (value.vendorIds || []).filter((id) => knownIds.has(id)) });
                    rows.set(ownerId, { ...normalized, updatedAt: value.updatedAt || null });
                } catch { /* ignore malformed individual preferences */ }
            }
        }
    } catch { /* missing store starts with all news */ }
    return {
        get: (ownerId) => structuredClone(rows.get(String(ownerId)) || defaults()),
        set(ownerId, input, now = new Date().toISOString()) {
            const value = { ...normalizeNewsMonitoring(input), updatedAt: now };
            const next = new Map(rows);
            next.set(String(ownerId), value);
            writeJsonAtomic(filePath, Object.fromEntries(next));
            rows.set(String(ownerId), value);
            return structuredClone(value);
        },
    };
}

export function createMonitoredVendorMatcher(preferences) {
    if (preferences.mode === 'all') return () => true;
    const selected = new Set(preferences.vendorIds);
    const cache = new WeakMap();
    return (item) => {
        if (!selected.size || !item || typeof item !== 'object') return false;
        if (cache.has(item)) return cache.get(item);
        // Current extraction is authoritative. Legacy rows fall back to their
        // text/assets, never the publisher name (a source is not an affected vendor).
        const ids = Array.isArray(item.vendors)
            ? item.vendors.map((vendor) => vendor?.id)
            : [...matchVendors(`${item.title || ''}\n${item.text || item.description || ''}`).map((vendor) => vendor.id),
                ...(item.assets || []).map((name) => idByName.get(String(name).toLowerCase()))];
        const matches = ids.some((id) => selected.has(id));
        cache.set(item, matches);
        return matches;
    };
}

export function filterMonitoredStories(stories, preferences) {
    if (preferences.mode === 'all') return stories;
    const matches = createMonitoredVendorMatcher(preferences);
    return stories.filter((story) => (story.sources || []).some(matches));
}

export function filterMonitoredNews(items, preferences, stories = []) {
    if (preferences.mode === 'all') return items;
    const matches = createMonitoredVendorMatcher(preferences);
    const relevantIds = new Set();
    for (const story of stories) {
        if ((story.sources || []).some(matches)) for (const id of [story.id, ...(story.aliases || [])]) relevantIds.add(id);
    }
    for (const item of items) if (item.storyId && matches(item)) relevantIds.add(item.storyId);
    // Keep the complete available coverage of a relevant event in one card,
    // including follow-ups that omit the supplier name.
    return items.filter((item) => matches(item) || (item.storyId && relevantIds.has(item.storyId)));
}
