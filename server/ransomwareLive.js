export const LATAM_COUNTRIES = new Set([
    'AR', 'BO', 'BR', 'CL', 'CO', 'CR', 'CU', 'DO', 'EC', 'GT', 'HN', 'MX',
    'NI', 'PA', 'PE', 'PR', 'PY', 'SV', 'UY', 'VE', 'BZ', 'GY', 'SR', 'GF',
]);

export const COUNTRY_NAMES = {
    AR: 'Argentina', BO: 'Bolivia', BR: 'Brazil', CL: 'Chile', CO: 'Colombia',
    CR: 'Costa Rica', CU: 'Cuba', DO: 'Dominican Republic', EC: 'Ecuador',
    GT: 'Guatemala', HN: 'Honduras', MX: 'Mexico', NI: 'Nicaragua', PA: 'Panama',
    PE: 'Peru', PR: 'Puerto Rico', PY: 'Paraguay', SV: 'El Salvador', UY: 'Uruguay',
    VE: 'Venezuela', US: 'United States of America', ES: 'Spain', IT: 'Italy',
    PL: 'Poland', DE: 'Germany', FR: 'France', GB: 'United Kingdom', CA: 'Canada',
    PT: 'Portugal', IE: 'Ireland', NL: 'Netherlands', BE: 'Belgium', CH: 'Switzerland',
    AT: 'Austria', CZ: 'Czechia', SK: 'Slovakia', HU: 'Hungary', RO: 'Romania',
    BG: 'Bulgaria', GR: 'Greece', SE: 'Sweden', NO: 'Norway', FI: 'Finland',
    DK: 'Denmark', UA: 'Ukraine', RU: 'Russia', TR: 'Turkey', BY: 'Belarus',
    RS: 'Serbia', HR: 'Croatia', ZA: 'South Africa', EG: 'Egypt', NG: 'Nigeria',
    GH: 'Ghana', KE: 'Kenya', MA: 'Morocco', DZ: 'Algeria', TN: 'Tunisia',
    AO: 'Angola', ET: 'Ethiopia', IN: 'India', CN: 'China', JP: 'Japan',
    KR: 'South Korea', TW: 'Taiwan', HK: 'Hong Kong', SG: 'Singapore',
    ID: 'Indonesia', MY: 'Malaysia', TH: 'Thailand', VN: 'Vietnam',
    PH: 'Philippines', PK: 'Pakistan', BD: 'Bangladesh', SA: 'Saudi Arabia',
    AE: 'United Arab Emirates', IL: 'Israel', QA: 'Qatar', KW: 'Kuwait',
    IR: 'Iran', AU: 'Australia', NZ: 'New Zealand',
};

export const AFRICA_COUNTRIES = new Set([
    'MA', 'DZ', 'TN', 'LY', 'EG', 'SD', 'ZA', 'NG', 'GH', 'KE', 'ET', 'AO',
    'CI', 'CM', 'SN', 'TZ', 'UG', 'ZM', 'ZW', 'MZ', 'BW', 'NA', 'RW', 'ML',
    'BF', 'BJ', 'NE', 'TD', 'MG', 'MU', 'MW', 'GA', 'CD', 'CG', 'SO', 'LR',
    'SL', 'TG', 'GN', 'MR', 'GM',
]);

const EUROPE_COUNTRIES = new Set([
    'ES', 'IT', 'PL', 'DE', 'FR', 'GB', 'PT', 'IE', 'NL', 'BE', 'CH', 'AT',
    'CZ', 'SK', 'HU', 'RO', 'BG', 'GR', 'SE', 'NO', 'FI', 'DK', 'UA', 'RU',
    'BY', 'RS', 'HR',
]);

const ASIA_COUNTRIES = new Set([
    'IN', 'CN', 'JP', 'KR', 'TW', 'HK', 'SG', 'ID', 'MY', 'TH', 'VN', 'PH',
    'PK', 'BD',
]);

const MIDDLE_EAST_COUNTRIES = new Set(['SA', 'AE', 'IL', 'QA', 'KW', 'IR', 'TR']);

// Focus regions for the priority threat map. Keys are the stable ids the UI
// sends; each maps to the ISO alpha-2 set used to tag/filter victims. Overlaps
// (Brazil inside LATAM, Morocco inside Africa) are fine — a selection is a set
// union, so a victim is only ever counted once per region key.
export const REGIONS = {
    latam: { label: 'LATAM', countries: LATAM_COUNTRIES },
    brazil: { label: 'Brasil', countries: new Set(['BR']) },
    us: { label: 'EUA', countries: new Set(['US']) },
    africa: { label: 'África', countries: AFRICA_COUNTRIES },
    europe: { label: 'Europa', countries: EUROPE_COUNTRIES },
    asia: { label: 'Ásia', countries: ASIA_COUNTRIES },
    middle_east: { label: 'Oriente Médio', countries: MIDDLE_EAST_COUNTRIES },
};

// Pre-selected in the UI on first load — the user's current priority regions.
export const DEFAULT_FOCUS_REGIONS = ['latam', 'brazil', 'us', 'africa'];

export const regionCodes = (keys = []) => {
    const set = new Set();
    for (const key of keys) {
        const region = REGIONS[key];
        if (region) for (const code of region.countries) set.add(code);
    }
    return set;
};

// Keep only victims located in the selected regions. Empty selection = no
// region constraint (used by the global scope).
export const filterByRegions = (victims, keys = []) => {
    const codes = regionCodes(keys);
    if (!codes.size) return victims;
    return victims.filter((victim) => codes.has(victim.country));
};

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

export const asArray = (value) => (
    Array.isArray(value) ? value
        : Array.isArray(value?.data) ? value.data
            : Array.isArray(value?.victims) ? value.victims
                : Array.isArray(value?.results) ? value.results
                    : []
);

export const countBy = (items, fn) => {
    const map = new Map();
    for (const item of items) {
        const key = fn(item);
        if (!key) continue;
        map.set(key, (map.get(key) || 0) + 1);
    }
    return [...map.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({ name, count }));
};

const text = (...values) => {
    for (const value of values) {
        if (value === undefined || value === null) continue;
        const normalized = String(value).trim();
        if (normalized && normalized !== 'N/A') return normalized;
    }
    return '';
};

const maybeArray = (value) => {
    if (Array.isArray(value)) return value.filter(Boolean);
    return value ? [value] : [];
};

export function normalizeVictim(v = {}, source = 'ransomware.live') {
    const country = text(v.country, v.country_code, v.countryCode).toUpperCase();
    const name = text(v.post_title, v.victim, v.name, v.website, v.domain, 'Unknown victim');
    const description = text(v.description);
    return {
        id: text(v.id, v.slug) || undefined,
        name,
        website: text(v.website, v.domain, v.url),
        group: text(v.group_name, v.group, 'unknown'),
        country,
        countryName: COUNTRY_NAMES[country] || country || 'Unknown',
        sector: text(v.activity, v.sector, v.industry, 'Not Found'),
        published: text(v.published, v.attackdate, v.attack_date, v.date, v.discovered) || null,
        discovered: text(v.discovered, v.published, v.date, v.attackdate, v.attack_date) || null,
        description: description ? description.slice(0, 500) : '',
        screenshot: text(v.screenshot),
        permalink: text(v.permalink, v.link),
        infostealer: v.infostealer ?? v.infostealer_detected ?? null,
        press: maybeArray(v.press),
        source: text(v.source, source),
    };
}

export function ransomwareLiveRequestOptions(apiKey = '') {
    const key = String(apiKey || '').trim();
    if (key) {
        return {
            source: 'ransomware.live Pro',
            url: 'https://api-pro.ransomware.live/victims/recent',
            options: {
                headers: { 'X-API-KEY': key },
                params: { order: 'discovered' },
                timeout: 10000,
                maxRedirects: 3,
            },
        };
    }
    return {
        source: 'ransomware.live',
        url: 'https://api.ransomware.live/v2/recentvictims',
        options: {
            timeout: 10000,
            maxRedirects: 3,
        },
    };
}

// Server-side sector filter — Pro-only (`/victims/` 401s without a key). Returns
// null when no key so callers can degrade to the global recent feed. `/victims/`
// requires at least one filter and returns the sector's full history, which the
// map then windows down; this is what surfaces niche sectors the 100-item recent
// feed never shows.
export function sectorVictimsRequestOptions(apiKey, sector) {
    const key = String(apiKey || '').trim();
    if (!key || !sector) return null;
    return {
        url: 'https://api-pro.ransomware.live/victims/',
        options: {
            headers: { 'X-API-KEY': key },
            params: { sector, order: 'discovered' },
            timeout: 15000,
            maxRedirects: 3,
        },
    };
}

// Pro `/listsectors`: every sector value plus a victim count, used to populate
// the UI sector picker with the exact strings the `sector` filter expects.
export function sectorListRequestOptions(apiKey) {
    const key = String(apiKey || '').trim();
    if (!key) return null;
    return {
        url: 'https://api-pro.ransomware.live/listsectors',
        options: {
            headers: { 'X-API-KEY': key },
            timeout: 12000,
            maxRedirects: 3,
        },
    };
}

export const victimTimestamp = (victim) => {
    const time = Date.parse(victim?.discovered || victim?.published || '');
    return Number.isNaN(time) ? null : time;
};

const sortVictims = (victims) => [...victims].sort((a, b) => (victimTimestamp(b) || 0) - (victimTimestamp(a) || 0));

const inCurrentWindow = (victim, days, now) => {
    const time = victimTimestamp(victim);
    if (!time) return true;
    return time >= now - days * DAY_MS && time <= now + HOUR_MS;
};

const inPreviousWindow = (victim, days, now) => {
    const time = victimTimestamp(victim);
    if (!time) return false;
    return time >= now - (days * 2 * DAY_MS) && time < now - days * DAY_MS;
};

const countryCounts = (victims) => countBy(victims, (v) => v.country)
    .map((country) => ({ ...country, countryName: COUNTRY_NAMES[country.name] || country.name }));

function summarizeVictimSet(victims, days, key = `${days}d`, label = `${days}d`) {
    const filtered = sortVictims(victims);
    const countries = countryCounts(filtered);
    const groups = countBy(filtered, (v) => v.group).slice(0, 12);
    const sectors = countBy(filtered, (v) => v.sector).slice(0, 12);
    return {
        key,
        label,
        days,
        totalVictims: filtered.length,
        countries,
        groups,
        sectors,
        topCountry: countries[0] || null,
        activeGroups: groups.length,
        latestVictim: filtered[0] || null,
    };
}

function summarizeWindow(victims, days, now, key = `${days}d`, label = `${days}d`) {
    return summarizeVictimSet(
        victims.filter((victim) => inCurrentWindow(victim, days, now)),
        days,
        key,
        label,
    );
}

export function buildThreatMapResponse(rawVictims, {
    days = 3,
    generatedAt = new Date().toISOString(),
    now = Date.now(),
    source = 'ransomware.live',
} = {}) {
    const windowDays = Math.max(1, Math.min(30, Number(days) || 3));
    const victims = sortVictims(asArray(rawVictims).map((victim) => normalizeVictim(victim, source)));
    const currentVictims = sortVictims(victims.filter((victim) => inCurrentWindow(victim, windowDays, now)));
    const previousVictims = victims.filter((victim) => inPreviousWindow(victim, windowDays, now));
    const current = summarizeWindow(victims, windowDays, now, `${windowDays}d`, `${windowDays}d`);
    const previous = summarizeVictimSet(previousVictims, windowDays, 'previous', 'previous');
    const countries = current.countries;
    const groups = current.groups;
    const sectors = current.sectors;
    const latamVictims = currentVictims.filter((victim) => LATAM_COUNTRIES.has(victim.country));
    const deltaVictims = current.totalVictims - previous.totalVictims;

    return {
        generatedAt,
        windowDays,
        source,
        totalVictims: current.totalVictims,
        victims: currentVictims,
        countries,
        groups,
        sectors,
        topCountry: countries[0] || null,
        activeGroups: groups.length,
        delta: {
            victims: deltaVictims,
            previousVictims: previous.totalVictims,
            percent: previous.totalVictims > 0 ? Math.round((deltaVictims / previous.totalVictims) * 100) : (current.totalVictims > 0 ? 100 : 0),
            direction: deltaVictims > 0 ? 'up' : deltaVictims < 0 ? 'down' : 'flat',
        },
        latam: {
            victims: latamVictims.length,
            countries: countryCounts(latamVictims),
            groups: countBy(latamVictims, (v) => v.group).slice(0, 8),
        },
    };
}
