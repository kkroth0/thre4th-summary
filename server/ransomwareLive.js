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

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

export const THREAT_MAP_WINDOWS = [
    { key: '24h', label: '24h', days: 1 },
    { key: '72h', label: '72h', days: 3 },
    { key: '7d', label: '7d', days: 7 },
    { key: '30d', label: '30d', days: 30 },
];

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

function buildTimeline(victims, days, now) {
    const bucketMs = days <= 3 ? 6 * HOUR_MS : DAY_MS;
    const bucketCount = Math.max(1, Math.ceil((days * DAY_MS) / bucketMs));
    const start = now - bucketCount * bucketMs;
    const buckets = Array.from({ length: bucketCount }, (_, index) => {
        const from = start + index * bucketMs;
        const to = from + bucketMs;
        const fromDate = new Date(from);
        return {
            from: fromDate.toISOString(),
            to: new Date(to).toISOString(),
            label: bucketMs < DAY_MS
                ? fromDate.toISOString().slice(5, 16).replace('T', ' ')
                : fromDate.toISOString().slice(5, 10),
            count: 0,
            countries: [],
            groups: [],
        };
    });
    const countrySets = buckets.map(() => new Set());
    const groupSets = buckets.map(() => new Set());
    for (const victim of victims) {
        const time = victimTimestamp(victim);
        if (!time || time < start || time > now + HOUR_MS) continue;
        const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((time - start) / bucketMs)));
        buckets[index].count += 1;
        if (victim.country) countrySets[index].add(victim.country);
        if (victim.group) groupSets[index].add(victim.group);
    }
    return buckets.map((bucket, index) => ({
        ...bucket,
        countries: [...countrySets[index]],
        groups: [...groupSets[index]],
    }));
}

function buildInsights(current, previous, currentVictims) {
    const delta = current.totalVictims - previous.totalVictims;
    const latamVictims = currentVictims.filter((victim) => LATAM_COUNTRIES.has(victim.country));
    const previousCountries = new Set(previous.countries.map((country) => country.name));
    const newCountries = current.countries
        .filter((country) => !previousCountries.has(country.name))
        .slice(0, 5);
    const evidenceCount = currentVictims.filter((victim) => (
        victim.screenshot || victim.permalink || victim.infostealer || victim.press?.length
    )).length;

    const insights = [{
        kind: 'volume',
        severity: delta > 5 ? 'high' : delta > 0 ? 'medium' : 'low',
        value: current.totalVictims,
        previous: previous.totalVictims,
        delta,
    }];
    if (current.groups[0]) {
        insights.push({
            kind: 'top-group',
            severity: current.groups[0].count >= 5 ? 'high' : 'medium',
            name: current.groups[0].name,
            count: current.groups[0].count,
        });
    }
    if (current.sectors[0]) {
        insights.push({
            kind: 'sector',
            severity: current.sectors[0].count >= 5 ? 'high' : 'medium',
            name: current.sectors[0].name,
            count: current.sectors[0].count,
        });
    }
    if (newCountries.length > 0) {
        insights.push({
            kind: 'new-countries',
            severity: newCountries.length >= 3 ? 'high' : 'medium',
            countries: newCountries,
            count: newCountries.length,
        });
    }
    if (latamVictims.length > 0) {
        insights.push({
            kind: 'latam',
            severity: latamVictims.length >= 3 ? 'high' : 'medium',
            count: latamVictims.length,
            countries: countryCounts(latamVictims),
        });
    }
    if (evidenceCount > 0) {
        insights.push({
            kind: 'evidence',
            severity: 'context',
            count: evidenceCount,
        });
    }
    return insights;
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
    const windows = THREAT_MAP_WINDOWS.map((window) => summarizeWindow(victims, window.days, now, window.key, window.label));
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
        windows,
        timeline: buildTimeline(currentVictims, windowDays, now),
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
        insights: buildInsights(current, previous, currentVictims),
    };
}
