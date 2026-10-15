import { createHash } from 'node:crypto';
import { analyzePhishing, extractNamedPhishingKits, PHISHING_VERSION } from './phishingIntel.js';

const unique = values => [...new Set(values.filter(Boolean))];
const names = values => unique((Array.isArray(values) ? values : []).map(value => typeof value === 'string' ? value : value?.name));
const normalize = value => String(value || '').normalize('NFD').replace(/\p{Mn}/gu, '').toLowerCase();
const hasTerm = (text, term) => term && new RegExp(`(^|[^a-z0-9])${normalize(term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^a-z0-9])`).test(normalize(text));
const LATAM = new Set(['Brazil', 'Latin America', 'Mexico', 'Argentina', 'Chile', 'Colombia', 'Peru']);
const countBy = (rows, valuesOf) => {
    const counts = new Map();
    for (const row of rows) for (const value of unique(valuesOf(row))) counts.set(value, (counts.get(value) || 0) + 1);
    return [...counts].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
};

function profileMatches(report, profiles) {
    const result = [];
    for (const profile of profiles) {
        const reasons = [];
        for (const sector of profile.sectors || []) if (report.sectors.includes(sector)) reasons.push(`Setor: ${sector}`);
        for (const region of profile.regions || []) if (report.regions.includes(region) || (region === 'Latin America' && report.regions.some(value => LATAM.has(value)))) reasons.push(`Região: ${region}`);
        for (const asset of profile.assets || []) {
            const term = asset.product || asset.vendor;
            if (hasTerm(`${report.title} ${report.description} ${report.brands.join(' ')}`, term)) reasons.push(`Tecnologia: ${term}`);
        }
        for (const brand of profile.brands || []) if (report.brands.some(value => hasTerm(value, brand))) reasons.push(`Marca imitada: ${brand}`);
        for (const id of profile.actors || []) if ((report.actors || []).some(actor => actor.id === id)) reasons.push('Ator acompanhado');
        if (reasons.length) result.push({ profileId: profile.id, profileName: profile.name, reasons: unique(reasons) });
    }
    return result;
}

// Existing correlation IDs are the grouping authority. Technique, malware,
// impersonated brand and vendor co-occurrence alone NEVER merge reports.
export function buildPhishingDataset(rows, { profiles = [], techniqueCatalog = [], filters = {}, limit = 20000, range = {} } = {}) {
    const catalog = new Map(techniqueCatalog.map(technique => [technique.id, technique]));
    const reports = [];
    const seenLinks = new Set();
    for (const row of rows) {
        if (!row?.link || seenLinks.has(row.link)) continue;
        seenLinks.add(row.link);
        const intel = row.phishingIntel?.version === PHISHING_VERSION ? row.phishingIntel : analyzePhishing(row);
        if (!intel.detected) continue;
        // Revalidate kit names using retained text/evidence without rerunning the
        // incident classifier on a shortened archival summary. The original body
        // may no longer be available, but its classification remains evidence.
        const kits = extractNamedPhishingKits([row.title, row.description, row.text, row.bodyText, ...intel.evidence.map(e => e.snippet)].filter(Boolean).join('\n'));
        const campaignMatches = (Array.isArray(row.campaigns) ? row.campaigns : []).filter(campaign => campaign?.id && campaign?.name &&
            [row.title, row.description, ...intel.evidence.filter(e => e.kind === 'classification' || e.kind === 'technique').map(e => e.snippet)].some(text => hasTerm(text, campaign.name)));
        const named = campaignMatches.length === 1 ? campaignMatches[0] : null;
        const groupId = named ? `campaign:${named.id}` : row.storyId ? `story:${row.storyId}` : `publication:${row.link}`;
        const report = {
            ...row, id: `PH-${createHash('sha256').update(row.link).digest('hex').slice(0, 10)}`,
            description: row.description || row.text || '', groupId,
            groupBasis: named ? 'named-campaign' : row.storyId ? 'correlated-story' : 'publication',
            campaignName: named?.name || '', primaryTechnique: intel.primaryTechnique,
            phishingTechniques: intel.techniques, vectors: intel.vectors, sectors: intel.sectors,
            regions: intel.regions, brands: intel.brands, actorNames: names(row.actors),
            software: unique([...names(row.malware), ...kits, ...intel.evidence.filter(e => e.label === 'RMM Abuse').map(e => e.term)]),
            nationState: intel.nationState,
            ttps: intel.ttps.map(ttp => ({ ...ttp, name: catalog.get(ttp.id)?.name || '', tactics: catalog.get(ttp.id)?.tactics || [] })),
            evidence: intel.evidence,
            sourceType: row.layer === 3 ? 'Pesquisa / fornecedor' : row.layer === 1 ? 'Advisory' : row.layer === 2 ? 'Notícia' : 'Não informado',
        };
        report.profileMatches = profileMatches(report, profiles);
        reports.push(report);
    }
    const facets = {
        techniques: unique(reports.flatMap(row => row.phishingTechniques)).sort(),
        sectors: unique(reports.flatMap(row => row.sectors)).sort(), regions: unique(reports.flatMap(row => row.regions)).sort(),
        brands: unique(reports.flatMap(row => row.brands)).sort(), profiles: profiles.map(({ id, name }) => ({ id, name })),
    };
    const query = normalize(filters.search).trim().split(/\s+/).filter(Boolean);
    const selected = reports.filter(row =>
        (!filters.technique || row.phishingTechniques.includes(filters.technique)) &&
        (!filters.sector || row.sectors.includes(filters.sector)) &&
        (!filters.region || row.regions.includes(filters.region) || (filters.region === 'LATAM' && row.regions.some(region => LATAM.has(region)))) &&
        (!filters.brand || row.brands.includes(filters.brand)) &&
        (!filters.profileId || row.profileMatches.some(match => match.profileId === filters.profileId)) &&
        (!filters.nationState || row.nationState === filters.nationState) &&
        query.every(term => normalize([row.title, row.description, row.source, row.campaignName, ...row.actorNames, ...row.software, ...row.phishingTechniques].join(' ')).includes(term)));
    const ordered = [...selected].sort((a, b) => String(b.pubDate).localeCompare(String(a.pubDate)) || a.link.localeCompare(b.link));
    const visible = ordered.slice(0, Math.max(1, Math.min(20000, Number(limit) || 20000)));
    const groups = new Map();
    for (const report of visible) {
        let group = groups.get(report.groupId);
        if (!group) {
            group = { id: report.groupId, name: report.campaignName || report.title, basis: report.groupBasis, reports: [] };
            groups.set(report.groupId, group);
        }
        group.reports.push(report);
    }
    const campaigns = [...groups.values()].map(group => ({
        ...group, firstPublished: group.reports.at(-1).pubDate, lastPublished: group.reports[0].pubDate,
        reportCount: group.reports.length, description: group.reports[0].description,
        techniques: unique(group.reports.flatMap(row => row.phishingTechniques)),
        vectors: unique(group.reports.flatMap(row => row.vectors)), brands: unique(group.reports.flatMap(row => row.brands)),
        sectors: unique(group.reports.flatMap(row => row.sectors)), regions: unique(group.reports.flatMap(row => row.regions)),
        actors: unique(group.reports.flatMap(row => row.actorNames)), software: unique(group.reports.flatMap(row => row.software)),
        ttpIds: unique(group.reports.flatMap(row => row.ttps.map(ttp => ttp.id))),
        sources: unique(group.reports.map(row => row.source)), links: unique(group.reports.map(row => row.link)),
        reportIds: group.reports.map(row => row.id), reports: undefined,
    }));
    const ttps = new Map();
    for (const report of visible) for (const ttp of report.ttps) {
        const row = ttps.get(ttp.id) || { id: ttp.id, name: ttp.name, tactics: ttp.tactics, reports: new Set(), groups: new Set(), reported: 0, inferred: 0 };
        if (!row.reports.has(report.id)) { row.reports.add(report.id); row.groups.add(report.groupId); row[ttp.basis]++; }
        ttps.set(ttp.id, row);
    }
    return {
        reports: visible, campaigns, facets, range, filters, total: selected.length, truncated: visible.length < selected.length,
        summary: {
            publications: visible.length, groups: campaigns.length, correlatedGroups: campaigns.filter(group => group.reportCount > 1).length,
            withTechnique: visible.filter(row => row.phishingTechniques.length).length,
            nationState: visible.filter(row => row.nationState === 'reported').length,
            brazil: visible.filter(row => row.regions.includes('Brazil')).length,
            distinctTtps: ttps.size,
            months: countBy(visible, row => /^\d{4}-\d{2}/.test(row.pubDate) ? [row.pubDate.slice(0, 7)] : []).sort((a, b) => a.label.localeCompare(b.label)),
            techniques: countBy(visible, row => row.phishingTechniques), sectors: countBy(visible, row => row.sectors),
            regions: countBy(visible, row => row.regions), sources: countBy(visible, row => [row.source]),
        },
        ttps: [...ttps.values()].map(row => ({ ...row, reports: row.reports.size, groups: row.groups.size })).sort((a, b) => b.reports - a.reports || a.id.localeCompare(b.id)),
    };
}

export function phishingQuery(query = {}) {
    const range = {};
    for (const key of ['from', 'to']) {
        if (!query[key]) continue;
        const date = String(query[key]);
        const parsed = new Date(date);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== date) throw Object.assign(new Error('Data inválida: use AAAA-MM-DD'), { status: 400, publicMessage: 'Data inválida: use AAAA-MM-DD' });
        range[key] = date;
    }
    if (range.from && range.to && range.from > range.to) throw Object.assign(new Error('Período invertido'), { status: 400, publicMessage: 'A data inicial deve preceder a final' });
    const filters = {};
    for (const key of ['search', 'technique', 'sector', 'region', 'brand', 'profileId', 'nationState']) if (query[key]) filters[key] = String(query[key]).trim().slice(0, 200);
    return { range, filters, limit: Math.max(1, Math.min(20000, parseInt(query.limit, 10) || 20000)) };
}
