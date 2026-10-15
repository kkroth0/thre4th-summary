import { createHash } from 'node:crypto';
import { normalizeIndicator } from './iocIntelligence.js';
import { declaredRepositoryMalware } from './repositorySources.js';

// Read-only comparison of archived extracted evidence with its materialized
// inventory. Does not claim that extraction or actor attribution is accurate.
export function auditNewsInventory(db, archive) {
    const observations = new Map(), links = new Map();
    for (const row of db.prepare("SELECT o.id,o.external_id,i.value FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.scope='global' AND o.provider='news'").all()) {
        if (!observations.has(row.external_id)) observations.set(row.external_id, new Map());
        observations.get(row.external_id).set(row.value, row.id);
    }
    for (const row of db.prepare("SELECT e.observation,e.kind,e.entity FROM entity_links e JOIN observations o ON o.id=e.observation WHERE o.scope='global' AND o.provider='news'").all()) {
        if (!links.has(row.observation)) links.set(row.observation, new Set());
        links.get(row.observation).add(row.kind + ':' + row.entity);
    }
    const names = new Set(db.prepare("SELECT DISTINCT kind,entity FROM intelligence_entity_names WHERE scope='global'").all().map(row => row.kind + ':' + row.entity));
    const states = new Set(db.prepare("SELECT id FROM intelligence_state WHERE id LIKE 'news:%'").all().map(row => row.id));
    const report = { publications: archive.length, publicationsWithIocs: 0, processedPublications: 0, validIocMentions: 0, rejectedIocMentions: 0,
        expectedEntityLinks: 0, missingObservations: 0, staleObservations: 0, missingEntityLinks: 0, staleEntityLinks: 0, unregisteredEntities: 0,
        missingPublicationStates: 0, coverageIsNotExtractionAccuracy: true };
    const unique = new Set();
    for (const row of archive) {
        const state = 'news:' + createHash('sha256').update(row.link).digest('hex');
        if (states.has(state)) report.processedPublications++; else report.missingPublicationStates++;
        const entities = new Set();
        const malware = row.repository ? [...new Map([...declaredRepositoryMalware({ ...row, repositoryReport: true }), ...(row.malware || [])].map(family => [family.name.toLowerCase(), family])).values()] : row.malware || [];
        for (const [kind, rows] of [['actor', row.actors || []], ['malware', malware], ['cve', (row.cves || []).map(id => ({ id, name: id }))]]) {
            for (const entity of rows) if (entity?.id && entity?.name) {
                entities.add(kind + ':' + String(entity.id).slice(0, 180));
                if (!names.has(kind + ':' + entity.id)) report.unregisteredEntities++;
            }
        }
        const values = new Set();
        for (const value of ['ips', 'domains', 'hashes', 'urls'].flatMap(kind => row.iocs?.[kind] || [])) {
            const ioc = normalizeIndicator(value);
            if (ioc) { values.add(ioc.value); unique.add(ioc.value); } else report.rejectedIocMentions++;
        }
        if (values.size) report.publicationsWithIocs++;
        report.validIocMentions += values.size;
        const actual = observations.get(row.link) || new Map();
        for (const value of actual.keys()) if (!values.has(value)) report.staleObservations++;
        for (const value of values) {
            report.expectedEntityLinks += entities.size;
            const observation = actual.get(value);
            if (!observation) { report.missingObservations++; report.missingEntityLinks += entities.size; continue; }
            const actualLinks = links.get(observation) || new Set();
            for (const entity of entities) if (!actualLinks.has(entity)) report.missingEntityLinks++;
            for (const entity of actualLinks) if (!entities.has(entity)) report.staleEntityLinks++;
        }
    }
    report.uniqueIndicators = unique.size;
    report.passed = ['missingObservations', 'staleObservations', 'missingEntityLinks', 'staleEntityLinks', 'unregisteredEntities', 'missingPublicationStates'].every(key => report[key] === 0);
    return report;
}
