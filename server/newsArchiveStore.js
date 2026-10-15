// Arquivo permanente do feed: link, título, fonte, data e categorias de todo
// item que já passou pelo boletim — nunca podado, ao contrário de
// newsStoryStore (60 dias) e do feed em memória (10 minutos de TTL). O pedido
// original foi "quero conseguir armazenar estas notícias, todas, os links e
// as categorias" — isto é a base de dados pra isso, consultável e exportável,
// sem tela nova. Mesmo padrão de fs-por-injeção do createStoryStore.
import { analyzePhishing, PHISHING_VERSION } from './phishingIntel.js';

export function createNewsArchiveStore({ filePath, readFileSync, writeJsonAtomic }) {
    let rows = [];
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        rows = Array.isArray(parsed) ? parsed.filter((r) => r && r.link) : [];
    } catch { /* arquivo ausente ou corrompido: arquivo vazio, não derruba o servidor */ }

    return {
        all: () => rows,
        size: () => rows.length,
        /** Recover retained body evidence for the same publication revision. */
        restorePhishingEvidence(candidates) {
            const byLink = new Map();
            for (const source of candidates || []) {
                if (source?.phishingIntel?.version !== PHISHING_VERSION || !source.phishingIntel.detected || !source.phishingIntel.evidence?.some(e => e.field === 'body')) continue;
                const previous = byLink.get(source.link);
                if (!previous || source.phishingIntel.evidence.length > previous.phishingIntel.evidence.length) byLink.set(source.link, source);
            }
            let changed = 0;
            const next = rows.map(row => {
                const source = byLink.get(row.link);
                const sameRevision = source && (row.contentHash && source.contentHash ? row.contentHash === source.contentHash : row.title === source.title && row.pubDate === source.pubDate && (row.description || row.text || '') === (source.description || source.text || ''));
                if (!sameRevision || row.phishingIntel?.evidence?.some(e => e.field === 'body')) return row;
                const categories = [...new Set([...(row.categories || []), 'Phishing'])];
                changed++;
                return { ...row, phishingIntel: source.phishingIntel, phishingTechniques: source.phishingIntel.techniques, categories };
            });
            if (changed) { writeJsonAtomic(filePath, next); rows = next; }
            return changed;
        },
        /** Upsert extracted metadata without duplicating the publication. */
        add(items) {
            const next = [...rows];
            const indices = new Map(next.map((row, index) => [row.link, index]));
            let additions = 0, changed = false;
            for (const item of Array.isArray(items) ? items : []) {
                if (!item?.link) continue;
                const index = indices.get(item.link);
                const old = index === undefined ? null : next[index];
                const row = {
                    link: item.link, title: item.title || "", source: item.source || "", pubDate: item.pubDate || "",
                    categories: Array.isArray(item.categories) ? item.categories : [], primaryCategory: item.primaryCategory || null,
                    phishingTechniques: Array.isArray(item.phishingTechniques) ? item.phishingTechniques : [],
                    archivedAt: old?.archivedAt || new Date().toISOString(),
                };
                for (const field of ["description", "text", "layer", "securityRelevant", "dateInferred", "publicationTimeKnown", "publicationDateBasis", "firstCollectedAt", "phishingIntel", "storyId", "contentHash", "extractionVersion", "cves", "actors", "malware", "campaigns", "ttpIds", "iocs", "vendors", "assets", "repository", "score", "severity", "kev", "epss", "sectors"]) {
                    if (item[field] !== undefined) row[field] = item[field];
                    else if (old?.[field] !== undefined) row[field] = old[field];
                }
                for (const field of ['articleTextAvailable', 'articleCollectionStatus']) {
                    if (item[field] !== undefined) row[field] = item[field];
                    else if (old?.[field] !== undefined) row[field] = old[field];
                }
                if (old && JSON.stringify(row) === JSON.stringify(old)) continue;
                changed = true;
                if (index === undefined) { indices.set(item.link, next.length); next.push(row); additions++; }
                else next[index] = row;
            }
            if (!changed) return 0;
            writeJsonAtomic(filePath, next);
            rows = next;
            return additions;
        },
        reclassifyPhishing({ bodyFor = () => '' } = {}) {
            let changed = 0;
            const next = rows.map(row => {
                if (row.phishingIntel?.version === PHISHING_VERSION) return row;
                const phishingIntel = analyzePhishing({ ...row, bodyText: bodyFor(row.link) });
                const categories = (row.categories || []).filter(category => category !== 'Phishing');
                if (phishingIntel.detected) categories.push('Phishing');
                changed++;
                return { ...row, phishingIntel, phishingTechniques: phishingIntel.techniques, categories,
                    primaryCategory: categories.includes(row.primaryCategory) ? row.primaryCategory : categories[0] || null };
            });
            if (changed) { writeJsonAtomic(filePath, next); rows = next; }
            return changed;
        },
        list({ category, source, from, to, limit } = {}) {
            let result = rows;
            if (category) result = result.filter((r) => (r.categories || []).includes(category));
            if (source) result = result.filter((r) => r.source === source);
            if (from) {
                const cutoff = new Date(from).getTime();
                if (!Number.isNaN(cutoff)) result = result.filter((r) => new Date(r.pubDate).getTime() >= cutoff);
            }
            if (to) {
                const cutoff = new Date(to).getTime();
                if (!Number.isNaN(cutoff)) result = result.filter((r) => new Date(r.pubDate).getTime() <= cutoff);
            }
            // Mais recente primeiro — mesma ordem padrão do feed.
            result = [...result].sort((a, b) => String(b.pubDate).localeCompare(String(a.pubDate)));
            return limit ? result.slice(0, Number(limit)) : result;
        },
    };
}
