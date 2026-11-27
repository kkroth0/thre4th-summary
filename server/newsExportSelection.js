import { completeNewsFeed } from './newsQuality.js';
import { filterMonitoredNews } from './newsMonitoring.js';

const timestamp = value => typeof value === 'string' && value.trim() ? Date.parse(value) : NaN;

// Export the same available publications as the feed. A restored RSS snapshot
// can be visible before its next successful archive commit.
export function selectNewsExportPublications({ current = [], archive = [], stories = [], sourceCache = [], preferences, from, to }) {
    const byLink = new Map();
    const remember = row => {
        if (row?.link) byLink.set(row.link, byLink.has(row.link) ? { ...byLink.get(row.link), ...row } : row);
    };
    // Retained source documents can recover a gap in the live snapshot. Never
    // copy a story's aggregate dates, IOCs or entities onto its publications.
    for (const story of stories) for (const source of story.sources || []) remember({ ...source, storyId: story.id });
    current.forEach(remember);
    // Persisted evidence revisions remain authoritative for duplicate URLs.
    archive.forEach(remember);
    const pending = new Set();
    for (const row of sourceCache) if (!byLink.has(row.link)) {
        byLink.set(row.link, row);
        pending.add(row.link);
    }

    const start = Date.parse(from), end = Date.parse(to);
    const raw = [...byLink.values()].flatMap(row => {
        let time = timestamp(row.pubDate);
        if (!Number.isFinite(time)) {
            const collectedAt = [row.firstCollectedAt, row.archivedAt].find(value => Number.isFinite(timestamp(value)));
            if (!collectedAt) return [];
            time = timestamp(collectedAt);
            row = { ...row, pubDate: new Date(time).toISOString(), dateInferred: true, publicationTimeKnown: false, publicationDateBasis: 'collected' };
        }
        return time >= start && time <= end ? [row] : [];
    }).sort((a, b) => timestamp(b.pubDate) - timestamp(a.pubDate) || a.link.localeCompare(b.link));
    // Source-only records were screened before their full text was discarded.
    const analyzed = completeNewsFeed([], raw.filter(row => !pending.has(row.link)));
    const projections = new Map(analyzed.map(row => [row.link, row]));
    const selected = raw.map(row => pending.has(row.link) ? row : projections.get(row.link)).filter(Boolean);
    const publications = filterMonitoredNews(selected, preferences, stories);
    const authorized = new Set(publications.map(row => row.link));
    return { publications, evidence: raw.filter(row => authorized.has(row.link)) };
}
