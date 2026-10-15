import { createHash } from 'node:crypto';
import { completeNewsFeed } from './newsQuality.js';
import { filterMonitoredNews } from './newsMonitoring.js';

// Immutable store arrays identify each published revision. Cache only the HTTP
// projection; SQLite and retained evidence remain the source of truth. Private
// selections are partitioned by owner and normalized preferences/query values.
export function createNewsFeedResponse({ maxBytes = 32 * 1024 * 1024, maxEntries = 8 } = {}) {
  let previous, completed, bytes = 0;
  const responses = new Map();
  return ({ current, archive, stories, owner, preferences, query = {} }) => {
    if (!previous || previous.current !== current || previous.archive !== archive || previous.stories !== stories) {
      completed = completeNewsFeed(current, archive);
      previous = { current, archive, stories }; responses.clear(); bytes = 0;
    }
    const filters = {
      minScore: parseInt(query.minScore, 10), severity: String(query.severity || ''),
      category: String(query.category || '').toLowerCase(), layer: parseInt(query.layer, 10), sort: String(query.sort || 'date'),
    };
    const key = JSON.stringify([owner, preferences, filters]);
    if (responses.has(key)) {
      const hit = responses.get(key); responses.delete(key); responses.set(key, hit); return hit;
    }
    let data = filterMonitoredNews(completed, preferences, stories);
    if (!Number.isNaN(filters.minScore)) data = data.filter(row => (row.score || 0) >= filters.minScore);
    if (filters.severity) data = data.filter(row => row.severity === filters.severity);
    if (filters.layer) data = data.filter(row => row.layer === filters.layer);
    if (filters.category) data = data.filter(row => (row.categories || []).some(category => category.toLowerCase().includes(filters.category)));
    if (filters.sort === 'relevance') data = [...data].sort((a, b) => (b.score || 0) - (a.score || 0) || new Date(b.pubDate) - new Date(a.pubDate));
    const body = JSON.stringify(data), size = Buffer.byteLength(body);
    const value = { body, etag: '"' + createHash('sha256').update(body).digest('hex') + '"', size };
    if (size <= maxBytes) {
      while (responses.size && (bytes + size > maxBytes || responses.size >= maxEntries)) {
        const oldest = responses.keys().next().value; bytes -= responses.get(oldest).size; responses.delete(oldest);
      }
      responses.set(key, value); bytes += size;
    }
    return value;
  };
}
