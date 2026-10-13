import { canonicalArticleUrl } from './feedCollector.js';

// Server-owned content only: browser requests cannot supply replacement text.
// The URL remains the evidence reference and is still validated by the worker.
export function prepareFeedJobDocuments(urls, { items = [], articleCache, rssCache } = {}) {
  return urls.flatMap(url => {
    const key = canonicalArticleUrl(url);
    const candidates=items.filter(row => canonicalArticleUrl(row.link) === key);
    const item = candidates.find(row=>row.text?.length>=1500)||candidates[0];
    if (!item) return [];
    const body = articleCache?.get(item.link);
    const original = rssCache?.get(item.feedUrl)?.items?.find(row => canonicalArticleUrl(row.link) === key);
    const text = body?.text || original?.text || item.text || '';
    if (text.length < 1500) return [];
    // Scan and merge IOCs before text limits. The worker's deterministic
    // extractor receives every collected indicator, including late tables.
    const iocText = ['ips','domains','hashes','urls'].flatMap(type => item.iocs?.[type] || []).join('\n');
    return [{ url, title: item.title, text: text.slice(0,64000), iocText,
      collectedAt: body?.collectedAt || original?.collectedAt || item.collectedAt }];
  });
}
