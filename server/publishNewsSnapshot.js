import { STORY_RETENTION_DAYS } from './newsStories.js';
import { correlateNewsFeedAsync } from './newsCorrelation.js';

export async function publishNewsSnapshot(items, { archive, stories, now = new Date() }) {
  if (archive.publishSnapshot) return archive.publishSnapshot(draft => publishNewsSnapshot(items, { ...draft, now }), stories);
  const cutoff = now.getTime() - STORY_RETENTION_DAYS * 86400000;
  const current = items.filter(item => Date.parse(item.pubDate) >= cutoff);
  const historical = items.filter(item => Date.parse(item.pubDate) < cutoff);
  const correlation = await correlateNewsFeedAsync(current, stories, now);
  // Historical repositories keep real dates and remain usable in actor
  // evidence/export without violating the current event correlation window.
  archive.add([...historical,...correlation.items].map(item => ({ ...item, categories:item.newsCategories || item.categories })));
  return correlation;
}
