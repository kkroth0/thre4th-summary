import { canonicalArticleUrl } from './feedCollector.js';
import { CORRELATION_VERSION, mergeIntoStories, mergeIntoStoriesAsync } from './newsStories.js';

// Persist a complete correlation result before exposing it to the newsletter.
// A failed grouping/write must leave the last successfully published feed in
// place, rather than silently serving every publication as an unrelated card.
export function correlateNewsFeed(items, store, now = new Date()) {
    const started = performance.now();
    const stories = mergeIntoStories(store.all(), items, now);
    return publishCorrelation(items, store, stories, started);
}

export async function correlateNewsFeedAsync(items, store, now = new Date()) {
    const started = performance.now();
    const stories = await mergeIntoStoriesAsync(store.all(), items, now);
    return publishCorrelation(items, store, stories, started);
}

function publishCorrelation(items, store, stories, started) {
    const byLink = new Map(stories.flatMap((story) => story.sources.map((source) => [canonicalArticleUrl(source.link) || source.link, story.id])));
    const sourceCount = stories.reduce((count, story) => count + story.sources.length, 0);
    if (byLink.size !== sourceCount) throw new Error('Correlation assigned the same publication to multiple events');
    const references = stories.flatMap((story) => [story.id, ...(story.aliases || [])]);
    if (new Set(references).size !== references.length) throw new Error('Correlation returned conflicting event IDs or aliases');
    const correlated = items.map((item) => ({ ...item, storyId: byLink.get(canonicalArticleUrl(item.link) || item.link) }));
    if (correlated.some((item) => !item.storyId)) throw new Error('Correlation returned publications without an event');
    store.save(stories);
    const visibleIds = new Set(correlated.map((item) => item.storyId));
    return { items: correlated, stories, stats: {
        version: CORRELATION_VERSION, elapsedMs: Math.round(performance.now() - started),
        events: visibleIds.size, retainedEvents: stories.length,
        multiSourceEvents: stories.filter((story) => visibleIds.has(story.id) && story.sources.length > 1).length,
        publications: correlated.length, unassigned: 0,
    } };
}
