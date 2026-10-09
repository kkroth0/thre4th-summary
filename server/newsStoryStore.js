// File-backed story store, same shape as createWatchlistStore: fs comes in by
// injection so the tests never touch the real state file. A corrupt or missing
// file is an empty store, never a crash — the feed has to keep serving news even
// when the grouping state is gone.
export function createStoryStore({ filePath, readFileSync, writeJsonAtomic }) {
    let stories = [];
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        stories = Array.isArray(parsed) ? parsed.filter((story) => story && story.id && Array.isArray(story.sources)) : [];
    } catch { /* empty store */ }

    return {
        all: () => stories,
        save(next) {
            const value = Array.isArray(next) ? next : [];
            // Write first: if writeJsonAtomic throws (disk full, EACCES), memory
            // must not advance past what's actually on disk, or a restart rewinds
            // and re-merges the gap into duplicate stories.
            writeJsonAtomic(filePath, value);
            stories = value;
            return stories;
        },
        get: (id) => stories.find((story) => story.id === id || (story.aliases || []).includes(id)) || null,
        list({ category, actor, days, limit, now = new Date() } = {}) {
            let result = stories;
            if (category) result = result.filter((story) => (story.categories || []).includes(category));
            if (actor) result = result.filter((story) => (story.actors || []).some((a) => a.id === actor));
            if (days) {
                const cutoff = now.getTime() - Number(days) * 86400000;
                result = result.filter((story) => new Date(story.lastSeen).getTime() >= cutoff);
            }
            return limit ? result.slice(0, Number(limit)) : result;
        },
    };
}
