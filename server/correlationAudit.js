import { canonicalArticleUrl } from './feedCollector.js';

const keyOf = (item) => canonicalArticleUrl(item.link) || item.link;

/** Pair metrics require analyst-reviewed expectedEvent labels. Unlabelled
 * publications count for integrity, but never fabricate precision/recall. */
export function auditCorrelations(items, stories) {
    const assignments = new Map();
    const duplicateLinks = [];
    for (const story of stories) for (const source of story.sources || []) {
        const key = keyOf(source);
        if (assignments.has(key)) duplicateLinks.push(key);
        assignments.set(key, story.id);
    }
    const unassigned = items.filter((item) => !assignments.has(keyOf(item))).map((item) => item.link);
    const labelled = items.filter((item) => item.expectedEvent);
    const falseMerges = [], missedPairs = [];
    let truePositive = 0, trueNegative = 0;
    for (let i = 0; i < labelled.length; i++) for (let j = i + 1; j < labelled.length; j++) {
        const a = labelled[i], b = labelled[j];
        const expected = a.expectedEvent === b.expectedEvent;
        const actual = assignments.has(keyOf(a)) && assignments.get(keyOf(a)) === assignments.get(keyOf(b));
        const pair = { links: [a.link, b.link], titles: [a.title, b.title] };
        if (actual && expected) truePositive++;
        else if (actual) falseMerges.push(pair);
        else if (expected) missedPairs.push(pair);
        else trueNegative++;
    }
    return {
        publications: items.length, events: stories.length,
        multiSourceEvents: stories.filter((story) => story.sources.length > 1).length,
        labelledPublications: labelled.length, labelledPairs: labelled.length * (labelled.length - 1) / 2,
        truePositive, trueNegative, falsePositive: falseMerges.length, falseNegative: missedPairs.length,
        precision: truePositive + falseMerges.length ? truePositive / (truePositive + falseMerges.length) : null,
        recall: truePositive + missedPairs.length ? truePositive / (truePositive + missedPairs.length) : null,
        duplicateLinks, unassigned, falseMerges, missedPairs,
    };
}
