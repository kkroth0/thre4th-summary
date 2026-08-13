// Actor names are attacker-chosen and often ordinary words — Akira, Reaper,
// Mantis, Elfin. Matching every alias against every headline would attribute a
// Kurosawa retrospective to a ransomware gang, so the index is split in two:
// names that cannot mean anything else, and names that need CTI context nearby.

// Codenames no one uses outside threat intel.
const CODENAME = /^(?:apt-?\d+|apt-[cq]-\d+|unc\d+|tag-\d+|ta\d+|storm-\d+|atk\d+)$/i;

// A common-word alias only counts when one of these sits in the same sentence.
export const ACTOR_CONTEXT_TERMS =
    /\b(?:group|gang|crew|operators?|ransomware|apt|campaign|threat actors?|grupo|quadrilha|campanha)\b/i;

// Below this an "alias" is noise: two letters match half the language.
const MIN_ALIAS_LENGTH = 3;

const PLACEHOLDER = '[unnamed group]';

const normalize = (value) =>
    String(value || '')
        .toLowerCase()
        .normalize('NFD')
        .replace(/[̀-ͯ]/g, '')
        .trim();

// Hyphens and digits belong to the name (storm-0558, apt-c-36), so they survive.
// Strip trailing sentence punctuation (., !, ?) but preserve internal punctuation.
const tokenize = (value) =>
    normalize(value)
        .split(/[^a-z0-9.@+-]+/)
        .filter(Boolean)
        .map(t => t.replace(/[.!?]+$/, ''))
        .filter(Boolean);

export function buildActorIndex(actors) {
    const distinctive = new Map();
    const common = new Map();
    for (const actor of Array.isArray(actors) ? actors : []) {
        if (!actor || !actor.id) continue;
        for (const raw of [actor.name, ...(actor.aliases || [])]) {
            const alias = String(raw || '').trim();
            const key = normalize(alias);
            if (!key || key === PLACEHOLDER) continue;
            if (alias.replace(/[^a-z0-9]/gi, '').length < MIN_ALIAS_LENGTH) continue;
            const entry = { id: actor.id, name: actor.name, matched: alias };
            if (CODENAME.test(alias)) {
                if (!distinctive.has(key)) distinctive.set(key, { ...entry, via: 'codename' });
            } else if (/\s/.test(alias)) {
                if (!distinctive.has(key)) distinctive.set(key, { ...entry, via: 'multiword' });
            } else if (!common.has(key)) {
                common.set(key, { ...entry, via: 'context' });
            }
        }
    }
    // Calculate max gram from the longest key in the index.
    const allKeys = [...distinctive.keys(), ...common.keys()];
    let maxGram = 4;
    for (const key of allKeys) {
        const wordCount = key.split(' ').length;
        if (wordCount > maxGram) {
            maxGram = wordCount;
        }
    }
    return { distinctive, common, maxGram };
}

export function matchActors(text, index) {
    const found = new Map();
    // Sentence-scoped: "A ransomware gang emerged. Akira Kurosawa died." must not
    // let the first sentence's context vouch for the second sentence's noun.
    const maxGram = (index && index.maxGram) || 4;
    for (const sentence of String(text || '').split(/(?<=[.!?])\s+|[\n\r]+/)) {
        const hasContext = ACTOR_CONTEXT_TERMS.test(sentence);
        const tokens = tokenize(sentence);
        for (let i = 0; i < tokens.length; i++) {
            // Longest gram first, so "Fancy Bear" wins over a hypothetical "Bear".
            for (let n = Math.min(maxGram, tokens.length - i); n >= 1; n--) {
                const gram = tokens.slice(i, i + n).join(' ');
                const strong = index.distinctive.get(gram);
                if (strong) {
                    if (!found.has(strong.id)) found.set(strong.id, strong);
                    i += n - 1;
                    break;
                }
                const loose = hasContext ? index.common.get(gram) : undefined;
                if (loose) {
                    if (!found.has(loose.id)) found.set(loose.id, loose);
                    i += n - 1;
                    break;
                }
            }
        }
    }
    return [...found.values()];
}
