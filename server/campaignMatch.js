// Mirrors malwareMatch.js: single-word aliases are distinctive by default
// (campaign codenames — "Operation Dream Job," "SolarWinds" — are coined
// specifically to be memorable and distinct, not drawn from ordinary CTI
// prose), with a small ambiguous-word stoplist for the exceptions found
// against the real catalog, demoted to needing a same-sentence context word.

// A common-word alias only counts when one of these sits in the same sentence.
export const CAMPAIGN_CONTEXT_TERMS =
    /\b(?:campaign|operation|attack|intrusion|breach|incident|hack|compromise|infiltration|espionage)\b/i;

// Below this an "alias" is noise: two letters match half the language.
const MIN_ALIAS_LENGTH = 3;

// Single-word campaign aliases that collide with ordinary prose or an
// unrelated proper noun — demoted to the `common` tier below.
const AMBIGUOUS_TIER_STOPLIST = new Set([
    'frankenstein', // C0001 — literary/pop-culture name, real prose-collision risk
]);

const PLACEHOLDER = '';

// 10/166 ATT&CK campaigns (as of 2026-10) have no real codename — MITRE's own
// `name` field is just the campaign's own id ("C0010"), because the
// researchers who wrote it up never gave the operation a memorable name.
// Nobody writes "c0010" in a headline, so indexing it as a matchable alias
// is pure noise — same reasoning actorMatch.js uses to drop "[Unnamed group]".
const ID_SHAPED_RE = /^c\d{4}$/i;

const normalize = (value) =>
    String(value || '')
        .toLowerCase()
        .normalize('NFD')
        .replace(/\p{Mn}/gu, '')
        .trim();

const tokenize = (value) =>
    normalize(value)
        .split(/[^a-z0-9.@+-]+/)
        .filter(Boolean)
        .map(t => t.replace(/[.!?]+$/, ''))
        .filter(Boolean);

export function buildCampaignIndex(campaigns) {
    const distinctive = new Map();
    const common = new Map();
    for (const campaign of Array.isArray(campaigns) ? campaigns : []) {
        if (!campaign || !campaign.id) continue;
        for (const raw of [campaign.name, ...(campaign.aliases || [])]) {
            const alias = String(raw || '').trim();
            const key = normalize(alias);
            if (!key || key === PLACEHOLDER) continue;
            if (alias.replace(/[^a-z0-9]/gi, '').length < MIN_ALIAS_LENGTH) continue;
            // Unconditional, not just when it equals this campaign's own id:
            // nobody ever writes a bare "C0010" in a headline, for ANY
            // campaign, so the shape alone is enough to disqualify it.
            if (ID_SHAPED_RE.test(alias)) continue;
            const entry = { id: campaign.id, name: campaign.name, matched: alias };
            if (/\s/.test(alias)) {
                if (!distinctive.has(key)) distinctive.set(key, { ...entry, via: 'multiword' });
            } else if (AMBIGUOUS_TIER_STOPLIST.has(key)) {
                if (!common.has(key)) common.set(key, { ...entry, via: 'context' });
            } else if (!distinctive.has(key)) {
                distinctive.set(key, { ...entry, via: 'distinctive' });
            }
        }
    }
    const allKeys = [...distinctive.keys(), ...common.keys()];
    let maxGram = 4;
    for (const key of allKeys) {
        const wordCount = key.split(' ').length;
        if (wordCount > maxGram) maxGram = wordCount;
    }
    return { distinctive, common, maxGram };
}

export function matchCampaigns(text, index) {
    const found = new Map();
    const maxGram = (index && index.maxGram) || 4;
    for (const sentence of String(text || '').split(/(?<=[.!?])\s+|[\n\r]+/)) {
        const hasContext = CAMPAIGN_CONTEXT_TERMS.test(sentence);
        const tokens = tokenize(sentence);
        for (let i = 0; i < tokens.length; i++) {
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
