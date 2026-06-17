// Lookalike / typosquat detection for phishing analysis.
// Flags domains that closely imitate a well-known brand domain via character
// substitution (paypa1.com), omission (microsft.com) or homoglyphs (rn -> m).

// Common phishing targets and their legitimate registrable domains.
const BRAND_DOMAINS = [
    "paypal.com", "microsoft.com", "apple.com", "google.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "linkedin.com", "dropbox.com",
    "docusign.com", "adobe.com", "office365.com", "outlook.com", "live.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com", "citibank.com",
    "americanexpress.com", "coinbase.com", "binance.com", "whatsapp.com",
    "steamcommunity.com", "mercadolivre.com.br", "nubank.com.br", "itau.com.br",
    "bradesco.com.br", "caixa.gov.br", "gov.br",
];

// Normalise common homoglyph / leetspeak substitutions so visual lookalikes
// collapse onto their real character before distance comparison.
const normalizeHomoglyphs = (s: string): string =>
    s.toLowerCase()
        .replace(/rn/g, "m")
        .replace(/vv/g, "w")
        .replace(/0/g, "o")
        .replace(/1/g, "l")
        .replace(/3/g, "e")
        .replace(/4/g, "a")
        .replace(/5/g, "s")
        .replace(/7/g, "t")
        .replace(/\$/g, "s");

// Levenshtein edit distance (iterative, single-row).
export const levenshtein = (a: string, b: string): number => {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 0; i < a.length; i++) {
        const curr = [i + 1];
        for (let j = 0; j < b.length; j++) {
            const cost = a[i] === b[j] ? 0 : 1;
            curr[j + 1] = Math.min(prev[j + 1] + 1, curr[j] + 1, prev[j] + cost);
        }
        prev = curr;
    }
    return prev[b.length];
};

// Strip a hostname to its registrable-ish label for comparison (drop sub-domains,
// keep the last two labels — good enough for lookalike scoring).
const registrable = (host: string): string => {
    const parts = host.toLowerCase().replace(/^www\./, "").split(".");
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
};

export interface TyposquatMatch {
    brand: string;       // the brand domain it imitates
    distance: number;    // homoglyph-normalised edit distance (0 = exact homoglyph match)
}

// Returns the closest brand a host imitates, or null. A host that IS the brand
// (exact match or legitimate sub-domain) is never flagged.
export const detectTyposquat = (host: string): TyposquatMatch | null => {
    if (!host) return null;
    const reg = registrable(host);

    // Legitimate: exact registrable match to a known brand.
    if (BRAND_DOMAINS.includes(reg)) return null;

    const normHost = normalizeHomoglyphs(reg);
    let best: TyposquatMatch | null = null;

    for (const brand of BRAND_DOMAINS) {
        if (normalizeHomoglyphs(brand) === normHost && brand !== reg) {
            // Same after homoglyph normalisation but not actually the brand -> strong lookalike.
            return { brand, distance: 0 };
        }
        // Compare the leading label (before the TLD) to catch paypal-support.com etc.
        const brandLabel = normalizeHomoglyphs(brand.split(".")[0]);
        const hostLabel = normalizeHomoglyphs(reg.split(".")[0]);
        const d = levenshtein(hostLabel, brandLabel);
        // Close but not equal, and long enough to avoid noise on short labels.
        if (brandLabel.length >= 5 && d > 0 && d <= 2 && (!best || d < best.distance)) {
            best = { brand, distance: d };
        }
    }
    return best;
};
