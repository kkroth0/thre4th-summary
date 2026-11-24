// Organization brand normalization, shared by news context and offline analysis.
const BRAND_LIMITS = { brandsPerProfile: 8, termMin: 4, termMax: 40 };

export function normalizeBrandTerm(raw) {
    const text = String(raw || '').trim().toLowerCase()
        .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
        .replace(/^www\./, '')
        .split(/[/?#]/)[0];
    // Domínio vira o rótulo: bancoxpto.com.br → bancoxpto. Nome composto com
    // ponto mas sem TLD conhecido é raro o bastante para tratar igual.
    const label = text.includes('.') ? text.split('.')[0] : text;
    if (!/^[a-z0-9][a-z0-9-]*$/.test(label)) return null;
    if (label.length < BRAND_LIMITS.termMin || label.length > BRAND_LIMITS.termMax) return null;
    return label;
}

export function normalizeBrands(input) {
    const list = Array.isArray(input) ? input : [];
    const terms = [];
    for (const raw of list) {
        const term = normalizeBrandTerm(raw);
        if (!term || terms.includes(term)) continue;
        terms.push(term);
    }
    if (terms.length > BRAND_LIMITS.brandsPerProfile) {
        const message = `no máximo ${BRAND_LIMITS.brandsPerProfile} marcas por perfil`;
        throw Object.assign(new Error(message), { status: 400, publicMessage: message });
    }
    return terms;
}
