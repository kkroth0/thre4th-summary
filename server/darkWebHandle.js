// Dark Web Informer (e feeds parecidos de monitoramento de dark web) nomeiam
// o vendedor/leaker numa frase fixa: 'An actor using the handle "X" claims...'.
// Isto NÃO é uma entidade do actors.json — handles de marketplace individuais
// são numerosos e efêmeros demais pra manter um dicionário estático (ao
// contrário de atores/grupos, que são um conjunto relativamente estável), então
// é extraído direto da frase em vez de casado contra um catálogo.
//
// Por desenho, isto NUNCA entra em newsStories.js como sinal de merge: duas
// notícias do mesmo vendedor com vítimas diferentes são duas notícias
// diferentes, exatamente como já vale para ator (ver newsStories.test.js, caso
// Cl0p/Fortra). O que isto habilita é mais fraco e mais seguro — mostrar que
// existe uma notícia relacionada, sem fundir os cards.
const HANDLE_RE = /\b(?:using|going|operating)\s+(?:the\s+|by\s+the\s+)?(?:handle|alias|username|moniker)\s+["']([^"']{2,40})["']/i;
const KNOWN_AS_RE = /\bknown\s+as\s+["']([^"']{2,40})["']/i;

export function extractSellerHandle(text) {
    const value = String(text || '');
    const match = HANDLE_RE.exec(value) || KNOWN_AS_RE.exec(value);
    return match ? match[1].trim() : null;
}

const normalize = (value) => String(value || '').trim().toLowerCase();

/**
 * Outras histórias (excluindo `excludeStoryId`) que têm pelo menos uma fonte
 * com o mesmo handle de vendedor — relacionadas, nunca fundidas.
 */
export function findRelatedBySeller(stories, handle, excludeStoryId) {
    const target = normalize(handle);
    if (!target) return [];
    const related = [];
    for (const story of Array.isArray(stories) ? stories : []) {
        if (!story || story.id === excludeStoryId) continue;
        const hit = (story.sources || []).some((source) => normalize(source.sellerHandle) === target);
        if (!hit) continue;
        const primary = story.sources?.[0];
        related.push({ storyId: story.id, title: story.title, link: primary?.link || null });
    }
    return related;
}

/** O primeiro handle não-nulo entre as fontes da história — usado pra consultar findRelatedBySeller. */
export const storySellerHandle = (story) =>
    (story?.sources || []).map((source) => source.sellerHandle).find(Boolean) || null;
