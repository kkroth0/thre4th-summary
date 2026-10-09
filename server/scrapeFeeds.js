// Fontes de pesquisa que não publicam RSS.
//
// Claroty Team82 e o blog da Nozomi são as duas melhores fontes de pesquisa OT
// abertas e nenhuma das duas tem feed. As páginas são renderizadas no servidor,
// então uma raspagem de listagem basta — e o retorno tem a mesma forma que
// parseFeed() produz, para score, atores, categorias e agrupamento de histórias
// virem de graça, sem tocar em refreshNewsletterFeed.
import * as cheerio from 'cheerio';

export const SCRAPE_SOURCES = [
    {
        source: 'Claroty Team82',
        url: 'https://claroty.com/team82/research?team82_resources_tab=team82_research',
        origin: 'https://claroty.com',
        linkPattern: /^\/team82\/research\/(?!white-papers\/)/,
        layer: 3,
        weight_boost: 15,
        // O post traz article:published_time, então a data é a de verdade.
        datedItems: true,
    },
    {
        source: 'Claroty Team82 White Papers',
        url: 'https://claroty.com/team82/research?team82_resources_tab=team82_white_papers',
        origin: 'https://claroty.com',
        linkPattern: /^\/team82\/research\/white-papers\//,
        layer: 3,
        weight_boost: 15,
        datedItems: true,
    },
    {
        source: 'Nozomi Networks Blog',
        url: 'https://www.nozominetworks.com/blog',
        origin: 'https://www.nozominetworks.com',
        linkPattern: /^\/blog\/[^/]+$/,
        layer: 3,
        weight_boost: 12,
        // O datePublished do JSON-LD é inconfiável — um post de dezembro/2024
        // chega como "Aug 12, 2026". Melhor datar pela primeira aparição do que
        // publicar uma data errada.
        datedItems: false,
    },
];

const clean = (value) => String(value || '').replace(/\s+/g, ' ').trim();

/** Itens da listagem, na mesma forma que parseFeed() devolve. */
export function parseListing(html, source) {
    const items = [];
    const seen = new Set();
    try {
        const $ = cheerio.load(html);
        $('a[href]').each((_, element) => {
            const href = $(element).attr('href') || '';
            let url;
            try { url = new URL(href, source.origin); } catch { return; }
            if (url.origin !== source.origin) return;
            if (!source.linkPattern.test(url.pathname)) return;

            const title = clean($(element).find('h1, h2, h3').first().text()) || clean($(element).text());
            if (title.length < 10) return;

            url.hash = '';
            url.search = '';
            const link = url.toString();
            if (seen.has(link)) return;
            seen.add(link);
            items.push({ title, link, source: source.source, layer: source.layer, weight_boost: source.weight_boost, description: '' });
        });
    } catch { /* HTML impossível de ler: nenhum item, nenhum crash */ }
    return items;
}

/** Data de publicação declarada pela própria página, ou null. */
export function publishedTime(html) {
    const match = String(html || '').match(/<meta[^>]+property=["']article:published_time["'][^>]+content=["']([^"']+)["']/i);
    if (!match) return null;
    const parsed = new Date(match[1]);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

/**
 * Raspa cada fonte e devolve só o que ainda não tinha sido visto.
 *
 * `seen` é o mapa persistido `{link: pubDate}`; a função não escreve em disco —
 * devolve o mapa novo e quem chamou decide gravar. `fetchText(url)` devolve o
 * HTML como string. Uma fonte que estoura entra em `errors` e não impede as outras.
 */
export async function collectScraped({ sources, fetchText, seen = {}, now = new Date(), maxNew = 10 }) {
    const nextSeen = { ...seen };
    const items = [];
    const errors = [];

    for (const source of sources) {
        try {
            const listing = parseListing(await fetchText(source.url), source);
            if (!listing.length) throw new Error('Listing returned no recognizable publications');
            // Uma fonte sem nenhum link conhecido é partida a frio: sem data real
            // não dá para publicar o histórico sem inventar quando aconteceu.
            const coldStart = !listing.some((item) => nextSeen[item.link]);
            let taken = 0;

            for (const item of listing) {
                if (nextSeen[item.link]) continue;
                if (coldStart && !source.datedItems) {
                    // Seed only undated historical listings. New publications
                    // after this baseline must never be discarded by the budget.
                    nextSeen[item.link] = now.toISOString();
                    continue;
                }
                if (taken >= maxNew) continue;
                taken += 1;

                let pubDate = now.toISOString();
                let dateInferred = true;
                if (source.datedItems) {
                    try {
                        const declared = publishedTime(await fetchText(item.link));
                        if (declared && new Date(declared).getTime() <= now.getTime() + 86400000) {
                            pubDate = declared;
                            dateInferred = false;
                        }
                    } catch { /* sem a data real, vale a primeira aparição */ }
                }
                nextSeen[item.link] = pubDate;
                items.push({ ...item, pubDate, dateInferred, firstCollectedAt: now.toISOString(), collectedAt: now.toISOString() });
            }
        } catch (error) {
            errors.push({ source: source.source, message: error.message });
        }
    }

    return { items, seen: nextSeen, errors };
}
