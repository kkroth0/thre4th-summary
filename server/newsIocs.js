// Colheita de IOC do corpo do artigo, para o feed conseguir responder "quem já
// mencionou este indicador".
//
// O refresh extrai IOC do texto do RSS, e RSS não traz IOC: medido em 2026-08-27,
// 895 itens de 24 fontes renderam zero indicador verdadeiro. O que rende é o
// corpo do artigo de laboratório de pesquisa — no Unit 42, 6, 1 e 16 IPs mais
// dezenas de hashes por post.
//
// Por isso a colheita é só da **layer 3** ("Threat research labs": SANS, Talos,
// Unit 42, Check Point, Securelist, Volexity, Mandiant). Buscar o corpo dos
// ~1200 itens de um refresh seria caro e, medido, quase todo o custo cairia em
// fonte que não publica indicador nenhum. A camada já está nos dados; não
// inventamos taxonomia nova para isso.

// Teto por refresh: o que segura o custo se um dia entrarem dez laboratórios.
export const RESEARCH_LAYER = 3;
export const DEFAULT_MAX_FETCHES = 40;

// Quantos corpos buscar ao mesmo tempo. Observado no primeiro deploy: com os 40
// disparados de uma vez, o refresh que roda no boot degradava o resto da API —
// chamadas à OTX que levam 0,5s passavam de 15s e morriam no timeout. O refresh
// não tem pressa; a busca do usuário tem.
export const FETCH_CONCURRENCY = Number(process.env.NEWS_IOC_CONCURRENCY) || 5;

export const isResearchItem = (item) => Number(item?.layer) === RESEARCH_LAYER;

const hasAny = (iocs) =>
    Boolean(iocs && (iocs.ips?.length || iocs.domains?.length || iocs.hashes?.length || iocs.urls?.length));

/**
 * Enriquece in-place os itens de pesquisa com `item.iocs` colhido do corpo.
 *
 * `fetchText(url)` devolve o texto legível do artigo (ou lança). `extract(text)`
 * é o extractIOCs. Ambos entram por parâmetro para o teste não tocar a rede.
 *
 * Falha de um artigo nunca derruba os outros nem o refresh: notícia sem IOC é
 * notícia, notícia que não chega é feed quebrado.
 */
export async function harvestResearchIocs(items, { fetchText, extract, maxFetches = DEFAULT_MAX_FETCHES, concurrency = FETCH_CONCURRENCY, onError } = {}) {
    const alvos = (items || []).filter((item) => isResearchItem(item) && item.link && !hasAny(item.iocs));
    // Os mais recentes primeiro: se o teto cortar, corta o artigo velho, que já
    // teve chance em refresh anterior.
    alvos.sort((a, b) => String(b.pubDate || '').localeCompare(String(a.pubDate || '')));

    let colhidos = 0;
    let falhas = 0;
    // O corpo volta num Map em vez de grudar no item: `item` é serializado no
    // /api/newsletter, e 30 artigos de 20 kB inchariam a resposta da API por
    // nada. Quem precisa do texto (a atribuição de ator) lê daqui.
    const textos = new Map();

    const fila = alvos.slice(0, maxFetches);
    const buscarUm = async (item) => {
        try {
            const texto = await fetchText(item.link);
            if (!texto) return;
            textos.set(item.link, texto);
            const iocs = extract(texto);
            if (!hasAny(iocs)) return;
            item.iocs = iocs;
            colhidos += 1;
        } catch (error) {
            falhas += 1;
            onError?.(item, error);
        }
    };
    // Em lotes, não tudo de uma vez: ver FETCH_CONCURRENCY.
    for (let i = 0; i < fila.length; i += concurrency) {
        await Promise.all(fila.slice(i, i + concurrency).map(buscarUm));
    }

    return { candidatos: alvos.length, buscados: Math.min(alvos.length, maxFetches), colhidos, falhas, textos };
}

// ---- Consulta: qual artigo mencionou este indicador --------------------------

const norm = (value) => String(value || '').trim().toLowerCase();

// Um mesmo indicador aparece como `1.2.3.4`, `1.2.3[.]4` e dentro de uma URL.
// A story guarda já refangado (é o que o extractIOCs devolve), então aqui basta
// normalizar caixa e espaço — mas a consulta pode chegar defangada do usuário.
export const refangQuery = (value) =>
    norm(value).replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':').replace(/^hxxp/, 'http');

const iocValues = (iocs) => [
    ...(iocs?.ips || []), ...(iocs?.domains || []), ...(iocs?.hashes || []), ...(iocs?.urls || []),
];

/**
 * Procura o indicador nas fontes das stories e devolve onde ele apareceu, com o
 * ator que a matéria atribuiu — que é o achado que interessa: "esse IP saiu no
 * Unit 42, atribuído ao FunkSec".
 */
export function findMentions(stories, indicator) {
    const alvo = refangQuery(indicator);
    if (!alvo) return [];

    const achados = [];
    for (const story of stories || []) {
        for (const source of story.sources || []) {
            const valores = iocValues(source.iocs).map(norm);
            // URL casa por prefixo: o artigo cita a URL inteira, e a consulta
            // costuma ser o domínio ou a URL sem a query string.
            if (!valores.some((v) => v === alvo || v.startsWith(`${alvo}/`))) continue;
            achados.push({
                storyId: story.id,
                title: source.title || story.title,
                source: source.source,
                link: source.link,
                pubDate: source.pubDate,
                actors: (story.actors || []).map((actor) => actor.name).filter(Boolean),
                categories: story.categories || [],
            });
        }
    }
    return achados.sort((a, b) => String(b.pubDate || '').localeCompare(String(a.pubDate || '')));
}
