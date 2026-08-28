/**
 * Knowledge: a coleção curada de fontes.
 *
 * Diferente do feed, que é um fluxo e some, aqui só entra o que o usuário
 * marcou — nada de histórico automático. Cada item já nasce indexado por
 * técnica e CVE, então uma fonte salva encontra hunts e reports que falam do
 * mesmo assunto (ver attackIndex.js).
 *
 * Seguir, não guardar: o item aponta para a cobertura (`storyId`), não só para
 * o artigo. A cobertura continua crescendo depois do clique — mergeIntoStories
 * absorve novos veículos por 14 dias —, então guardamos quantos veículos havia
 * no momento em que o usuário seguiu (`followedSourceCount`). A diferença entre
 * aquele número e o de agora é o que a aba mostra como novidade.
 *
 * Só as funções puras moram aqui; as rotas ficam inline no index.js, no mesmo
 * formato do store de scans salvos.
 */
import crypto from 'crypto';
import { extractRefs } from './attackIndex.js';

export const KNOWLEDGE_CAP = 500;

const CONTROL_CHARS = /[\x00-\x1F\x7F]/g;
const clean = (value, max) =>
    String(value ?? '').replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const uniq = (arr) => [...new Set(arr)].sort();

/**
 * Valida e normaliza o que o cliente mandou salvar.
 *
 * As telas de origem (sugestões do boletim, advisories) já trazem `cves` e as
 * técnicas que o scoreArticle inferiu do artigo, então o resultado é a união
 * disso com o que der pra extrair do título. Título raramente cita "T1486" — a
 * coluna Técnicas ficava toda de traço quando dependia só dele.
 *
 * Lança Error com mensagem pública; a rota traduz para 400.
 */
export function normalizeKnowledgeInput(input = {}, now = new Date().toISOString()) {
    const url = clean(input.url, 2048);
    if (!url) throw new Error('url obrigatória');

    let host;
    try {
        host = new URL(url).hostname;
    } catch {
        throw new Error('url inválida');
    }

    const title = clean(input.title, 300) || url;
    const scanned = extractRefs(title);
    const published = clean(input.publishedAt, 40);

    // Aceita ids de story do próprio feed: 12 hex (ver storyId em newsStories.js).
    const storyId = /^[0-9a-f]{12}$/i.test(String(input.storyId || '')) ? String(input.storyId).toLowerCase() : '';
    const followedSourceCount = Number.isInteger(input.sourceCount) && input.sourceCount > 0
        ? Math.min(input.sourceCount, 100)
        : 0;

    return {
        id: crypto.randomBytes(6).toString('hex'),
        title,
        url,
        host,
        storyId,
        followedSourceCount,
        source: clean(input.source, 120),
        publishedAt: Number.isNaN(Date.parse(published)) ? '' : published,
        savedAt: now,
        // Aceita "T1486" e o rótulo inteiro do scoreArticle ("T1486 — Data
        // Encrypted for Impact"); o índice casa por id.
        techniques: uniq([
            ...(Array.isArray(input.techniques) ? input.techniques : [])
                .map((t) => (clean(t, 80).toUpperCase().match(/T\d{4}(?:\.\d{3})?/) || [''])[0]),
            ...scanned.techniques,
        ].filter(Boolean)),
        cves: uniq([
            ...(Array.isArray(input.cves) ? input.cves : []).map((c) => clean(c, 30).toUpperCase()),
            ...scanned.cves,
        ].filter(Boolean)),
    };
}

/** Insere no topo, de-dup por URL (mantém o recém-salvo) e aplica o teto. */
export function addKnowledgeItem(list = [], item, cap = KNOWLEDGE_CAP) {
    return [item, ...list.filter((k) => k.url !== item.url)].slice(0, cap);
}
