/**
 * Knowledge: a coleção curada de fontes.
 *
 * Diferente do feed, que é um fluxo e some, aqui só entra o que o usuário
 * marcou — nada de histórico automático. Cada item já nasce indexado por
 * técnica e CVE, então uma fonte salva encontra hunts e reports que falam do
 * mesmo assunto (ver attackIndex.js).
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
 * As telas de origem (sugestões do boletim, advisories) já trazem `cves`, então
 * o resultado é a união disso com o que der pra extrair do título — que é onde
 * costuma aparecer o CVE ou o ID de técnica.
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

    return {
        id: crypto.randomBytes(6).toString('hex'),
        title,
        url,
        host,
        source: clean(input.source, 120),
        publishedAt: Number.isNaN(Date.parse(published)) ? '' : published,
        savedAt: now,
        techniques: scanned.techniques,
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
