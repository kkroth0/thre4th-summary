// Geração de hunt/KQL com LLM, presa ao schema real do workspace.
//
// O modelo escreve KQL plausível sozinho — o problema é que ele inventa nome de
// coluna e de tabela com a mesma confiança com que acerta. Duas travas:
//
//   1. o prompt leva só as tabelas da fonte escolhida, como verdade única;
//   2. a resposta passa por unknownTables() antes de virar hunt.
//
// A segunda é a que importa: prompt é pedido, verificação é garantia.

import { renderCatalogForPrompt } from './sentinelTables.js';

const clean = (value, max) => String(value ?? '').replace(/[\x00-\x1F\x7F]/g, ' ').trim().slice(0, max);

export const GENERATOR_SYSTEM = [
    'Você é um analista de threat hunting escrevendo para o Microsoft Sentinel.',
    'Responda SOMENTE com um objeto JSON com estas chaves:',
    '"title": título curto da hunt, em português do Brasil.',
    '"hypothesis": a hipótese em uma frase, em português do Brasil — o que se procura e por quê.',
    '"query": a consulta KQL. Use EXCLUSIVAMENTE as tabelas e colunas listadas abaixo.',
    '"dataSources": as tabelas que a consulta usa.',
    '"falsePositives": o que costuma cair na consulta sem ser ameaça, em português do Brasil.',
    '"notes": como triar o resultado, em português do Brasil.',
    'Se as tabelas disponíveis não permitirem testar a hipótese, devolva "query" vazia',
    'e explique o porquê em "notes". Nunca invente nome de tabela ou de coluna.',
    'A consulta precisa ter janela temporal explícita (ago() ou between) e um project',
    'com os campos-chave da tabela — o analista lê a saída, não só roda.',
    'Prefira os campos marcados como pivô temporal, filtro e métrica.',
].join('\n');

/** Monta o prompt do usuário: hipótese + o schema que ele pode usar. */
export function buildGeneratePrompt({ catalog, hypothesis, sources = [], techniques = [], context = [], examples = [] }) {
    const schema = renderCatalogForPrompt(catalog, { sources, context });
    if (!schema) throw new Error('nenhuma tabela disponível para as fontes escolhidas');

    const reference = examples.length
        ? [
            '',
            'Consultas de referência já validadas neste ambiente — siga o formato:',
            ...examples.map((item) => `# ${item.id} — ${item.question}\n${item.query}`),
        ].join('\n')
        : '';

    return [
        `Hipótese: ${clean(hypothesis, 2000)}`,
        techniques.length ? `Técnicas ATT&CK: ${techniques.map((id) => clean(id, 20)).join(', ')}` : '',
        '',
        'Tabelas disponíveis (nome, origem e colunas):',
        schema,
        reference,
    ].filter(Boolean).join('\n');
}

// Palavra curta e palavra de ligação não dizem do que a hipótese trata.
const STOPWORDS = new Set(['para', 'com', 'por', 'uma', 'dos', 'das', 'nos', 'nas', 'que', 'sobre', 'entre']);

const words = (text) => String(text ?? '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/\p{Mn}/gu, '')
    .split(/[^a-z0-9_]+/)
    .filter((word) => word.length > 3 && !STOPWORDS.has(word));

/**
 * Até `limit` consultas curadas para servir de exemplo no prompt. O ranking é
 * contagem de palavra em comum entre a hipótese e a pergunta/objetivo da
 * consulta — determinístico e sem chamada extra. Exemplo que usa tabela fora
 * das fontes escolhidas fica de fora: ensinar a consultar o que o analista não
 * selecionou é pior que não dar exemplo.
 */
export function pickExamples({ library = [], hypothesis = '', sources = [], catalog = [], limit = 3 }) {
    const wanted = new Set(sources.map((source) => source.toLowerCase()));
    const inScope = new Set(catalog
        .filter((entry) => !wanted.size || wanted.has(entry.source.toLowerCase()))
        .map((entry) => entry.table.toLowerCase()));
    const terms = new Set(words(hypothesis));

    return library
        .map((item) => {
            const tables = (item.tables || []).map((table) => table.toLowerCase());
            const usable = !tables.length || tables.some((table) => inScope.has(table));
            if (!usable) return null;
            const overlap = words(`${item.question} ${item.objective}`).filter((word) => terms.has(word)).length;
            return { item, score: overlap };
        })
        .filter((entry) => entry && entry.score > 0)
        .sort((a, b) => b.score - a.score || a.item.id.localeCompare(b.item.id))
        .slice(0, limit)
        .map((entry) => entry.item);
}

// Onde um nome de tabela aparece em KQL: no começo da consulta, depois de
// union/join, ou dentro de um let. Basta para pegar alucinação — não é um
// parser de KQL.
// ponytail: heurística de linha; se a consulta gerada passar a usar formas mais
// exóticas (materialize, funções salvas), trocar por parser de verdade.
const TABLE_REFS = [
    /^\s*([A-Za-z][A-Za-z0-9_]*)\s*(?:\||$)/gm,
    /\bunion\s+(?:isfuzzy\s*=\s*\w+\s+)?([A-Za-z][A-Za-z0-9_]*)/gi,
    /\bjoin\s+(?:kind\s*=\s*\w+\s+)?\(?\s*([A-Za-z][A-Za-z0-9_]*)/gi,
];

// Palavras que abrem linha em KQL sem serem tabela.
const KQL_KEYWORDS = new Set([
    'let', 'union', 'join', 'where', 'project', 'summarize', 'extend', 'order', 'sort',
    'take', 'limit', 'top', 'distinct', 'count', 'render', 'mv', 'parse', 'search',
    'datatable', 'print', 'range', 'evaluate', 'invoke', 'lookup', 'on', 'by', 'and', 'or',
]);

/** Todas as tabelas citadas pela consulta, sem repetir. */
export function extractTables(kql) {
    const found = new Set();
    for (const pattern of TABLE_REFS) {
        for (const match of String(kql ?? '').matchAll(pattern)) {
            const name = match[1];
            if (name && !KQL_KEYWORDS.has(name.toLowerCase())) found.add(name);
        }
    }
    return [...found];
}

/**
 * As tabelas que a consulta cita e o workspace não tem. Lista vazia = a
 * consulta só toca em tabela que existe. Aliases de `let` são descontados: quem
 * define o nome na própria consulta pode usá-lo depois.
 */
export function unknownTables(kql, catalog) {
    const known = new Set(catalog.map((entry) => entry.table.toLowerCase()));
    const aliases = new Set(
        [...String(kql ?? '').matchAll(/\blet\s+([A-Za-z][A-Za-z0-9_]*)\s*=/gi)].map((match) => match[1].toLowerCase()),
    );

    return extractTables(kql).filter((name) => {
        const lower = name.toLowerCase();
        return !known.has(lower) && !aliases.has(lower);
    });
}

/** Normaliza a resposta do modelo pro formato de hunt, sem confiar em nada. */
export function normalizeGenerated(payload, catalog) {
    const query = clean(payload?.query, 20000);
    const missing = query ? unknownTables(query, catalog) : [];

    return {
        title: clean(payload?.title, 300),
        hypothesis: clean(payload?.hypothesis, 4000),
        query,
        dataSources: (Array.isArray(payload?.dataSources) ? payload.dataSources : [])
            .map((item) => clean(item, 120)).filter(Boolean).slice(0, 20),
        falsePositives: clean(payload?.falsePositives, 4000),
        notes: clean(payload?.notes, 4000),
        unknownTables: missing,
    };
}
