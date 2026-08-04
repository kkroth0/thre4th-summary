// Catálogo próprio de hunts (threat-hunting-ptbr), ao lado do HEARTH.
//
// O HEARTH é em inglês e genérico; este é escrito em português e já aponta pras
// tabelas do workspace. Traduzir o HEARTH com LLM sairia caro e pior do que o
// texto que já existe aqui — então o catálogo próprio entra como fonte, não
// como tradução.
//
// Cada hunt é um markdown com seções fixas:
//
//     # Título
//     ## Objetivo         -> hipótese
//     ## Cadência         -> diária/semanal/mensal
//     ## Tabelas Sentinel -> lista de links, o texto do link é a tabela
//     ## Ferramentas      -> lista de links
//     ## KQL              -> link pro .kql (o conteúdo mora em outro arquivo)
//
// O KQL não vem no catálogo de propósito: são 237 arquivos, e só o hunt que o
// analista adota precisa do corpo da consulta.

const CONTROL_CHARS = /[\x00-\x1F\x7F]/g;
const clean = (value, max) => String(value ?? '').replace(CONTROL_CHARS, ' ').trim().slice(0, max);

// A secao vem em portugues ("Caça Semanal"); a pasta, em ingles (hunts/weekly).
const CADENCES = [
    ['daily', /di[áa]ri/i, /(^|\/)daily(\/|$)/i],
    ['weekly', /semanal/i, /(^|\/)weekly(\/|$)/i],
    ['monthly', /mensal/i, /(^|\/)monthly(\/|$)/i],
    ['intel', /intel/i, /(^|\/)intel(\/|$)/i],
];

/** Quebra o markdown em { secao: conteudo }, preservando a ordem das linhas. */
function splitSections(markdown) {
    const sections = {};
    let current = null;

    for (const raw of String(markdown ?? '').split('\n')) {
        const heading = /^##\s+(.+?)\s*$/.exec(raw);
        if (heading) {
            current = heading[1].toLowerCase();
            sections[current] = [];
            continue;
        }
        if (current) sections[current].push(raw);
    }

    return Object.fromEntries(Object.entries(sections).map(([key, lines]) => [key, lines.join('\n').trim()]));
}

/** Itens de lista markdown; em `- [Texto](link)` fica só o texto. */
function listItems(block, max = 40) {
    return [...new Set(
        String(block ?? '').split('\n')
            .map((line) => /^\s*[-*]\s+(.*)$/.exec(line)?.[1])
            .filter(Boolean)
            .map((item) => clean(/\[([^\]]+)\]/.exec(item)?.[1] ?? item, 120))
            .filter(Boolean),
    )].slice(0, max);
}

const cadenceOf = (text, path) => {
    for (const [value, inText, inPath] of CADENCES) if (inText.test(text) || inPath.test(path)) return value;
    return '';
};

/** Converte um arquivo de hunt do repo no formato que a UI e o adopt usam. */
export function parsePtbrHunt(markdown, path = '') {
    const text = String(markdown ?? '');
    const title = clean(/^#\s+(.+?)\s*$/m.exec(text)?.[1], 300);
    if (!title) throw new Error('hunt sem título');

    const sections = splitSections(text);
    const objective = clean(sections['objetivo'], 4000);

    return {
        id: clean(path.replace(/^hunts\//, '').replace(/\.md$/, ''), 200),
        origin: 'ptbr',
        title,
        // Sem objetivo a hunt nao tem hipotese, e hipotese e obrigatoria no
        // modelo privado — cair pro titulo mantem o adopt possivel.
        hypothesis: objective || title,
        cadence: cadenceOf(sections['cadência'] || sections['cadencia'] || '', path),
        dataSources: listItems(sections['tabelas sentinel']),
        technologies: listItems(sections['ferramentas']),
        // O link do KQL vem como `caminho.kql` em crase ou como link markdown.
        queryPath: clean(/\(([^)]*\.kql)\)/.exec(sections['kql'] || '')?.[1]?.replace(/^\.\.\//, '').replace(/^\.\.\//, '') ?? '', 300),
        notes: clean(sections['fluxo de trabalho do analista'], 5000),
        expected: clean(sections['resultado esperado'], 5000),
        sourcePath: clean(path, 300),
    };
}

/** Só arquivos de hunt: README de pasta não é hunt. */
export function isHuntPath(path) {
    return /^hunts\/[^/]+\/[^/]+\.md$/.test(path) && !/README\.md$/i.test(path);
}
