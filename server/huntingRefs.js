// Os mapeamentos do workspace viram dado do app. O XLSX é insumo de build:
// quem lê aqui é o gerador de hunt e a biblioteca da tela, e nenhum dos dois
// pode depender de planilha aberta na máquina de alguém.
//
// A anonimização mora neste arquivo, não numa limpeza manual do JSON, porque
// regenerar tem que ser seguro: o script roda de novo e o nome não volta.

// Termos que não podem alcançar o repositório, o prompt nem o PDF.
const FORBIDDEN = [/\bEY\b/gi, /votorantim\w*/gi];

export function anonymize(text) {
    let out = String(text ?? '');
    for (const pattern of FORBIDDEN) out = out.replace(pattern, '');
    // A remoção deixa espaço duplo e espaço antes de pontuação. Sem isto o
    // texto anonimizado fica visivelmente remendado.
    return out.replace(/\s{2,}/g, ' ').replace(/\s+([,.;:])/g, '$1').replace(/^[\s-]+|[\s-]+$/g, '').trim();
}

/** Trava de build: o artefato não sai daqui com termo proibido dentro. */
export function assertAnonymous(value) {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    for (const pattern of FORBIDDEN) {
        const hit = serialized.match(new RegExp(pattern.source, 'i'));
        if (hit) throw new Error(`termo proibido no artefato: ${hit[0]}`);
    }
    return value;
}

// O tipo lógico do dicionário diz o que o campo serve para fazer numa caça —
// é isso que ordena as colunas no prompt do gerador.
const ROLE_BY_TYPE = { datetime: 'pivot', numeric: 'metric', dynamic: 'parse' };

export const fieldRole = (logicalType) =>
    ROLE_BY_TYPE[String(logicalType ?? '').toLowerCase().trim()] || 'filter';

// Casos de uso vêm separados por ';' e campos por ','. Nenhum dos dois usa o
// separador do outro dentro do item, então um split serve para os dois.
const splitList = (value) => String(value ?? '')
    .split(/[;,]/)
    .map((item) => anonymize(item).replace(/\.$/, ''))
    .filter(Boolean);

/** Contexto por tabela, com o papel de cada campo-chave vindo do dicionário. */
export function buildTableContext(contextRows = [], dictionaryRows = []) {
    const typeByField = new Map();
    for (const [table, , field, logicalType] of dictionaryRows) {
        if (table && field) typeByField.set(`${String(table).trim()}|${String(field).trim()}`, logicalType);
    }

    return contextRows
        .filter((row) => row[0])
        .map(([table, domain, category, , purpose, useCases, keyFields, caution]) => {
            const name = String(table).trim();
            return {
                table: name,
                domain: anonymize(domain),
                category: anonymize(category),
                purpose: anonymize(purpose),
                useCases: splitList(useCases),
                caution: anonymize(caution),
                keyFields: splitList(keyFields).map((field) => {
                    const type = String(typeByField.get(`${name}|${field}`) ?? '').trim();
                    return { name: field, type: type || 'string/bool', role: fieldRole(type) };
                }),
            };
        });
}

/**
 * Biblioteca de consultas curadas. O id sai da seção e da posição dentro dela,
 * então rodar o script de novo devolve os mesmos ids — a tela e o prompt citam
 * esse id, e id que muda a cada build não serve para citar nada.
 */
export function buildKqlLibrary(rows = []) {
    const counters = new Map();

    return rows
        .filter((row) => row[0] && row[4])
        .map(([section, question, tables, objective, query, params, validation]) => {
            const sectionNumber = (String(section).trim().match(/^(\d+)/) || [, '0'])[1];
            const seq = (counters.get(sectionNumber) ?? 0) + 1;
            counters.set(sectionNumber, seq);

            return {
                id: `kql-${sectionNumber.padStart(2, '0')}-${String(seq).padStart(2, '0')}`,
                section: anonymize(section),
                question: anonymize(question),
                objective: anonymize(objective),
                tables: splitList(tables),
                query: anonymize(query),
                params: splitList(params),
                validation: anonymize(validation),
            };
        });
}
