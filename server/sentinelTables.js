// Catálogo de tabelas do Sentinel — o chão do gerador de hunt.
//
// Sem isto o modelo inventa nome de coluna: ele sabe as tabelas padrão da
// Microsoft de cor, mas não conhece as custom (Cloudflare_CL, Netskope*_CL,
// TrendMicro_XDR_*_CL, SAP_CL), que são as que mudam de ambiente pra ambiente
// e são justamente onde o hunt interessante mora.
//
// A fonte é o dump em markdown do threat-hunting-ptbr, que sai do getschema do
// próprio workspace. O formato é plano:
//
//     Cloudflare_CL
//
//      ClientIP_s (string)
//      EdgeStartTimestamp_t (datetime)
//
// Tabela é a linha sem sufixo de tipo; coluna é a linha que termina em
// "(tipo)". Não há indentação diferente entre as duas, então o sufixo é o
// único separador confiável.

const CONTROL_CHARS = /[\x00-\x1F\x7F]/g;
const clean = (value, max) => String(value ?? '').replace(CONTROL_CHARS, ' ').trim().slice(0, max);

// Nome de tabela e de coluna no KQL: letra, depois letras/números/underscore.
const IDENT = /^[A-Za-z][A-Za-z0-9_]*$/;
const COLUMN_LINE = /^([A-Za-z][A-Za-z0-9_]*)\s+\(([A-Za-z0-9_]+)\)$/;

// ponytail: a origem sai do prefixo do nome porque o dump não carrega essa
// informação — o getschema só devolve tabela e coluna. Se um dia o dump vier
// com a solução junto, isto vira leitura em vez de palpite.
const SOURCE_RULES = [
    [/^Cloudflare/i, 'Cloudflare'],
    [/^Netskope/i, 'Netskope'],
    [/^TrendMicro/i, 'Trend Vision One'],
    [/^SAP/i, 'SAP'],
    [/^(Azure|App|Signin|Audit|Security|Sentinel|Threat|Watchlist|Anomalies|Heartbeat|Syslog|Usage|Operation|LAQuery|Function)/i, 'Sentinel'],
];

function sourceOf(table) {
    for (const [pattern, name] of SOURCE_RULES) if (pattern.test(table)) return name;
    return table.endsWith('_CL') ? 'Custom' : 'Sentinel';
}

/** Lê o dump markdown e devolve [{ table, source, columns:[{name,type}] }]. */
export function parseSentinelTables(markdown) {
    const catalog = [];
    let current = null;

    for (const raw of String(markdown ?? '').split('\n')) {
        const line = clean(raw, 400);
        if (!line) continue;

        const column = COLUMN_LINE.exec(line);
        if (column) {
            // Coluna solta, antes de qualquer tabela: ignora em vez de estourar.
            if (current) current.columns.push({ name: column[1], type: column[2].toLowerCase() });
            continue;
        }

        // Linha sem "(tipo)" que parece identificador abre uma tabela nova.
        // Qualquer outra coisa (título de seção, prosa) não é tabela nem coluna.
        if (IDENT.test(line)) {
            current = { table: line, source: sourceOf(line), columns: [] };
            catalog.push(current);
        }
    }

    return catalog.filter((entry) => entry.columns.length > 0);
}

/** As fontes presentes, pra UI oferecer o filtro sem varrer tudo de novo. */
export function catalogSources(catalog) {
    return [...new Set(catalog.map((entry) => entry.source))].sort();
}

const ROLE_LABEL = { pivot: 'pivô temporal', filter: 'filtro', metric: 'métrica', parse: 'parsing' };

/**
 * Renderiza o catálogo pro prompt. Filtra por fonte quando pedido: mandar as 53
 * tabelas (3,5 mil colunas) num hunt de Cloudflare só queima contexto e piora a
 * resposta. `maxColumns` corta as tabelas gigantes — a OAT do Trend tem 387
 * colunas e sozinha estoura qualquer janela útil.
 *
 * Com `context` (o mapeamento do workspace), a tabela ganha o para-que-serve e
 * as colunas saem ordenadas por utilidade, com o papel de cada campo-chave.
 * O corte de `maxColumns` cai no fim da lista, então ordenar é o que garante
 * que o pivô temporal sobreviva ao corte.
 */
export function renderCatalogForPrompt(catalog, { sources = [], maxColumns = 60, context = [] } = {}) {
    const wanted = new Set(sources.map((source) => source.toLowerCase()));
    const chosen = wanted.size
        ? catalog.filter((entry) => wanted.has(entry.source.toLowerCase()))
        : catalog;

    const contextByTable = new Map(context.map((entry) => [entry.table.toLowerCase(), entry]));

    return chosen.map((entry) => {
        const info = contextByTable.get(entry.table.toLowerCase());
        const roleByColumn = new Map((info?.keyFields || []).map((field) => [field.name.toLowerCase(), field.role]));

        const ordered = [
            ...entry.columns.filter((column) => roleByColumn.has(column.name.toLowerCase())),
            ...entry.columns.filter((column) => !roleByColumn.has(column.name.toLowerCase())),
        ];
        const shown = ordered.slice(0, maxColumns);
        const omitted = ordered.length - shown.length;

        const cols = shown.map((column) => {
            const role = roleByColumn.get(column.name.toLowerCase());
            return `  ${column.name}: ${column.type}${role ? ` — ${ROLE_LABEL[role] || role}` : ''}`;
        }).join('\n');

        const purpose = info?.purpose ? `\n  Para que serve: ${info.purpose}` : '';
        const tail = omitted > 0 ? `\n  … +${omitted} colunas` : '';
        return `${entry.table} (${entry.source})${purpose}\n${cols}${tail}`;
    }).join('\n\n');
}
