# Hunting: KQL ancorada e relatório da execução — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ancorar o gerador de KQL nos mapeamentos do workspace e fazer a execução de uma hunt virar relatório PDF com hipótese, objetivo, janela investigada, consultas e recomendações.

**Architecture:** Um script converte três XLSX em dois JSON versionados e anonimizados (`huntingContext.json`, `kqlLibrary.json`). Deles bebem três consumidores independentes: o prompt do gerador (campos-chave primeiro, exemplos curados), a biblioteca navegável na aba Queries, e o relatório PDF. O modelo de hunt cresce para carregar os campos do formulário; o PDF sai no cliente com jsPDF, sobre um renderer extraído do exportador de boletim.

**Tech Stack:** Node 20 + Express (ESM, sem TypeScript no servidor), React 18 + TypeScript + Vite + shadcn/ui no cliente, `exceljs` (já instalado) para ler XLSX, `jspdf` + `jspdf-autotable` (já instalados) para PDF, `node:test` + `assert/strict` para teste.

**Spec:** `docs/superpowers/specs/2026-08-13-hunting-kql-e-relatorio-design.md`

## Global Constraints

- **Nenhum artefato pode conter "consultoria de origem" ou "Votorantim"** — nem dado, nem prompt, nem tela, nem PDF. Os padrões proibidos são `/\bEY\b/gi` e `/votorantim\w*/gi`, verificados por teste.
- `hunting-docs/` está no `.gitignore` e **nunca** é commitado. Os XLSX são insumo; o artefato versionado é `server/data/*.json`.
- Copy de interface e mensagem de erro em **português do Brasil**.
- **Nenhuma dependência nova.** `exceljs`, `jspdf` e `jspdf-autotable` já estão no `package.json`.
- Todo campo novo de hunt e de execução é **opcional**: registro gravado antes continua válido e é migrado na leitura, nunca no disco.
- Servidor é ESM puro sem TypeScript; cliente é TypeScript estrito. Não misturar.
- Comandos de verificação: `npm run test:server`, `npm run test:unit`, `npm run lint`, `npm run typecheck`, `npm run build`.
- Commit por task, mensagem em português, prefixo `feat:` / `fix:` / `test:` / `docs:`.

---

## Fase 1 — Dados

### Task 1: Conversão pura dos mapeamentos

Funções puras que transformam linhas de planilha em dado do app. Ficam separadas do script de I/O porque é aqui que mora a regra (anonimização, papel de campo, id estável) e é isso que precisa de teste.

**Files:**
- Create: `server/huntingRefs.js`
- Test: `server/test/huntingRefs.test.js`

**Interfaces:**
- Consumes: nada.
- Produces: `anonymize(text) -> string`, `assertAnonymous(value) -> value` (lança `Error` se sobrar termo proibido), `fieldRole(logicalType) -> 'pivot'|'filter'|'metric'|'parse'`, `buildTableContext(contextRows, dictionaryRows) -> Array<{table, domain, category, purpose, useCases, caution, keyFields: Array<{name, type, role}>}>`, `buildKqlLibrary(rows) -> Array<{id, section, question, objective, tables, query, params, validation}>`. `contextRows`, `dictionaryRows` e `rows` são `string[][]` — uma linha de planilha por item, células já em texto.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/huntingRefs.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
    anonymize, assertAnonymous, fieldRole, buildTableContext, buildKqlLibrary,
} from '../huntingRefs.js';

// Colunas do "Contexto por Tabela": tabela, domínio, categoria, descrição,
// propósito, casos de uso, campos-chave, cautela.
const CONTEXT_ROWS = [
    ['SigninLogs', 'Identidade e Acesso', 'Identidade', 'Tabela do domínio identidade.',
        'Investigar autenticação e risco de conta.', 'Password spray; conta comprometida.',
        'TimeGenerated, UserPrincipalName, RiskLevelDuringSignIn',
        'Usar somente campos presentes no esquema mapeado.'],
];

// Colunas do "Dicionário de Campos": tabela, domínio, campo, tipo, uso.
const DICT_ROWS = [
    ['SigninLogs', 'Identidade e Acesso', 'TimeGenerated', 'datetime', 'Pivô temporal'],
    ['SigninLogs', 'Identidade e Acesso', 'UserPrincipalName', 'string/bool', 'Filtro'],
];

// Colunas do "Catálogo Completo": seção, pergunta, tabelas, objetivo, KQL,
// parâmetros, cobertura.
const KQL_ROWS = [
    ['1. Triagem e Inventário', 'Onde o IOC aparece?', 'search *', 'Direcionar a investigação',
        'let ioc="<IOC>"; search ioc | where TimeGenerated > ago(30d)', 'IOC, janela', 'Validada pelo esquema'],
    ['4. Rede, SASE e WAF', 'Tráfego de ou para IP', 'CommonSecurityLog', 'Dimensionar conexões',
        'let ip="<IP>"; CommonSecurityLog | where SourceIP == ip', 'IP, janela', 'Validada pelo esquema'],
    ['4. Rede, SASE e WAF', 'Acesso a domínio', 'CommonSecurityLog', 'Localizar requisições',
        'let d="<DOMINIO>"; CommonSecurityLog | where RequestURL has d', 'domínio, janela', 'Validada pelo esquema'],
];

test('o papel do campo sai do tipo lógico do dicionário', () => {
    assert.equal(fieldRole('datetime'), 'pivot');
    assert.equal(fieldRole('numeric'), 'metric');
    assert.equal(fieldRole('dynamic'), 'parse');
    assert.equal(fieldRole('string/bool'), 'filter');
    assert.equal(fieldRole(''), 'filter', 'tipo ausente não vira papel inventado');
});

test('campo-chave sem entrada no dicionário ainda entra, como filtro', () => {
    const [table] = buildTableContext(CONTEXT_ROWS, DICT_ROWS);
    assert.deepEqual(table.keyFields.map((f) => [f.name, f.role]), [
        ['TimeGenerated', 'pivot'],
        ['UserPrincipalName', 'filter'],
        ['RiskLevelDuringSignIn', 'filter'],
    ]);
    assert.deepEqual(table.useCases, ['Password spray', 'conta comprometida']);
    assert.equal(table.domain, 'Identidade e Acesso');
});

test('o id da consulta é estável e numerado por seção', () => {
    assert.deepEqual(buildKqlLibrary(KQL_ROWS).map((item) => item.id), [
        'kql-01-01', 'kql-04-01', 'kql-04-02',
    ]);
});

test('a consulta preserva placeholder e tabelas', () => {
    const [, rede] = buildKqlLibrary(KQL_ROWS);
    assert.deepEqual(rede.tables, ['CommonSecurityLog']);
    assert.match(rede.query, /<IP>/);
    assert.deepEqual(rede.params, ['IP', 'janela']);
});

test('linha sem KQL não vira item da biblioteca', () => {
    assert.deepEqual(buildKqlLibrary([['1. Triagem', 'Pergunta', 'Tabela', 'Objetivo', '', '', '']]), []);
});

test('anonimização tira os termos proibidos do texto', () => {
    assert.equal(anonymize('Mapeamento consultoria de origem - Microsoft Sentinel Votorantim'), 'Mapeamento - Microsoft Sentinel');
    assert.equal(anonymize('inventário da Votorantim S.A.'), 'inventário da S.A.');
});

test('assertAnonymous barra o artefato que ainda tem termo proibido', () => {
    assert.throws(() => assertAnonymous({ table: 'X', note: 'padrão consultoria de origem' }), /termo proibido/);
    assert.throws(() => assertAnonymous('inventário Votorantim'), /termo proibido/);
    assert.doesNotThrow(() => assertAnonymous({ table: 'SigninLogs' }));
});

test('nome de produto não é nome de cliente e fica', () => {
    const [item] = buildKqlLibrary([['4. Rede', 'WAF', 'Cloudflare_CL', 'Investigar',
        'Cloudflare_CL | where SecurityAction_s == "block"', 'janela', 'Validada']]);
    assert.match(item.query, /Cloudflare_CL/);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `node --test server/test/huntingRefs.test.js`
Expected: FAIL — `Cannot find module '../huntingRefs.js'`.

- [ ] **Step 3: Implementar `server/huntingRefs.js`**

```js
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
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `node --test server/test/huntingRefs.test.js`
Expected: PASS, 8 testes.

- [ ] **Step 5: Commit**

```bash
git add server/huntingRefs.js server/test/huntingRefs.test.js
git commit -m "feat: converter mapeamentos do workspace em dado do app, já anonimizado"
```

---

### Task 2: Script de build e os dois JSON

**Files:**
- Create: `server/scripts/build-hunting-refs.mjs`
- Create: `server/data/huntingContext.json` (gerado pelo script)
- Create: `server/data/kqlLibrary.json` (gerado pelo script)

**Interfaces:**
- Consumes: `buildTableContext`, `buildKqlLibrary`, `assertAnonymous` da Task 1.
- Produces: os dois JSON, cada um `{ generated_at: string, tables: [...] }` e `{ generated_at: string, queries: [...] }`.

- [ ] **Step 1: Escrever o script**

Criar `server/scripts/build-hunting-refs.mjs`:

```js
#!/usr/bin/env node
/**
 * Converte os mapeamentos do workspace (XLSX, em hunting-docs/) nos dois JSON
 * que o app carrega. Mesmo contrato do build-actors.mjs: a planilha é insumo,
 * o JSON é o artefato versionado.
 *
 * Os arquivos de origem ficam fora do git e têm nome livre — o script acha
 * cada um por padrão no nome, então ninguém precisa renomear nada.
 *
 * Roda manualmente:
 *     node server/scripts/build-hunting-refs.mjs
 */
import ExcelJS from 'exceljs';
import { readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildTableContext, buildKqlLibrary, assertAnonymous } from '../huntingRefs.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCS_DIR = join(__dirname, '..', '..', 'hunting-docs');
const DATA_DIR = join(__dirname, '..', 'data');

// Cabeçalho na linha 4, dados a partir da 5 — vale para as três planilhas.
const HEADER_ROW = 4;

const MATCHERS = {
    kql: /kql/i,
    context: /contextualizad/i,
    dictionary: /completo/i,
};

function findWorkbookPath(kind) {
    const file = readdirSync(DOCS_DIR).find((name) => name.endsWith('.xlsx') && MATCHERS[kind].test(name));
    if (!file) throw new Error(`planilha de ${kind} não encontrada em hunting-docs/`);
    return join(DOCS_DIR, file);
}

const cellText = (cell) => {
    const value = cell?.value;
    if (value == null) return '';
    if (typeof value === 'object') return String(value.text ?? value.result ?? '').trim();
    return String(value).trim();
};

/** Linhas depois do cabeçalho, com número fixo de colunas e sem linha vazia. */
function rowsAfterHeader(sheet, columns) {
    const rows = [];
    sheet.eachRow((row, index) => {
        if (index <= HEADER_ROW) return;
        const cells = [];
        for (let column = 1; column <= columns; column += 1) cells.push(cellText(row.getCell(column)));
        if (cells.some(Boolean)) rows.push(cells);
    });
    return rows;
}

async function sheetRows(kind, sheetName, columns) {
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(findWorkbookPath(kind));
    const sheet = workbook.getWorksheet(sheetName);
    if (!sheet) throw new Error(`aba "${sheetName}" não encontrada na planilha de ${kind}`);
    return rowsAfterHeader(sheet, columns);
}

async function main() {
    const [contextRows, dictionaryRows, kqlRows] = await Promise.all([
        sheetRows('context', 'Contexto por Tabela', 8),
        sheetRows('dictionary', 'Dicionário de Campos', 5),
        sheetRows('kql', 'Catálogo Completo', 7),
    ]);

    const generated_at = new Date().toISOString();
    const tables = buildTableContext(contextRows, dictionaryRows);
    const queries = buildKqlLibrary(kqlRows);
    if (!tables.length) throw new Error('nenhuma tabela convertida — conferir a aba de contexto');
    if (!queries.length) throw new Error('nenhuma consulta convertida — conferir a aba de catálogo');

    const context = assertAnonymous({ generated_at, tables });
    const library = assertAnonymous({ generated_at, queries });

    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(join(DATA_DIR, 'huntingContext.json'), JSON.stringify(context, null, 0), 'utf8');
    writeFileSync(join(DATA_DIR, 'kqlLibrary.json'), JSON.stringify(library, null, 0), 'utf8');

    const withKeyFields = tables.filter((table) => table.keyFields.length).length;
    process.stderr.write(
        `Escreveu ${tables.length} tabelas (${withKeyFields} com campo-chave) e ${queries.length} consultas em ${DATA_DIR}\n`,
    );
}

main().catch((error) => {
    console.error('build-hunting-refs falhou:', error.message);
    process.exit(1);
});
```

- [ ] **Step 2: Rodar o script**

Run: `node server/scripts/build-hunting-refs.mjs`
Expected: `Escreveu 45 tabelas (45 com campo-chave) e 41 consultas em .../server/data`

Se falhar com "termo proibido no artefato", a anonimização não cobriu um caso: acrescentar o padrão em `FORBIDDEN` (`server/huntingRefs.js`), com um caso no teste da Task 1, e rodar de novo. Não editar o JSON à mão.

- [ ] **Step 3: Conferir o artefato**

Run:
```bash
node -e "const c=require('./server/data/huntingContext.json'),l=require('./server/data/kqlLibrary.json');
console.log(c.tables.length,'tabelas |',l.queries.length,'consultas');
console.log(c.tables.find(t=>t.table==='CommonSecurityLog').keyFields.slice(0,4));
console.log(l.queries[0].id, '|', l.queries[0].question);"
grep -ril "votorantim\|\bEY\b" server/data/huntingContext.json server/data/kqlLibrary.json || echo "sem termo proibido"
```
Expected: contagens acima de zero, campos-chave com `role`, e `sem termo proibido`.

- [ ] **Step 4: Commit**

```bash
git add server/scripts/build-hunting-refs.mjs server/data/huntingContext.json server/data/kqlLibrary.json
git commit -m "feat: gerar contexto de tabelas e biblioteca de KQLs a partir dos mapeamentos"
```

---

## Fase 2 — Gerador ancorado

### Task 3: Contexto e campos-chave no prompt

**Files:**
- Modify: `server/sentinelTables.js:81-94` (`renderCatalogForPrompt`)
- Test: `server/test/sentinelTables.test.js`

**Interfaces:**
- Consumes: o formato de `huntingContext.json` da Task 2.
- Produces: `renderCatalogForPrompt(catalog, { sources, maxColumns, context })` — `context` é `Array<{table, purpose, keyFields}>`; ausente, a saída é byte a byte a de hoje.

- [ ] **Step 1: Escrever o teste que falha**

Acrescentar a `server/test/sentinelTables.test.js`:

```js
const CATALOG_CTX = [{
    table: 'SigninLogs',
    source: 'Sentinel',
    columns: [
        { name: 'AlternateSignInName', type: 'string' },
        { name: 'TimeGenerated', type: 'datetime' },
        { name: 'UserPrincipalName', type: 'string' },
    ],
}];

const CONTEXT = [{
    table: 'SigninLogs',
    purpose: 'Investigar autenticação e risco de conta.',
    keyFields: [
        { name: 'TimeGenerated', type: 'datetime', role: 'pivot' },
        { name: 'UserPrincipalName', type: 'string/bool', role: 'filter' },
    ],
}];

test('campo-chave vem antes do resto e leva o papel junto', () => {
    const rendered = renderCatalogForPrompt(CATALOG_CTX, { context: CONTEXT });
    const linhas = rendered.split('\n').filter((line) => line.startsWith('  ') && line.includes(':'));
    assert.match(linhas[0], /TimeGenerated: datetime — pivô temporal/);
    assert.match(linhas[1], /UserPrincipalName: string — filtro/);
    assert.match(linhas[2], /AlternateSignInName/, 'coluna comum vai para o fim');
    assert.match(rendered, /Para que serve: Investigar autenticação/);
});

test('campo-chave não é cortado pelo teto de colunas', () => {
    const rendered = renderCatalogForPrompt(CATALOG_CTX, { context: CONTEXT, maxColumns: 1 });
    assert.match(rendered, /TimeGenerated/);
    assert.doesNotMatch(rendered, /AlternateSignInName/);
    assert.match(rendered, /\+2 colunas/);
});

test('sem contexto a saída é a de hoje', () => {
    const rendered = renderCatalogForPrompt(CATALOG_CTX, {});
    assert.equal(rendered, 'SigninLogs (Sentinel)\n  AlternateSignInName: string\n  TimeGenerated: datetime\n  UserPrincipalName: string');
});
```

Se `server/test/sentinelTables.test.js` não existir, criar com o cabeçalho:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderCatalogForPrompt } from '../sentinelTables.js';
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `node --test server/test/sentinelTables.test.js`
Expected: FAIL — o primeiro teste não acha `pivô temporal` na saída.

- [ ] **Step 3: Implementar**

Substituir `renderCatalogForPrompt` em `server/sentinelTables.js`:

```js
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
            return `  ${column.name}: ${column.type}${role ? ` — ${ROLE_LABEL[role]}` : ''}`;
        }).join('\n');

        const purpose = info?.purpose ? `\n  Para que serve: ${info.purpose}` : '';
        const tail = omitted > 0 ? `\n  … +${omitted} colunas` : '';
        return `${entry.table} (${entry.source})${purpose}\n${cols}${tail}`;
    }).join('\n\n');
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `node --test server/test/sentinelTables.test.js server/test/huntGenerator.test.js`
Expected: PASS — inclusive os testes antigos do gerador, que não passam `context`.

- [ ] **Step 5: Commit**

```bash
git add server/sentinelTables.js server/test/sentinelTables.test.js
git commit -m "feat: ordenar coluna por utilidade e levar propósito da tabela ao prompt"
```

---

### Task 4: Exemplos curados no prompt

**Files:**
- Modify: `server/huntGenerator.js:15-40` (`GENERATOR_SYSTEM`, `buildGeneratePrompt`)
- Modify: `server/index.js:3346-3360` (`generateQuery`)
- Test: `server/test/huntGenerator.test.js`

**Interfaces:**
- Consumes: `renderCatalogForPrompt(..., { context })` da Task 3; `kqlLibrary.json` da Task 2.
- Produces: `pickExamples({ library, hypothesis, sources, catalog, limit }) -> Array<queryItem>`; `buildGeneratePrompt({ catalog, hypothesis, sources, techniques, context, examples })` — `examples` é a lista devolvida por `pickExamples`.

- [ ] **Step 1: Escrever o teste que falha**

Acrescentar a `server/test/huntGenerator.test.js`:

```js
import { pickExamples } from '../huntGenerator.js';

const LIBRARY = [
    { id: 'kql-04-01', question: 'Tráfego de ou para IP', objective: 'Dimensionar conexões e portas',
      tables: ['CommonSecurityLog'], query: 'CommonSecurityLog | where SourceIP == ip' },
    { id: 'kql-02-01', question: 'Histórico de login por conta', objective: 'Analisar IP e risco',
      tables: ['SigninLogs'], query: 'SigninLogs | where UserPrincipalName =~ upn' },
    { id: 'kql-02-02', question: 'Falhas de múltiplas contas por IP', objective: 'Identificar password spray',
      tables: ['SigninLogs'], query: 'SigninLogs | where ResultType != 0' },
];

const CATALOG_REDE = [
    { table: 'CommonSecurityLog', source: 'Cloudflare', columns: [{ name: 'SourceIP', type: 'string' }] },
    { table: 'SigninLogs', source: 'Sentinel', columns: [{ name: 'UserPrincipalName', type: 'string' }] },
];

test('exemplo casa por palavra da hipótese e respeita a fonte escolhida', () => {
    const picked = pickExamples({
        library: LIBRARY, hypothesis: 'possível password spray contra contas corporativas',
        sources: ['Sentinel'], catalog: CATALOG_REDE,
    });
    assert.deepEqual(picked.map((item) => item.id), ['kql-02-02']);
});

test('exemplo de tabela fora da fonte escolhida não entra', () => {
    const picked = pickExamples({
        library: LIBRARY, hypothesis: 'tráfego suspeito de portas incomuns',
        sources: ['Sentinel'], catalog: CATALOG_REDE,
    });
    assert.ok(picked.every((item) => item.id !== 'kql-04-01'), 'CommonSecurityLog é Cloudflare, não Sentinel');
});

test('o teto de exemplos é respeitado e o desempate é estável', () => {
    const picked = pickExamples({
        library: LIBRARY, hypothesis: 'login conta IP risco portas conexões',
        sources: [], catalog: CATALOG_REDE, limit: 2,
    });
    assert.equal(picked.length, 2);
    assert.deepEqual(picked.map((item) => item.id), pickExamples({
        library: LIBRARY, hypothesis: 'login conta IP risco portas conexões',
        sources: [], catalog: CATALOG_REDE, limit: 2,
    }).map((item) => item.id), 'mesma entrada, mesma saída');
});

test('exemplo escolhido entra no prompt com o id', () => {
    const prompt = buildGeneratePrompt({
        catalog: CATALOG_REDE, hypothesis: 'password spray', sources: ['Sentinel'],
        examples: [LIBRARY[2]],
    });
    assert.match(prompt, /kql-02-02/);
    assert.match(prompt, /SigninLogs \| where ResultType != 0/);
});

test('o system prompt exige janela e project', () => {
    assert.match(GENERATOR_SYSTEM, /janela temporal/i);
    assert.match(GENERATOR_SYSTEM, /project/i);
});
```

Acrescentar `GENERATOR_SYSTEM` ao import existente do arquivo de teste.

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `node --test server/test/huntGenerator.test.js`
Expected: FAIL — `pickExamples is not a function`.

- [ ] **Step 3: Implementar em `server/huntGenerator.js`**

Acrescentar ao final do `GENERATOR_SYSTEM`, antes do `].join('\n')`:

```js
    'A consulta precisa ter janela temporal explícita (ago() ou between) e um project',
    'com os campos-chave da tabela — o analista lê a saída, não só roda.',
    'Prefira os campos marcados como pivô temporal, filtro e métrica.',
```

Acrescentar depois de `buildGeneratePrompt`:

```js
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
```

Substituir o corpo de `buildGeneratePrompt`:

```js
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
```

- [ ] **Step 4: Ligar em `server/index.js`**

Acrescentar aos imports do topo (junto do import de `huntGenerator.js`): `pickExamples`.

Acrescentar perto de `getSentinelTables`:

```js
// Contexto e biblioteca são arquivos do repo, não rede: lê uma vez no boot.
const huntingRefs = (() => {
    const read = (file, key) => {
        try {
            return JSON.parse(fs.readFileSync(path.join(__dirname, 'data', file), 'utf8'))[key] || [];
        } catch (error) {
            console.error(`referência de hunting indisponível (${file}):`, error.message);
            return [];
        }
    };
    return { context: read('huntingContext.json', 'tables'), library: read('kqlLibrary.json', 'queries') };
})();
```

Substituir o corpo de `generateQuery` (linhas ~3346-3351):

```js
async function generateQuery({ hypothesis, sources = [], techniques = [] }) {
    if (!process.env.OPENROUTER_API_KEY) throw new Error('OPENROUTER_API_KEY não configurada');

    const catalog = await getSentinelTables();
    const examples = pickExamples({ library: huntingRefs.library, hypothesis, sources, catalog });
    const userPrompt = buildGeneratePrompt({
        catalog, hypothesis, sources, techniques, context: huntingRefs.context, examples,
    });
```

E a última linha da função (`server/index.js:3373`), que hoje é

```js
    return normalizeGenerated(JSON.parse(raw), catalog);
```

passa a ser

```js
    return { ...normalizeGenerated(JSON.parse(raw), catalog), examplesUsed: examples.map((item) => item.id) };
```

- [ ] **Step 5: Rodar os testes e confirmar que passam**

Run: `npm run test:server`
Expected: PASS — todos, inclusive smoke.

- [ ] **Step 6: Commit**

```bash
git add server/huntGenerator.js server/index.js server/test/huntGenerator.test.js
git commit -m "feat: ancorar o gerador em consultas curadas do mesmo ambiente"
```

---

### Task 5: Aviso de coluna inexistente

**Files:**
- Modify: `server/huntGenerator.js` (novo `unknownColumns`, `normalizeGenerated`)
- Modify: `src/services/threatApi.ts:1821-1834` (`GeneratedHunt`)
- Modify: `src/pages/Hunting.tsx` (aviso ao lado do de tabela)
- Test: `server/test/huntGenerator.test.js`

**Interfaces:**
- Consumes: `extractTables(kql)` que já existe.
- Produces: `unknownColumns(kql, catalog) -> string[]`; `normalizeGenerated` passa a devolver `unknownColumns`.

- [ ] **Step 1: Escrever o teste que falha**

Acrescentar a `server/test/huntGenerator.test.js`:

```js
import { unknownColumns } from '../huntGenerator.js';

const CATALOG_COL = [{
    table: 'SigninLogs',
    source: 'Sentinel',
    columns: [
        { name: 'TimeGenerated', type: 'datetime' },
        { name: 'UserPrincipalName', type: 'string' },
        { name: 'ResultType', type: 'string' },
    ],
}];

test('coluna que não existe na tabela citada vira aviso', () => {
    const kql = 'SigninLogs | where TimeGenerated > ago(1d) | where UserRiskScore > 5';
    assert.deepEqual(unknownColumns(kql, CATALOG_COL), ['UserRiskScore']);
});

test('nome definido pela própria consulta não vira aviso', () => {
    const kql = [
        'let upn="a@b.test";',
        'SigninLogs',
        '| where UserPrincipalName =~ upn',
        '| extend Pais="BR"',
        '| summarize Falhas=countif(ResultType != 0) by UserPrincipalName, Pais',
        '| sort by Falhas desc',
    ].join(' ');
    assert.deepEqual(unknownColumns(kql, CATALOG_COL), []);
});

test('literal de texto não é lido como coluna', () => {
    const kql = 'SigninLogs | where UserPrincipalName has "Go-http-client" | project TimeGenerated';
    assert.deepEqual(unknownColumns(kql, CATALOG_COL), []);
});

test('consulta sem tabela conhecida não gera aviso de coluna', () => {
    // unknownTables já reporta o problema; dois avisos para o mesmo erro é ruído.
    assert.deepEqual(unknownColumns('TabelaInventada | where Qualquer == 1', CATALOG_COL), []);
});

test('normalizeGenerated devolve as colunas desconhecidas', () => {
    const out = normalizeGenerated(
        { query: 'SigninLogs | where UserRiskScore > 5', title: 'x', hypothesis: 'y' },
        CATALOG_COL,
    );
    assert.deepEqual(out.unknownColumns, ['UserRiskScore']);
    assert.deepEqual(out.unknownTables, []);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `node --test server/test/huntGenerator.test.js`
Expected: FAIL — `unknownColumns is not a function`.

- [ ] **Step 3: Implementar em `server/huntGenerator.js`**

Acrescentar depois de `unknownTables`:

```js
// Operador, palavra-chave e literal de KQL que aparecem soltos numa consulta.
// Função é descontada por outro caminho: nome seguido de "(" nunca é coluna.
const KQL_OPERATORS = new Set([
    ...KQL_KEYWORDS,
    'has', 'has_any', 'has_all', 'hasprefix', 'hassuffix', 'contains', 'startswith', 'endswith',
    'matches', 'regex', 'in', 'not', 'between', 'asc', 'desc', 'nulls', 'first', 'last',
    'isfuzzy', 'kind', 'hint', 'inner', 'leftouter', 'rightouter', 'fullouter', 'anti', 'semi',
    'true', 'false', 'null', 'project-away', 'project-keep', 'project-rename', 'mv-expand',
    'materialize', 'with', 'step', 'from', 'to', 'as', 'd', 'h', 'm', 's',
]);

// Comentário e literal saem antes: "Go-http-client" não é nome de coluna.
const stripLiterals = (kql) => String(kql ?? '')
    .replace(/\/\/[^\n]*/g, ' ')
    .replace(/"(?:[^"\\]|\\.)*"/g, ' ')
    .replace(/'(?:[^'\\]|\\.)*'/g, ' ');

/**
 * Colunas citadas pela consulta que não existem em nenhuma tabela que ela toca.
 * É aviso, não bloqueio: KQL tem forma demais para uma heurística de linha
 * decidir sozinha, e barrar consulta boa é pior que deixar passar um aviso.
 *
 * ponytail: varredura de identificador com desconto de alias e de chamada de
 * função. Se o ruído incomodar, trocar por parser de KQL de verdade.
 */
export function unknownColumns(kql, catalog) {
    const text = stripLiterals(kql);
    const tables = new Set(extractTables(kql).map((name) => name.toLowerCase()));

    const known = new Set();
    for (const entry of catalog) {
        if (!tables.has(entry.table.toLowerCase())) continue;
        for (const column of entry.columns) known.add(column.name.toLowerCase());
    }
    // Nenhuma tabela conhecida: quem fala disso é unknownTables.
    if (!known.size) return [];

    const defined = new Set(tables);
    for (const match of text.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])/g)) defined.add(match[1].toLowerCase());
    for (const entry of catalog) defined.add(entry.table.toLowerCase());

    const found = new Set();
    for (const match of text.matchAll(/([A-Za-z_][A-Za-z0-9_]*)(\s*\()?/g)) {
        const [, name, call] = match;
        if (call) continue;
        const lower = name.toLowerCase();
        if (KQL_OPERATORS.has(lower) || defined.has(lower) || known.has(lower)) continue;
        found.add(name);
    }
    return [...found];
}
```

Em `normalizeGenerated`, acrescentar ao objeto devolvido:

```js
        unknownTables: missing,
        unknownColumns: query ? unknownColumns(query, catalog) : [],
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `node --test server/test/huntGenerator.test.js`
Expected: PASS.

- [ ] **Step 5: Mostrar o aviso na tela**

Em `src/services/threatApi.ts`, na interface `GeneratedHunt`, depois de `unknownTables`:

```ts
    /** Colunas que a consulta cita e nenhuma tabela citada tem — aviso, não erro. */
    unknownColumns: string[];
    /** Ids das consultas curadas usadas como exemplo no prompt. */
    examplesUsed: string[];
```

O aviso de tabela é um toast em `src/pages/Hunting.tsx:774-775`, dentro do
handler de geração. O de coluna é irmão dele e vem logo depois, porque os dois
podem valer ao mesmo tempo — tabela inventada e coluna inventada são erros
diferentes do mesmo palpite:

```tsx
      if (result.unknownTables.length) {
        toast.warning(`Revise: a consulta cita tabela que o workspace não tem — ${result.unknownTables.join(", ")}`);
      } else if (!result.query) {
        toast.info("O modelo não conseguiu montar a consulta com essas tabelas. Veja as notas.");
      } else {
        toast.success(`Consulta gerada com ${result.model}`);
      }

      if (result.unknownColumns?.length) {
        toast.warning(`Confira: coluna fora do esquema mapeado — ${result.unknownColumns.join(", ")}`);
      }
```

- [ ] **Step 6: Verificar tipo e build**

Run: `npm run typecheck && npm run lint`
Expected: sem erro.

- [ ] **Step 7: Commit**

```bash
git add server/huntGenerator.js server/test/huntGenerator.test.js src/services/threatApi.ts src/pages/Hunting.tsx
git commit -m "feat: avisar quando a consulta gerada cita coluna que não existe"
```

---

## Fase 3 — Biblioteca curada na tela

### Task 6: Rota das consultas curadas

**Files:**
- Modify: `server/index.js` (rota nova depois de `/api/hunts/kql/content`)
- Modify: `src/services/threatApi.ts` (tipo + fetch)
- Test: `server/test/smoke.test.js`

**Interfaces:**
- Consumes: `huntingRefs.library` da Task 4.
- Produces: `GET /api/hunts/kql/curated` → `{ queries: CuratedQuery[], total: number, sections: string[] }`; no cliente, `fetchCuratedKql()` e o tipo `CuratedQuery`.

- [ ] **Step 1: Implementar a rota**

Em `server/index.js`, depois da rota `/api/hunts/kql/content`:

```js
// Biblioteca curada: 41 consultas com pergunta, objetivo e parâmetros. Vai
// inteira — são poucos KB, não precisa do carregamento sob demanda que as 237
// do repositório precisam.
app.get('/api/hunts/kql/curated', requirePremium, (req, res) => {
    const queries = huntingRefs.library;
    res.json({
        queries,
        total: queries.length,
        sections: [...new Set(queries.map((item) => item.section).filter(Boolean))],
    });
});
```

- [ ] **Step 2: Cliente**

Em `src/services/threatApi.ts`, junto das outras funções de hunt:

```ts
export interface CuratedQuery {
    id: string;
    section: string;
    question: string;
    objective: string;
    tables: string[];
    query: string;
    params: string[];
    validation: string;
}

export const fetchCuratedKql = async (): Promise<{ queries: CuratedQuery[]; total: number; sections: string[] }> =>
    handleResponse(await fetch('/api/hunts/kql/curated'), 'Hunting');
```

- [ ] **Step 3: Verificar**

Run: `npm run typecheck && npm run test:server`
Expected: sem erro; testes passam.

- [ ] **Step 4: Commit**

```bash
git add server/index.js src/services/threatApi.ts
git commit -m "feat: publicar a biblioteca curada de KQLs"
```

---

### Task 7: Origem "Curadas" na aba Queries

**Files:**
- Modify: `src/pages/Hunting.tsx:1165-1194` (aba `kql`)
- Create: `src/pages/huntingKql.ts`
- Test: `src/pages/huntingKql.test.ts`

**Interfaces:**
- Consumes: `CuratedQuery` da Task 6.
- Produces: `fillParams(query, values) -> string`, `paramPlaceholders(query) -> string[]`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `src/pages/huntingKql.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { fillParams, paramPlaceholders } from "./huntingKql.ts";

test("acha os placeholders da consulta, sem repetir", () => {
  const query = 'let ioc="<IOC>"; search ioc | where Campo has "<IOC>" or Outro == "<UPN>"';
  assert.deepEqual(paramPlaceholders(query), ["IOC", "UPN"]);
});

test("substitui só o que foi preenchido", () => {
  const query = 'let ioc="<IOC>"; let upn="<UPN>";';
  assert.equal(fillParams(query, { IOC: "1.2.3.4" }), 'let ioc="1.2.3.4"; let upn="<UPN>";');
});

test("valor com caractere especial de regex não quebra a substituição", () => {
  assert.equal(fillParams('x="<IOC>"', { IOC: "a$b\\c" }), 'x="a$b\\c"');
});

test("consulta sem placeholder volta igual", () => {
  const query = "SigninLogs | where ResultType != 0";
  assert.equal(fillParams(query, { IOC: "1.2.3.4" }), query);
  assert.deepEqual(paramPlaceholders(query), []);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `npm run test:unit`
Expected: FAIL — módulo `huntingKql.ts` não existe.

- [ ] **Step 3: Implementar `src/pages/huntingKql.ts`**

```ts
// Consulta curada vem com placeholder no lugar do indicador: <IOC>, <UPN>,
// <IP>, <DOMINIO>. Quem copia precisa do valor dentro, não do sinal de onde
// ele deveria ir.

const PLACEHOLDER = /<([A-Z_]{2,30})>/g;

/** Os placeholders da consulta, na ordem em que aparecem e sem repetir. */
export function paramPlaceholders(query: string): string[] {
  return [...new Set([...(query || "").matchAll(PLACEHOLDER)].map((match) => match[1]))];
}

/**
 * Troca os placeholders pelos valores preenchidos. O que não foi preenchido
 * fica como está — consulta meio parametrizada ainda é útil para copiar e
 * terminar no Sentinel.
 */
export function fillParams(query: string, values: Record<string, string>): string {
  return (query || "").replace(PLACEHOLDER, (whole, name: string) => {
    const value = values[name];
    return value && value.trim() ? value : whole;
  });
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `npm run test:unit`
Expected: PASS.

- [ ] **Step 5: Ligar na tela**

Em `src/pages/Hunting.tsx`:

Imports:
```tsx
import { fetchCuratedKql, type CuratedQuery } from "@/services/threatApi";
import { fillParams, paramPlaceholders } from "./huntingKql";
```

Estado, junto dos outros `useState` do componente `Hunting`:
```tsx
const [curated, setCurated] = useState<CuratedQuery[]>([]);
const [kqlOrigin, setKqlOrigin] = useState<"curated" | "repo">("curated");
const [openCurated, setOpenCurated] = useState<CuratedQuery | null>(null);
const [paramValues, setParamValues] = useState<Record<string, string>>({});
```

Carregamento, junto do `useEffect` que já busca `kqlIndex`:
```tsx
useEffect(() => {
  fetchCuratedKql().then((data) => setCurated(data.queries)).catch(() => setCurated([]));
}, []);
```

Na `TabsContent value="kql"`, antes do campo de busca, o seletor de origem:
```tsx
<Tabs value={kqlOrigin} onValueChange={(value) => setKqlOrigin(value as "curated" | "repo")}>
  <TabsList>
    <TabsTrigger value="curated">Curadas <span className="ml-2 text-xs text-muted-foreground">{curated.length}</span></TabsTrigger>
    <TabsTrigger value="repo">Repositório <span className="ml-2 text-xs text-muted-foreground">{kqlIndex.length}</span></TabsTrigger>
  </TabsList>
</Tabs>
```

A grade de curadas, irmã da grade que já existe, renderizada quando `kqlOrigin === "curated"`:
```tsx
{curated
  .filter((item) => `${item.section} ${item.question} ${item.objective}`.toLowerCase().includes(kqlQuery.trim().toLowerCase()))
  .slice(0, 60)
  .map((item) => (
    <button
      key={item.id}
      type="button"
      onClick={() => { setOpenCurated(item); setParamValues({}); }}
      className="rounded-md border p-3 text-left transition-colors hover:border-primary/50"
    >
      <div className="truncate text-sm font-medium">{item.question}</div>
      <div className="mt-0.5 truncate text-xs text-muted-foreground">{item.objective}</div>
      <div className="mt-1 font-mono text-[11px] text-muted-foreground">{item.tables.join(", ")}</div>
    </button>
  ))}
```

O diálogo da consulta curada, com um campo por placeholder e o `KqlBlock` que já existe recebendo a consulta preenchida:
```tsx
<Dialog open={!!openCurated} onOpenChange={(next) => !next && setOpenCurated(null)}>
  <DialogContent className="sm:max-w-3xl">
    <DialogHeader>
      <DialogTitle>{openCurated?.question}</DialogTitle>
      <DialogDescription>{openCurated?.objective} · {openCurated?.validation}</DialogDescription>
    </DialogHeader>
    {!!openCurated && (
      <div className="space-y-4">
        {paramPlaceholders(openCurated.query).length > 0 && (
          <div className="grid gap-3 sm:grid-cols-2">
            {paramPlaceholders(openCurated.query).map((name) => (
              <div key={name} className="space-y-1.5">
                <Label htmlFor={`param-${name}`}>{name}</Label>
                <Input
                  id={`param-${name}`}
                  value={paramValues[name] || ""}
                  onChange={(event) => setParamValues((prev) => ({ ...prev, [name]: event.target.value }))}
                  placeholder={`Valor para <${name}>`}
                />
              </div>
            ))}
          </div>
        )}
        <KqlBlock query={fillParams(openCurated.query, paramValues)} />
      </div>
    )}
  </DialogContent>
</Dialog>
```

- [ ] **Step 6: Verificar**

Run: `npm run typecheck && npm run lint && npm run build`
Expected: sem erro.

- [ ] **Step 7: Commit**

```bash
git add src/pages/Hunting.tsx src/pages/huntingKql.ts src/pages/huntingKql.test.ts
git commit -m "feat: consultas curadas parametrizáveis na aba de queries"
```

---

## Fase 4 — Modelo

### Task 8: Campos de documentação e lista de consultas na hunt

**Files:**
- Modify: `server/hunts.js:56-106` (`normalizeHuntInput`), `server/hunts.js:229-246` (`withDefaults`)
- Modify: `src/services/threatApi.ts:1689-1714` (`PrivateHunt`)
- Test: `server/test/hunts.test.js`

**Interfaces:**
- Consumes: nada.
- Produces: hunt com `objective`, `scope`, `exclusions`, `priority`, `huntType`, `intelSource: {title, url}`, `queries: Array<{id, label, query}>`; `query` continua existindo como espelho de `queries[0].query`.

- [ ] **Step 1: Escrever o teste que falha**

Acrescentar a `server/test/hunts.test.js`:

```js
const base = { title: 'Hunt', hypothesis: 'Hipótese' };
const owner = { ownerSub: 'u1' };

test('campos de documentação entram validados', () => {
    const hunt = normalizeHuntInput({
        ...base, objective: 'Validar interação com a infraestrutura da campanha',
        scope: 'Perímetro e endpoint', exclusions: 'Navegação legítima',
        priority: 'alta', huntType: 'intel',
        intelSource: { title: 'Relatório de campanha', url: 'https://exemplo.test/rel' },
    }, owner);

    assert.equal(hunt.objective, 'Validar interação com a infraestrutura da campanha');
    assert.equal(hunt.priority, 'alta');
    assert.equal(hunt.huntType, 'intel');
    assert.deepEqual(hunt.intelSource, { title: 'Relatório de campanha', url: 'https://exemplo.test/rel' });
});

test('prioridade e tipo fora da lista são recusados', () => {
    assert.throws(() => normalizeHuntInput({ ...base, priority: 'urgentíssima' }, owner), /prioridade/i);
    assert.throws(() => normalizeHuntInput({ ...base, huntType: 'chute' }, owner), /tipo de hunting/i);
});

test('origem de inteligência só aceita http(s)', () => {
    assert.throws(
        () => normalizeHuntInput({ ...base, intelSource: { title: 'x', url: 'javascript:alert(1)' } }, owner),
        /URL de inteligência/i,
    );
});

test('lista de consultas ganha id e vira espelho de query', () => {
    const hunt = normalizeHuntInput({
        ...base,
        queries: [
            { label: 'IOC principal', query: 'CommonSecurityLog | where SourceIP == ip' },
            { label: '', query: '' },
            { label: 'Domínios', query: 'CommonSecurityLog | where RequestURL has d' },
        ],
    }, owner);

    assert.deepEqual(hunt.queries.map((item) => item.id), ['q1', 'q3']);
    assert.equal(hunt.queries.length, 2, 'consulta vazia não entra');
    assert.equal(hunt.query, 'CommonSecurityLog | where SourceIP == ip', 'query espelha a primeira');
});

test('hunt salva só com query ganha a lista na leitura', () => {
    const antiga = { id: 'TH-2026-001', title: 'x', hypothesis: 'y', query: 'SigninLogs | take 10' };
    const hunt = withDefaults(antiga);
    assert.deepEqual(hunt.queries, [{ id: 'q1', label: '', query: 'SigninLogs | take 10' }]);
    assert.equal(hunt.objective, '', 'campo novo tem padrão, não undefined');
    assert.equal(hunt.priority, '');
});

test('hunt sem consulta nenhuma tem lista vazia', () => {
    assert.deepEqual(normalizeHuntInput(base, owner).queries, []);
    assert.deepEqual(withDefaults({ id: 'TH-2026-002', title: 'x', hypothesis: 'y' }).queries, []);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `node --test server/test/hunts.test.js`
Expected: FAIL — `hunt.objective` é `undefined`.

- [ ] **Step 3: Implementar em `server/hunts.js`**

Acrescentar perto das outras constantes do topo:

```js
const PRIORITIES = new Set(['', 'baixa', 'media', 'alta', 'critica']);
const HUNT_TYPES = new Set(['', 'hypothesis', 'intel']);
export const QUERIES_CAP = 20;

/** URL de origem da inteligência. Só http(s): o resto não é referência, é vetor. */
const cleanUrl = (value) => {
    const url = clean(value, 500);
    if (!url) return '';
    if (!/^https?:\/\//i.test(url)) throw new Error('URL de inteligência inválida');
    return url;
};

/**
 * A hunt do formulário tem várias consultas — IOC principal, domínios,
 * enumeração — e cada uma precisa de rótulo para o relatório citar. Consulta
 * sem corpo é descartada; o id sobrevive à ordem, então evidência gravada
 * continua apontando para a consulta certa depois de remover outra.
 */
function cleanQueries(input, fallback) {
    const list = (Array.isArray(input) ? input : [])
        .map((item, index) => ({
            id: clean(item?.id, 20) || `q${index + 1}`,
            label: clean(item?.label, 160),
            query: clean(item?.query, 100000),
        }))
        .filter((item) => item.query)
        .slice(0, QUERIES_CAP);

    if (list.length) return list;
    return fallback ? [{ id: 'q1', label: '', query: fallback }] : [];
}
```

Dentro de `normalizeHuntInput`, antes do `return`:

```js
    const priority = clean(input.priority, 20).toLowerCase();
    if (!PRIORITIES.has(priority)) throw new Error('prioridade inválida');

    const huntType = clean(input.huntType, 20).toLowerCase();
    if (!HUNT_TYPES.has(huntType)) throw new Error('tipo de hunting inválido');

    const queries = cleanQueries(input.queries, clean(input.query, 100000));
```

E no objeto devolvido, trocar a linha `query: clean(input.query, 100000),` por:

```js
        queries,
        // Espelho da primeira consulta: o detalhe da hunt e /api/hunts/by-technique
        // ainda leem `query`. Some quando os dois passarem a ler `queries`.
        query: queries[0]?.query || '',
        objective: clean(input.objective, 4000),
        scope: clean(input.scope, 4000),
        exclusions: clean(input.exclusions, 4000),
        priority,
        huntType,
        intelSource: {
            title: clean(input.intelSource?.title, 300),
            url: cleanUrl(input.intelSource?.url),
        },
```

Em `withDefaults`, acrescentar ao objeto devolvido:

```js
        queries: Array.isArray(hunt?.queries) && hunt.queries.length
            ? hunt.queries
            : (hunt?.query ? [{ id: 'q1', label: '', query: hunt.query }] : []),
        objective: hunt?.objective || '',
        scope: hunt?.scope || '',
        exclusions: hunt?.exclusions || '',
        priority: PRIORITIES.has(hunt?.priority) ? hunt.priority : '',
        huntType: HUNT_TYPES.has(hunt?.huntType) ? hunt.huntType : '',
        intelSource: {
            title: hunt?.intelSource?.title || '',
            url: hunt?.intelSource?.url || '',
        },
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `npm run test:server`
Expected: PASS — os 23 testes antigos de hunts inclusive.

- [ ] **Step 5: Tipos do cliente**

Em `src/services/threatApi.ts`, na interface `PrivateHunt`, depois de `query`:

```ts
    /** Consultas da hunt; `query` é o espelho da primeira. */
    queries: { id: string; label: string; query: string }[];
    objective: string;
    scope: string;
    exclusions: string;
    /** '', 'baixa', 'media', 'alta' ou 'critica'. */
    priority: string;
    /** '', 'hypothesis' ou 'intel'. */
    huntType: string;
    intelSource: { title: string; url: string };
```

- [ ] **Step 6: Acompanhar as quatro funções do formulário**

`HuntInput` é `Omit<PrivateHunt, …>`, então o campo novo no tipo quebra o
`inputOf` no mesmo commit — o typecheck só fecha com as quatro funções em dia.
Elas andam juntas: tipo, vazio, hidratação e payload. Mexer em três e esquecer
a quarta é o jeito de o campo salvar e não voltar na edição.

Em `HuntForm` (`src/pages/Hunting.tsx:36`), acrescentar ao tipo:

```tsx
  objective: string; scope: string; exclusions: string; priority: string; huntType: string;
  intelSourceTitle: string; intelSourceUrl: string;
  queries: { id: string; label: string; query: string }[];
```

Em `EMPTY_FORM` (linha 43):

```tsx
  objective: "", scope: "", exclusions: "", priority: "", huntType: "",
  intelSourceTitle: "", intelSourceUrl: "", queries: [],
```

Em `formOf` (linha 50):

```tsx
  objective: hunt.objective || "", scope: hunt.scope || "", exclusions: hunt.exclusions || "",
  priority: hunt.priority || "", huntType: hunt.huntType || "",
  intelSourceTitle: hunt.intelSource?.title || "", intelSourceUrl: hunt.intelSource?.url || "",
  queries: hunt.queries || [],
```

Em `inputOf` (linha 57):

```tsx
  objective: form.objective, scope: form.scope, exclusions: form.exclusions,
  priority: form.priority, huntType: form.huntType,
  intelSource: { title: form.intelSourceTitle, url: form.intelSourceUrl },
  queries: form.queries,
```

O `query: form.query` de `inputOf` sai — o servidor deriva de `queries[0]`. O
campo `query` do `HuntForm` fica por enquanto: quem o usa é o `<Textarea>`
único que a Task 12 substitui.

Run: `npm run typecheck`
Expected: sem erro.

- [ ] **Step 7: Commit**

```bash
git add server/hunts.js server/test/hunts.test.js src/services/threatApi.ts src/pages/Hunting.tsx
git commit -m "feat: hunt carrega objetivo, escopo, prioridade e lista de consultas"
```

---

### Task 9: Janela investigada, recomendações e evidência na execução

**Files:**
- Modify: `server/hunts.js:13-14` (`RUN_OUTCOMES`), `server/hunts.js:113-145` (`normalizeRunInput`)
- Modify: `src/services/threatApi.ts:1716-1730` (`RunOutcome`, `HuntRun`)
- Test: `server/test/hunts.test.js`

**Interfaces:**
- Consumes: `queries[].id` da Task 8 (a evidência aponta para eles).
- Produces: run com `windowStart`, `windowEnd`, `recommendations`, `evidence: Array<{queryId, result}>`; `RUN_OUTCOMES` com cinco valores.

- [ ] **Step 1: Escrever o teste que falha**

Acrescentar a `server/test/hunts.test.js`:

```js
test('a janela investigada é normalizada para ISO', () => {
    const run = normalizeRunInput({
        state: 'done', outcome: 'none',
        windowStart: '2026-07-01T00:00:00-03:00', windowEnd: '2026-08-13T23:59:00-03:00',
    });
    assert.equal(run.windowStart, '2026-07-01T03:00:00.000Z');
    assert.equal(run.windowEnd, '2026-08-14T02:59:00.000Z');
});

test('janela invertida ou inválida é recusada', () => {
    assert.throws(() => normalizeRunInput({
        windowStart: '2026-08-13T00:00:00Z', windowEnd: '2026-07-01T00:00:00Z',
    }), /janela/i);
    assert.throws(() => normalizeRunInput({ windowStart: 'ontem' }), /timestamp inicial/i);
});

test('janela vazia continua válida', () => {
    const run = normalizeRunInput({});
    assert.equal(run.windowStart, '');
    assert.equal(run.windowEnd, '');
});

test('os quatro resultados do formulário são aceitos', () => {
    for (const outcome of ['none', 'suspicious', 'incident', 'falsepositive', 'legitimate']) {
        assert.equal(normalizeRunInput({ state: 'done', outcome }).outcome, outcome);
    }
    assert.throws(() => normalizeRunInput({ state: 'done', outcome: 'talvez' }), /resultado inválido/i);
});

test('evidência sem consulta ou sem resultado é descartada', () => {
    const run = normalizeRunInput({
        state: 'done', outcome: 'none',
        evidence: [
            { queryId: 'q1', result: '0 eventos' },
            { queryId: '', result: 'órfã' },
            { queryId: 'q2', result: '' },
            { queryId: 'q3', result: '15.425 requisições' },
        ],
    });
    assert.deepEqual(run.evidence, [
        { queryId: 'q1', result: '0 eventos' },
        { queryId: 'q3', result: '15.425 requisições' },
    ]);
});

test('recomendações entram na execução fechada', () => {
    const run = normalizeRunInput({ state: 'done', outcome: 'legitimate', recommendations: 'Revisar permissões de convidado.' });
    assert.equal(run.recommendations, 'Revisar permissões de convidado.');
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `node --test server/test/hunts.test.js`
Expected: FAIL — `run.windowStart` é `undefined`.

- [ ] **Step 3: Implementar em `server/hunts.js`**

Trocar a constante:

```js
// Os cinco resultados do formulário de hunting. 'none' = sem achados;
// 'falsepositive' e 'legitimate' separam "o alerta era ruído" de "a atividade
// existe e é legítima" — conclusões diferentes, tratativas diferentes.
export const RUN_OUTCOMES = ['none', 'suspicious', 'incident', 'falsepositive', 'legitimate'];
export const EVIDENCE_CAP = 20;
```

Acrescentar perto dos helpers do arquivo:

```js
/** Timestamp opcional em ISO. Texto que não é data é erro, não silêncio. */
const isoOrEmpty = (value, label) => {
    const raw = clean(value, 40);
    if (!raw) return '';
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) throw new Error(`${label} inválido`);
    return date.toISOString();
};
```

Dentro de `normalizeRunInput`, antes do `return`:

```js
    // A janela investigada não é quando o analista trabalhou: uma caça aberta
    // hoje pode olhar julho. O relatório precisa das duas coisas.
    const windowStart = isoOrEmpty(input.windowStart, 'timestamp inicial');
    const windowEnd = isoOrEmpty(input.windowEnd, 'timestamp final');
    if (windowStart && windowEnd && windowEnd < windowStart) throw new Error('janela invertida');

    const evidence = (Array.isArray(input.evidence) ? input.evidence : [])
        .map((item) => ({ queryId: clean(item?.queryId, 20), result: clean(item?.result, 300) }))
        .filter((item) => item.queryId && item.result)
        .slice(0, EVIDENCE_CAP);
```

E no objeto devolvido:

```js
        windowStart,
        windowEnd,
        recommendations: clean(input.recommendations, 5000),
        evidence,
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `npm run test:server`
Expected: PASS.

- [ ] **Step 5: Tipos do cliente**

Em `src/services/threatApi.ts`:

```ts
export type RunOutcome = 'none' | 'suspicious' | 'incident' | 'falsepositive' | 'legitimate';
```

e na interface `HuntRun`, depois de `findings`:

```ts
    /** Janela investigada — não confundir com startedAt/finishedAt. */
    windowStart: string;
    windowEnd: string;
    recommendations: string;
    evidence: { queryId: string; result: string }[];
```

Em `src/pages/Hunting.tsx:444`, completar `OUTCOME_LABEL`:

```tsx
const OUTCOME_LABEL: Record<RunOutcome, string> = {
  none: "Sem achados",
  suspicious: "Suspeito",
  incident: "Incidente",
  falsepositive: "Falso positivo",
  legitimate: "Atividade legítima",
};
```

- [ ] **Step 6: Verificar**

Run: `npm run typecheck && npm run lint`
Expected: sem erro.

- [ ] **Step 7: Commit**

```bash
git add server/hunts.js server/test/hunts.test.js src/services/threatApi.ts src/pages/Hunting.tsx
git commit -m "feat: execução guarda janela investigada, recomendações e evidência"
```

---

## Fase 5 — Relatório

### Task 10: Renderer de PDF compartilhado

**Files:**
- Create: `src/utils/reportPdf.ts`
- Modify: `src/utils/boletimExport.ts:18-24` (tipos) e `:95-163` (`exportBoletimPDF`)
- Test: `src/utils/boletimExport.test.ts` (tem que passar **sem alteração**)

**Interfaces:**
- Consumes: `jspdf`, `jspdf-autotable` por `import()` dinâmico.
- Produces: `type Block` (com `code` e `fields`), `type ReportSection`, `REPORT_COLORS`, `rgb(hex)`, `exportSectionsPdf({ sections, header, footer, filename })`.

- [ ] **Step 1: Criar `src/utils/reportPdf.ts`**

```ts
// Renderer de PDF compartilhado. O boletim e o relatório de hunting descrevem
// as mesmas coisas — seção, texto, lista, tabela, bloco de código, grade de
// campos — e divergem só no cabeçalho. Manter dois renderers significava dois
// lugares para consertar quebra de página.
export const REPORT_COLORS = {
    blue: '1565C0', navy: '172033', slate: '526274', border: 'DCE3EE', white: 'FFFFFF', mist: 'F1F5F9',
} as const;

export const rgb = (hex: string): [number, number, number] =>
    [0, 2, 4].map((offset) => parseInt(hex.substr(offset, 2), 16)) as [number, number, number];

export type Block =
    | { kind: 'text'; text: string }
    | { kind: 'bullets'; items: string[] }
    | { kind: 'table'; head: string[]; rows: string[][] }
    | { kind: 'code'; text: string }
    | { kind: 'fields'; rows: [string, string][] };

export type ReportSection = { title: string; blocks: Block[] };

export type ReportHeader = { title: string; subtitle: string; right?: string };

/**
 * Desenha as seções e salva. `footer`, quando vem, é repetido em todas as
 * páginas com a numeração — é o rodapé de documento controlado.
 */
export async function exportSectionsPdf({ sections, header, footer, filename }: {
    sections: ReportSection[];
    header: ReportHeader;
    footer?: string;
    filename: string;
}): Promise<void> {
    const [{ jsPDF }, { default: autoTable }] = await Promise.all([import('jspdf'), import('jspdf-autotable')]);

    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 14;
    const width = pageW - margin * 2;

    doc.setFillColor(...rgb(REPORT_COLORS.navy));
    doc.rect(0, 0, pageW, 46, 'F');
    doc.setFillColor(...rgb(REPORT_COLORS.blue));
    doc.rect(0, 46, pageW, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text(doc.splitTextToSize(header.title, width).slice(0, 2), margin, 20);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(203, 213, 225);
    doc.text(header.subtitle, margin, 38);
    if (header.right) doc.text(header.right.slice(0, 80), pageW - margin, 38, { align: 'right' });

    let y = 58;
    // Quebra de página manual: cada bloco pede o espaço que precisa antes de
    // desenhar. Sem isso o texto sai por baixo da margem.
    const room = (need: number) => { if (y + need > pageH - margin - (footer ? 8 : 0)) { doc.addPage(); y = margin + 6; } };

    for (const part of sections) {
        room(16);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(11);
        doc.setTextColor(...rgb(REPORT_COLORS.blue));
        doc.text(part.title.toUpperCase(), margin, y);
        y += 6;
        doc.setTextColor(...rgb(REPORT_COLORS.navy));

        for (const block of part.blocks) {
            if (block.kind === 'table' || block.kind === 'fields') {
                const table = block.kind === 'table'
                    ? { head: [block.head], body: block.rows }
                    : { head: undefined, body: block.rows.map(([label, value]) => [label, value]) };
                autoTable(doc, {
                    startY: y,
                    head: table.head,
                    body: table.body,
                    styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
                    headStyles: { fillColor: rgb(REPORT_COLORS.navy), textColor: 255 },
                    columnStyles: block.kind === 'fields' ? { 0: { fontStyle: 'bold', cellWidth: 42 } } : undefined,
                    margin: { left: margin, right: margin },
                });
                y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
                continue;
            }

            if (block.kind === 'code') {
                doc.setFont('courier', 'normal');
                doc.setFontSize(7.5);
                const lines = block.text.split('\n').flatMap((line) => doc.splitTextToSize(line, width - 6));
                for (const line of lines) {
                    room(5);
                    doc.setFillColor(...rgb(REPORT_COLORS.mist));
                    doc.rect(margin, y - 3.2, width, 4.4, 'F');
                    doc.text(line, margin + 2, y);
                    y += 4.4;
                }
                doc.setFont('helvetica', 'normal');
                y += 3;
                continue;
            }

            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
            const lines = block.kind === 'text'
                ? doc.splitTextToSize(block.text, width)
                : block.items.flatMap((item) => doc.splitTextToSize(`•  ${item}`, width - 3));
            for (const line of lines) {
                room(6);
                doc.text(line, block.kind === 'text' ? margin : margin + 3, y);
                y += 4.6;
            }
            y += 3;
        }
        y += 2;
    }

    if (footer) {
        const pages = doc.getNumberOfPages();
        for (let page = 1; page <= pages; page += 1) {
            doc.setPage(page);
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(7);
            doc.setTextColor(...rgb(REPORT_COLORS.slate));
            doc.text(footer, margin, pageH - 8);
            doc.text(`Página ${page} de ${pages}`, pageW - margin, pageH - 8, { align: 'right' });
        }
    }

    doc.save(`${filename}.pdf`);
}
```

- [ ] **Step 2: Boletim passa a usar o renderer**

Em `src/utils/boletimExport.ts`:

Trocar a declaração local de `Block`/`ReportSection` (linhas ~20-24) por um reexport, para não quebrar quem importa daqui:

```ts
import { exportSectionsPdf, REPORT_COLORS, rgb, type Block, type ReportSection } from './reportPdf';
export type { Block, ReportSection };
```

Trocar a constante `COLORS` local por `REPORT_COLORS` nas referências do PPTX (`COLORS.navy` → `REPORT_COLORS.navy`), ou manter `const COLORS = REPORT_COLORS;` — a segunda é um diff menor e não mexe no PPTX.

Substituir todo o corpo de `exportBoletimPDF` por:

```ts
export async function exportBoletimPDF(job: BoletimJob): Promise<void> {
    const report = job.json;
    if (!report) throw new Error('Relatório sem conteúdo');

    await exportSectionsPdf({
        sections: boletimSections(report),
        header: {
            title: report.titulo || job.title || job.url,
            subtitle: subtitle(job),
            right: report.source_url || undefined,
        },
        filename: boletimFilename(job),
    });
}
```

Remover o `rgb` local se ficar sem uso (o PPTX usa hex, não rgb) — o lint acusa.

- [ ] **Step 3: Rodar o teste de não-regressão**

Run: `npm run test:unit && npm run typecheck && npm run lint`
Expected: PASS — `boletimExport.test.ts` sem nenhuma alteração.

- [ ] **Step 4: Conferir o PDF na mão**

Run: `npm run dev`, abrir a workstation de relatórios, gerar um boletim e exportar PDF.
Expected: mesmo documento de antes — cabeçalho azul-marinho, seções, tabelas.

- [ ] **Step 5: Commit**

```bash
git add src/utils/reportPdf.ts src/utils/boletimExport.ts
git commit -m "refactor: extrair o renderer de PDF que o boletim e o hunting compartilham"
```

---

### Task 11: Seções do relatório de hunting

**Files:**
- Create: `src/utils/huntReportExport.ts`
- Test: `src/utils/huntReportExport.test.ts`

**Interfaces:**
- Consumes: `PrivateHunt`, `HuntRun` de `threatApi`; `Block`, `ReportSection`, `exportSectionsPdf` da Task 10; `formatKql` de `src/utils/kql.ts`.
- Produces: `type ReportIdentity = { company: string; unit: string; analyst: string }`, `huntReportSections(hunt, run, identity) -> ReportSection[]`, `huntReportFilename(hunt, run) -> string`, `exportHuntReportPDF(hunt, run, identity) -> Promise<void>`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `src/utils/huntReportExport.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { huntReportSections, huntReportFilename } from "./huntReportExport.ts";
import type { PrivateHunt, HuntRun } from "@/services/threatApi";

const hunt = {
  id: "TH-2026-004", ownerSub: "u1", title: "Campanha de portais expostos",
  hypothesis: "Um ator pode ter interagido com ativos da organização.",
  objective: "Validar interação com a infraestrutura da campanha.",
  scope: "Tráfego de perímetro e telemetria de endpoint.",
  exclusions: "Navegação legítima a portais públicos.",
  priority: "alta", huntType: "intel",
  intelSource: { title: "Relatório de campanha", url: "https://exemplo.test/rel" },
  tactics: [], techniques: ["T1595.001", "T1071.001"], cves: [], technologies: [], dataSources: [],
  queries: [
    { id: "q1", label: "IOC principal (IP)", query: 'let IOC="203.0.113.9"; CommonSecurityLog | where SourceIP == IOC' },
    { id: "q2", label: "Domínios da campanha", query: 'CommonSecurityLog | where RequestURL has "exemplo"' },
  ],
  query: "", queryLang: "kql", notes: "", falsePositives: "", status: "ready",
  sourceReportId: "", hearthId: "", cadence: "monthly", adoptedFrom: "", sourceId: "",
  runs: [], createdAt: "2026-08-13T12:00:00.000Z", updatedAt: "2026-08-13T12:00:00.000Z",
} as unknown as PrivateHunt;

const run = {
  id: "r1", state: "done", outcome: "none", events: 0, hosts: 0,
  findings: "Sem achados relacionados à campanha.",
  recommendations: "Revisar permissões de convidado.",
  windowStart: "2026-07-01T03:00:00.000Z", windowEnd: "2026-08-14T02:59:00.000Z",
  evidence: [{ queryId: "q1", result: "0 eventos" }],
  startedAt: "2026-08-13T12:00:00.000Z", finishedAt: "2026-08-13T18:00:00.000Z",
  updatedAt: "2026-08-13T18:00:00.000Z",
} as unknown as HuntRun;

const identity = { company: "Organização", unit: "Todas", analyst: "Analista CTI" };

test("as seções saem na ordem do formulário", () => {
  assert.deepEqual(huntReportSections(hunt, run, identity).map((s) => s.title), [
    "Identificação do hunting",
    "Hipótese e escopo",
    "Resultados e conclusões",
    "Fontes de dados e consultas",
    "Mapeamento MITRE ATT&CK",
    "Tratativas e recomendações",
    "Anexo A — Consultas realizadas",
  ]);
});

test("a identificação leva id, janela investigada e resultado", () => {
  const [identificacao] = huntReportSections(hunt, run, identity);
  const fields = identificacao.blocks.find((block) => block.kind === "fields");
  assert.ok(fields && fields.kind === "fields");
  const byLabel = Object.fromEntries(fields.rows);
  assert.equal(byLabel["ID do hunt"], "TH-2026-004");
  assert.equal(byLabel["Analista responsável"], "Analista CTI");
  assert.equal(byLabel["Prioridade"], "Alta");
  assert.equal(byLabel["Tipo de hunting"], "Intel-driven");
  assert.equal(byLabel["Resultado"], "Sem achados");
  assert.match(byLabel["Janela investigada"], /2026/);
});

test("seção sem conteúdo não é impressa", () => {
  const semRecomendacao = { ...run, recommendations: "" } as HuntRun;
  const titles = huntReportSections(hunt, semRecomendacao, identity).map((s) => s.title);
  assert.ok(!titles.includes("Tratativas e recomendações"));
});

test("o anexo numera a consulta e casa a evidência pelo id", () => {
  const anexo = huntReportSections(hunt, run, identity).at(-1)!;
  const texts = anexo.blocks.map((block) =>
    block.kind === "text" ? block.text : block.kind === "code" ? "CODE" : block.kind);
  assert.deepEqual(texts, [
    "KQL-01 — IOC principal (IP)", "CODE", "Resultado observado: 0 eventos",
    "KQL-02 — Domínios da campanha", "CODE",
  ]);
});

test("a KQL do anexo é quebrada por operador", () => {
  const anexo = huntReportSections(hunt, run, identity).at(-1)!;
  const code = anexo.blocks.find((block) => block.kind === "code");
  assert.ok(code && code.kind === "code");
  assert.match(code.text, /\n\| where SourceIP == IOC/);
});

test("as fontes de dados saem das tabelas que as consultas citam", () => {
  const fontes = huntReportSections(hunt, run, identity)[3];
  const bullets = fontes.blocks.find((block) => block.kind === "bullets");
  assert.ok(bullets && bullets.kind === "bullets");
  assert.deepEqual(bullets.items, ["CommonSecurityLog"]);
});

test("a técnica vira link do ATT&CK", () => {
  const mitre = huntReportSections(hunt, run, identity)[4];
  const table = mitre.blocks.find((block) => block.kind === "table");
  assert.ok(table && table.kind === "table");
  assert.deepEqual(table.rows[0], ["T1595.001", "https://attack.mitre.org/techniques/T1595/001/"]);
});

test("o nome do arquivo identifica hunt e execução", () => {
  assert.equal(huntReportFilename(hunt, run), "hunting-TH-2026-004-2026-08-13");
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `npm run test:unit`
Expected: FAIL — módulo `huntReportExport.ts` não existe.

- [ ] **Step 3: Implementar `src/utils/huntReportExport.ts`**

```ts
// Relatório de hunting: uma execução vira documento. A hipótese, o objetivo e
// as consultas são da hunt; a janela investigada, o resultado, os achados e as
// recomendações são da execução — por isso o relatório se prende a ela.
import { formatKql } from './kql';
import { exportSectionsPdf, type Block, type ReportSection } from './reportPdf';
import type { HuntRun, PrivateHunt } from '@/services/threatApi';

/** Quem assina o documento. Constante entre relatórios, então mora na tela. */
export type ReportIdentity = { company: string; unit: string; analyst: string };

const PRIORITY_LABEL: Record<string, string> = {
    baixa: 'Baixa', media: 'Média', alta: 'Alta', critica: 'Crítica',
};

const TYPE_LABEL: Record<string, string> = {
    hypothesis: 'Hypothesis-driven', intel: 'Intel-driven',
};

const OUTCOME_LABEL: Record<string, string> = {
    none: 'Sem achados', suspicious: 'Suspeito', incident: 'Incidente',
    falsepositive: 'Falso positivo', legitimate: 'Atividade legítima',
};

const date = (value?: string | null) => (value ? new Date(value).toLocaleString('pt-BR') : '');
const day = (value?: string | null) => (value ? new Date(value).toISOString().slice(0, 10) : '');

const text = (value?: string): Block[] => (value && value.trim() ? [{ kind: 'text', text: value.trim() }] : []);
const bullets = (items: string[]): Block[] => (items.length ? [{ kind: 'bullets', items }] : []);
const section = (title: string, blocks: Block[]): ReportSection[] => (blocks.length ? [{ title, blocks }] : []);

/** Técnica T1595.001 → /techniques/T1595/001/ */
const techniqueUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;

// Tabelas citadas pelas consultas. Mesma heurística do servidor, do lado do
// cliente: o que abre a consulta ou vem depois de union/join é tabela.
//
// O `formatKql` vem antes de propósito. A consulta curada chega numa linha só
// e o padrão de início de linha não acharia nada nela; quebrando por operador,
// a tabela passa a abrir a sua própria linha.
const TABLE_REFS = [/^\s*([A-Za-z][A-Za-z0-9_]*)\s*(?:\||$)/gm, /\bunion\s+(?:isfuzzy\s*=\s*\w+\s+)?([A-Za-z][A-Za-z0-9_]*)/gi];
const NOT_A_TABLE = new Set(['let', 'union', 'join', 'search', 'print', 'range', 'datatable']);

function queryTables(hunt: PrivateHunt): string[] {
    const found = new Set<string>();
    const defined = new Set<string>();
    for (const item of hunt.queries || []) {
        const formatted = formatKql(item.query);
        for (const match of formatted.matchAll(/\blet\s+([A-Za-z][A-Za-z0-9_]*)\s*=/gi)) defined.add(match[1].toLowerCase());
        for (const pattern of TABLE_REFS) {
            for (const match of formatted.matchAll(pattern)) {
                const name = match[1];
                if (!NOT_A_TABLE.has(name.toLowerCase()) && !defined.has(name.toLowerCase())) found.add(name);
            }
        }
    }
    return [...found];
}

export function huntReportSections(hunt: PrivateHunt, run: HuntRun, identity: ReportIdentity): ReportSection[] {
    const window = [date(run.windowStart), date(run.windowEnd)].filter(Boolean).join(' até ');
    const resultByQuery = new Map((run.evidence || []).map((item) => [item.queryId, item.result]));

    const identification: [string, string][] = ([
        ['ID do hunt', hunt.id],
        ['Data de abertura', date(hunt.createdAt)],
        ['Analista responsável', identity.analyst],
        ['Empresa', identity.company],
        ['Investida', identity.unit],
        ['Prioridade', PRIORITY_LABEL[hunt.priority] || ''],
        ['Tipo de hunting', TYPE_LABEL[hunt.huntType] || ''],
        ['Janela investigada', window],
        ['Resultado', OUTCOME_LABEL[run.outcome] || ''],
        ['Origem de inteligência', [hunt.intelSource?.title, hunt.intelSource?.url].filter(Boolean).join(' — ')],
    ] as [string, string][]).filter(([, value]) => value);

    const counts = [run.events ? `Eventos: ${run.events}` : '', run.hosts ? `Hosts: ${run.hosts}` : ''].filter(Boolean);

    const annex: Block[] = (hunt.queries || []).flatMap((item, index) => [
        { kind: 'text', text: `KQL-${String(index + 1).padStart(2, '0')} — ${item.label || 'Consulta'}` } as Block,
        { kind: 'code', text: formatKql(item.query) } as Block,
        ...(resultByQuery.get(item.id)
            ? [{ kind: 'text', text: `Resultado observado: ${resultByQuery.get(item.id)}` } as Block]
            : []),
    ]);

    return [
        ...section('Identificação do hunting', identification.length ? [{ kind: 'fields', rows: identification }] : []),
        ...section('Hipótese e escopo', [
            ...text(hunt.hypothesis),
            ...text(hunt.objective ? `Objetivo: ${hunt.objective}` : ''),
            ...text(hunt.scope ? `Escopo: ${hunt.scope}` : ''),
            ...text(hunt.exclusions ? `Exclusões: ${hunt.exclusions}` : ''),
        ]),
        ...section('Resultados e conclusões', [...text(run.findings), ...bullets(counts)]),
        ...section('Fontes de dados e consultas', bullets(queryTables(hunt))),
        ...section('Mapeamento MITRE ATT&CK', (hunt.techniques || []).length
            ? [{ kind: 'table', head: ['Técnica', 'Referência'], rows: hunt.techniques.map((id) => [id, techniqueUrl(id)]) }]
            : []),
        ...section('Tratativas e recomendações', text(run.recommendations)),
        ...section('Anexo A — Consultas realizadas', annex),
    ];
}

export const huntReportFilename = (hunt: PrivateHunt, run: HuntRun) =>
    `hunting-${hunt.id}-${day(run.finishedAt || run.startedAt)}`;

export async function exportHuntReportPDF(hunt: PrivateHunt, run: HuntRun, identity: ReportIdentity): Promise<void> {
    await exportSectionsPdf({
        sections: huntReportSections(hunt, run, identity),
        header: {
            title: hunt.title,
            subtitle: `Formulário de Threat Hunting · ${hunt.id}`,
            right: identity.company || undefined,
        },
        footer: ['CONFIDENCIAL', identity.company].filter(Boolean).join(' · '),
        filename: huntReportFilename(hunt, run),
    });
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `npm run test:unit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/utils/huntReportExport.ts src/utils/huntReportExport.test.ts
git commit -m "feat: montar o relatório de hunting a partir da execução"
```

---

### Task 12: Campos e editor de consultas no formulário da hunt

**Files:**
- Modify: `src/pages/Hunting.tsx:36-63` (`HuntForm`, `EMPTY_FORM`, `formOf`, `inputOf`), `:111-238` (`HuntFormDialog`), `:765-772` (handler de geração)

**Interfaces:**
- Consumes: os campos da Task 8.
- Produces: formulário que envia `objective`, `scope`, `exclusions`, `priority`, `huntType`, `intelSource` e `queries`.

A Task 8 já deixou `HuntForm`, `EMPTY_FORM`, `formOf` e `inputOf` com os campos
novos. Aqui é só a interface: os campos aparecem, o editor de consultas
substitui o `<Textarea>` único, e o campo `query` do `HuntForm` some no fim.

- [ ] **Step 1: Bloco "Documentação" no diálogo**

Dentro de `HuntFormDialog`, depois do campo de hipótese. O projeto não tem
`Collapsible` em `src/components/ui/`, e um `<details>` nativo resolve sem
componente novo:

```tsx
<details className="rounded-md border p-3">
  <summary className="cursor-pointer text-sm font-medium">Documentação do relatório</summary>
  <div className="mt-3 space-y-3">
    <div className="space-y-1.5">
      <Label htmlFor="hunt-objective">Objetivo</Label>
      <Textarea id="hunt-objective" rows={2} value={form.objective}
        onChange={(event) => onChange({ ...form, objective: event.target.value })}
        placeholder="O que esta caça precisa validar." />
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1.5">
        <Label htmlFor="hunt-scope">Escopo</Label>
        <Textarea id="hunt-scope" rows={2} value={form.scope}
          onChange={(event) => onChange({ ...form, scope: event.target.value })} />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="hunt-exclusions">Exclusões</Label>
        <Textarea id="hunt-exclusions" rows={2} value={form.exclusions}
          onChange={(event) => onChange({ ...form, exclusions: event.target.value })} />
      </div>
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1.5">
        <Label>Prioridade</Label>
        <Select value={form.priority || "none"} onValueChange={(value) => onChange({ ...form, priority: value === "none" ? "" : value })}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="none">Não definida</SelectItem>
            <SelectItem value="baixa">Baixa</SelectItem>
            <SelectItem value="media">Média</SelectItem>
            <SelectItem value="alta">Alta</SelectItem>
            <SelectItem value="critica">Crítica</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1.5">
        <Label>Tipo</Label>
        <Select value={form.huntType || "none"} onValueChange={(value) => onChange({ ...form, huntType: value === "none" ? "" : value })}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="none">Não definido</SelectItem>
            <SelectItem value="hypothesis">Hypothesis-driven</SelectItem>
            <SelectItem value="intel">Intel-driven</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1.5">
        <Label htmlFor="hunt-intel-title">Origem de inteligência</Label>
        <Input id="hunt-intel-title" value={form.intelSourceTitle}
          onChange={(event) => onChange({ ...form, intelSourceTitle: event.target.value })}
          placeholder="Título do relatório de origem" />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="hunt-intel-url">Link</Label>
        <Input id="hunt-intel-url" value={form.intelSourceUrl}
          onChange={(event) => onChange({ ...form, intelSourceUrl: event.target.value })}
          placeholder="https://" />
      </div>
    </div>
  </div>
</details>
```

- [ ] **Step 2: Editor de consultas**

Substituir o campo único de consulta pelo editor de lista:

```tsx
<div className="space-y-2">
  <div className="flex items-center justify-between">
    <Label>Consultas</Label>
    <Button type="button" variant="ghost" size="sm"
      onClick={() => onChange({
        ...form,
        queries: [...form.queries, { id: `q${form.queries.length + 1}`, label: "", query: "" }],
      })}>
      Adicionar consulta
    </Button>
  </div>
  {form.queries.map((item, index) => (
    <div key={item.id} className="space-y-2 rounded-md border p-3">
      <div className="flex items-center gap-2">
        <Input
          value={item.label}
          onChange={(event) => onChange({
            ...form,
            queries: form.queries.map((q, i) => (i === index ? { ...q, label: event.target.value } : q)),
          })}
          placeholder={`Rótulo da KQL-${String(index + 1).padStart(2, "0")}`}
        />
        <Button type="button" variant="ghost" size="sm"
          onClick={() => onChange({ ...form, queries: form.queries.filter((_, i) => i !== index) })}>
          Remover
        </Button>
      </div>
      <Textarea
        rows={5}
        className="font-mono text-xs"
        value={item.query}
        onChange={(event) => onChange({
          ...form,
          queries: form.queries.map((q, i) => (i === index ? { ...q, query: event.target.value } : q)),
        })}
      />
    </div>
  ))}
  {!form.queries.length && (
    <p className="text-xs text-muted-foreground">Nenhuma consulta ainda. Gere uma pela hipótese ou adicione à mão.</p>
  )}
</div>
```

- [ ] **Step 3: O gerador preenche a primeira consulta**

No handler de geração (`src/pages/Hunting.tsx:765-772`), a linha

```tsx
        query: formatKql(result.query) || form.query,
```

sai e dá lugar a:

```tsx
        queries: form.queries.length
          ? form.queries.map((item, index) => (index === 0 ? { ...item, query: formatKql(result.query) || item.query } : item))
          : (result.query ? [{ id: "q1", label: "Consulta gerada", query: formatKql(result.query) }] : []),
```

- [ ] **Step 4: Verificar**

Run: `npm run typecheck && npm run lint && npm run build`
Expected: sem erro.

Run: `npm run dev` — criar uma hunt com duas consultas e objetivo, salvar, reabrir e conferir que voltou tudo.

- [ ] **Step 5: Commit**

```bash
git add src/pages/Hunting.tsx
git commit -m "feat: formulário da hunt com documentação e várias consultas"
```

---

### Task 13: Fechar execução com janela e evidência, e exportar o relatório

**Files:**
- Modify: `src/pages/Hunting.tsx:542-612` (`FinishRunDialog`), quadro de execução e detalhe da hunt
- Create: `src/pages/huntReportIdentity.ts`
- Test: `src/pages/huntReportIdentity.test.ts`

**Interfaces:**
- Consumes: `exportHuntReportPDF`, `ReportIdentity` da Task 11; campos de run da Task 9.
- Produces: `loadIdentity() -> ReportIdentity`, `saveIdentity(identity) -> void` (persistência em `localStorage`, chave `hunt-report-identity`).

- [ ] **Step 1: Escrever o teste que falha**

Criar `src/pages/huntReportIdentity.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { loadIdentity, saveIdentity, IDENTITY_KEY } from "./huntReportIdentity.ts";

const store = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage = {
  getItem: (key: string) => store.get(key) ?? null,
  setItem: (key: string, value: string) => { store.set(key, value); },
  removeItem: (key: string) => { store.delete(key); },
};

test("sem nada salvo devolve identidade vazia", () => {
  store.clear();
  assert.deepEqual(loadIdentity(), { company: "", unit: "", analyst: "" });
});

test("o que foi salvo volta", () => {
  store.clear();
  saveIdentity({ company: "Organização", unit: "Todas", analyst: "Analista" });
  assert.deepEqual(loadIdentity(), { company: "Organização", unit: "Todas", analyst: "Analista" });
});

test("JSON corrompido não derruba a tela", () => {
  store.clear();
  store.set(IDENTITY_KEY, "{isso não é json");
  assert.deepEqual(loadIdentity(), { company: "", unit: "", analyst: "" });
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `npm run test:unit`
Expected: FAIL — módulo não existe.

- [ ] **Step 3: Implementar `src/pages/huntReportIdentity.ts`**

```ts
// Empresa, investida e analista são os mesmos em todo relatório — não têm por
// que ser digitados por hunt nem gravados no servidor. Mesmo padrão dos perfis
// de organização da página de Atores.
import type { ReportIdentity } from "@/utils/huntReportExport";

export const IDENTITY_KEY = "hunt-report-identity";

const EMPTY: ReportIdentity = { company: "", unit: "", analyst: "" };

export function loadIdentity(): ReportIdentity {
  try {
    const raw = JSON.parse(localStorage.getItem(IDENTITY_KEY) || "{}");
    return {
      company: String(raw.company || ""),
      unit: String(raw.unit || ""),
      analyst: String(raw.analyst || ""),
    };
  } catch {
    return { ...EMPTY };
  }
}

export function saveIdentity(identity: ReportIdentity): void {
  try {
    localStorage.setItem(IDENTITY_KEY, JSON.stringify(identity));
  } catch {
    /* sem persistência, o relatório do dia ainda sai */
  }
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

Run: `npm run test:unit`
Expected: PASS.

- [ ] **Step 5: Ampliar `FinishRunDialog`**

A assinatura passa a receber as consultas da hunt e a devolver os campos novos:

```tsx
function FinishRunDialog({ open, saving, queries, onClose, onFinish }: {
  open: boolean;
  saving: boolean;
  queries: { id: string; label: string }[];
  onClose: () => void;
  onFinish: (input: {
    outcome: RunOutcome; events: number; hosts: number; findings: string;
    windowStart: string; windowEnd: string; recommendations: string;
    evidence: { queryId: string; result: string }[];
  }) => void;
}) {
```

Estado novo:

```tsx
  const [windowStart, setWindowStart] = useState("");
  const [windowEnd, setWindowEnd] = useState("");
  const [recommendations, setRecommendations] = useState("");
  const [evidence, setEvidence] = useState<Record<string, string>>({});
```

Campos novos, depois do resultado:

```tsx
<div className="grid grid-cols-2 gap-3">
  <div className="space-y-1.5">
    <Label htmlFor="run-window-start">Timestamp inicial</Label>
    <Input id="run-window-start" type="datetime-local" value={windowStart}
      onChange={(event) => setWindowStart(event.target.value)} />
  </div>
  <div className="space-y-1.5">
    <Label htmlFor="run-window-end">Timestamp final</Label>
    <Input id="run-window-end" type="datetime-local" value={windowEnd}
      onChange={(event) => setWindowEnd(event.target.value)} />
  </div>
</div>

{queries.length > 0 && (
  <div className="space-y-2">
    <Label>Resultado observado por consulta</Label>
    {queries.map((item, index) => (
      <div key={item.id} className="flex items-center gap-2">
        <span className="w-40 shrink-0 truncate text-xs text-muted-foreground">
          KQL-{String(index + 1).padStart(2, "0")} — {item.label || "Consulta"}
        </span>
        <Input
          value={evidence[item.id] || ""}
          onChange={(event) => setEvidence((prev) => ({ ...prev, [item.id]: event.target.value }))}
          placeholder="0 eventos"
        />
      </div>
    ))}
  </div>
)}

<div className="space-y-1.5">
  <Label htmlFor="run-recommendations">Tratativas e recomendações</Label>
  <Textarea id="run-recommendations" rows={3} value={recommendations}
    onChange={(event) => setRecommendations(event.target.value)}
    placeholder="O que sugerir para as áreas responsáveis." />
</div>
```

No `onFinish` do botão:

```tsx
onClick={() => onFinish({
  outcome, events: Number(events) || 0, hosts: Number(hosts) || 0, findings,
  // datetime-local não tem fuso; o servidor normaliza para ISO.
  windowStart, windowEnd, recommendations,
  evidence: Object.entries(evidence)
    .filter(([, result]) => result.trim())
    .map(([queryId, result]) => ({ queryId, result })),
})}
```

Passar `queries={selectedHunt?.queries || []}` onde o diálogo é usado.

- [ ] **Step 6: Botão do relatório**

No card da execução fechada e no `HuntDetail`:

```tsx
<Button
  variant="outline"
  size="sm"
  onClick={() => exportHuntReportPDF(hunt, run, loadIdentity())}
>
  Relatório PDF
</Button>
```

Com um diálogo de identidade que abre na primeira vez (quando `loadIdentity().analyst` está vazio), com três campos (empresa, investida, analista) e `saveIdentity` ao confirmar.

- [ ] **Step 7: Verificar de ponta a ponta**

Run: `npm run test:unit && npm run test:server && npm run typecheck && npm run lint && npm run build`
Expected: tudo verde.

Run: `npm run dev` — criar hunt com duas consultas, abrir execução, fechar com janela e evidência, exportar PDF.
Expected: PDF com as sete seções, KQL quebrada por operador no anexo, rodapé com CONFIDENCIAL e paginação, e **nenhuma** ocorrência de consultoria de origem ou Votorantim.

- [ ] **Step 8: Commit**

```bash
git add src/pages/Hunting.tsx src/pages/huntReportIdentity.ts src/pages/huntReportIdentity.test.ts
git commit -m "feat: fechar execução com janela e evidência, e exportar o relatório em PDF"
```

---

## Verificação final

- [ ] `npm run test:server && npm run test:unit && npm run lint && npm run typecheck && npm run build`
- [ ] `grep -ril "votorantim" server/data src dist docs || echo "limpo"` → `limpo`
- [ ] `git status --short` → só o que os commits do plano tocaram; `hunting-docs/` não aparece
- [ ] `git push origin main` e conferir o run do CI
