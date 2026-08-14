import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSentinelTables, catalogSources, renderCatalogForPrompt } from '../sentinelTables.js';

// Trecho no formato real do Tables_Data.md: linhas em branco entre tudo, tabela
// sem sufixo, coluna com "(tipo)".
const DUMP = `
LogManagement

 Cloudflare_CL

 ClientIP_s (string)

 EdgeStartTimestamp_t (datetime)

 NetskopeAlerts_CL

 alert_name_s (string)

 count_d (real)
`;

test('separa tabela de coluna pelo sufixo de tipo', () => {
    const catalog = parseSentinelTables(DUMP);

    assert.deepEqual(catalog.map((entry) => entry.table), ['Cloudflare_CL', 'NetskopeAlerts_CL']);
    assert.deepEqual(catalog[0].columns, [
        { name: 'ClientIP_s', type: 'string' },
        { name: 'EdgeStartTimestamp_t', type: 'datetime' },
    ]);
    // "LogManagement" é cabeçalho de seção sem colunas e não vira tabela.
    assert.equal(catalog.some((entry) => entry.table === 'LogManagement'), false);
});

test('deduz a origem pelo prefixo do nome', () => {
    const catalog = parseSentinelTables(DUMP);
    assert.deepEqual(catalogSources(catalog), ['Cloudflare', 'Netskope']);
    assert.equal(parseSentinelTables(' TrendMicro_XDR_OAT_CL\n\n x (string)\n')[0].source, 'Trend Vision One');
    assert.equal(parseSentinelTables(' SAP_CL\n\n x (string)\n')[0].source, 'SAP');
    assert.equal(parseSentinelTables(' SigninLogs\n\n x (string)\n')[0].source, 'Sentinel');
    assert.equal(parseSentinelTables(' Coisa_CL\n\n x (string)\n')[0].source, 'Custom');
});

test('o prompt leva so a fonte pedida e corta tabela gigante', () => {
    const catalog = parseSentinelTables(DUMP);

    const onlyCloudflare = renderCatalogForPrompt(catalog, { sources: ['cloudflare'] });
    assert.match(onlyCloudflare, /Cloudflare_CL/);
    assert.doesNotMatch(onlyCloudflare, /NetskopeAlerts_CL/);

    const wide = parseSentinelTables([' Larga_CL', ...Array.from({ length: 80 }, (_, i) => ` c${i} (string)`)].join('\n\n'));
    const rendered = renderCatalogForPrompt(wide, { maxColumns: 10 });
    assert.match(rendered, /\+70 colunas/);
    assert.equal((rendered.match(/: string/g) || []).length, 10);
});

test('entrada quebrada nao derruba o parser', () => {
    assert.deepEqual(parseSentinelTables(''), []);
    assert.deepEqual(parseSentinelTables(null), []);
    // Coluna antes de qualquer tabela é descartada em vez de estourar.
    assert.deepEqual(parseSentinelTables(' orfa (string)\n'), []);
    // Tabela declarada sem coluna nenhuma não entra no catálogo.
    assert.deepEqual(parseSentinelTables(' Vazia_CL\n\n Outra_CL\n\n x (int)\n').map((e) => e.table), ['Outra_CL']);
});

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
    // "Para que serve" também começa com dois espaços e tem ":" — exclui pra sobrar só coluna.
    const linhas = rendered.split('\n')
        .filter((line) => line.startsWith('  ') && line.includes(':') && !line.includes('Para que serve'));
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
