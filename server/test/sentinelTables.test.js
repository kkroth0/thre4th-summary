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
