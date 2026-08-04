import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGeneratePrompt, extractTables, unknownTables, normalizeGenerated } from '../huntGenerator.js';

const CATALOG = [
    { table: 'Cloudflare_CL', source: 'Cloudflare', columns: [{ name: 'ClientIP_s', type: 'string' }] },
    { table: 'SigninLogs', source: 'Sentinel', columns: [{ name: 'UserPrincipalName', type: 'string' }] },
];

test('o prompt leva so a fonte pedida e estoura quando nao sobra tabela', () => {
    const prompt = buildGeneratePrompt({ catalog: CATALOG, hypothesis: 'saída incomum', sources: ['Cloudflare'] });
    assert.match(prompt, /Hipótese: saída incomum/);
    assert.match(prompt, /Cloudflare_CL/);
    assert.doesNotMatch(prompt, /SigninLogs/, 'tabela de outra fonte não entra no contexto');

    assert.throws(
        () => buildGeneratePrompt({ catalog: CATALOG, hypothesis: 'x', sources: ['Netskope'] }),
        /nenhuma tabela disponível/,
    );
});

test('acha a tabela no comeco, no union e no join', () => {
    const kql = `Cloudflare_CL
| where ClientIP_s != ""
| join kind=inner (SigninLogs | project UserPrincipalName) on $left.ClientIP_s == $right.UserPrincipalName
| union OutraTabela_CL`;

    const tables = extractTables(kql);
    assert.ok(tables.includes('Cloudflare_CL'));
    assert.ok(tables.includes('SigninLogs'));
    assert.ok(tables.includes('OutraTabela_CL'));
    // Operador não é tabela.
    assert.equal(tables.includes('where'), false);
    assert.equal(tables.includes('join'), false);
});

test('denuncia tabela que o workspace nao tem', () => {
    assert.deepEqual(unknownTables('Cloudflare_CL | take 10', CATALOG), []);
    assert.deepEqual(unknownTables('TabelaInventada_CL | take 10', CATALOG), ['TabelaInventada_CL']);

    // Alias declarado no próprio KQL vale como tabela conhecida.
    const comLet = `let recentes = Cloudflare_CL | where ClientIP_s != "";
recentes
| take 10`;
    assert.deepEqual(unknownTables(comLet, CATALOG), []);
});

test('a resposta do modelo e podada e marcada quando alucina', () => {
    const boa = normalizeGenerated({
        title: 'Saída para domínio novo',
        hypothesis: 'tráfego para domínio recém-registrado',
        query: 'Cloudflare_CL | take 10',
        dataSources: ['Cloudflare_CL'],
        notes: 'triar por host',
    }, CATALOG);
    assert.deepEqual(boa.unknownTables, []);
    assert.equal(boa.title, 'Saída para domínio novo');

    const alucinada = normalizeGenerated({ title: 't', query: 'FirewallEventos_CL | take 10' }, CATALOG);
    assert.deepEqual(alucinada.unknownTables, ['FirewallEventos_CL']);

    // Consulta vazia é resposta legítima ("não dá pra testar com estas tabelas")
    // e não deve ser acusada de alucinação.
    const semQuery = normalizeGenerated({ title: 't', query: '', notes: 'faltam tabelas de DNS' }, CATALOG);
    assert.deepEqual(semQuery.unknownTables, []);
    assert.equal(semQuery.notes, 'faltam tabelas de DNS');

    // Campo ausente não vira "undefined" na tela.
    assert.equal(normalizeGenerated({}, CATALOG).title, '');
    assert.deepEqual(normalizeGenerated({}, CATALOG).dataSources, []);
});
