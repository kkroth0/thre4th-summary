import test from 'node:test';
import assert from 'node:assert/strict';
import { GENERATOR_SYSTEM, buildGeneratePrompt, extractTables, unknownTables, normalizeGenerated, pickExamples } from '../huntGenerator.js';

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
