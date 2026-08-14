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
    assert.equal(anonymize('Mapeamento EY - Microsoft Sentinel Votorantim'), 'Mapeamento - Microsoft Sentinel');
    assert.equal(anonymize('inventário da Votorantim S.A.'), 'inventário da S.A.');
});

test('assertAnonymous barra o artefato que ainda tem termo proibido', () => {
    assert.throws(() => assertAnonymous({ table: 'X', note: 'padrão EY' }), /termo proibido/);
    assert.throws(() => assertAnonymous('inventário Votorantim'), /termo proibido/);
    assert.doesNotThrow(() => assertAnonymous({ table: 'SigninLogs' }));
});

test('nome de produto não é nome de cliente e fica', () => {
    const [item] = buildKqlLibrary([['4. Rede', 'WAF', 'Cloudflare_CL', 'Investigar',
        'Cloudflare_CL | where SecurityAction_s == "block"', 'janela', 'Validada']]);
    assert.match(item.query, /Cloudflare_CL/);
});
