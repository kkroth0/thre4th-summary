import test from 'node:test';
import assert from 'node:assert/strict';
import { filterExactIocs, iocMatchesQuery } from '../threatfoxMatch.js';

// O falso positivo que motiva o filtro inteiro.
test('IP parecido não casa', () => {
    assert.equal(iocMatchesQuery('11.1.1.100', '1.1.1.1'), false);
    assert.equal(iocMatchesQuery('11.1.1.100:443', '1.1.1.1'), false);
    assert.equal(iocMatchesQuery('1.1.1.1', '1.1.1.1'), true);
});

test('C2 guardado como ip:porta casa a consulta pelo IP', () => {
    assert.equal(iocMatchesQuery('185.220.101.5:8080', '185.220.101.5'), true);
    assert.equal(iocMatchesQuery('evil.example.com:443', 'evil.example.com'), true);
});

test('URL casa a consulta pelo host, e o host casa a consulta pela URL', () => {
    assert.equal(iocMatchesQuery('http://evil.example.com/payload.exe', 'evil.example.com'), true);
    assert.equal(iocMatchesQuery('evil.example.com', 'http://evil.example.com/x'), true);
    // Domínio diferente que só contém o termo não passa.
    assert.equal(iocMatchesQuery('http://evil.example.com.br/x', 'evil.example.com'), false);
});

test('hash e URL idênticos casam; vazio nunca casa', () => {
    const sha = 'a'.repeat(64);
    assert.equal(iocMatchesQuery(sha, sha.toUpperCase()), true);
    assert.equal(iocMatchesQuery('', '1.1.1.1'), false);
    assert.equal(iocMatchesQuery('1.1.1.1', ''), false);
});

test('a resposta perde só o que não casa, preservando o resto do payload', () => {
    const payload = {
        query_status: 'ok',
        data: [
            { ioc: '1.1.1.1:443', malware_printable: 'Emotet' },
            { ioc: '11.1.1.100', malware_printable: 'Mirai' },
        ],
    };
    const filtered = filterExactIocs(payload, '1.1.1.1');
    assert.deepEqual(filtered.data.map((d) => d.malware_printable), ['Emotet']);
    assert.equal(filtered.query_status, 'ok');
});

// Erro da API não pode ser reescrito pelo filtro: o front distingue "não achei"
// de "a base não respondeu".
test('payload que não é resultado passa intacto', () => {
    const err = { query_status: 'no_result' };
    assert.equal(filterExactIocs(err, '1.1.1.1'), err);
    assert.equal(filterExactIocs(null, '1.1.1.1'), null);
});
