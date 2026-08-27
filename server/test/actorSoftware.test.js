import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSoftwareIndex, softwareKey } from '../actorSoftware.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const actor = (over = {}) => ({ id: 'G0001', name: 'Wizard Spider', software: [], ...over });

test('a família aponta para todos os grupos que a usam, sem repetir ator', () => {
    const index = buildSoftwareIndex([
        actor({ software: [{ id: 'S0367', name: 'Emotet' }, { id: 'S0367', name: 'Emotet' }] }),
        actor({ id: 'G0092', name: 'TA505', software: [{ name: 'Emotet' }, { name: 'TrickBot' }] }),
    ]);
    assert.deepEqual(index[softwareKey('Emotet')], [
        { id: 'G0001', name: 'Wizard Spider' },
        { id: 'G0092', name: 'TA505' },
    ]);
    assert.deepEqual(index[softwareKey('TrickBot')], [{ id: 'G0092', name: 'TA505' }]);
});

// "Gh0st RAT", "gh0strat" e "Gh0stRAT" são a mesma família em bases diferentes.
test('a chave ignora espaço, caixa e pontuação', () => {
    const index = buildSoftwareIndex([actor({ software: ['Gh0st RAT'] })]);
    assert.ok(index[softwareKey('gh0strat')]);
    assert.ok(index[softwareKey('Gh0stRAT')]);
    assert.equal(softwareKey('Agent Tesla'), 'agenttesla');
});

test('grupo sem nome não entra no índice', () => {
    const index = buildSoftwareIndex([actor({ name: '[Unnamed group]', software: ['Emotet'] })]);
    assert.equal(index[softwareKey('Emotet')], undefined);
});

// O índice serve a planilha do cliente: se o catálogo real deixar de trazer
// software, o enriquecimento inteiro perde a atribuição por família em silêncio.
test('o catálogo real produz um índice utilizável', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(here, '..', 'data', 'actors.json'), 'utf8'));
    const index = buildSoftwareIndex(raw.actors);
    assert.ok(Object.keys(index).length > 300, 'poucas famílias indexadas');
    assert.deepEqual(index[softwareKey('Emotet')], [{ id: 'G0102', name: 'Wizard Spider' }]);
    // Ferramenta compartilhada: o enriquecimento conta com esse número alto
    // para NÃO atribuir grupo a partir dela.
    assert.ok(index[softwareKey('Cobalt Strike')].length > 10);
});
