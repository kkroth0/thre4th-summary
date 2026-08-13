import test from 'node:test';
import assert from 'node:assert/strict';
import { buildActorIndex, matchActors } from '../actorMatch.js';

const index = buildActorIndex([
    { id: 'a1', name: 'APT28', aliases: ['Sofacy', 'Fancy Bear'] },
    { id: 'a2', name: 'Akira', aliases: [] },
    { id: 'a3', name: 'Scattered Spider', aliases: ['UNC3944'] },
    { id: 'a4', name: '[Unnamed group]', aliases: [] },
    { id: 'a5', name: 'AIZ', aliases: ['XY'] },
]);

const ids = (text) => matchActors(text, index).map((hit) => hit.id).sort();

test('codinome casa em qualquer contexto', () => {
    assert.deepEqual(ids('APT28 targets embassies'), ['a1']);
    assert.deepEqual(ids('Attributed to UNC3944 operators'), ['a3']);
});

test('nome de duas palavras casa sem precisar de contexto', () => {
    assert.deepEqual(ids('Fancy Bear resurfaces in new intrusion'), ['a1']);
    assert.deepEqual(ids('Scattered Spider hits an airline'), ['a3']);
});

test('palavra comum só casa com termo de contexto na mesma frase', () => {
    assert.deepEqual(ids('The Akira ransomware gang leaked the data'), ['a2']);
    assert.deepEqual(ids('Akira Kurosawa retrospective opens today'), []);
    assert.deepEqual(ids('Sofacy analysis published'), []);
    assert.deepEqual(ids('Sofacy APT analysis published'), ['a1']);
});

test('contexto não vaza de uma frase para a outra', () => {
    assert.deepEqual(ids('A new ransomware gang emerged. Akira Kurosawa died in 1998.'), []);
});

test('três caracteres é o piso, não o corte', () => {
    assert.deepEqual(ids('AIZ group claimed it'), ['a5'], 'AIZ tem 3 e fica');
    assert.deepEqual(ids('XY group claimed it'), [], 'XY tem 2 e sai');
    assert.deepEqual(ids('AIZ released a statement'), [], 'palavra comum ainda exige contexto');
});

test('o placeholder de grupo sem nome fica fora do índice', () => {
    assert.deepEqual(ids('[Unnamed group] did it'), []);
});

test('via reporta a regra e o alias que casou', () => {
    assert.deepEqual(matchActors('Fancy Bear strikes', index), [
        { id: 'a1', name: 'APT28', matched: 'Fancy Bear', via: 'multiword' },
    ]);
    assert.deepEqual(matchActors('APT28 strikes', index), [
        { id: 'a1', name: 'APT28', matched: 'APT28', via: 'codename' },
    ]);
    assert.deepEqual(matchActors('the Akira gang', index), [
        { id: 'a2', name: 'Akira', matched: 'Akira', via: 'context' },
    ]);
});

test('o mesmo ator citado duas vezes aparece uma vez só', () => {
    assert.equal(matchActors('APT28 and Sofacy APT are the same group', index).length, 1);
});

test('texto vazio ou nulo não quebra', () => {
    assert.deepEqual(matchActors('', index), []);
    assert.deepEqual(matchActors(null, index), []);
    assert.deepEqual(buildActorIndex(null).distinctive.size, 0);
});
