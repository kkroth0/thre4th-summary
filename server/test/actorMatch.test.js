import test from 'node:test';
import assert from 'node:assert/strict';
import { buildActorIndex, matchActors } from '../actorMatch.js';

const index = buildActorIndex([
    { id: 'a1', name: 'APT28', aliases: ['Sofacy', 'Fancy Bear'] },
    { id: 'a2', name: 'Akira', aliases: [] },
    { id: 'a3', name: 'Scattered Spider', aliases: ['UNC3944'] },
    { id: 'a4', name: '[Unnamed group]', aliases: [] },
    { id: 'a5', name: 'AIZ', aliases: ['XY'] },
    { id: 'a6', name: 'Russian Angry Hackers Did It', aliases: [] },
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

test('ator antes de período final é achado', () => {
    assert.deepEqual(ids('Attributed to APT28.'), ['a1'], 'codinome antes de período');
    assert.deepEqual(ids('Researchers linked the intrusion to Scattered Spider.'), ['a3'], 'nome de duas palavras antes de período');
    // Same names mid-sentence should still match
    assert.deepEqual(ids('APT28 was active'), ['a1']);
    assert.deepEqual(ids('Scattered Spider operates'), ['a3']);
});

test('nomes com mais de quatro palavras são achados', () => {
    assert.deepEqual(ids('Russian Angry Hackers Did It is active'), ['a6']);
    assert.deepEqual(ids('Russian Angry Hackers Did It operates worldwide.'), ['a6']);
});

test('contexto não vaza de uma frase para a outra (ator também)', () => {
    // Verify sentence scoping still works even with period-stripping
    assert.deepEqual(ids('A new ransomware gang emerged. Russian Angry Hackers Did It was mentioned.'), ['a6']);
    assert.deepEqual(ids('A new group emerged. Russian Angry Hackers Did It operates.'), ['a6']);
});

test('texto vazio ou nulo não quebra', () => {
    assert.deepEqual(matchActors('', index), []);
    assert.deepEqual(matchActors(null, index), []);
    assert.deepEqual(buildActorIndex(null).distinctive.size, 0);
});

// Fix 4: hyper-common single-word aliases (play, silence, tick, platinum,
// mirage, venom, cleaver) stay out of the common tier entirely — the context
// terms meant to gate them (group, gang, campaign, threat actors...) are
// themselves ordinary CTI vocabulary, so the two-tier rule alone still let
// them false-positive.
const stoplistIndex = buildActorIndex([
    { id: 'g1040', name: 'Play', aliases: [] },
    { id: 'g0091', name: 'Silence', aliases: [] },
    { id: 'g0003', name: 'Cleaver', aliases: ['Play Ransomware'] },
]);
const stoplistIds = (text) => matchActors(text, stoplistIndex).map((hit) => hit.id).sort();

test('aliases da stoplist não casam mesmo com termo de contexto na frase', () => {
    assert.deepEqual(stoplistIds('Threat actors play a long game against telecom operators'), []);
    assert.deepEqual(stoplistIds('The gang kept a strange silence after the breach campaign'), []);
});

test('aliases da stoplist continuam casando como parte de um nome multi-palavra', () => {
    assert.deepEqual(stoplistIds('Play Ransomware group claims a new victim'), ['g0003']);
});
