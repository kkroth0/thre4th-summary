import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildCampaignIndex, matchCampaigns } from '../campaignMatch.js';

const index = buildCampaignIndex([
    { id: 'c1', name: 'Operation Dream Job', aliases: ['Operation North Star', 'Operation Interception'] },
    { id: 'c2', name: 'SolarWinds', aliases: ['Sunburst'] },
    { id: 'c3', name: 'Frankenstein', aliases: [] },
    { id: 'c4', name: 'C0010', aliases: ['C0010'] },
    { id: 'c5', name: 'AIZ', aliases: ['XY'] },
]);

const ids = (text) => matchCampaigns(text, index).map((hit) => hit.id).sort();

test('campanha explicitamente nomeada fora do catálogo pode correlacionar novas coberturas', () => {
    assert.equal(ids("A malware campaign dubbed 'Midnight Mimosa' was discovered.")[0], 'reported:midnight-mimosa');
    assert.equal(ids('The campaign, dubbed Midnight Mimosa, affects devices.')[0], 'reported:midnight-mimosa');
    assert.deepEqual(ids('An Android malware campaign expands globally.'), []);
    assert.deepEqual(ids('The campaign was discussed by Midnight Mimosa researchers.'), []);
    assert.deepEqual(ids('The campaign named Operation Dream Job is active.'), ['c1'], 'nomes já catalogados não duplicam');
});

test('nome multi-palavra casa sem precisar de contexto', () => {
    assert.deepEqual(ids('Operation Dream Job infrastructure linked to new intrusion'), ['c1']);
    assert.deepEqual(ids('Researchers tie new activity to Operation North Star'), ['c1']);
});

test('palavra única cunhada casa em qualquer lugar por padrão', () => {
    assert.deepEqual(ids('SolarWinds supply chain breach detailed in new report'), ['c2']);
    assert.deepEqual(ids('Sunburst backdoor code reused in unrelated malware'), ['c2']);
});

test('campanha sem nome próprio (id como nome) não entra no índice', () => {
    assert.deepEqual(ids('C0010 was active throughout 2022'), [], 'c0010 não é um nome de verdade, é o próprio id');
});

test('alias ambíguo só casa com termo de contexto na mesma frase', () => {
    assert.deepEqual(ids('The Frankenstein campaign combined several malware families'), ['c3']);
    assert.deepEqual(ids("Frankenstein's monster is a classic literary trope"), []);
});

test('contexto não vaza de uma frase para a outra', () => {
    assert.deepEqual(ids("A new operation emerged. Frankenstein's monster appeared in the film."), []);
});

test('três caracteres é o piso, não o corte', () => {
    assert.deepEqual(ids('AIZ was observed targeting several banks'), ['c5']);
    assert.deepEqual(ids('XY was observed targeting several banks'), []);
});

test('o mesmo campanha citada duas vezes aparece uma vez só', () => {
    assert.equal(matchCampaigns('Operation Dream Job and Operation North Star are the same campaign', index).length, 1);
});

test('via reporta a regra e o alias que casou', () => {
    assert.deepEqual(matchCampaigns('Operation Dream Job strikes', index), [
        { id: 'c1', name: 'Operation Dream Job', matched: 'Operation Dream Job', via: 'multiword' },
    ]);
    assert.deepEqual(matchCampaigns('SolarWinds strikes', index), [
        { id: 'c2', name: 'SolarWinds', matched: 'SolarWinds', via: 'distinctive' },
    ]);
    assert.deepEqual(matchCampaigns('the Frankenstein campaign', index), [
        { id: 'c3', name: 'Frankenstein', matched: 'Frankenstein', via: 'context' },
    ]);
});

test('texto vazio ou nulo não quebra', () => {
    assert.deepEqual(matchCampaigns('', index), []);
    assert.deepEqual(matchCampaigns(null, index), []);
    assert.deepEqual(buildCampaignIndex(null).distinctive.size, 0);
});

// O catálogo real é dado externo: quem manda no comportamento é ele.
const catalog = JSON.parse(
    readFileSync(new URL('../data/campaigns.json', import.meta.url), 'utf8'),
).campaigns;
const catalogIndex = buildCampaignIndex(catalog);
const catalogNames = (text) =>
    matchCampaigns(text, catalogIndex).map((hit) => hit.name.toLowerCase());

test('o catálogo atribui campanhas reais sem precisar de termo de contexto', () => {
    for (const [campaign, sentence] of [
        ['operation dream job', 'Operation Dream Job infrastructure seized by international law enforcement'],
        // O catálogo real registra "SolarWinds Compromise", não a forma curta
        // "SolarWinds" sozinha — diferente do malware, campanha não segue um
        // padrão "marca + tipo" previsível o bastante pra derivar com segurança
        // (ver comentário no build-actors.mjs sobre essa decisão).
        ['solarwinds compromise', 'The SolarWinds Compromise is detailed in a new court filing'],
    ]) {
        assert.ok(
            catalogNames(sentence).includes(campaign),
            `${campaign} deveria ser atribuído em: ${sentence}`,
        );
    }
});

test('nenhuma campanha com nome igual ao próprio id aparece no catálogo real', () => {
    const idShaped = catalog.filter((c) => /^c\d{4}$/i.test(c.name));
    for (const c of idShaped) {
        assert.deepEqual(catalogNames(`${c.name} was active`), [], `${c.name} não deveria casar pelo próprio id`);
    }
});
