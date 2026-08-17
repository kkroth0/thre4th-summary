import test from 'node:test';
import assert from 'node:assert/strict';
import { buildThreatModel } from '../orgThreatModel.js';

const catalog = [
    { id: 'G0034', name: 'Sandworm', country: 'Russia', sectors: ['Energy'], targets: ['Ukraine'], techniques: [{ id: 'T1486' }] },
    { id: 'G0007', name: 'APT28', country: 'Russia', sectors: ['Government'], targets: ['Brazil'], techniques: [{ id: 'T1566' }, { id: 'T1486' }] },
    { id: 'G0999', name: 'Irrelevante', country: 'China', sectors: ['Retail'], targets: ['Japan'], techniques: [{ id: 'T1059' }] },
];

const profile = (over = {}) => ({ id: 'org_1', name: 'X', sectors: [], regions: [], assets: [], ot: { present: false, vendors: [], protocols: [] }, actors: [], ...over });

test('ator entra pelo setor atacado', () => {
    const model = buildThreatModel(profile({ sectors: ['Energy'] }), catalog);
    assert.deepEqual(model.actorIds, ['G0034']);
});

test('ator entra pela região atacada', () => {
    const model = buildThreatModel(profile({ regions: ['Brazil'] }), catalog);
    assert.deepEqual(model.actorIds, ['G0007']);
});

test('ator fixado entra mesmo sem casar setor ou região', () => {
    const model = buildThreatModel(profile({ actors: ['G0999'] }), catalog);
    assert.deepEqual(model.actorIds, ['G0999']);
    assert.deepEqual(model.pinnedIds, ['G0999']);
});

test('perfil vazio não puxa ator nenhum', () => {
    const model = buildThreatModel(profile(), catalog);
    assert.deepEqual(model.actorIds, []);
    assert.deepEqual(model.techniques, []);
});

test('técnicas são a união dos atores relevantes, sem repetição', () => {
    const model = buildThreatModel(profile({ sectors: ['Energy', 'Government'] }), catalog);
    assert.deepEqual(model.techniques, ['T1486', 'T1566']);
});

// Só o servidor tem o TARGET_REGIONS; o cliente precisa dos termos para casar
// "brazilian" num título. Mandar só as regiões escolhidas mantém isso pequeno.
test('regiões viajam com seus termos, e só as escolhidas', () => {
    const model = buildThreatModel(profile({ regions: ['Brazil'] }), catalog);
    assert.equal(model.regions.length, 1);
    assert.equal(model.regions[0].label, 'Brazil');
    assert.ok(model.regions[0].terms.includes('brazilian'));
});

test('o modelo é JSON puro, porque viaja até o navegador', () => {
    const model = buildThreatModel(profile({ sectors: ['Energy'], assets: [{ vendor: 'Fortinet', product: 'FortiGate' }] }), catalog);
    assert.deepEqual(JSON.parse(JSON.stringify(model)), model);
    assert.deepEqual(model.assets, [{ vendor: 'Fortinet', product: 'FortiGate' }]);
    assert.deepEqual(model.actors, [{ id: 'G0034', name: 'Sandworm', country: 'Russia' }]);
});

test('catálogo ausente não quebra', () => {
    assert.deepEqual(buildThreatModel(profile({ sectors: ['Energy'] }), null).actorIds, []);
    assert.deepEqual(buildThreatModel(null, catalog).actorIds, []);
});
