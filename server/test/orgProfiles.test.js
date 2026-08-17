import test from 'node:test';
import assert from 'node:assert/strict';
import {
    ORG_LIMITS,
    ORG_REGIONS,
    ORG_SECTORS,
    createProfileStore,
    normalizeProfileInput,
} from '../orgProfiles.js';

const owner = { sub: 'user-1', login: 'analyst' };
const now = '2026-08-17T12:00:00.000Z';

function memoryStore() {
    const files = new Map();
    return createProfileStore({
        filePath: 'profiles.json',
        readFileSync(path) {
            if (!files.has(path)) throw new Error('missing');
            return files.get(path);
        },
        writeJsonAtomic(path, data) { files.set(path, JSON.stringify(data)); },
    });
}

test('o vocabulário sai das listas que o resto do app já produz', () => {
    assert.ok(ORG_SECTORS.includes('Energy'), 'setores vêm de SECTOR_RULES');
    assert.ok(ORG_SECTORS.includes('Manufacturing'));
    assert.ok(ORG_REGIONS.includes('Brazil'), 'regiões vêm de TARGET_REGION_LABELS');
});

test('normaliza um perfil completo', () => {
    const profile = normalizeProfileInput({
        name: '  Cliente X  ',
        sectors: ['Energy', 'Energy'],
        regions: ['Brazil'],
        assets: [{ vendor: ' Fortinet ', product: 'FortiGate' }, { vendor: 'Fortinet', product: 'FortiGate' }],
        ot: { present: true, vendors: ['Siemens'], protocols: ['Modbus'] },
        actors: ['G0034', 'G0034'],
    }, null, now, owner, new Set(['G0034']));

    assert.match(profile.id, /^org_[0-9a-f]{16}$/);
    assert.equal(profile.ownerId, 'user-1');
    assert.equal(profile.ownerLogin, 'analyst');
    assert.equal(profile.name, 'Cliente X');
    assert.deepEqual(profile.sectors, ['Energy'], 'setor repetido entra uma vez');
    assert.deepEqual(profile.assets, [{ vendor: 'Fortinet', product: 'FortiGate' }], 'ativo repetido entra uma vez');
    assert.deepEqual(profile.ot, { present: true, vendors: ['Siemens'], protocols: ['Modbus'] });
    assert.deepEqual(profile.actors, ['G0034']);
    assert.equal(profile.createdAt, now);
    assert.equal(profile.updatedAt, now);
});

test('nome é obrigatório', () => {
    assert.throws(() => normalizeProfileInput({ name: '   ' }, null, now, owner), { status: 400 });
});

// Um setor digitado errado nunca casaria com notícia nenhuma, e o usuário não
// teria como perceber. Falhar alto é o que torna o vocabulário fechado útil.
test('vocabulário fora da lista é rejeitado, não ignorado', () => {
    assert.throws(() => normalizeProfileInput({ name: 'X', sectors: ['Energia'] }, null, now, owner), { status: 400 });
    assert.throws(() => normalizeProfileInput({ name: 'X', regions: ['Brasil'] }, null, now, owner), { status: 400 });
});

// Mesmo motivo do MIN_ALIAS_LENGTH em actorMatch.js: abaixo de 3 caracteres um
// termo casa com meia língua.
test('ativo curto demais é rejeitado', () => {
    assert.throws(() => normalizeProfileInput({ name: 'X', assets: [{ product: 'AD' }] }, null, now, owner), { status: 400 });
});

test('ator inexistente no catálogo é rejeitado', () => {
    assert.throws(
        () => normalizeProfileInput({ name: 'X', actors: ['G9999'] }, null, now, owner, new Set(['G0034'])),
        { status: 400 },
    );
});

test('update preserva id, dono e createdAt', () => {
    const first = normalizeProfileInput({ name: 'A' }, null, now, owner);
    const later = '2026-08-18T12:00:00.000Z';
    const second = normalizeProfileInput({ name: 'B' }, first, later, owner);
    assert.equal(second.id, first.id);
    assert.equal(second.ownerId, 'user-1');
    assert.equal(second.createdAt, now);
    assert.equal(second.updatedAt, later);
    assert.equal(second.name, 'B');
});

test('store isola por dono', () => {
    const store = memoryStore();
    store.create(owner, { name: 'Meu' }, now);
    store.create({ sub: 'user-2', login: 'outro' }, { name: 'Alheio' }, now);

    const mine = store.list('user-1');
    assert.equal(mine.length, 1);
    assert.equal(mine[0].name, 'Meu');
    assert.throws(() => store.get('user-1', store.list('user-2')[0].id), { status: 404 });
    assert.equal(store.remove('user-1', store.list('user-2')[0].id), false);
});

test('store barra no limite de perfis', () => {
    const store = memoryStore();
    for (let i = 0; i < ORG_LIMITS.profilesPerUser; i++) store.create(owner, { name: `P${i}` }, now);
    assert.throws(() => store.create(owner, { name: 'excedente' }, now), { status: 409 });
});

test('arquivo corrompido vira store vazio, não exceção', () => {
    const store = createProfileStore({
        filePath: 'x.json',
        readFileSync: () => '{ isso não é json',
        writeJsonAtomic: () => {},
    });
    assert.deepEqual(store.list('user-1'), []);
});
