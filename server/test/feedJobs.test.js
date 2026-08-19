import test from 'node:test';
import assert from 'node:assert/strict';
import { isJobId, jobSummary, orphanDeckFiles, pruneJobsMap } from '../feedJobs.js';

const job = (id, status, ownerSub, day, extra = {}) => ({
    id,
    status,
    ownerSub,
    url: `https://example.com/${id}`,
    type: 'vuln',
    title: id,
    json: status === 'done' ? { titulo: id } : null,
    error: null,
    createdAt: `2026-08-${String(day).padStart(2, '0')}T00:00:00.000Z`,
    updatedAt: `2026-08-${String(day).padStart(2, '0')}T00:00:00.000Z`,
    ...extra,
});

const mapOf = (...jobs) => Object.fromEntries(jobs.map((j) => [j.id, j]));

test('jobSummary tira o boletim e sinaliza que ele existe', () => {
    const done = jobSummary(job('a', 'done', 'u1', 1));
    assert.equal(done.hasReport, true);
    assert.equal('json' in done, false);
    assert.equal(done.title, 'a');

    assert.equal(jobSummary(job('b', 'pending', 'u1', 1)).hasReport, false);
});

test('boletim entregue não é podado pela churn de outro usuário', () => {
    const store = mapOf(
        job('antigo-u1', 'done', 'u1', 1),
        ...Array.from({ length: 150 }, (_, i) => job(`u2-${i}`, 'done', 'u2', 2)),
    );
    pruneJobsMap(store, { maxTransient: 100, keptPerOwner: 200 });
    assert.ok(store['antigo-u1'], 'o boletim do u1 tem que sobreviver');
    assert.equal(Object.keys(store).length, 151);
});

test('acima do teto do dono, sai o boletim mais antigo dele', () => {
    const store = mapOf(...Array.from({ length: 5 }, (_, i) => job(`r${i}`, 'done', 'u1', i + 1)));
    const dropped = pruneJobsMap(store, { keptPerOwner: 3 });
    assert.equal(dropped, 2);
    assert.deepEqual(Object.keys(store).sort(), ['r2', 'r3', 'r4']);
});

test('cada dono tem o seu teto, contado em separado', () => {
    const store = mapOf(
        ...Array.from({ length: 4 }, (_, i) => job(`u1-${i}`, 'done', 'u1', i + 1)),
        ...Array.from({ length: 2 }, (_, i) => job(`u2-${i}`, 'done', 'u2', i + 1)),
    );
    pruneJobsMap(store, { keptPerOwner: 3 });
    assert.deepEqual(Object.keys(store).sort(), ['u1-1', 'u1-2', 'u1-3', 'u2-0', 'u2-1']);
});

test('pending e error têm teto global próprio e não afetam os done', () => {
    const store = mapOf(
        job('done-velho', 'done', 'u1', 1),
        ...Array.from({ length: 4 }, (_, i) => job(`p${i}`, 'pending', 'u1', i + 1)),
        job('err', 'error', 'u1', 5),
    );
    pruneJobsMap(store, { maxTransient: 2, keptPerOwner: 200 });
    assert.ok(store['done-velho']);
    // Sobram os 2 transientes mais novos: o error do dia 5 e o pending do dia 4.
    assert.deepEqual(Object.keys(store).sort(), ['done-velho', 'err', 'p3']);
});

test('store vazio ou sem nada a podar não quebra', () => {
    assert.equal(pruneJobsMap({}), 0);
    assert.equal(pruneJobsMap(undefined), 0);
    const store = mapOf(job('a', 'done', 'u1', 1));
    assert.equal(pruneJobsMap(store), 0);
    assert.equal(Object.keys(store).length, 1);
});

test('isJobId só aceita UUID — é a guarda contra path traversal no diretório dos decks', () => {
    assert.equal(isJobId('3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b'), true);
    for (const bad of ['../../etc/passwd', 'deck', '', null, undefined,
                       '3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b/../x',
                       '../3f1c2b4a-5d6e-4f70-8a9b-0c1d2e3f4a5b']) {
        assert.equal(isJobId(bad), false, String(bad));
    }
});

test('varredura devolve só os decks sem job, inclusive o .tmp de gravação interrompida', () => {
    const store = { 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee': { id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' } };
    const files = [
        'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.pptx',        // job vivo: fica
        'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.pdf',         // idem, o PDF do deck
        'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee.pptx',        // job podado: sai
        'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee.pdf',         // sai junto
        'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee.pptx.tmp',    // gravação órfã: sai
    ];
    assert.deepEqual(orphanDeckFiles(files, store), [
        'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee.pptx',
        'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee.pdf',
        'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee.pptx.tmp',
    ]);
    assert.deepEqual(orphanDeckFiles([], store), []);
});
