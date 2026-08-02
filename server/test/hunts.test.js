import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHearthData } from '../hearth.js';
import { HUNTS_CAP, normalizeHuntInput, upsertHunt } from '../hunts.js';

const now = '2026-08-01T12:00:00.000Z';

test('parseia o catálogo HEARTH e preserva autoria e mapeamento ATT&CK', () => {
    const source = `// generated\nconst HUNTS_DATA = ${JSON.stringify([{
        id: 'H001',
        category: 'Flames',
        title: 'PowerShell incomum pode indicar execução maliciosa.',
        tactic: 'Execution, Defense Evasion',
        techniques: ['T1059.001', 'T1218'],
        tags: ['powershell'],
        submitter: { name: 'Analista', link: 'https://example.com/analista' },
        why: 'Comportamento fora do padrão.',
        references: '- https://attack.mitre.org/techniques/T1059/001/',
        file_path: 'Flames/H001.md',
        status: 'current',
        created: '2026-07-30T10:00:00Z',
    }])};`;

    assert.deepEqual(parseHearthData(source), [{
        id: 'H001',
        origin: 'hearth',
        category: 'Flames',
        title: 'PowerShell incomum pode indicar execução maliciosa.',
        tactics: ['Execution', 'Defense Evasion'],
        techniques: ['T1059.001', 'T1218'],
        tags: ['powershell'],
        submitter: { name: 'Analista', link: 'https://example.com/analista' },
        notes: '',
        why: 'Comportamento fora do padrão.',
        references: '- https://attack.mitre.org/techniques/T1059/001/',
        status: 'current',
        created: '2026-07-30T10:00:00Z',
        sourceUrl: 'https://github.com/THORCollective/HEARTH/blob/main/Flames/H001.md',
    }]);
});

test('rejeita um hunts-data.js sem array JSON', () => {
    assert.throws(() => parseHearthData('const HUNTS_DATA = nope;'), /catálogo HEARTH inválido/);
});

test('normaliza um hunt privado sem confiar no dono ou linguagem enviados', () => {
    const hunt = normalizeHuntInput({
        ownerSub: 'atacante',
        title: '  Logon   anômalo\n',
        hypothesis: '  Contas comprometidas podem gerar logons fora do padrão. ',
        tactics: ['Credential Access', 'Credential Access'],
        techniques: ['t1078', 'T1078'],
        cves: ['cve-2026-54121'],
        technologies: ['Microsoft Sentinel', 'Microsoft Sentinel'],
        dataSources: ['SigninLogs'],
        query: 'SigninLogs\n| where RiskLevelDuringSignIn == "high"',
        queryLang: 'esql',
        status: 'ready',
    }, { ownerSub: 'github:42', now });

    assert.equal(hunt.ownerSub, 'github:42');
    assert.equal(hunt.title, 'Logon anômalo');
    assert.equal(hunt.hypothesis, 'Contas comprometidas podem gerar logons fora do padrão.');
    assert.deepEqual(hunt.tactics, ['Credential Access']);
    assert.deepEqual(hunt.techniques, ['T1078']);
    assert.deepEqual(hunt.cves, ['CVE-2026-54121']);
    assert.deepEqual(hunt.technologies, ['Microsoft Sentinel']);
    assert.deepEqual(hunt.dataSources, ['SigninLogs']);
    assert.equal(hunt.queryLang, 'kql');
    assert.equal(hunt.status, 'ready');
    assert.equal(hunt.createdAt, now);
    assert.equal(hunt.updatedAt, now);
    assert.match(hunt.id, /^[0-9a-f]{12}$/);
});

test('rejeita campos essenciais, refs inválidas e status desconhecido', () => {
    assert.throws(() => normalizeHuntInput({ hypothesis: 'x' }, { ownerSub: 'u', now }), /título obrigatório/);
    assert.throws(() => normalizeHuntInput({ title: 'x' }, { ownerSub: 'u', now }), /hipótese obrigatória/);
    assert.throws(() => normalizeHuntInput({ title: 'x', hypothesis: 'y', techniques: ['T99999'] }, { ownerSub: 'u', now }), /técnica inválida/);
    assert.throws(() => normalizeHuntInput({ title: 'x', hypothesis: 'y', cves: ['2026-1234'] }, { ownerSub: 'u', now }), /CVE inválido/);
    assert.throws(() => normalizeHuntInput({ title: 'x', hypothesis: 'y', status: 'public' }, { ownerSub: 'u', now }), /status inválido/);
});

test('atualiza sem trocar id, dono ou data de criação', () => {
    const original = normalizeHuntInput({ title: 'v1', hypothesis: 'hipótese' }, { ownerSub: 'u1', now });
    const updated = normalizeHuntInput({ ...original, title: 'v2', ownerSub: 'u2' }, {
        ownerSub: 'u1',
        id: original.id,
        createdAt: original.createdAt,
        now: '2026-08-02T12:00:00.000Z',
    });

    assert.equal(updated.id, original.id);
    assert.equal(updated.ownerSub, 'u1');
    assert.equal(updated.createdAt, now);
    assert.equal(updated.updatedAt, '2026-08-02T12:00:00.000Z');
    assert.equal(updated.title, 'v2');
});

test('upsert mantém o mais recente no topo e respeita o teto por usuário', () => {
    let hunts = [];
    for (let i = 0; i < HUNTS_CAP + 2; i += 1) {
        hunts = upsertHunt(hunts, { id: String(i), title: `hunt ${i}` });
    }
    hunts = upsertHunt(hunts, { id: String(HUNTS_CAP), title: 'atualizado' });

    assert.equal(hunts.length, HUNTS_CAP);
    assert.equal(hunts[0].title, 'atualizado');
    assert.equal(hunts.filter((hunt) => hunt.id === String(HUNTS_CAP)).length, 1);
});
