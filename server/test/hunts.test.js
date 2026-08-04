import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHearthData } from '../hearth.js';
import {
    HUNTS_CAP,
    normalizeHuntInput,
    upsertHunt,
    normalizeRunInput,
    upsertRun,
    monthlySummary,
    RUNS_CAP,
    withDefaults,
    overdueHunts,
} from '../hunts.js';

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

// ─── Execução (controle mensal) ───────────────────────────────────────────
test('execução só aceita estado e resultado conhecidos', () => {
    assert.throws(() => normalizeRunInput({ state: 'quase' }), /estado de execução inválido/);
    assert.throws(() => normalizeRunInput({ state: 'done', outcome: 'talvez' }), /resultado inválido/);
    assert.throws(() => normalizeRunInput({ state: 'running', outcome: 'incident' }), /só em execução finalizada/);
    assert.throws(() => normalizeRunInput({ state: 'done', events: -1 }), /contagem inválida/);
    assert.throws(() => normalizeRunInput({ state: 'done', events: 'muitos' }), /contagem inválida/);
});

test('execução finalizada carimba o fim; aberta não', () => {
    const aberta = normalizeRunInput({ state: 'running' }, { now: '2026-08-10T12:00:00.000Z' });
    assert.equal(aberta.finishedAt, null);
    assert.equal(aberta.outcome, 'none');

    const fechada = normalizeRunInput(
        { state: 'done', outcome: 'suspicious', events: 12, hosts: 3, findings: 'tráfego para domínio recém-registrado' },
        { now: '2026-08-11T12:00:00.000Z' },
    );
    assert.equal(fechada.finishedAt, '2026-08-11T12:00:00.000Z');
    assert.equal(fechada.events, 12);
    assert.match(fechada.findings, /domínio recém-registrado/);
});

test('upsertRun troca a execução pelo id e respeita o teto', () => {
    const hunt = { id: 'h1', runs: [] };
    const primeira = normalizeRunInput({ state: 'running' }, { id: 'r1' });
    const comUma = upsertRun(hunt, primeira);
    assert.equal(comUma.runs.length, 1);

    const fechada = normalizeRunInput({ state: 'done' }, { id: 'r1' });
    const trocada = upsertRun(comUma, fechada);
    assert.equal(trocada.runs.length, 1, 'mesma execução não duplica');
    assert.equal(trocada.runs[0].state, 'done');

    const cheia = { id: 'h1', runs: Array.from({ length: RUNS_CAP }, (_, i) => ({ id: `old${i}` })) };
    assert.equal(upsertRun(cheia, normalizeRunInput({ state: 'pending' })).runs.length, RUNS_CAP);
});

test('resumo do mês conta por estado e só pontua achado do que fechou', () => {
    const hunts = [
        { id: 'h1', title: 'Egress', runs: [
            normalizeRunInput({ state: 'done', outcome: 'incident', events: 4 }, { id: 'a', startedAt: '2026-08-03T10:00:00.000Z' }),
            normalizeRunInput({ state: 'running' }, { id: 'b', startedAt: '2026-08-20T10:00:00.000Z' }),
            normalizeRunInput({ state: 'done', outcome: 'none' }, { id: 'c', startedAt: '2026-07-05T10:00:00.000Z' }),
        ] },
        { id: 'h2', title: 'Admin', runs: [
            normalizeRunInput({ state: 'pending' }, { id: 'd', startedAt: '2026-08-28T10:00:00.000Z' }),
        ] },
    ];

    const agosto = monthlySummary(hunts, '2026-08');
    assert.equal(agosto.total, 3, 'a execução de julho fica fora');
    assert.deepEqual(agosto.byState, { pending: 1, running: 1, done: 1 });
    assert.deepEqual(agosto.byOutcome, { none: 0, suspicious: 0, incident: 1 });
    assert.equal(agosto.runs[0].title, 'Egress', 'a execução carrega a hunt de origem');

    assert.equal(monthlySummary(hunts, '2026-09').total, 0);
});

test('origem só aceita catálogo conhecido e sobrevive ao update', () => {
    const adotada = normalizeHuntInput(
        { title: 'Egress', hypothesis: 'saida incomum', origin: 'ptbr', sourceId: 'weekly/top-egress' },
        { ownerSub: 'u1' },
    );
    assert.equal(adotada.origin, 'ptbr');
    assert.equal(adotada.sourceId, 'weekly/top-egress');

    // Origem inventada não vira rótulo: cai pra 'own'.
    assert.equal(normalizeHuntInput({ title: 't', hypothesis: 'h', origin: 'inventada' }, { ownerSub: 'u1' }).origin, 'own');
    assert.equal(normalizeHuntInput({ title: 't', hypothesis: 'h' }, { ownerSub: 'u1' }).origin, 'own');

    // O PATCH passa a hunt inteira pelo normalize; a origem não pode se perder.
    const editada = normalizeHuntInput({ ...adotada, title: 'Egress revisado' }, { ownerSub: 'u1', id: adotada.id });
    assert.equal(editada.origin, 'ptbr');
    assert.equal(editada.sourceId, 'weekly/top-egress');
});

test('hunt salva antes dos campos novos nao chega quebrada no cliente', () => {
    // Exatamente o formato que estava no disco antes de runs/origin existirem.
    const antiga = { id: 'h1', title: 'Egress', hypothesis: 'saida', techniques: [] };
    const corrigida = withDefaults(antiga);

    assert.equal(corrigida.origin, 'own', 'sem origem vira própria, e não undefined');
    assert.deepEqual(corrigida.runs, [], 'sem execuções vira lista vazia, e não undefined');
    assert.equal(corrigida.sourceId, '');
    assert.equal(corrigida.title, 'Egress', 'o resto passa intacto');

    // Origem inventada no disco também é normalizada.
    assert.equal(withDefaults({ origin: 'sei-la' }).origin, 'own');
    assert.equal(withDefaults({ origin: 'ptbr' }).origin, 'ptbr');
});

// ─── Cadência: o que ficou pra trás ───────────────────────────────────────
const DIA = 24 * 60 * 60 * 1000;
const AGORA = Date.parse('2026-08-04T12:00:00.000Z');
const runEm = (iso) => ({ id: iso, state: 'done', outcome: 'none', startedAt: iso });

test('sem cadência a hunt nunca vence', () => {
    const semRitmo = [{ id: 'h1', title: 'Ad hoc', cadence: '', runs: [] }];
    assert.deepEqual(overdueHunts(semRitmo, AGORA), []);

    // 'intel' é sob demanda: chega inteligência, roda. Não tem atraso.
    const sobDemanda = [{ id: 'h2', title: 'IOC sweep', cadence: 'intel', runs: [] }];
    assert.deepEqual(overdueHunts(sobDemanda, AGORA), []);
});

test('vence quando passou o intervalo, e não antes', () => {
    const recente = [{ id: 'h1', title: 'Semanal', cadence: 'weekly', runs: [runEm(new Date(AGORA - 3 * DIA).toISOString())] }];
    assert.deepEqual(overdueHunts(recente, AGORA), [], 'três dias não vence uma semanal');

    const atrasada = [{ id: 'h1', title: 'Semanal', cadence: 'weekly', runs: [runEm(new Date(AGORA - 10 * DIA).toISOString())] }];
    const vencidas = overdueHunts(atrasada, AGORA);
    assert.equal(vencidas.length, 1);
    assert.equal(vencidas[0].daysLate, 3, 'dez dias em cadência de sete: três de atraso');
});

test('hunt que nunca rodou aparece primeiro, depois a mais atrasada', () => {
    const lista = [
        { id: 'atrasada', title: 'Atrasada', cadence: 'daily', runs: [runEm(new Date(AGORA - 9 * DIA).toISOString())] },
        { id: 'nunca', title: 'Nunca rodou', cadence: 'monthly', runs: [] },
        { id: 'pouco', title: 'Pouco atrasada', cadence: 'daily', runs: [runEm(new Date(AGORA - 3 * DIA).toISOString())] },
    ];

    assert.deepEqual(overdueHunts(lista, AGORA).map((item) => item.id), ['nunca', 'atrasada', 'pouco']);
    assert.equal(overdueHunts(lista, AGORA)[0].lastRunAt, null);
});

test('a execução que conta é a mais recente, mesmo fora de ordem na lista', () => {
    // Reabrir e fechar mexe na ordem da lista: não dá pra confiar no topo.
    const foraDeOrdem = [{
        id: 'h1', title: 'Semanal', cadence: 'weekly',
        runs: [runEm(new Date(AGORA - 30 * DIA).toISOString()), runEm(new Date(AGORA - 2 * DIA).toISOString())],
    }];
    assert.deepEqual(overdueHunts(foraDeOrdem, AGORA), [], 'a de dois dias atrás é a que vale');
});

test('cadência inválida não vira rótulo', () => {
    const hunt = normalizeHuntInput({ title: 't', hypothesis: 'h', cadence: 'quinzenal' }, { ownerSub: 'u1' });
    assert.equal(hunt.cadence, '');
    assert.equal(normalizeHuntInput({ title: 't', hypothesis: 'h', cadence: 'weekly' }, { ownerSub: 'u1' }).cadence, 'weekly');
});
