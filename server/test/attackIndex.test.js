import test from 'node:test';
import assert from 'node:assert/strict';
import {
    extractRefs,
    groupByField,
    refsOfReport,
    relatedTo,
    techniqueCoverage,
} from '../attackIndex.js';

// Recorte da matriz real: T1566 com duas sub-técnicas em initial-access, e
// T1059 em execution para provar que uma tática não vaza na outra.
const taxonomy = {
    tactics: [
        { id: 'TA0001', name: 'Initial Access', shortname: 'initial-access' },
        { id: 'TA0002', name: 'Execution', shortname: 'execution' },
    ],
    techniques: [
        { id: 'T1059', name: 'Command and Scripting Interpreter', tactics: ['execution'] },
        { id: 'T1059.001', name: 'PowerShell', tactics: ['execution'] },
        { id: 'T1566', name: 'Phishing', tactics: ['initial-access'] },
        { id: 'T1566.001', name: 'Spearphishing Attachment', tactics: ['initial-access'] },
        { id: 'T1566.002', name: 'Spearphishing Link', tactics: ['initial-access'] },
    ],
};

test('extractRefs pega técnica, sub-técnica e CVE de 5 dígitos', () => {
    const refs = extractRefs('Explora CVE-2026-54121 via T1566.002 e depois T1059.');
    assert.deepEqual(refs.techniques, ['T1059', 'T1566.002']);
    assert.deepEqual(refs.cves, ['CVE-2026-54121']);
});

test('extractRefs normaliza, deduplica e ignora entrada não-texto', () => {
    const refs = extractRefs('cve-2026-1234 CVE-2026-1234 t1059 T1059');
    assert.deepEqual(refs.techniques, ['T1059']);
    assert.deepEqual(refs.cves, ['CVE-2026-1234']);
    assert.deepEqual(extractRefs(null), { techniques: [], cves: [] });
});

test('extractRefs não casa ID mais longo que uma técnica', () => {
    // T15667 não é técnica; o limite de palavra tem que barrar.
    assert.deepEqual(extractRefs('T15667 e TA0001').techniques, []);
});

test('refsOfReport colhe dos campos estruturados e da prosa do boletim', () => {
    const refs = refsOfReport({
        cve_id: 'CVE-2026-54121',
        sumario_executivo: 'Cadeia começa em T1566.002.',
        tecnologias_afetadas: [{ cve: 'CVE-2026-9999' }],
        mitre_ttps: [{ id: 'T1003.006', nome: 'DCSync' }],
    });
    assert.deepEqual(refs.techniques, ['T1003.006', 'T1566.002']);
    assert.deepEqual(refs.cves, ['CVE-2026-54121', 'CVE-2026-9999']);
});

test('relatedTo cruza por técnica ou CVE e preserva as chaves dos pools', () => {
    const pools = {
        hunts: [
            { id: 'H1', techniques: ['T1566.002'] },
            { id: 'H2', techniques: ['T1078'] },
        ],
        reports: [{ id: 'R1', techniques: [], cves: ['CVE-2026-54121'] }],
        actors: [{ id: 'G1', techniques: [{ id: 'T1566.002', name: 'Spearphishing Link' }] }],
    };
    const out = relatedTo({ techniques: ['t1566.002'], cves: ['CVE-2026-54121'] }, pools);
    assert.deepEqual(Object.keys(out), ['hunts', 'reports', 'actors']);
    assert.deepEqual(out.hunts.map((h) => h.id), ['H1']);
    assert.deepEqual(out.reports.map((r) => r.id), ['R1']);
    // Ator traz técnica como objeto {id,name,url}, não string.
    assert.deepEqual(out.actors.map((a) => a.id), ['G1']);
});

test('relatedTo devolve pools vazios quando o alvo não tem refs', () => {
    const out = relatedTo({}, { hunts: [{ id: 'H1', techniques: ['T1566'] }] });
    assert.deepEqual(out.hunts, []);
});

test('groupByField ordena por frequência e depois por nome', () => {
    const hunts = [
        { dataSources: ['SigninLogs', 'DeviceEvents'] },
        { dataSources: ['SigninLogs'] },
        { dataSources: ['  '] },
        {},
    ];
    assert.deepEqual(groupByField(hunts, 'dataSources'), [
        { value: 'SigninLogs', count: 2 },
        { value: 'DeviceEvents', count: 1 },
    ]);
});

test('techniqueCoverage marca covered, partial e none', () => {
    const items = [{ techniques: ['T1566.002'] }, { techniques: ['T1059'] }];
    const { tactics, covered, total } = techniqueCoverage(items, taxonomy);

    const initialAccess = tactics.find((t) => t.shortname === 'initial-access');
    const phishing = initialAccess.techniques.find((t) => t.id === 'T1566');
    // Ninguém aponta para T1566, mas T1566.002 está coberta.
    assert.equal(phishing.state, 'partial');
    assert.equal(phishing.count, 0);
    assert.deepEqual(
        phishing.subs.map((s) => [s.id, s.state]),
        [['T1566.001', 'none'], ['T1566.002', 'covered']],
    );

    const execution = tactics.find((t) => t.shortname === 'execution');
    const interpreter = execution.techniques.find((t) => t.id === 'T1059');
    assert.equal(interpreter.state, 'covered');

    // Sub-técnicas não entram como linha de topo.
    assert.deepEqual(initialAccess.techniques.map((t) => t.id), ['T1566']);
    assert.equal(initialAccess.covered, 0);
    assert.equal(initialAccess.total, 1);

    // Denominador é a matriz inteira, sub-técnicas incluídas.
    assert.equal(total, 5);
    assert.equal(covered, 2);
});

test('techniqueCoverage ignora ID que não existe na taxonomia', () => {
    const { covered, total } = techniqueCoverage([{ techniques: ['T9999'] }], taxonomy);
    assert.equal(covered, 0);
    assert.equal(total, 5);
});

test('techniqueCoverage aguenta entrada vazia', () => {
    const { tactics, covered } = techniqueCoverage([], taxonomy);
    assert.equal(covered, 0);
    assert.equal(tactics.length, 2);
});
