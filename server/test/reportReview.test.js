import test from 'node:test';
import assert from 'node:assert/strict';
import { reviewReport } from '../reportReview.js';

const original = () => ({ deck_type: 'campaign', titulo: 'Original', sumario_executivo: 'Original summary',
    source_url: 'https://lab.example/report', iocs: [{ valor: 'malicious.example' }],
    srr_avancado: { acoes_prioritarias: ['Old action'], risco: { nivel: 'Alto' } },
    mitre_ttps: [{ id: 'T1566', contexto: '[POTENCIAL] Investigar a mensagem.', evidencia: 'The phishing message', fontes: ['https://lab.example/report'] }],
});

test('editorial revision preserves original facts and evidence, marking manual MITRE changes', () => {
    const before = original();
    const result = reviewReport(before, { titulo: 'Revised', recomendacoes: [{ titulo: 'Prevenção', itens: ['New action'] }],
        mitre_ttps: [{ id: 'T1566', contexto: '[EM EXPLORAÇÃO] Mensagem conferida pelo analista.' }] });
    assert.equal(before.titulo, 'Original');
    assert.equal(result.titulo, 'Revised');
    assert.deepEqual(result.iocs, before.iocs);
    assert.equal(result.mitre_ttps[0].evidencia, 'The phishing message');
    assert.deepEqual(result.mitre_ttps[0].fontes, before.mitre_ttps[0].fontes);
    assert.equal(result.mitre_ttps[0].classificacao, 'revisao_manual');
    assert.equal(result.srr_avancado.acoes_prioritarias, undefined);
    assert.deepEqual(result.srr_avancado.risco, before.srr_avancado.risco);
});

test('rebuilding without edits preserves analysis and rejects unapproved edits', () => {
    assert.deepEqual(reviewReport(original()), original());
    for (const patch of [{ source_url: 'file:///private' }, { iocs: [] }, { titulo: '' }, { mitre_ttps: [] },
        { mitre_ttps: [{ id: 'T9999', contexto: '[POTENCIAL] Fake' }] },
        { mitre_ttps: [{ id: 'T1566', contexto: 'Unclassified' }] }]) {
        assert.throws(() => reviewReport(original(), patch), { status: 400 });
    }
});
