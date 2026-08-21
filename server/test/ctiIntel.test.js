import test from 'node:test';
import assert from 'node:assert/strict';
import { protectTerms, restoreTerms } from '../ctiIntel.js';

// ─── Proteção de terminologia na tradução ──────────────────────────────────

test('termos técnicos saem mascarados e voltam intactos', () => {
    const { masked, terms } = protectTerms('A Buffer Overflow allows Remote Code Execution via path traversal.');

    assert.equal(masked, 'A TSQ0 allows TSQ1 via TSQ2.');
    assert.deepEqual(terms, ['Buffer Overflow', 'Remote Code Execution', 'path traversal']);
    // Simula o tradutor: mexe na prosa em volta, não nos marcadores.
    assert.equal(
        restoreTerms('Um TSQ0 permite TSQ1 via TSQ2.', terms),
        'Um Buffer Overflow permite Remote Code Execution via path traversal.',
    );
});

test('a caixa do termo como publicado é preservada', () => {
    const { terms } = protectTerms('um buffer overflow e um SQL INJECTION');

    assert.deepEqual(terms, ['buffer overflow', 'SQL INJECTION']);
});

test('marcador 1 não casa dentro do marcador 10', () => {
    const terms = Array.from({ length: 11 }, (_, i) => `termo${i}`);

    assert.equal(restoreTerms('TSQ10 e TSQ1', terms), 'termo10 e termo1');
});

test('marcador sobrevive a mudança de caixa e espaço do tradutor', () => {
    const { terms } = protectTerms('a race condition');

    assert.equal(restoreTerms('uma tsq 0', terms), 'uma race condition');
});

test('texto sem termo técnico passa sem marcador', () => {
    const { masked, terms } = protectTerms('O fabricante liberou a correção.');

    assert.equal(masked, 'O fabricante liberou a correção.');
    assert.deepEqual(terms, []);
});
