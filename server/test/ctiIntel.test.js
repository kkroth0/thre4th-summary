import test from 'node:test';
import assert from 'node:assert/strict';
import { protectTerms, restoreTerms, scoreArticle, CTI_FEEDS, collapseKernelNotices, isTransientFeedError } from '../ctiIntel.js';

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

// ─── Gate do NOISE_PENALTY em scoreArticle ─────────────────────────────────
// A penalidade de ruído só pode derrubar conteúdo puramente promocional —
// não pode apagar um advisory real só porque ele cita "webinar" ou "curso"
// de passagem junto de um CVE/categoria de ataque de verdade.

test('agenda de evento do Dark Reading ("[Virtual Event] ...") recebe a penalidade de ruído', () => {
    const result = scoreArticle('[Virtual Event] How to Defend Against AI-Powered Attacks');

    assert.equal(result.score, 0);
    assert.ok(result.reasons.some((r) => r.startsWith('Noise Detected')));
});

test('post puramente promocional recebe a penalidade de ruído', () => {
    const result = scoreArticle('Join us for our upcoming webinar on cloud security best practices');

    assert.equal(result.score, 0);
    assert.ok(result.reasons.some((r) => r.startsWith('Noise Detected')));
});

test('advisory real não perde a penalidade de ruído por citar termo promocional de passagem', () => {
    const withoutNoise = scoreArticle('Critical RCE actively exploited in the wild, CVE-2026-1234');
    const withNoise = scoreArticle('Critical RCE actively exploited in the wild, CVE-2026-1234 — join us for a webinar recap');

    assert.ok(!withNoise.reasons.some((r) => r.startsWith('Noise Detected')));
    assert.equal(withNoise.score, withoutNoise.score);
});

// ─── Catálogo de feeds (CTI_FEEDS) ──────────────────────────────────────────

// ─── Erro transitório vs. permanente no fetch de feed ──────────────────────

test('5xx e 429 são transitórios; 4xx comum não é', () => {
    assert.equal(isTransientFeedError({ response: { status: 503 } }), true);
    assert.equal(isTransientFeedError({ response: { status: 500 } }), true);
    assert.equal(isTransientFeedError({ response: { status: 429 } }), true);
    assert.equal(isTransientFeedError({ response: { status: 404 } }), false);
    assert.equal(isTransientFeedError({ response: { status: 403 } }), false);
});

test('timeout e conexão resetada são transitórios; falha de DNS não é', () => {
    assert.equal(isTransientFeedError({ code: 'ECONNABORTED' }), true);
    assert.equal(isTransientFeedError({ code: 'ETIMEDOUT' }), true);
    assert.equal(isTransientFeedError({ code: 'ECONNRESET' }), true);
    assert.equal(isTransientFeedError({ code: 'ECONNREFUSED' }), true);
    assert.equal(isTransientFeedError({ code: 'ENOTFOUND' }), false);
    assert.equal(isTransientFeedError({ code: 'EAI_AGAIN' }), false);
});

test('erro sem status e sem code reconhecido não é transitório', () => {
    assert.equal(isTransientFeedError({}), false);
    assert.equal(isTransientFeedError(new Error('boom')), false);
});

test('CTI_FEEDS não tem URL duplicada', () => {
    const urls = CTI_FEEDS.map((f) => f.url);
    assert.equal(new Set(urls).size, urls.length);
});

test('todo feed built-in declara source, layer e weight_boost', () => {
    for (const feed of CTI_FEEDS) {
        assert.ok(feed.source, `feed sem source: ${feed.url}`);
        assert.ok([1, 2, 3, 4].includes(feed.layer), `feed com layer inválida: ${feed.source}`);
        assert.equal(typeof feed.weight_boost, 'number', `feed sem weight_boost: ${feed.source}`);
    }
});

// ─── NOISE_VOLUME não pode ser neutralizado pelo gate do NOISE_PENALTY ─────
// linux kernel praticamente sempre vem com CVE de verdade — se o gate de
// "sinal concreto" também bloqueasse o NOISE_VOLUME, a penalidade nunca mais
// dispararia, e é exatamente o oposto do que ela existe para fazer.

test('menção a linux kernel com CVE real ainda leva a penalidade de volume', () => {
    const withKernel = scoreArticle('CVE-2026-9999 fixed in linux kernel');
    const withoutKernel = scoreArticle('CVE-2026-9999 fixed in some other package');

    assert.ok(withKernel.reasons.some((r) => r.startsWith('Low Interest')));
    assert.ok(withKernel.score < withoutKernel.score);
});

// ─── Colapso das USN de kernel do Ubuntu ───────────────────────────────────

test('um único aviso de kernel no dia passa direto, sem colapsar', () => {
    const items = [
        { source: 'Ubuntu Security Notices', title: 'linux-aws vulnerabilities', link: 'https://ubuntu.com/a', pubDate: '2026-09-15T10:00:00Z', score: 40, cves: ['CVE-2026-1'] },
    ];

    assert.deepEqual(collapseKernelNotices(items), items);
});

test('vários avisos de kernel do Ubuntu no mesmo dia viram um card só', () => {
    const items = [
        { source: 'Ubuntu Security Notices', title: 'linux-aws vulnerabilities', link: 'https://ubuntu.com/a', pubDate: '2026-09-15T08:00:00Z', score: 40, cves: ['CVE-2026-1'] },
        { source: 'Ubuntu Security Notices', title: 'linux-gcp vulnerabilities', link: 'https://ubuntu.com/b', pubDate: '2026-09-15T09:00:00Z', score: 70, cves: ['CVE-2026-1', 'CVE-2026-2'] },
        { source: 'Ubuntu Security Notices', title: 'linux-oem-6.8 vulnerabilities', link: 'https://ubuntu.com/c', pubDate: '2026-09-15T10:00:00Z', score: 55, cves: ['CVE-2026-2'] },
    ];

    const result = collapseKernelNotices(items);

    assert.equal(result.length, 1);
    assert.match(result[0].title, /3 Ubuntu flavors patched/);
    assert.match(result[0].title, /linux-aws/);
    assert.deepEqual(result[0].cves.sort(), ['CVE-2026-1', 'CVE-2026-2']);
    // O mais severo (score 70) vira a base — nada crítico some atrás de um flavor mais brando.
    assert.equal(result[0].score, 70);
    assert.match(result[0].description, /linux-aws vulnerabilities: https:\/\/ubuntu\.com\/a/);
    assert.match(result[0].description, /linux-gcp vulnerabilities: https:\/\/ubuntu\.com\/b/);
});

test('aviso do Ubuntu que não é de kernel não é colapsado', () => {
    const items = [
        { source: 'Ubuntu Security Notices', title: 'Firefox vulnerabilities', link: 'https://ubuntu.com/x', pubDate: '2026-09-15T08:00:00Z', score: 30 },
        { source: 'Ubuntu Security Notices', title: 'OpenSSL vulnerabilities', link: 'https://ubuntu.com/y', pubDate: '2026-09-15T09:00:00Z', score: 30 },
    ];

    assert.deepEqual(collapseKernelNotices(items), items);
});

test('título de kernel de outra fonte não é colapsado — a regra é só do Ubuntu', () => {
    const items = [
        { source: 'Some Other Feed', title: 'linux-aws vulnerabilities', link: 'https://example.com/a', pubDate: '2026-09-15T08:00:00Z', score: 40 },
        { source: 'Some Other Feed', title: 'linux-gcp vulnerabilities', link: 'https://example.com/b', pubDate: '2026-09-15T09:00:00Z', score: 40 },
    ];

    assert.deepEqual(collapseKernelNotices(items), items);
});
