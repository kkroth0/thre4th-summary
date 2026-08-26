import test from 'node:test';
import assert from 'node:assert/strict';

import {
    TICKET_LIMITS, OPEN_STATUS, shouldAutoOpen, ticketFromHit, attachEvidence, applyStatus,
    noteRecurrence, markDns, buildDailyDigest, takedownRequest, applyTicketRetention, createTicketStore, selectAutoOpen,
} from '../phishTickets.js';

const NOW = '2026-08-26T12:00:00.000Z';
const daysAgo = (n) => new Date(new Date(NOW).getTime() - n * 86400000).toISOString();

const hit = (over = {}) => ({
    id: 'p1:golpe.com', profileId: 'p1', ownerId: 'u1', apexDomain: 'golpe.com', domain: 'www.golpe.com',
    url: 'https://www.golpe.com/', term: 'bancoxpto', title: 'Login', score: 90, reasons: ['fresh-domain', 'brand-glued'],
    scanUrl: 'https://urlscan.io/result/abc/', screenshot: 'https://urlscan.io/screenshots/abc.png',
    firstSeen: NOW, status: 'new', ...over,
});

const memoryStore = () => createTicketStore({
    filePath: '/dev/null',
    readFileSync: () => { throw new Error('vazio'); },
    writeJsonAtomic: () => {},
});

// ─── Abertura ───────────────────────────────────────────────────────────────

test('score alto abre sozinho; score baixo espera triagem', () => {
    assert.equal(shouldAutoOpen(hit({ score: TICKET_LIMITS.autoOpenScore })), true);
    assert.equal(shouldAutoOpen(hit({ score: TICKET_LIMITS.autoOpenScore - 1 })), false);
});

// Dispensar é decisão de quem olhou. A rodada seguinte não pode desfazê-la
// abrindo ticket para o mesmo domínio.
test('achado dispensado nunca abre ticket, mesmo com score alto', () => {
    assert.equal(shouldAutoOpen(hit({ score: 100, status: 'dismissed' })), false);
});

test('o ticket nasce do achado, com a chave do achado e o histórico começado', () => {
    const ticket = ticketFromHit(hit(), { at: NOW });
    assert.equal(ticket.id, 'p1:golpe.com', 'a chave é a mesma do achado');
    assert.equal(ticket.status, 'open');
    assert.equal(ticket.openedBy, 'auto');
    assert.equal(ticket.events.length, 1);
    assert.equal(ticket.events[0].kind, 'opened');
    assert.match(ticket.events[0].note, /score 90/);
});

// ─── Ciclo de vida ──────────────────────────────────────────────────────────

test('cada transição grava quem, quando e a nota', () => {
    let ticket = ticketFromHit(hit(), { at: NOW });
    ticket = applyStatus(ticket, 'takedown', { at: '2026-08-27T09:00:00.000Z', by: 'matheus', note: 'enviado para abuse@bluehost.com' });

    assert.equal(ticket.status, 'takedown');
    assert.equal(ticket.updatedAt, '2026-08-27T09:00:00.000Z');
    const last = ticket.events.at(-1);
    assert.equal(last.kind, 'status:takedown');
    assert.equal(last.by, 'matheus');
    assert.match(last.note, /abuse@bluehost/);
});

test('estado inválido é recusado e repetir o mesmo estado não polui o histórico', () => {
    const ticket = ticketFromHit(hit(), { at: NOW });
    assert.throws(() => applyStatus(ticket, 'resolvido', { at: NOW }), /estado inválido/);
    assert.equal(applyStatus(ticket, 'open', { at: NOW }).events.length, 1);
});

// ─── Reincidência ───────────────────────────────────────────────────────────

// Ticket encerrado cujo domínio reaparece não vira tarefa nova: reabre com a
// data da volta, senão a fila perde a história do golpista insistente.
test('domínio que volta reabre o ticket encerrado em vez de abrir outro', () => {
    let ticket = applyStatus(ticketFromHit(hit(), { at: daysAgo(20) }), 'down', { at: daysAgo(15) });
    ticket = noteRecurrence(ticket, { at: NOW });

    assert.equal(ticket.status, 'open');
    assert.equal(ticket.reopenedAt, NOW);
    assert.equal(ticket.events.at(-1).kind, 'reopened');
});

test('ticket já aberto não é reaberto', () => {
    const ticket = ticketFromHit(hit(), { at: daysAgo(1) });
    assert.equal(noteRecurrence(ticket, { at: NOW }), ticket);
});

// ─── DNS ────────────────────────────────────────────────────────────────────

// Domínio que parou de resolver é candidato a derrubado, não conclusão: pode ter
// sido o takedown, pode ter sido o golpista mudando de casa. Quem fecha é o
// analista.
test('domínio que para de resolver é anotado, mas o ticket continua aberto', () => {
    const ticket = markDns(ticketFromHit(hit(), { at: daysAgo(2) }), false, { at: NOW });
    assert.equal(ticket.dns.deadAt, NOW);
    assert.equal(ticket.status, 'open', 'o sistema fechou o ticket sozinho');
    assert.equal(ticket.events.at(-1).kind, 'dns:dead');
});

test('a queda é anotada uma vez só, não a cada rodada', () => {
    let ticket = markDns(ticketFromHit(hit(), { at: daysAgo(2) }), false, { at: daysAgo(1) });
    ticket = markDns(ticket, false, { at: NOW });
    assert.equal(ticket.events.filter((e) => e.kind === 'dns:dead').length, 1);
    assert.equal(ticket.dns.checkedAt, NOW, 'a checagem mais recente continua sendo registrada');
});

// ─── Evidência e pedido ─────────────────────────────────────────────────────

test('a evidência do RDAP entra no ticket e sai no texto do pedido', () => {
    const ticket = attachEvidence(ticketFromHit(hit(), { at: NOW }), {
        at: NOW, ip: '45.79.222.138', asn: 'AS63949',
        registration: { registrar: 'Key-Systems GmbH', registeredAt: '2026-08-25T00:00:00Z' },
        hosting: { network: 'LINODE-AP' },
        targets: [{ kind: 'hosting', email: 'abuse@linode.com' }],
    });

    const pt = takedownRequest(ticket, { brand: 'Banco XPTO' });
    assert.match(pt, /Banco XPTO/);
    assert.match(pt, /golpe\.com/);
    assert.match(pt, /45\.79\.222\.138/);
    assert.match(pt, /Key-Systems/);
    assert.match(pt, /urlscan\.io\/result/);

    const en = takedownRequest(ticket, { language: 'en', brand: 'Banco XPTO' });
    assert.match(en, /requesting its suspension/);
    assert.match(en, /45\.79\.222\.138/);
});

test('o pedido sai mesmo sem RDAP, com o que existe', () => {
    const text = takedownRequest(ticketFromHit(hit(), { at: NOW }));
    assert.match(text, /golpe\.com/);
    assert.ok(!text.includes('Registrar:'), 'inventou campo que não existe');
});

// ─── Resumo do dia ──────────────────────────────────────────────────────────

test('o resumo separa o que abriu, o que voltou, o que caiu e o que envelheceu', () => {
    const tickets = [
        ticketFromHit(hit({ id: 'p1:hoje.com', apexDomain: 'hoje.com', score: 95 }), { at: NOW }),
        { ...ticketFromHit(hit({ id: 'p1:voltou.com', apexDomain: 'voltou.com' }), { at: daysAgo(30) }), reopenedAt: NOW },
        markDns(ticketFromHit(hit({ id: 'p1:caiu.com', apexDomain: 'caiu.com' }), { at: daysAgo(5) }), false, { at: NOW }),
        applyStatus(ticketFromHit(hit({ id: 'p1:parado.com', apexDomain: 'parado.com' }), { at: daysAgo(10) }), 'analysis', { at: daysAgo(9) }),
        applyStatus(ticketFromHit(hit({ id: 'p1:fechado.com', apexDomain: 'fechado.com' }), { at: daysAgo(40) }), 'closed', { at: daysAgo(39) }),
    ];

    const digest = buildDailyDigest(tickets, { date: NOW, now: new Date(NOW) });

    assert.deepEqual(digest.opened.map((t) => t.apexDomain), ['hoje.com']);
    assert.deepEqual(digest.reopened.map((t) => t.apexDomain), ['voltou.com']);
    assert.deepEqual(digest.dropped.map((t) => t.apexDomain), ['caiu.com']);
    assert.ok(digest.aging.some((t) => t.apexDomain === 'parado.com'), 'ticket parado há 9 dias não envelheceu');
    assert.ok(!digest.aging.some((t) => t.apexDomain === 'fechado.com'), 'ticket fechado não envelhece');
    assert.equal(digest.openCount, 4);
});

// ─── Retenção e store ───────────────────────────────────────────────────────

test('ticket aberto nunca some por idade; encerrado antigo sai', () => {
    const kept = applyTicketRetention([
        applyStatus(ticketFromHit(hit({ id: 'p1:antigo-aberto.com' }), { at: daysAgo(400) }), 'analysis', { at: daysAgo(400) }),
        applyStatus(ticketFromHit(hit({ id: 'p1:antigo-fechado.com' }), { at: daysAgo(400) }), 'closed', { at: daysAgo(400) }),
    ], { profileId: 'p1', now: new Date(NOW) });

    assert.deepEqual(kept.map((t) => t.id), ['p1:antigo-aberto.com']);
});

test('o store filtra por dono e o filtro "open" cobre os três estados em aberto', () => {
    const store = memoryStore();
    store.upsert(ticketFromHit(hit(), { at: NOW }));
    store.upsert(applyStatus(ticketFromHit(hit({ id: 'p1:outro.com', apexDomain: 'outro.com' }), { at: NOW }), 'takedown', { at: NOW }));
    store.upsert(applyStatus(ticketFromHit(hit({ id: 'p1:velho.com', apexDomain: 'velho.com' }), { at: NOW }), 'closed', { at: NOW }));

    assert.equal(store.list('u1', { status: 'open' }).length, 2);
    assert.equal(store.list('u1').length, 3);
    assert.equal(store.list('u2').length, 0);
    assert.throws(() => store.get('u2', 'p1:golpe.com'), /não encontrado/);
    assert.deepEqual(OPEN_STATUS, ['open', 'analysis', 'takedown']);
});

test('apagar o perfil leva os tickets junto', () => {
    const store = memoryStore();
    store.upsert(ticketFromHit(hit(), { at: NOW }));
    store.dropProfile('p1');
    assert.equal(store.all().length, 0);
});

// Medido contra o feed real: "bradesco" trouxe 100 achados numa rodada, 80 deles
// com score de abertura automática, quase todos no mesmo IP — uma campanha só.
// Sem teto, a fila do dia seguinte nasce impossível de trabalhar.
test('campanha em massa não estoura a fila: abre os de maior score até o teto', () => {
    const enxurrada = Array.from({ length: 80 }, (_, i) => hit({
        id: `p1:golpe${i}.com`, apexDomain: `golpe${i}.com`, score: i < 30 ? 100 : 85,
    }));

    const escolhidos = selectAutoOpen(enxurrada);
    assert.equal(escolhidos.length, TICKET_LIMITS.maxAutoOpenPerRun);
    assert.ok(escolhidos.every((item) => item.score === 100), 'deixou de fora achado mais forte');
});

test('o teto não descarta o achado, só adia o ticket', () => {
    const abaixo = hit({ id: 'p1:fraco.com', score: TICKET_LIMITS.autoOpenScore - 1 });
    assert.deepEqual(selectAutoOpen([abaixo]), [], 'score baixo não abre sozinho');
    // Promover na mão continua funcionando: é o caminho do botão "É phishing".
    assert.equal(ticketFromHit(abaixo, { at: NOW, openedBy: 'manual' }).openedBy, 'manual');
});
