// Fila de trabalho da vigilância de marca: o achado vira ticket quando merece
// alguém em cima dele.
//
// A diferença entre lista e fila é o que fica gravado. O achado responde "o que
// apareceu"; o ticket responde "o que a gente fez, quando, e como terminou" —
// que é a pergunta de quem volta ao assunto três semanas depois.
//
// A evidência é congelada na abertura de propósito: domínio de phishing morre
// rápido, e o pedido de derrubada precisa da prova de quando estava no ar.

export const TICKET_STATUS = ['open', 'analysis', 'takedown', 'down', 'closed'];
export const OPEN_STATUS = ['open', 'analysis', 'takedown'];

export const TICKET_LIMITS = {
    // Domínio de até 2 dias, marca colada em outra palavra e página no ar dão 80
    // sozinhos. Abaixo disso o achado espera triagem na lista, sem virar tarefa.
    autoOpenScore: 80,
    // Dias sem sair do lugar antes de o ticket aparecer como envelhecido no
    // resumo do dia. Página de phishing vive horas; três dias parado é muito.
    agingDays: 3,
    // Teto de abertura automática por rodada. Campanha em massa contra marca
    // famosa traz dezenas de domínios de score 100 de uma vez — medido: 80 numa
    // rodada só para "bradesco", todos no mesmo IP. Sem teto, a fila do dia
    // seguinte é impossível de trabalhar e deixa de ser levada a sério. O resto
    // continua na lista de achados e pode ser promovido na mão.
    maxAutoOpenPerRun: 20,
    closedRetentionDays: 180,
    perProfile: 500,
};

export const createTicketError = (status, publicMessage) =>
    Object.assign(new Error(publicMessage), { status, publicMessage });

export const shouldAutoOpen = (hit) =>
    Boolean(hit) && hit.status !== 'dismissed' && Number(hit.score) >= TICKET_LIMITS.autoOpenScore;

/**
 * Quais achados a rodada abre sozinha: os de maior score, até o teto.
 *
 * A ordem é por score porque, quando a campanha estoura, o que fica de fora
 * precisa ser o mais fraco — e continua visível na lista de achados.
 */
export function selectAutoOpen(hits, { limit = TICKET_LIMITS.maxAutoOpenPerRun } = {}) {
    return (Array.isArray(hits) ? hits : [])
        .filter(shouldAutoOpen)
        .sort((a, b) => b.score - a.score || String(a.apexDomain).localeCompare(String(b.apexDomain)))
        .slice(0, limit);
}

const event = (kind, { at, by = 'sistema', note = '' } = {}) => ({ at, kind, by, note });

export function ticketFromHit(hit, { at, by = 'sistema', openedBy = 'auto' } = {}) {
    if (!hit || !hit.id) throw createTicketError(400, 'achado inválido');
    return {
        // Mesma chave do achado: um ticket por domínio por perfil, para o mesmo
        // domínio voltando não abrir tarefa nova.
        id: hit.id,
        profileId: hit.profileId,
        ownerId: hit.ownerId,
        apexDomain: hit.apexDomain,
        domain: hit.domain,
        url: hit.url,
        term: hit.term,
        title: hit.title,
        score: hit.score,
        reasons: [...(hit.reasons || [])],
        scanUrl: hit.scanUrl,
        screenshot: hit.screenshot,
        firstSeen: hit.firstSeen,
        status: 'open',
        openedAt: at,
        openedBy,
        updatedAt: at,
        // Preenchida logo depois pela consulta RDAP; o ticket existe mesmo se
        // ela falhar, porque a fila não pode depender de registro de terceiro.
        evidence: null,
        targets: [],
        dns: { checkedAt: null, aliveAt: null, deadAt: null },
        events: [event('opened', { at, by, note: openedBy === 'auto' ? `score ${hit.score}` : '' })],
    };
}

export function attachEvidence(ticket, { registration, hosting, targets, ip, asn, country, at }) {
    return {
        ...ticket,
        evidence: { ip: ip ?? null, asn: asn ?? null, country: country ?? null, registration: registration ?? null, hosting: hosting ?? null, capturedAt: at },
        targets: targets || [],
        updatedAt: at,
    };
}

export function applyStatus(ticket, status, { at, by = 'analista', note = '' } = {}) {
    if (!TICKET_STATUS.includes(status)) throw createTicketError(400, 'estado inválido');
    if (ticket.status === status) return ticket;
    return {
        ...ticket,
        status,
        updatedAt: at,
        events: [...ticket.events, event(`status:${status}`, { at, by, note })],
    };
}

/**
 * O mesmo domínio voltando a aparecer numa rodada.
 *
 * Ticket já encerrado não vira ticket novo: reabre com a data da volta. É o que
 * mostra golpista insistente — e sem isso a fila perde a história, que é
 * exatamente o que ela existe para guardar.
 */
export function noteRecurrence(ticket, { at, note = '' } = {}) {
    if (OPEN_STATUS.includes(ticket.status)) return ticket;
    return {
        ...ticket,
        status: 'open',
        updatedAt: at,
        reopenedAt: at,
        events: [...ticket.events, event('reopened', { at, note: note || 'domínio voltou a aparecer' })],
    };
}

/**
 * Resultado da checagem de DNS do domínio do ticket.
 *
 * Domínio que parou de resolver é forte candidato a derrubado, mas quem fecha é
 * o analista: pode ter sido o takedown, pode ter sido o golpista trocando de
 * casa antes da próxima campanha. O sistema anota o fato e não conclui.
 */
export function markDns(ticket, alive, { at } = {}) {
    const dns = { ...ticket.dns, checkedAt: at };
    const events = [...ticket.events];
    if (alive) {
        dns.aliveAt = at;
        if (ticket.dns.deadAt && !ticket.dns.aliveAt) events.push(event('dns:back', { at, note: 'domínio voltou a resolver' }));
    } else if (!ticket.dns.deadAt) {
        dns.deadAt = at;
        events.push(event('dns:dead', { at, note: 'domínio parou de resolver' }));
    }
    return { ...ticket, dns, events, updatedAt: at };
}

const dayOf = (value) => String(value || '').slice(0, 10);

/**
 * O resumo do dia, derivado dos tickets em vez de gravado num store à parte:
 * a fila já guarda tudo que ele precisa, e uma edição gravada só criaria dois
 * lugares para a mesma verdade envelhecer em desacordo.
 */
export function buildDailyDigest(tickets, { date, now = new Date() } = {}) {
    const day = dayOf(date || now.toISOString());
    const mine = (Array.isArray(tickets) ? tickets : []);
    const agingCutoff = new Date(now).getTime() - TICKET_LIMITS.agingDays * 86400000;

    const opened = mine.filter((ticket) => dayOf(ticket.openedAt) === day);
    const reopened = mine.filter((ticket) => ticket.reopenedAt && dayOf(ticket.reopenedAt) === day);
    const dropped = mine.filter((ticket) => ticket.dns?.deadAt && dayOf(ticket.dns.deadAt) === day);
    const aging = mine.filter((ticket) => OPEN_STATUS.includes(ticket.status)
        && new Date(ticket.updatedAt).getTime() < agingCutoff);

    const byStatus = {};
    for (const ticket of mine) byStatus[ticket.status] = (byStatus[ticket.status] || 0) + 1;

    const bySeverity = (a, b) => b.score - a.score || String(a.apexDomain).localeCompare(String(b.apexDomain));
    return {
        date: day,
        opened: opened.sort(bySeverity),
        reopened: reopened.sort(bySeverity),
        dropped: dropped.sort(bySeverity),
        aging: aging.sort((a, b) => String(a.updatedAt).localeCompare(String(b.updatedAt))),
        byStatus,
        openCount: mine.filter((ticket) => OPEN_STATUS.includes(ticket.status)).length,
    };
}

const line = (label, value) => (value ? `${label}: ${value}\n` : '');

/**
 * O texto do pedido, pronto para colar no e-mail de abuse.
 *
 * Sem adjetivo e sem ameaça: quem lê abuse@ recebe centenas por dia e age sobre
 * o que dá para verificar em trinta segundos — a URL, o IP, e o link do scan
 * público que mostra a página como ela estava.
 */
export function takedownRequest(ticket, { language = 'pt', brand = '' } = {}) {
    const target = brand || ticket.term || ticket.apexDomain;
    const seen = String(ticket.firstSeen || ticket.openedAt || '').slice(0, 10);
    const facts = line('Domain', ticket.apexDomain)
        + line('URL', ticket.url)
        + line('IP', ticket.evidence?.ip)
        + line('Network', ticket.evidence?.hosting?.network)
        + line('Registrar', ticket.evidence?.registration?.registrar)
        + line('Registered', String(ticket.evidence?.registration?.registeredAt || '').slice(0, 10))
        + line('First seen', seen)
        + line('Evidence', ticket.scanUrl);

    if (language === 'en') {
        return `Subject: Phishing content abusing the "${target}" brand — ${ticket.apexDomain}

Hello,

The domain below is hosting content that impersonates the "${target}" brand and is being used to deceive users. We are requesting its suspension.

${facts}
The evidence link is a public urlscan.io capture showing the page as served, including the requests it made.

We are available for any additional information.

Regards,`;
    }

    return `Assunto: Conteúdo de phishing abusando da marca "${target}" — ${ticket.apexDomain}

Prezados,

O domínio abaixo hospeda conteúdo que se passa pela marca "${target}" e é usado para enganar usuários. Solicitamos a suspensão.

${facts}
O link de evidência é uma captura pública do urlscan.io mostrando a página como ela foi servida, com as requisições que fez.

Ficamos à disposição para qualquer informação adicional.

Atenciosamente,`;
}

export function applyTicketRetention(tickets, { profileId, now = new Date() } = {}) {
    const cutoff = now.getTime() - TICKET_LIMITS.closedRetentionDays * 86400000;
    const others = [];
    const mine = [];
    for (const ticket of tickets || []) {
        if (profileId && ticket.profileId !== profileId) { others.push(ticket); continue; }
        // Ticket aberto nunca some por idade: fila que apaga tarefa não é fila.
        if (OPEN_STATUS.includes(ticket.status) || new Date(ticket.updatedAt).getTime() >= cutoff) mine.push(ticket);
    }
    mine.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    return [...others, ...mine.slice(0, TICKET_LIMITS.perProfile)];
}

export function createTicketStore({ filePath, readFileSync, writeJsonAtomic }) {
    let tickets = [];
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        tickets = Array.isArray(parsed) ? parsed.filter((ticket) => ticket && ticket.id && ticket.profileId) : [];
    } catch { /* store vazio: a fila recomeça, o app não cai */ }

    const save = () => writeJsonAtomic(filePath, tickets);
    const replace = (next) => { tickets = tickets.map((ticket) => (ticket.id === next.id ? next : ticket)); save(); return next; };

    return {
        all: () => tickets,
        list(ownerId, { profileId, status } = {}) {
            return tickets
                .filter((ticket) => ticket.ownerId === ownerId)
                .filter((ticket) => !profileId || ticket.profileId === profileId)
                .filter((ticket) => (status === 'open' ? OPEN_STATUS.includes(ticket.status) : !status || ticket.status === status))
                .sort((a, b) => b.score - a.score || String(b.updatedAt).localeCompare(String(a.updatedAt)));
        },
        get(ownerId, id) {
            const found = tickets.find((ticket) => ticket.id === id && ticket.ownerId === ownerId);
            if (!found) throw createTicketError(404, 'ticket não encontrado');
            return found;
        },
        byId: (id) => tickets.find((ticket) => ticket.id === id) || null,
        upsert(ticket, { now = new Date() } = {}) {
            const existing = tickets.find((item) => item.id === ticket.id);
            if (existing) return replace(ticket);
            tickets = applyTicketRetention([...tickets, ticket], { profileId: ticket.profileId, now });
            save();
            return ticket;
        },
        setStatus(ownerId, id, status, options) {
            return replace(applyStatus(this.get(ownerId, id), status, options));
        },
        dropProfile(profileId) {
            tickets = tickets.filter((ticket) => ticket.profileId !== profileId);
            save();
        },
    };
}
