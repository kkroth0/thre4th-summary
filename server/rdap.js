// RDAP: quem registrou o domínio e quem hospeda o IP — e, principalmente, para
// onde mandar o pedido de derrubada.
//
// É o registro oficial em JSON, público e sem chave. Substitui o WHOIS de texto
// livre, que cada registro formatava do seu jeito.
//
// O caminho do IP importa mais que o do domínio: o hosting derruba a página em
// horas, o registrador leva dias e às vezes exige processo. Por isso os dois são
// consultados, mas a falha de um nunca impede o outro.

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
// Uma porta de entrada só para IP: a ARIN redireciona para o RIR certo
// (LACNIC, RIPE, APNIC) e o fetch segue o 30x sozinho.
const IP_RDAP = 'https://rdap.arin.net/registry/ip/';

// O bootstrap da IANA muda uma vez por semana, na melhor das hipóteses.
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

// Canais que valem para qualquer domínio, independentemente de registro e
// hospedagem. Não substituem o abuse do hosting: entram junto.
export const STANDING_CHANNELS = [
    { name: 'Google Safe Browsing', url: 'https://safebrowsing.google.com/safebrowsing/report_phish/' },
    { name: 'APWG', email: 'reportphishing@apwg.org' },
    { name: 'PhishTank', url: 'https://www.phishtank.com/add_web_phish.php' },
];

// .br tem CERT.br, que é o CSIRT nacional e trabalha com os provedores locais.
export const BR_CHANNELS = [{ name: 'CERT.br', email: 'cert@cert.br' }];

const asArray = (value) => (Array.isArray(value) ? value : []);

// vcardArray é ["vcard", [["version",{},"text","4.0"], ["email",{},"text","x@y"]]].
// O formato é feio, mas é padrão e não muda.
const vcardValues = (entity, field) => {
    const card = asArray(asArray(entity.vcardArray)[1]);
    return card.filter((row) => asArray(row)[0] === field).map((row) => row[3]).filter(Boolean);
};

/**
 * Varre as entidades em profundidade atrás de e-mail de abuse.
 *
 * O contato de abuse quase nunca está no primeiro nível: no .com ele é uma
 * entidade *dentro* da entidade do registrador, e no RDAP de IP está dentro da
 * organização dona da faixa. Ler só o topo devolve nada e parece que o registro
 * não publica contato.
 */
export function abuseContacts(node, seen = new Set()) {
    const found = [];
    for (const entity of asArray(node?.entities)) {
        const roles = asArray(entity.roles);
        if (roles.includes('abuse')) {
            for (const email of vcardValues(entity, 'email')) {
                const address = String(email).trim().toLowerCase();
                if (address.includes('@') && !seen.has(address)) { seen.add(address); found.push(address); }
            }
        }
        found.push(...abuseContacts(entity, seen));
    }
    return found;
}

const entityByRole = (node, role) =>
    asArray(node?.entities).find((entity) => asArray(entity.roles).includes(role)) || null;

const eventDate = (node, action) =>
    asArray(node?.events).find((event) => event.eventAction === action)?.eventDate || null;

export function createRdap({ fetchImpl = fetch, timeoutMs = 12000, now = () => Date.now() } = {}) {
    let bootstrap = { at: 0, byTld: new Map() };

    const getJson = async (url) => {
        const response = await fetchImpl(url, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) return null;
        return response.json();
    };

    const loadBootstrap = async () => {
        if (bootstrap.byTld.size && now() - bootstrap.at < BOOTSTRAP_TTL_MS) return bootstrap.byTld;
        const body = await getJson(BOOTSTRAP_URL);
        const byTld = new Map();
        for (const [tlds, urls] of asArray(body?.services)) {
            const base = asArray(urls)[0];
            if (!base) continue;
            for (const tld of asArray(tlds)) byTld.set(String(tld).toLowerCase(), base.endsWith('/') ? base : `${base}/`);
        }
        // Bootstrap fora do ar não pode apagar o que já estava em memória.
        if (byTld.size) bootstrap = { at: now(), byTld };
        return bootstrap.byTld;
    };

    return {
        /** Nem todo TLD publica RDAP — .cn e .ph, por exemplo, não publicam. */
        async serverFor(domain) {
            const tld = String(domain || '').toLowerCase().split('.').pop();
            if (!tld) return null;
            const byTld = await loadBootstrap();
            return byTld.get(tld) || null;
        },

        async domain(name) {
            const domain = String(name || '').toLowerCase();
            const base = await this.serverFor(domain);
            if (!base) return { domain, supported: false, abuse: [] };

            const body = await getJson(`${base}domain/${encodeURIComponent(domain)}`);
            if (!body) return { domain, supported: true, found: false, abuse: [] };

            const registrar = entityByRole(body, 'registrar');
            return {
                domain,
                supported: true,
                found: true,
                registrar: registrar ? (vcardValues(registrar, 'fn')[0] || registrar.handle || null) : null,
                registeredAt: eventDate(body, 'registration'),
                expiresAt: eventDate(body, 'expiration'),
                nameservers: asArray(body.nameservers).map((ns) => String(ns.ldhName || '').toLowerCase()).filter(Boolean),
                status: asArray(body.status),
                abuse: abuseContacts(body),
            };
        },

        async ip(address) {
            const value = String(address || '');
            if (!value) return { ip: value, found: false, abuse: [] };
            const body = await getJson(`${IP_RDAP}${encodeURIComponent(value)}`);
            if (!body) return { ip: value, found: false, abuse: [] };
            return {
                ip: value,
                found: true,
                network: body.name || null,
                range: [body.startAddress, body.endAddress].filter(Boolean).join(' - ') || null,
                holder: vcardValues(entityByRole(body, 'registrant') || {}, 'fn')[0] || null,
                abuse: abuseContacts(body),
            };
        },
    };
}

/**
 * Onde mandar o pedido, em ordem de quem costuma resolver mais rápido.
 *
 * Hospedagem primeiro: quem tem o arquivo no disco derruba em horas. Registrador
 * depois: tira o domínio do ar inteiro, mas é mais lento e mais burocrático. Os
 * canais fixos entram sempre — não derrubam nada sozinhos, mas colocam a URL nas
 * listas que os navegadores consultam, o que corta o alcance do golpe hoje.
 */
export function takedownTargets({ domain, hosting, registration }) {
    const targets = [];
    for (const email of hosting?.abuse || []) {
        targets.push({ kind: 'hosting', email, label: hosting.holder || hosting.network || 'hospedagem' });
    }
    for (const email of registration?.abuse || []) {
        targets.push({ kind: 'registrar', email, label: registration.registrar || 'registrador' });
    }
    for (const channel of STANDING_CHANNELS) targets.push({ kind: 'channel', ...channel });
    if (String(domain || '').endsWith('.br')) {
        for (const channel of BR_CHANNELS) targets.push({ kind: 'channel', ...channel });
    }
    return targets;
}
