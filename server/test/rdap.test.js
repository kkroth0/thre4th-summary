import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { createRdap, abuseContacts, takedownTargets, STANDING_CHANNELS } from '../rdap.js';

// Respostas reais, aparadas: Verisign (.com), registro.br (.br), ARIN (IP) e o
// bootstrap da IANA. O aninhamento das entidades foi preservado, que é
// justamente onde o contato de abuse se esconde.
const fixture = (name) => JSON.parse(fs.readFileSync(new URL(`./fixtures/rdap/${name}.json`, import.meta.url), 'utf8'));

const routed = (routes) => {
    const calls = [];
    const fetchImpl = async (url) => {
        calls.push(url);
        const key = Object.keys(routes).find((part) => url.includes(part));
        if (!key) return { ok: false, status: 404, json: async () => ({}) };
        const value = routes[key];
        if (value === null) return { ok: false, status: 404, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => value };
    };
    return { fetchImpl, calls };
};

const DEFAULT_ROUTES = {
    'data.iana.org': fixture('bootstrap'),
    'rdap.verisign.com': fixture('domain-com'),
    'rdap.registro.br': fixture('domain-br'),
    'rdap.arin.net': fixture('ip'),
};

// O contato de abuse quase nunca está no primeiro nível — no .com ele é uma
// entidade dentro da entidade do registrador. Ler só o topo devolve vazio e
// parece que o registro não publica contato.
test('acha o e-mail de abuse aninhado dentro do registrador', () => {
    assert.deepEqual(abuseContacts(fixture('domain-com')), ['abuse@key-systems.net']);
});

test('acha os e-mails de abuse do RDAP de IP, sem repetir', () => {
    const emails = abuseContacts(fixture('ip'));
    assert.ok(emails.includes('abuse@bluehost.com'), emails.join(','));
    assert.equal(new Set(emails).size, emails.length, 'repetiu endereço');
});

test('entidade sem vcard ou sem papel de abuse não vira contato', () => {
    assert.deepEqual(abuseContacts({ entities: [{ roles: ['technical'], vcardArray: ['vcard', [['email', {}, 'text', 'tec@x.com']]] }] }), []);
    assert.deepEqual(abuseContacts({}), []);
});

test('o TLD decide o servidor, pelo bootstrap da IANA', async () => {
    const rdap = createRdap(routed(DEFAULT_ROUTES));
    assert.equal(await rdap.serverFor('exemplo.com'), 'https://rdap.verisign.com/com/v1/');
    assert.equal(await rdap.serverFor('exemplo.com.br'), 'https://rdap.registro.br/');
    assert.match(await rdap.serverFor('exemplo.space'), /radix/);
});

// .cn e .ph não publicam RDAP — e phishing adora esses TLDs. Precisa dizer isso
// em vez de parecer que a consulta falhou.
test('TLD sem RDAP responde "não suportado" em vez de erro', async () => {
    const rdap = createRdap(routed(DEFAULT_ROUTES));
    assert.equal(await rdap.serverFor('golpe.ph'), null);
    const result = await rdap.domain('golpe.ph');
    assert.deepEqual(result, { domain: 'golpe.ph', supported: false, abuse: [] });
});

test('consulta de domínio devolve registrador, datas e abuse', async () => {
    const rdap = createRdap(routed(DEFAULT_ROUTES));
    const result = await rdap.domain('votorantimcimentos.com');

    assert.equal(result.registrar, 'Key-Systems GmbH');
    assert.equal(String(result.registeredAt).slice(0, 10), '2014-09-11');
    assert.deepEqual(result.abuse, ['abuse@key-systems.net']);
    assert.ok(result.nameservers.length);
});

test('consulta de IP devolve rede e abuse da hospedagem', async () => {
    const rdap = createRdap(routed(DEFAULT_ROUTES));
    const result = await rdap.ip('162.241.62.181');

    assert.equal(result.network, 'UNIFIEDLAYER-NETWORK-16');
    assert.ok(result.abuse.includes('abuse@bluehost.com'));
    assert.match(result.range, /162\.240\.0\.0/);
});

test('registro fora do ar não derruba a consulta', async () => {
    const rdap = createRdap(routed({ 'data.iana.org': fixture('bootstrap'), 'rdap.verisign.com': null }));
    assert.deepEqual(await rdap.domain('exemplo.com'), { domain: 'exemplo.com', supported: true, found: false, abuse: [] });
});

// Uma consulta por hora não justifica baixar 70 KB de bootstrap toda vez.
test('o bootstrap é buscado uma vez e reaproveitado', async () => {
    const { fetchImpl, calls } = routed(DEFAULT_ROUTES);
    const rdap = createRdap({ fetchImpl });
    await rdap.domain('a.com');
    await rdap.domain('b.com');
    assert.equal(calls.filter((url) => url.includes('data.iana.org')).length, 1);
});

// Hospedagem primeiro: quem tem o arquivo no disco derruba em horas; o
// registrador tira o domínio inteiro, mas é lento.
test('os destinos saem na ordem de quem resolve mais rápido', () => {
    const targets = takedownTargets({
        domain: 'golpe.com',
        hosting: { abuse: ['abuse@hosting.com'], holder: 'Hosting X' },
        registration: { abuse: ['abuse@registrar.com'], registrar: 'Registrar Y' },
    });

    assert.equal(targets[0].kind, 'hosting');
    assert.equal(targets[1].kind, 'registrar');
    assert.equal(targets.filter((t) => t.kind === 'channel').length, STANDING_CHANNELS.length);
});

test('domínio .br ganha o CERT.br junto dos canais fixos', () => {
    const targets = takedownTargets({ domain: 'golpe.com.br', hosting: null, registration: null });
    assert.ok(targets.some((t) => t.email === 'cert@cert.br'));

    const outro = takedownTargets({ domain: 'golpe.com', hosting: null, registration: null });
    assert.ok(!outro.some((t) => t.email === 'cert@cert.br'));
});
