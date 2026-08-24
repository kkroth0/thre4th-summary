import test from 'node:test';
import assert from 'node:assert/strict';
import { NEWS_CATEGORIES, categorize } from '../newsCategories.js';

const item = (over = {}) => ({ title: '', description: '', threats: [], cves: [], actors: [], ...over });

test('a ordem de precedência é a acordada', () => {
    assert.deepEqual(NEWS_CATEGORIES, [
        'Ransomware', 'APTs', 'Data Leaks', 'OT/ICS', 'Vulnerabilities', 'Malware', 'Microsoft',
        'Finance/Banking', 'Health/Pharma',
    ]);
});

test('uma história entra em todas as categorias que bateram', () => {
    const result = categorize(item({
        title: 'Cl0p exploits Oracle EBS zero-day',
        threats: ['Ransomware'],
        cves: ['CVE-2025-61882'],
        actors: [{ id: 'a1', name: 'Cl0p', via: 'context' }],
    }));
    assert.deepEqual(result.categories, ['Ransomware', 'Vulnerabilities']);
    assert.equal(result.primary, 'Ransomware', 'a principal sai da precedência');
});

// Cl0p é gangue de ransomware, não APT: um match por contexto não é atribuição
// forte o bastante para carimbar APTs. Só codinome ou nome composto carimba.
test('match por contexto não promove a história a APTs', () => {
    const byContext = categorize(item({ title: 'The Akira gang leaked it', actors: [{ id: 'a', name: 'Akira', via: 'context' }] }));
    assert.ok(!byContext.categories.includes('APTs'));
});

test('APTs vem do match distintivo ou de termo nation-state', () => {
    assert.deepEqual(categorize(item({ title: 'x', actors: [{ id: 'a', name: 'APT28', via: 'codename' }] })).categories, ['APTs']);
    assert.deepEqual(categorize(item({ title: 'x', actors: [{ id: 'a', name: 'Scattered Spider', via: 'multiword' }] })).categories, ['APTs']);
    assert.deepEqual(categorize(item({ title: 'A state-sponsored campaign' })).categories, ['APTs']);
});

test('Data Leaks reconhece vazamento em PT e EN', () => {
    assert.ok(categorize(item({ title: 'Data breach exposes 2M customers' })).categories.includes('Data Leaks'));
    assert.ok(categorize(item({ title: 'Vazamento de dados atinge banco' })).categories.includes('Data Leaks'));
});

test('OT/ICS reconhece o vocabulário industrial', () => {
    for (const term of ['SCADA', 'Modbus', 'PLC', 'OPC UA', 'Siemens S7', 'Rockwell']) {
        assert.ok(categorize(item({ title: `Flaw found in ${term} stack` })).categories.includes('OT/ICS'), term);
    }
});

// Fornecedores industriais e protocolos OT — vocabulário das fontes de pesquisa
// (Claroty Team82, Nozomi). Removidas as marcas ambíguas (BMS = Bristol-Myers,
// Emerson = conglomerado + sobrenome, Honeywell = aeroespacial/EPI, Copeland = sobrenome).
test('OT/ICS reconhece os fornecedores e protocolos das fontes de pesquisa OT', () => {
    const terms = [
        'Phoenix Contact', 'Danfoss', 'EnOcean', 'LonTalk',
        'Yokogawa', 'Mitsubishi Electric', 'Omron', 'WAGO', 'Beckhoff',
        'Moxa', 'Advantech', 'IEC 61850', 'IEC 60870', 'EtherNet/IP', 'BACnet',
        'building management system',
    ];
    for (const term of terms) {
        assert.ok(
            categorize(item({ title: `Vulnerabilities found in ${term} controllers` })).categories.includes('OT/ICS'),
            term,
        );
    }
});

// Termos descartados por ambiguidade não casam em contexto não-industrial, mesmo
// quando mencionados — seguindo o padrão de MICROSOFT que também trata as formas
// genéricas diferente das qualificadas.
test('OT/ICS não casa com termos ambíguos em contexto não-industrial', () => {
    const falsePositives = [
        'Bristol-Myers Squibb (BMS) reports earnings',
        'Emerson Collective funds new initiative',
        'Honeywell home security camera flaw exposes feeds',
        'John Copeland elected to board',
    ];
    for (const title of falsePositives) {
        assert.ok(!categorize(item({ title })).categories.includes('OT/ICS'), title);
    }
});

test('Vulnerabilities vem de CVE, de classe de falha ou de exploração ativa', () => {
    assert.ok(categorize(item({ title: 'x', cves: ['CVE-2026-1'] })).categories.includes('Vulnerabilities'));
    assert.ok(categorize(item({ title: 'Remote code execution in the parser' })).categories.includes('Vulnerabilities'));
    assert.ok(categorize(item({ title: 'Bug is actively exploited' })).categories.includes('Vulnerabilities'));
});

test('Malware não inclui ransomware, que tem categoria própria', () => {
    assert.deepEqual(categorize(item({ title: 'x', threats: ['Infostealer'] })).categories, ['Malware']);
    assert.deepEqual(categorize(item({ title: 'x', threats: ['Ransomware'] })).categories, ['Ransomware']);
});

test('Microsoft reconhece a marca e os produtos', () => {
    for (const term of ['Microsoft', 'Windows', 'Exchange Server', 'SharePoint', 'Azure', 'Entra ID', 'Hyper-V']) {
        assert.ok(categorize(item({ title: `${term} under attack` })).categories.includes('Microsoft'), term);
    }
});

// Deferred minor #3: exchange/teams/outlook/defender are ordinary CTI-headline
// vocabulary on their own — only the qualified Microsoft forms should count.
test('Microsoft não casa com palavras genéricas do vocabulário de CTI', () => {
    const falsePositives = [
        'Lazarus Group linked to the exchange heist',
        'Crypto exchange Bybit loses $1.5B in largest heist ever',
        'Red teams increasingly abuse legitimate tooling',
        'Security teams struggle with alert fatigue',
        'Threat outlook for 2026: what CISOs should expect',
        'A defender perspective on detection engineering',
    ];
    for (const title of falsePositives) {
        assert.ok(!categorize(item({ title })).categories.includes('Microsoft'), title);
    }
});

test('Microsoft exige a forma qualificada para exchange/teams/outlook/defender', () => {
    const positives = [
        'Exchange Server vulnerability under active exploitation',
        'Exchange Online outage affects tenants',
        'Attackers target Microsoft Teams users with malware',
        'New phishing campaign abuses Microsoft Defender alerts',
        'Windows Defender flagged as vulnerable to bypass',
        'Microsoft Outlook zero-day exploited in the wild',
        'Credentials phished via a fake outlook.com login page',
    ];
    for (const title of positives) {
        assert.ok(categorize(item({ title })).categories.includes('Microsoft'), title);
    }
});

test('item sem nenhum sinal fica sem categoria em vez de cair num balde errado', () => {
    assert.deepEqual(categorize(item({ title: 'Conference agenda published' })), { categories: [], primary: null });
});

test('entrada malformada não quebra', () => {
    assert.deepEqual(categorize(null), { categories: [], primary: null });
    assert.deepEqual(categorize({}), { categories: [], primary: null });
});

// Notícia chega em PT, ES ou EN — os baldes de setor casam sinônimo em cada uma.
test('Finance/Banking reconhece o vocabulário financeiro em PT, ES e EN', () => {
    const titles = [
        'Banking trojan targets customers of major banks',
        'Troiano bancário ataca clientes de bancos brasileiros',
        'Ataque atinge instituição financeira e o sistema Pix',
        'Ransomware golpea al sector bancario mexicano',
        'Nueva campaña contra instituciones financieras en Chile',
        'Fintech breach exposes payment gateway credentials',
        'Malware drena caixas eletrônicos de cooperativa de crédito',
    ];
    for (const title of titles) {
        assert.ok(categorize(item({ title })).categories.includes('Finance/Banking'), title);
    }
});

test('Health/Pharma reconhece o vocabulário de saúde em PT, ES e EN', () => {
    const titles = [
        'Ransomware hits hospital network, patient records exposed',
        'Healthcare provider discloses HIPAA breach',
        'Vazamento expõe prontuários de pacientes em rede de saúde',
        'Ataque derruba sistema de saúde e farmácias no interior',
        'Hackers atacan el sistema de salud y una clínica privada',
        'Farmacéutica confirma robo de datos de pacientes',
        'Flaw in medical devices lets attackers alter EHR data',
    ];
    for (const title of titles) {
        assert.ok(categorize(item({ title })).categories.includes('Health/Pharma'), title);
    }
});

// Setor é balde adicional: a categoria principal continua sendo a da ameaça.
test('os baldes de setor não roubam a categoria principal', () => {
    const result = categorize(item({ title: 'Ransomware hits a hospital', threats: ['Ransomware'] }));
    assert.deepEqual(result.categories, ['Ransomware', 'Health/Pharma']);
    assert.equal(result.primary, 'Ransomware');
});

// Termo genérico de manchete não carimba setor — mesmo critério de MICROSOFT/OT_ICS.
test('vocabulário genérico não carimba os baldes de setor', () => {
    const falsePositives = [
        'The financial impact of a breach keeps growing',
        'Credit card data found on a dark web forum',
        'Taylor Swift ticket scam spreads via SMS',
        'Report on the financial health of the security market',
    ];
    for (const title of falsePositives) {
        const { categories } = categorize(item({ title }));
        assert.ok(!categories.includes('Finance/Banking'), title);
        assert.ok(!categories.includes('Health/Pharma'), title);
    }
});

// Post de marketing que lista setores de passagem carimbava saúde e finanças.
// Setor vem do título — quem foi atacado está na manchete, não no meio do texto.
test('menção de setor no corpo não carimba o balde de setor', () => {
    const { categories } = categorize(item({
        title: 'Wazuh and AI for enhanced SOC workflows',
        description: 'From healthcare and finance to manufacturing and education, organizations rely on AI.',
    }));
    assert.ok(!categories.includes('Health/Pharma'));
    assert.ok(!categories.includes('Finance/Banking'));
});
