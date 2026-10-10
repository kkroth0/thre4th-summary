import test from 'node:test';
import assert from 'node:assert/strict';
import { VENDOR_CATALOG } from '../vendorCatalog.js';
import { matchVendors } from '../vendorMatch.js';
import { scoreArticle } from '../ctiIntel.js';
import { enrichFeedItems, EXTRACTION_VERSION } from '../feedEnrichment.js';
import { mergeIntoStories } from '../newsStories.js';
import { categorize } from '../newsCategories.js';
import { KEV_PRODUCT_ALIASES, OFFICIAL_PRODUCT_ALIASES } from '../vendorProductAliases.js';

const names = (text) => matchVendors(text).map((vendor) => vendor.name);

test('produtos adicionais têm fonte e fornecedor existente, sem aliases órfãos', () => {
    for (const name of new Set([...Object.keys(KEV_PRODUCT_ALIASES), ...Object.keys(OFFICIAL_PRODUCT_ALIASES)])) {
        const vendor = VENDOR_CATALOG.find((entry) => entry.name === name);
        assert.ok(vendor, `Fornecedor inexistente: ${name}`);
        for (const alias of [...(KEV_PRODUCT_ALIASES[name] ?? []), ...(OFFICIAL_PRODUCT_ALIASES[name]?.aliases ?? [])]) {
            assert.ok(vendor.aliases.includes(alias), `Alias não integrado: ${alias}`);
            assert.ok(names(`${alias} security advisory`).includes(name), `Produto não reconhecido: ${alias}`);
        }
        if (OFFICIAL_PRODUCT_ALIASES[name]) assert.match(OFFICIAL_PRODUCT_ALIASES[name].source, /^https:\/\//);
    }
});

test('produtos sem marca na manchete reconhecem o fornecedor correto', () => {
    for (const [text, expected] of [
        ['MegaRAC SP-X BMC vulnerability', 'American Megatrends'],
        ['Ryzen and EPYC security update', 'AMD'],
        ['OmniSwitch remote code execution', 'Alcatel-Lucent'],
        ['ApsaraDB security bulletin', 'Alibaba Cloud'],
        ['AlmaLinux OS security update', 'AlmaLinux'],
        ['Amcrest View Pro security advisory', 'Amcrest'],
        ['MiCollab authentication bypass', 'Mitel'],
        ['Nexus Repository critical vulnerability', 'Sonatype'],
        ['TwinCAT security bulletin', 'Beckhoff'],
        ['CENTUM VP security bulletin', 'Yokogawa'],
        ['Conjur security bulletin', 'CyberArk'],
    ]) assert.deepEqual(names(text), [expected], text);
});

test('produtos genéricos e siglas isoladas não viram fornecedores', () => {
    assert.deepEqual(names('falcon, singularity, instinct, rainbow, orion, core, command center, enterprise, backup, docs, reader, salt, ECS, OSS, FTA, ACI, RS, PRA and NX'), []);
    assert.deepEqual(names('Telerik Report Server security advisory'), ['Telerik']);
    assert.deepEqual(names('Brocade Fabric OS security advisory'), ['Brocade']);
    assert.deepEqual(names('Langflow security advisory'), ['Langflow']);
    assert.deepEqual(names('Zimbra Collaboration Suite security advisory'), ['Zimbra']);
});

test('catálogo tem IDs e aliases sem duplicatas entre fornecedores', () => {
    const ids = new Set(), aliases = new Map();
    for (const vendor of VENDOR_CATALOG) {
        assert.ok(vendor.id && vendor.name && vendor.sector && vendor.aliases.length);
        assert.ok(!ids.has(vendor.id), `ID duplicado: ${vendor.id}`);
        ids.add(vendor.id);
        for (const alias of vendor.aliases) {
            const key = alias.toLowerCase();
            assert.ok(!aliases.has(key) || aliases.get(key) === vendor.id, `Alias ${alias} atribuído a duas entidades`);
            aliases.set(key, vendor.id);
        }
    }
});

test('aliases de produtos identificam fornecedores e nomes canônicos', () => {
    const result = names('FortiGate e PAN-OS, NetScaler, MOVEit, ScreenConnect, Confluence, ESXi, ManageEngine, TeamCity e Protheus');
    for (const name of ['Fortinet', 'Palo Alto Networks', 'Citrix', 'Progress Software', 'ConnectWise', 'Atlassian', 'VMware', 'Zoho', 'JetBrains', 'TOTVS']) {
        assert.ok(result.includes(name), `Não identificou ${name}`);
    }
    assert.equal(new Set(result).size, result.length);
});

test('cada setor tem cobertura de fornecedores em textos reais de advisory', () => {
    const examples = [
        ['AWS advisory', 'Amazon Web Services'], ['Google Cloud advisory', 'Google'],
        ['BeyondTrust advisory', 'BeyondTrust'], ['MikroTik advisory', 'MikroTik'],
        ['ServiceNow advisory', 'ServiceNow'], ['Veeam advisory', 'Veeam'],
        ['OpenSSL advisory', 'OpenSSL'], ['WordPress advisory', 'WordPress'],
        ['Qualcomm advisory', 'Qualcomm'], ['Schneider Electric advisory', 'Schneider Electric'],
        ['ISH Tecnologia advisory', 'ISH Tecnologia'], ['Siemens S7 advisory', 'Siemens'],
    ];
    for (const [text, expected] of examples) assert.ok(names(text).includes(expected), text);
});

test('vários fornecedores e aliases somam a categoria uma única vez', () => {
    const result = scoreArticle('Fortinet FortiGate FortiOS Cisco Juniper Microsoft Azure AWS');
    assert.equal(result.score, 10);
    assert.equal(result.categories.filter((name) => name === 'Critical Vendor').length, 1);
    assert.equal(result.assets.filter((name) => name === 'Fortinet').length, 1);
    for (const name of ['Fortinet', 'Cisco', 'Juniper Networks', 'Microsoft', 'Amazon Web Services']) assert.ok(result.assets.includes(name));
});

test('nomes e produtos preservam pontuação, caixa e whitespace', () => {
    assert.deepEqual(names('WS_FTP Server bulletin'), ['Progress Software']);
    assert.deepEqual(names('WS FTP Server bulletin'), ['Progress Software']);
    assert.ok(names('NOTEPAD++ bulletin').includes('Notepad++'));
    assert.ok(names('B&R Automation bulletin').includes('B&R Automation'));
    assert.ok(names('Pepperl+Fuchs bulletin').includes('Pepperl+Fuchs'));
    assert.ok(names('check\npoint and red\that').includes('Check Point'));
    assert.ok(names('check\npoint and red\that').includes('Red Hat'));
});

test('marcas ambíguas exigem aliases qualificados ou siglas na caixa correta', () => {
    const prose = 'a recipe with apple, salt, chef, box, arm, progress, meta, zoom, carrier, puppet, ghost, temporal, sick and tree sap';
    assert.deepEqual(names(prose), []);
    assert.deepEqual(names('Pressione F5 e verifique o campo HP e a assinatura RSA.'), []);
    assert.ok(names('SAP bulletin').includes('SAP'));
    assert.ok(names('RSA SecurID bulletin').includes('RSA Security'));
    assert.ok(names('Arm Cortex advisory').includes('Arm'));
    assert.ok(names('macOS advisory').includes('Apple'));
});

test('menções parciais dentro de outras palavras não identificam fornecedor', () => {
    assert.deepEqual(names('ciscofake myfortinet githubusercontent notepadplusplus sapling rédistribuição'), []);
});

test('produto e prefixo de nome não criam um segundo fornecedor', () => {
    assert.deepEqual(names('Hewlett Packard Enterprise security bulletin'), ['Hewlett Packard Enterprise']);
    assert.deepEqual(names('TeamCity security bulletin'), ['JetBrains']);
    assert.deepEqual(names('Ivanti Neurons security bulletin'), ['Ivanti']);
});

test('catálogo ampliado mantém a penalidade de marketing e os sinais reais', () => {
    assert.equal(scoreArticle('Webinar sobre CrowdStrike, Veeam e TOTVS no Brasil', 20).score, 0);
    const advisory = scoreArticle('BeyondTrust CVE-2026-12345 — webinar sobre a correção');
    assert.ok(advisory.score > 0);
    assert.ok(!advisory.categories.includes('Noise Detected'));
});

test('metadados de fornecedores chegam à evidência por publicação', () => {
    const now = new Date('2026-10-09T12:00:00Z');
    const [item] = enrichFeedItems([{ title: 'FortiGate CVE-2026-12345', description: '', link: 'https://vendor.example/a', source: 'PSIRT', pubDate: now.toISOString() }], {
        actors: () => [], malware: () => [], campaigns: () => [], seller: () => null, categorize,
    });
    const [story] = mergeIntoStories([], [item], now);
    assert.equal(item.extractionVersion, EXTRACTION_VERSION);
    assert.deepEqual(story.sources[0].assets, ['Fortinet']);
    assert.equal(story.sources[0].vendors[0].id, 'fortinet');
    assert.equal(story.sources[0].vendors[0].matched, 'FortiGate');
});

test('mesmo fornecedor não é evidência suficiente para juntar incidentes', () => {
    const now = new Date('2026-10-09T12:00:00Z');
    const articles = ['CVE-2026-11111 Alpha gateway', 'CVE-2026-22222 Bravo endpoint'].map((title, i) => ({
        ...scoreArticle(title + ' Fortinet'), title, link: 'https://vendor.example/' + i,
        source: 'PSIRT', pubDate: now.toISOString(), newsCategories: ['Vulnerabilities'],
    }));
    assert.equal(mergeIntoStories([], articles, now).length, 2);
});
