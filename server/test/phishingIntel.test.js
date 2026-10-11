import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzePhishing } from '../phishingIntel.js';

const cases = [
    ['Wazza Phishkit uses device code phishing themed Adobe', ['Device Code Phishing', 'Phishing-as-a-Service']],
    ['Wazza phishing campaign abuses device code login', ['Device Code Phishing']],
    ['Impostores do Bank of America usam ScreenConnect', ['Brand Impersonation', 'RMM Abuse']],
    ['Campanha ClickFix usa CAPTCHA falso para roubar credenciais', ['ClickFix', 'Credential Harvesting']],
    ['Attackers use fake Cloudflare verification in phishing campaign', ['ClickFix']],
    ['New AiTM kit captures passwords through fake login pages', ['AiTM / Adversary-in-the-Middle', 'Credential Harvesting']],
    ['Smishing campaign uses malicious text messages', ['Smishing']],
    ['Vishing fake helpdesk campaign targets employees', ['Vishing']],
    ['Phishing campaign delivers ScreenConnect through Microsoft Power BI', ['RMM Abuse', 'SaaS Abuse']],
    ['Fake sponsorships target YouTubers in phishing campaign', ['Fake Sponsorship']],
    ['Attackers use malicious OAuth apps to steal access tokens', ['OAuth Consent Phishing']],
    ['Phishing via WhatsApp delivers a malicious attachment', ['Messaging App Lure', 'Spearphishing Attachment']],
    ['QR-code phishing targets bank customers', ['Quishing']],
    ['BEC email invoice fraud targets banks', ['Business Email Compromise']],
    ['Grupo de golpes por SMS mira bancos brasileiros', ['Smishing']],
    ['CAPTCHAs falsos espalham malware em campanha', ['ClickFix']],
    ['Instaladores falsos roubam credenciais', ['Fake Download / Update', 'Credential Harvesting']],
];
for (const [title, techniques] of cases) test(`contextual techniques: ${title}`, () => {
    const intel = analyzePhishing({ title });
    assert.equal(intel.detected, true);
    for (const technique of techniques) assert.ok(intel.techniques.includes(technique), technique);
    assert.ok(intel.evidence.every(e => e.field === 'title' && e.term && e.snippet));
});

for (const title of ['How to prevent phishing with employee training', 'Phishing-resistant MFA protects organizations', 'BEC quarterly financial results', 'Recommended ScreenConnect configuration', 'No evidence of phishing in the data breach']) test(`negative context: ${title}`, () => {
    assert.equal(analyzePhishing({ title }).detected, false);
});

test('advisory recommendations and publisher footers do not create phishing incidents', () => {
    const intel = analyzePhishing({ title: 'Cisco patches router RCE', description: 'A vulnerability affects routers.', bodyText: 'CVE-2026-12345 enables RCE.\nRecommendations\nWatch for phishing campaigns using fake login pages.\nRelated articles\nNew ClickFix campaign delivers malware.' });
    assert.equal(intel.detected, false);
});
test('body evidence is accepted for an actual incident and deduplicated', () => {
    const intel = analyzePhishing({ title: 'Research findings', bodyText: 'Researchers discovered a phishing campaign using fake login pages.\nAttackers spread phishing emails.\nCampaign sends phishing messages.' });
    assert.equal(intel.detected, true);
    assert.equal(intel.evidence.filter(e => e.kind === 'classification').length, 1);
    assert.ok(intel.evidence.some(e => e.field === 'body' && e.label === 'Credential Harvesting'));
});
test('actor origin is not victim geography and service mention is not a brand impersonation', () => {
    const intel = analyzePhishing({ title: 'Chinese attackers target banks in Brazil with phishing via WhatsApp', description: 'The campaign uses fake Adobe login pages to capture credentials.' });
    assert.deepEqual(intel.regions, ['Brazil']);
    assert.deepEqual(intel.sectors, ['Financial']);
    assert.deepEqual(intel.brands, ['Adobe']);
    assert.equal(intel.nationState, 'unknown');
});
test('ordinary pronouns do not create country tags', () => {
    assert.deepEqual(analyzePhishing({ title: 'Phishing targets us through fake login pages' }).regions, []);
});
test('MITRE citations and rule inferences have distinct provenance', () => {
    const intel = analyzePhishing({ title: 'ClickFix phishing campaign', bodyText: 'Attackers copy and paste malicious commands, T1204.004.' });
    assert.equal(intel.ttps.find(ttp => ttp.id === 'T1204.004').basis, 'reported');
    assert.equal(intel.ttps.find(ttp => ttp.id === 'T1566').basis, 'inferred');
    assert.equal(analyzePhishing({ title: 'Phishing steals credentials from a phone call' }).ttps.some(ttp => ttp.id === 'T1056.003'), false);
});
test('named kit and explicit nation-state evidence are retained without inferring affiliation', () => {
    const intel = analyzePhishing({ title: 'Wazza Phishkit used in state-sponsored phishing campaign' });
    assert.deepEqual(intel.kits, ['Wazza']);
    assert.equal(intel.nationState, 'reported');
    assert.equal(analyzePhishing({ title: 'Phishing campaign; no evidence of state-sponsored actors' }).nationState, 'unknown');
});
