import test from 'node:test';
import assert from 'node:assert/strict';
import { NEWS_CATEGORIES, categorize } from '../newsCategories.js';

const item = (over = {}) => ({ title: '', description: '', threats: [], cves: [], actors: [], ...over });

test('a ordem de precedência é a acordada', () => {
    assert.deepEqual(NEWS_CATEGORIES, [
        'Ransomware', 'APTs', 'Data Leaks', 'OT/ICS', 'Vulnerabilities', 'Malware', 'Microsoft',
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
    for (const term of ['Microsoft', 'Windows', 'Exchange', 'SharePoint', 'Azure', 'Entra ID', 'Hyper-V']) {
        assert.ok(categorize(item({ title: `${term} under attack` })).categories.includes('Microsoft'), term);
    }
});

test('item sem nenhum sinal fica sem categoria em vez de cair num balde errado', () => {
    assert.deepEqual(categorize(item({ title: 'Conference agenda published' })), { categories: [], primary: null });
});

test('entrada malformada não quebra', () => {
    assert.deepEqual(categorize(null), { categories: [], primary: null });
    assert.deepEqual(categorize({}), { categories: [], primary: null });
});
