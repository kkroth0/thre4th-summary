import test from 'node:test';
import assert from 'node:assert/strict';
import { extractSellerHandle, findRelatedBySeller, storySellerHandle } from '../darkWebHandle.js';

test('extrai o handle da frase padrão do Dark Web Informer', () => {
    assert.equal(
        extractSellerHandle('An actor using the handle "ChimeraZ" claims to be selling a dataset.'),
        'ChimeraZ',
    );
    assert.equal(
        extractSellerHandle("An actor using the handle 'TimeSape' is publicizing a breach claim."),
        'TimeSape',
    );
});

test('reconhece variantes razoáveis da frase', () => {
    assert.equal(extractSellerHandle('A threat actor going by the alias "GhostVendor" posted the leak.'), 'GhostVendor');
    assert.equal(extractSellerHandle('The seller, known as "DataBroker99", listed the database.'), 'DataBroker99');
});

test('texto sem a frase padrão devolve null', () => {
    assert.equal(extractSellerHandle('Ransomware group leaks stolen hospital records.'), null);
    assert.equal(extractSellerHandle(''), null);
    assert.equal(extractSellerHandle(null), null);
});

const story = (over = {}) => ({
    id: 's1', title: 'T', sources: [{ link: 'https://a.example/1', sellerHandle: null }], ...over,
});

test('findRelatedBySeller acha outras histórias do mesmo vendedor, exclui a própria', () => {
    const stories = [
        story({ id: 's1', title: 'Assurimo leak', sources: [{ link: 'https://a.example/1', sellerHandle: 'ChimeraZ' }] }),
        story({ id: 's2', title: 'French MoJ leak', sources: [{ link: 'https://a.example/2', sellerHandle: 'ChimeraZ' }] }),
        story({ id: 's3', title: 'Pare-Brise breach', sources: [{ link: 'https://a.example/3', sellerHandle: 'TimeSape' }] }),
    ];
    const related = findRelatedBySeller(stories, 'ChimeraZ', 's1');
    assert.deepEqual(related.map((r) => r.storyId), ['s2']);
    assert.deepEqual(findRelatedBySeller(stories, 'ChimeraZ', 's2').map((r) => r.storyId), ['s1']);
});

test('findRelatedBySeller é case-insensitive e devolve [] sem handle', () => {
    const stories = [
        story({ id: 's1', sources: [{ link: 'https://a.example/1', sellerHandle: 'ChimeraZ' }] }),
        story({ id: 's2', sources: [{ link: 'https://a.example/2', sellerHandle: 'chimeraz' }] }),
    ];
    assert.deepEqual(findRelatedBySeller(stories, 'CHIMERAZ', 's1').map((r) => r.storyId), ['s2']);
    assert.deepEqual(findRelatedBySeller(stories, null, 's1'), []);
    assert.deepEqual(findRelatedBySeller(stories, '', 's1'), []);
});

test('storySellerHandle acha o primeiro handle não-nulo entre as fontes', () => {
    assert.equal(storySellerHandle(story({ sources: [{ link: 'x', sellerHandle: null }, { link: 'y', sellerHandle: 'ChimeraZ' }] })), 'ChimeraZ');
    assert.equal(storySellerHandle(story({ sources: [] })), null);
    assert.equal(storySellerHandle(null), null);
});
