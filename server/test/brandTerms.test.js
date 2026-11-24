import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeBrandTerm, normalizeBrands } from '../brandTerms.js';

test('organization news context keeps normalized, distinct brand names', () => {
    assert.equal(normalizeBrandTerm('https://www.Example.com.br/login'), 'example');
    assert.deepEqual(normalizeBrands(['EXAMPLE', 'example.com', 'other-brand', 'bad term', 'abc']), ['example', 'other-brand']);
    assert.deepEqual(normalizeBrands(null), []);
});

test('organization profiles retain their public brand validation error', () => {
    assert.throws(() => normalizeBrands(Array.from({ length: 9 }, (_, index) => `brand${index}`)), error => {
        assert.equal(error.status, 400);
        assert.equal(error.publicMessage, error.message);
        return true;
    });
});
