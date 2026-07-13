import test from 'node:test';
import assert from 'node:assert/strict';
import { detectQueryType, sanitizeQuery } from '../iocValidation.js';

test('accepts a globally routable IPv6 address as an IP', () => {
  assert.equal(detectQueryType('2606:4700:4700::1111'), 'ip');
  assert.equal(sanitizeQuery('2606:4700:4700::1111', 'ip'), '2606:4700:4700::1111');
});

test('rejects non-global and malformed IPv6 addresses', () => {
  for (const value of ['::1', '::', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '2001:::1']) {
    assert.equal(detectQueryType(value), 'unknown', value);
    assert.throws(() => sanitizeQuery(value, 'ip'), /Invalid|non-public/i, value);
  }
});

test('keeps an HTTP URL with a bracketed IPv6 literal classified as URL', () => {
  assert.equal(detectQueryType('https://[2606:4700:4700::1111]/status'), 'url');
  assert.equal(
    sanitizeQuery('https://[2606:4700:4700::1111]/status', 'url'),
    'https://[2606:4700:4700::1111]/status',
  );
});
