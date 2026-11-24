import assert from 'node:assert/strict';
import test from 'node:test';
import { isRouteActive, isWorkspaceRoute } from './navigation';

test('active navigation respects route boundaries and ignores link query and hash', () => {
  assert.equal(isRouteActive('/settings?section=monitoring#vendors', '/settings'), true);
  assert.equal(isRouteActive('/atores', '/atores/example'), true);
  assert.equal(isRouteActive('/cves', '/cves-other'), false);
  assert.equal(isRouteActive('/', '/newsletter'), false);
});
test('the workspace includes internal tools and account routes while public entry pages retain their layout', () => {
  for (const path of ['/dashboard', '/bulk', '/malware', '/newsletter', '/analyzer', '/settings', '/profile', '/admin']) assert.equal(isWorkspaceRoute(path), true);
  for (const path of ['/', '/login', '/cadastro', '/not-found', '/settings-other']) assert.equal(isWorkspaceRoute(path), false);
});


test('retired feature routes are absent from the workspace', () => {
  for (const path of ['/hunting', '/phishing-analyzer', '/domain-monitoring', '/attack-surface', '/exposure-watchlist']) {
    assert.equal(isWorkspaceRoute(path), false, path);
  }
});
