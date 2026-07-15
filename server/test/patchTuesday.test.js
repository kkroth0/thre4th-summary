import test from 'node:test';
import assert from 'node:assert/strict';
import { isEarlyDoc, isChromiumVuln, normalizeCvrf } from '../patchTuesday.js';

// Minimal CVRF shape. Threat types: 0 = impact, 1 = exploit status, 3 = severity.
const vuln = (cve, { title = '', severity, impact = 'Elevation of Privilege', exploit = '' } = {}) => ({
  CVE: cve,
  Title: { Value: title || `${cve} title` },
  Threats: [
    { Type: 0, Description: { Value: impact } },
    { Type: 1, Description: { Value: exploit } },
    ...(severity ? [{ Type: 3, Description: { Value: severity } }] : [])
  ],
  ProductStatuses: [{ Type: 3, ProductID: ['1'] }]
});

const cvrf = (title, vulnerabilities) => ({
  DocumentTitle: { Value: title },
  DocumentTracking: { Identification: { ID: { Value: '2026-Jul' } }, CurrentReleaseDate: '2026-07-14T07:00:00' },
  ProductTree: { FullProductName: [{ ProductID: '1', Value: 'Windows 11' }] },
  Vulnerability: vulnerabilities
});

test('flags the pre-release draft that shares the real Patch Tuesday id', () => {
  // Microsoft ships this under the same id (2026-Jul) and swaps it in place on
  // release day. Serving it as the month's patch set hid two exploited 0-days.
  assert.equal(isEarlyDoc('July 2026 Early Security Updates'), true);
  assert.equal(isEarlyDoc('July 2026 Security Updates'), false);
});

test('counts Chromium restatements separately instead of in the headline totals', () => {
  const doc = cvrf('July 2026 Security Updates', [
    vuln('CVE-2026-1', { severity: 'Critical' }),
    vuln('CVE-2026-2', { severity: 'Important' }),
    // Chromium entries carry no MSRC severity — folded in, they inflate the
    // total and manufacture a bogus "Unknown" bucket.
    vuln('CVE-2026-3', { title: 'Microsoft Edge (Chromium-based) Spoofing Vulnerability' }),
    vuln('CVE-2026-4', { title: 'Microsoft Edge (Chromium-based) RCE Vulnerability' })
  ]);

  const { totals, vulnerabilities } = normalizeCvrf(doc);

  assert.equal(totals.total, 2, 'headline total is Microsoft-only');
  assert.equal(totals.chromium, 2, 'Chromium counted on its own line');
  assert.equal(totals.unknown, 0, 'Chromium must not create an Unknown bucket');
  assert.equal(totals.critical, 1);
  assert.equal(vulnerabilities.length, 4, 'every CVE is still available to the table');
});

test('surfaces exploited and disclosed CVEs above everything else', () => {
  const doc = cvrf('July 2026 Security Updates', [
    vuln('CVE-2026-QUIET', { severity: 'Critical' }),
    vuln('CVE-2026-CHROME', { title: 'Microsoft Edge (Chromium-based) Spoofing Vulnerability' }),
    vuln('CVE-2026-DISCLOSED', { severity: 'Important', exploit: 'Publicly Disclosed: Yes; Exploited: No' }),
    vuln('CVE-2026-ZERODAY', { severity: 'Important', exploit: 'Publicly Disclosed: No; Exploited: Yes' })
  ]);

  const { totals, topCves } = normalizeCvrf(doc);

  assert.equal(totals.exploited, 1);
  assert.equal(totals.disclosed, 1);
  assert.equal(topCves[0].cve, 'CVE-2026-ZERODAY', 'an exploited 0-day leads the list');
  assert.equal(topCves[1].cve, 'CVE-2026-DISCLOSED');
  assert.equal(topCves.at(-1).cve, 'CVE-2026-CHROME', 'Chromium noise sinks to the bottom');
});

test('identifies Chromium restatements without catching first-party Edge bugs', () => {
  assert.equal(isChromiumVuln('Microsoft Edge (Chromium-based) Spoofing Vulnerability'), true);
  // Edge for Android is Microsoft's own code, not a restated Chrome CVE.
  assert.equal(isChromiumVuln('Microsoft Edge for Android Information Disclosure Vulnerability'), false);
});
