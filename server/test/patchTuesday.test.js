import test from 'node:test';
import assert from 'node:assert/strict';
import { isEarlyDoc, isChromiumVuln, isAzureLinuxVuln, normalizeCvrf } from '../patchTuesday.js';

// Minimal CVRF shape. Threat types: 0 = impact, 1 = exploit status, 3 = severity.
// product '1' = Windows 11, '2' = an Azure Linux package.
const vuln = (cve, { title = '', severity, impact = 'Elevation of Privilege', exploit = '', products = ['1'] } = {}) => ({
  CVE: cve,
  Title: { Value: title || `${cve} title` },
  Threats: [
    { Type: 0, Description: { Value: impact } },
    { Type: 1, Description: { Value: exploit } },
    ...(severity ? [{ Type: 3, Description: { Value: severity } }] : [])
  ],
  ProductStatuses: [{ Type: 3, ProductID: products }]
});

const cvrf = (title, vulnerabilities) => ({
  DocumentTitle: { Value: title },
  DocumentTracking: { Identification: { ID: { Value: '2026-Jul' } }, CurrentReleaseDate: '2026-07-14T07:00:00' },
  ProductTree: {
    FullProductName: [
      { ProductID: '1', Value: 'Windows 11' },
      { ProductID: '2', Value: 'azl3 kernel 6.6.143.1-1 on Azure Linux 3.0' }
    ]
  },
  Vulnerability: vulnerabilities
});

test('flags the pre-release draft that shares the real Patch Tuesday id', () => {
  // Microsoft ships this under the same id (2026-Jul) and swaps it in place on
  // release day. Serving it as the month's patch set hid two exploited 0-days.
  assert.equal(isEarlyDoc('July 2026 Early Security Updates'), true);
  assert.equal(isEarlyDoc('July 2026 Security Updates'), false);
});

test('counts upstream republications separately instead of in the headline totals', () => {
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
  assert.equal(totals.upstream, 2, 'Chromium counted on its own line');
  assert.equal(totals.unknown, 0, 'Chromium must not create an Unknown bucket');
  assert.equal(totals.critical, 1);
  assert.equal(vulnerabilities.length, 4, 'every CVE is still available to the table');
});

test('excludes the Azure Linux package stream, which no title test catches', () => {
  // August 2026: 751 entries in the document, 329 of them Azure Linux packages
  // and *zero* Chromium. The title-only filter passed all 329 through, so the
  // page headlined 751 against the portals' ~420.
  const doc = cvrf('August 2026 Security Updates', [
    vuln('CVE-2026-1', { severity: 'Critical' }),
    // Rated Important by MSRC and titled like any upstream commit — nothing but
    // the affected product identifies it as not-Microsoft's-code.
    vuln('CVE-2026-2', { severity: 'Important', title: 'sctp: don\'t free the ASCONF\'s own transport', products: ['2'] }),
    vuln('CVE-2026-3', { severity: 'Important', title: 'btrfs: reject free space cache with more entries than pages', products: ['2'] }),
    // Affects Windows *and* an Azure Linux package: Microsoft's own bug, counted.
    vuln('CVE-2026-4', { severity: 'Moderate', products: ['1', '2'] })
  ]);

  const { totals } = normalizeCvrf(doc);

  assert.equal(totals.total, 2, 'Azure Linux packages stay out of the headline');
  assert.equal(totals.upstream, 2);
  assert.equal(totals.important, 0, 'their MSRC severity must not inflate the buckets either');
  assert.equal(totals.moderate, 1, 'a shared Windows/Azure Linux CVE is still Microsoft\'s');
});

test('identifies Azure Linux packages by product, not by title', () => {
  assert.equal(isAzureLinuxVuln(['azl3 clamav 1.5.3-1 on Azure Linux 3.0']), true);
  assert.equal(isAzureLinuxVuln(['CBL-Mariner 2.0']), true);
  // The CBL-Mariner 2.0 stream names packages without naming the distro at all.
  // Matching only "Azure Linux"/"CBL-Mariner" missed 319 of April 2026's entries.
  assert.equal(isAzureLinuxVuln(['cbl2 net-snmp 5.9.4-1']), true);
  assert.equal(isAzureLinuxVuln(['cbl2 libdwarf 0.9.0-3', 'azl3 libdwarf 0.9.0-1 on Azure Linux 3.0']), true);
  assert.equal(isAzureLinuxVuln(['Windows 11', 'azl3 perl 5.38.2-514 on Azure Linux 3.0']), false);
  assert.equal(isAzureLinuxVuln(['Azure Storage Explorer']), false, 'a real Microsoft product on Azure');
  assert.equal(isAzureLinuxVuln(['Windows Subsystem for Linux (WSL2)']), false, "Microsoft's own code");
  assert.equal(isAzureLinuxVuln([]), false, 'no products is not evidence of upstream');
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
  assert.equal(topCves.at(-1).cve, 'CVE-2026-CHROME', 'upstream noise sinks to the bottom');
});

test('identifies Chromium restatements without catching first-party Edge bugs', () => {
  assert.equal(isChromiumVuln('Microsoft Edge (Chromium-based) Spoofing Vulnerability'), true);
  // Edge for Android is Microsoft's own code, not a restated Chrome CVE — even
  // when MSRC files it under the generic Chromium-based Edge product.
  assert.equal(isChromiumVuln('Microsoft Edge for Android Information Disclosure Vulnerability'), false);
  assert.equal(isChromiumVuln('Microsoft Edge for Android Information Disclosure Vulnerability', ['Microsoft Edge (Chromium-based)']), false);
  // Restatements that carry Chrome's own bug wording instead of an MSRC title.
  // The August 2026 document gained 38 of these in a same-day revision; every
  // one leads with its CVE id, which MSRC never does for its own bugs.
  assert.equal(isChromiumVuln('CVE-2026-19137 Use after free in WebGL', ['Microsoft Edge (Chromium-based)']), true);
  assert.equal(isChromiumVuln('CVE-2026-19138 Heap buffer overflow in CrashReporting', ['Microsoft Edge (Chromium-based)']), true);
  assert.equal(isChromiumVuln('CVE-2026-13862', ['Microsoft Edge (Chromium-based)']), true, 'bare id, no description at all');
  assert.equal(isChromiumVuln('', ['Microsoft Edge (Chromium-based)']), true);
  assert.equal(isChromiumVuln('CVE-2026-13862', ['Windows 11']), false, 'an untitled Windows CVE is still Microsoft\'s');
});
