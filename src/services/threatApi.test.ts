import test from "node:test";
import assert from "node:assert/strict";
import { detectIOCType, fetchThreatData, fetchThreatDataProgressive, fetchAttackSurfaceCredits, formatVendorData, resolveVendorsForQuery } from "./threatApi";
import { refang } from "@/utils/defang";
import { isSupportedAnalyzerQuery } from "@/utils/iocExtract";

test("detects a public IPv6 address as IP and an IPv6 literal URL as URL", () => {
  assert.equal(detectIOCType("2606:4700:4700::1111"), "ip");
  assert.equal(detectIOCType("https://[2606:4700:4700::1111]/status"), "url");
});

test('manual enrichment refresh requests fresh data; normal lookups permit cached responses', async () => {
  const previous = globalThis.fetch;
  const bodies: { query: string; fresh?: boolean }[] = [];
  globalThis.fetch = async (_input, options) => {
    bodies.push(JSON.parse(String(options?.body)));
    return new Response(JSON.stringify({ data: { ip_str: '9.9.9.10', ports: [], data: [] } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    await fetchThreatData('9.9.9.10', ['Shodan']);
    let completed = 0;
    await fetchThreatDataProgressive('9.9.9.10', ['Shodan'], () => { completed++; }, { fresh: true });
    assert.deepEqual(bodies, [{ query: '9.9.9.10' }, { query: '9.9.9.10', fresh: true }]);
    assert.equal(completed, 1);
  } finally { globalThis.fetch = previous; }
});

test("routes IPv6 only to providers backed by IPv6-capable endpoints", () => {
  const selected = [
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "AlienVault OTX", "Shodan",
    "ThreatFox",
  ];

  assert.deepEqual(resolveVendorsForQuery("2606:4700:4700::1111", selected), [
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox",
  ]);
});

test("refanged input makes defanged IOCs searchable", () => {
  // Before the refang, each of these was rejected as "unknown" and aborted the scan.
  assert.equal(isSupportedAnalyzerQuery(refang("evil[.]com")), true);
  assert.equal(isSupportedAnalyzerQuery(refang("1.2.3[.]4")), true);
  assert.equal(isSupportedAnalyzerQuery(refang("hxxps://bad[.]com/x")), true);
});

test("OpenPhish exposes a capital-S Status the aggregator can count", () => {
  assert.equal(formatVendorData("OpenPhish", { listed: true, status: "Listed as phishing" }, "http://x").Status, "Phishing");
  assert.equal(formatVendorData("OpenPhish", { listed: false, status: "x" }, "http://x").Status, "Clean");

});

test("loads Shodan credits without exposing account data", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ plan: "member", queryCredits: 99 }));

  try {
    assert.deepEqual(await fetchAttackSurfaceCredits(), { plan: "member", queryCredits: 99 });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('missing PhishStats results and unverified PhishTank reports do not become malicious or clean votes', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (path) => new Response(JSON.stringify(String(path).endsWith('/phishstats') ? [] : {results:{in_database:true,verified:false,valid:false}}));
  try { const result = await fetchThreatData('https://example.com/', ['PhishStats','PhishTank']); assert.equal(result.detections,0); assert.equal(result.reportingVendors,0); assert.equal(result.threatLevel,'unknown'); }
  finally { globalThis.fetch = original; }
});
