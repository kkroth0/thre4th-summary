import test from "node:test";
import assert from "node:assert/strict";
import { detectIOCType, resolveVendorsForQuery, formatVendorData } from "./threatApi";
import { refang } from "@/utils/defang";
import { isSupportedAnalyzerQuery } from "@/utils/iocExtract";

test("detects a public IPv6 address as IP and an IPv6 literal URL as URL", () => {
  assert.equal(detectIOCType("2606:4700:4700::1111"), "ip");
  assert.equal(detectIOCType("https://[2606:4700:4700::1111]/status"), "url");
});

test("routes IPv6 only to providers backed by IPv6-capable endpoints", () => {
  const selected = [
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "AlienVault OTX", "Shodan",
    "ThreatFox", "Pulsedive", "MetaDefender", "Team Cymru", "Censys",
  ];

  assert.deepEqual(resolveVendorsForQuery("2606:4700:4700::1111", selected), [
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox",
    "Pulsedive", "MetaDefender", "Censys",
  ]);
});

test("refanged input makes defanged IOCs searchable", () => {
  // Before the refang, each of these was rejected as "unknown" and aborted the scan.
  assert.equal(isSupportedAnalyzerQuery(refang("evil[.]com")), true);
  assert.equal(isSupportedAnalyzerQuery(refang("1.2.3[.]4")), true);
  assert.equal(isSupportedAnalyzerQuery(refang("hxxps://bad[.]com/x")), true);
});

test("OpenPhish and Team Cymru expose a capital-S Status the aggregator can count", () => {
  assert.equal(formatVendorData("OpenPhish", { listed: true, status: "Listed as phishing" }, "http://x").Status, "Phishing");
  assert.equal(formatVendorData("OpenPhish", { listed: false, status: "x" }, "http://x").Status, "Clean");

  // Hash MHR hit → malicious verdict.
  assert.equal(formatVendorData("Team Cymru", { listed: true, last_seen: "123" }, "abc").Status, "Malicious");
  // IP → ASN enrichment: no Status, so it stays out of the malicious/clean vote.
  const cymruIp = formatVendorData("Team Cymru", { asn: "15169", bgp_prefix: "8.8.8.0/24", country: "US" }, "8.8.8.8");
  assert.equal(cymruIp.Status, undefined);
  assert.equal(cymruIp.ASN, "15169");
});
