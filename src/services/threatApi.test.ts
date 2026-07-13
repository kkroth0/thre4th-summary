import test from "node:test";
import assert from "node:assert/strict";
import { detectIOCType, resolveVendorsForQuery } from "./threatApi";

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
