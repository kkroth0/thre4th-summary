import test from "node:test";
import assert from "node:assert/strict";
import { buildNetworkOverview } from "./networkOverview.ts";

test("builds the ordered overview with deterministic fallbacks", () => {
  const items = buildNetworkOverview([
    { name: "IP Geolocation", data: { ISP: "Google LLC", Organization: "Google LLC", Country: "United States (US)", Region: "California", City: "Mountain View", AS: "AS15169", Network: "Unknown" } },
    { name: "AbuseIPDB", data: { ISP: "Fallback ISP", ASN: "AS15169", "CIDR/Network": "8.8.8.0/24" } },
  ]);

  assert.deepEqual(items.map(({ label, value }) => [label, value]), [
    ["ISP", "Google LLC"], ["Organization", "Google LLC"], ["Country", "United States (US)"],
    ["Region", "California"], ["City", "Mountain View"], ["ASN/AS", "AS15169"], ["Network", "8.8.8.0/24"],
  ]);
});

test("omits empty and placeholder values", () => {
  assert.deepEqual(buildNetworkOverview([{ name: "IP Geolocation", data: { ISP: "Unknown", Country: "N/A" } }]), []);
});
