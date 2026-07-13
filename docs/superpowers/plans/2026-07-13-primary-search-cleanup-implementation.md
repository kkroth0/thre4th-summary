# Primary Search Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Focus the primary analyzer on IPv4/IPv6/domain/URL/hash searches, remove Criminal IP and obsolete result cards, and promote a clearer Geographic & Network Data overview to the top of each useful result.

**Architecture:** Move query parsing and network-field composition into small pure utilities that can be tested with Node's built-in test runner. Keep provider routing in `threatApi.ts`, but normalize persisted provider selections against one supported-provider list. Replace the monolithic three-card `ThreatCharts` section with a focused, responsive `GeographicNetworkOverview` rendered directly after `ThreatSummary`.

**Tech Stack:** React 18, TypeScript 5.8, Vite 6, Tailwind CSS, Node 22 built-in test runner, Express 5.

## Global Constraints

- The primary analyzer accepts only public IPv4 and IPv6 addresses, domains, HTTP/HTTPS URLs, and MD5/SHA-1/SHA-256 hashes.
- CVE dashboards, advisory feeds, and CVE enrichment outside the primary analyzer remain unchanged.
- ASN remains an enrichment field and is not a search input.
- Criminal IP is removed rather than conditionally hidden.
- Geolocation and provider Top 10 visualizations are removed without replacement.
- Geographic & Network Data reuses existing provider responses and makes no new network request.
- No new runtime or test dependency is added.
- Direct IPv6 input accepts compressed and full globally routable forms; loopback, unspecified, unique-local, link-local, multicast, documentation, and other non-global ranges are rejected.

---

### Task 1: Make supported IOC parsing a tested contract

**Files:**
- Modify: `src/utils/iocExtract.ts`
- Create: `src/utils/iocExtract.test.ts`
- Modify: `src/pages/Index.tsx`
- Modify: `src/components/SearchForm.tsx`
- Modify: `package.json`

**Interfaces:**
- Produces: `detectAnalyzerQueryType(query: string): "ip" | "domain" | "hash" | "url" | "unknown"`.
- Produces: `isSupportedAnalyzerQuery(query: string): boolean`.
- Preserves: `extractIocsFromText(text: string): string[]` and `MAX_ANALYZER_TARGETS`.

- [x] **Step 1: Write failing extraction and classification tests**

```ts
import test from "node:test";
import assert from "node:assert/strict";
import {
  detectAnalyzerQueryType,
  extractIocsFromText,
  isSupportedAnalyzerQuery,
} from "./iocExtract.ts";

test("extracts supported IOC types and excludes CVE identifiers", () => {
  const text = [
    "8.8.8.8 example.com https://example.com/path",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "CVE-2024-3094",
  ].join("\n");

  assert.deepEqual(extractIocsFromText(text), [
    "8.8.8.8",
    "https://example.com/path",
    "example.com",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  ]);
});

test("classifies only supported primary-search inputs", () => {
  assert.equal(detectAnalyzerQueryType("8.8.8.8"), "ip");
  assert.equal(detectAnalyzerQueryType("2001:4860:4860::8888"), "ip");
  assert.equal(detectAnalyzerQueryType("example.com"), "domain");
  assert.equal(detectAnalyzerQueryType("https://example.com/a"), "url");
  assert.equal(detectAnalyzerQueryType("d41d8cd98f00b204e9800998ecf8427e"), "hash");
  assert.equal(detectAnalyzerQueryType("CVE-2024-3094"), "unknown");
  assert.equal(detectAnalyzerQueryType("AS15169"), "unknown");
  assert.equal(isSupportedAnalyzerQuery("999.1.1.1"), false);
});
```

- [x] **Step 2: Run the test and verify RED**

Run: `node --experimental-strip-types --test src/utils/iocExtract.test.ts`

Expected: FAIL because `detectAnalyzerQueryType` and `isSupportedAnalyzerQuery` are not exported and CVE is still extracted.

- [x] **Step 3: Implement the shared parser and remove CVE extraction**

```ts
export type AnalyzerQueryType = "ip" | "domain" | "hash" | "url" | "unknown";

const IPV4_QUERY_REGEX = /^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

export const detectAnalyzerQueryType = (query: string): AnalyzerQueryType => {
  const value = query.trim();
  if (/^https?:\/\/[^ "<>]+$/i.test(value)) return "url";
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(value)) return "hash";
  if (IPV4_QUERY_REGEX.test(value)) return "ip";
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(value)) return "domain";
  return "unknown";
};

export const isSupportedAnalyzerQuery = (query: string) => detectAnalyzerQueryType(query) !== "unknown";
```

Remove `CVE_GLOBAL_REGEX` and `cves` from `extractIocsFromText`. In `Index.tsx`, replace duplicated regular-expression validation with `isSupportedAnalyzerQuery`. In `SearchForm.tsx`, change upload errors and placeholders to list only IP, domain, URL, and hash.

- [x] **Step 4: Add and run the frontend unit-test script**

Add to `package.json`:

```json
"test:unit": "node --experimental-strip-types --test src/**/*.test.ts"
```

Run: `npm run test:unit`

Expected: PASS with the extraction and classification tests.

- [x] **Step 5: Commit the IOC contract**

```bash
git add package.json src/utils/iocExtract.ts src/utils/iocExtract.test.ts src/pages/Index.tsx src/components/SearchForm.tsx
git commit -m "fix: limit primary search to supported IOC types"
```

### Task 2: Remove Criminal IP and normalize saved providers

**Files:**
- Modify: `src/services/threatApi.ts`
- Create: `src/config/vendorCatalog.ts`
- Modify: `src/components/VendorFilter.tsx`
- Modify: `src/pages/Index.tsx`
- Modify: `src/pages/VendorDirectory.tsx`
- Modify: `src/pages/Settings.tsx`
- Modify: `src/components/VendorContent.tsx`
- Modify: `src/components/VendorDataTable.tsx`
- Modify: `server/index.js`
- Modify: `server/.env.example`
- Modify: `README.md`
- Create: `src/config/vendorCatalog.test.ts`

**Interfaces:**
- Produces: `SUPPORTED_VENDORS: readonly string[]` from `src/config/vendorCatalog.ts`.
- Produces: `normalizeVendorSelection(saved: unknown): string[]`.
- Criminal IP must be absent from provider routing, UI catalogs, API-key catalogs, and backend routes.

- [x] **Step 1: Write a failing saved-selection normalization test**

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { normalizeVendorSelection, SUPPORTED_VENDORS } from "./vendorCatalog.ts";

test("drops removed and unknown vendors from persisted selections", () => {
  assert.equal(SUPPORTED_VENDORS.includes("Criminal IP"), false);
  assert.deepEqual(
    normalizeVendorSelection(["VirusTotal", "Criminal IP", "Unknown Vendor"]),
    ["VirusTotal"],
  );
});
```

- [x] **Step 2: Run the focused test and verify RED**

Run: `node --experimental-strip-types --test src/config/vendorCatalog.test.ts`

Expected: FAIL because the exports do not exist and Criminal IP is still routed.

- [x] **Step 3: Define the supported-provider boundary and remove frontend references**

Create `vendorCatalog.ts` as the dependency-free source of provider names and persisted-selection normalization, then consume it in `threatApi.ts`, `Index.tsx`, and `VendorFilter.tsx`:

```ts
export const SUPPORTED_VENDORS = Object.freeze([
  "IP Geolocation", "WHOIS", "VirusTotal", "AbuseIPDB", "AlienVault OTX",
  "Shodan", "URLhaus", "MalwareBazaar", "ThreatFox", "Google Safe Browsing",
  "PhishTank", "Pulsedive", "Hybrid Analysis", "CIRCL hashlookup",
  "MetaDefender", "PhishStats", "Ransomware.live", "OpenPhish", "Team Cymru", "Censys",
] as const);

export const normalizeVendorSelection = (saved: unknown): string[] => {
  if (!Array.isArray(saved)) return [...SUPPORTED_VENDORS];
  const allowed = new Set(SUPPORTED_VENDORS);
  return saved.filter((name): name is string => typeof name === "string" && allowed.has(name));
};
```

Delete the Criminal IP support entry, formatter case, fetcher, external URL, and vendor-map entry. Consume `SUPPORTED_VENDORS` in `Index.tsx` and use `normalizeVendorSelection` while restoring `localStorage`. Delete Criminal IP from `VendorFilter`, `VendorDirectory`, `Settings`, vendor-specific renderers, icons, sorting tiers, and copied links.

- [x] **Step 4: Remove the backend integration**

Delete `POST /api/criminalip`, `CRIMINALIP_API_KEY` from integration-status responses and environment examples, and Criminal IP documentation. Keep unrelated CVE and attack-surface routes unchanged.

- [x] **Step 5: Verify Criminal IP is absent and tests pass**

Run: `rg -n -i "criminal.?ip|CRIMINALIP" src server README.md API_RESOURCES.md ENDPOINTS.txt`

Expected: no matches.

Run: `npm run test:unit && node --check server/index.js`

Expected: PASS.

- [x] **Step 6: Commit provider removal**

```bash
git add src server README.md API_RESOURCES.md ENDPOINTS.txt
git commit -m "refactor: remove Criminal IP integration"
```

### Task 3: Build a tested Geographic & Network Data model

**Files:**
- Create: `src/utils/networkOverview.ts`
- Create: `src/utils/networkOverview.test.ts`
- Create: `src/components/GeographicNetworkOverview.tsx`

**Interfaces:**
- Consumes: `VendorData[]` from `src/types/threat-intelligence.ts`.
- Produces: `NetworkOverviewItem = { key: "isp" | "organization" | "country" | "region" | "city" | "asn" | "network"; label: string; value: string }`.
- Produces: `buildNetworkOverview(vendors: VendorData[]): NetworkOverviewItem[]`.
- Produces: `<GeographicNetworkOverview vendorData={VendorData[]} />`.

- [x] **Step 1: Write failing precedence and placeholder tests**

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { buildNetworkOverview } from "./networkOverview.ts";

test("builds the ordered overview with deterministic fallbacks", () => {
  const items = buildNetworkOverview([
    { name: "IP Geolocation", data: { ISP: "Google LLC", Organization: "Google LLC", Country: "United States (US)", Region: "California", City: "Mountain View", AS: "AS15169", Network: "Unknown" } },
    { name: "AbuseIPDB", data: { ISP: "Fallback ISP", ASN: "AS15169", "CIDR/Network": "8.8.8.0/24" } },
  ]);

  assert.deepEqual(items.map(({ label, value }) => [label, value]), [
    ["ISP", "Google LLC"],
    ["Organization", "Google LLC"],
    ["Country", "United States (US)"],
    ["Region", "California"],
    ["City", "Mountain View"],
    ["ASN/AS", "AS15169"],
    ["Network", "8.8.8.0/24"],
  ]);
});

test("omits empty and placeholder values", () => {
  assert.deepEqual(buildNetworkOverview([
    { name: "IP Geolocation", data: { ISP: "Unknown", Country: "N/A" } },
  ]), []);
});
```

- [x] **Step 2: Run the focused test and verify RED**

Run: `node --experimental-strip-types --test src/utils/networkOverview.test.ts`

Expected: FAIL because `buildNetworkOverview` does not exist.

- [x] **Step 3: Implement the pure field-composition utility**

```ts
const EMPTY_VALUES = new Set(["", "unknown", "n/a", "none", "not available", "-"]);

const usable = (value: unknown): value is string | number =>
  (typeof value === "string" || typeof value === "number") &&
  !EMPTY_VALUES.has(String(value).trim().toLowerCase());

const first = (...values: unknown[]) => values.find(usable);

export const buildNetworkOverview = (vendors: VendorData[]): NetworkOverviewItem[] => {
  const data = (name: string) => vendors.find((vendor) => vendor.name === name && !vendor.error)?.data ?? {};
  const geo = data("IP Geolocation");
  const abuse = data("AbuseIPDB");
  const vt = data("VirusTotal");
  const shodan = data("Shodan");
  const censys = data("Censys");
  const candidates = [
    ["isp", "ISP", first(geo.ISP, abuse.ISP, shodan.ISP)],
    ["organization", "Organization", first(geo.Organization, shodan.Organization, vt["AS Owner"])],
    ["country", "Country", first(geo.Country, abuse.Country, vt.Country)],
    ["region", "Region", first(geo.Region)],
    ["city", "City", first(geo.City)],
    ["asn", "ASN/AS", first(geo.AS, abuse.ASN, shodan.ASN, censys.ASN, vt.ASN)],
    ["network", "Network", first(abuse["CIDR/Network"], vt.Network, censys["BGP Prefix"])],
  ] as const;
  return candidates.filter((entry) => usable(entry[2])).map(([key, label, value]) => ({ key, label, value: String(value) }));
};
```

- [x] **Step 4: Build the responsive overview component**

Render nothing for an empty model. Otherwise render a full-width bordered panel with a header and `grid-cols-1 sm:grid-cols-2 xl:grid-cols-4`; render every item as a padded fact cell with icon, uppercase label, wrapping value, and monospaced styling for ASN and network values. Use localized title text from `LanguageContext` and do not add map, coordinate, score, or pagination behavior.

- [x] **Step 5: Run unit tests and typecheck**

Run: `npm run test:unit && npm run typecheck`

Expected: PASS.

- [x] **Step 6: Commit the overview model and component**

```bash
git add src/utils/networkOverview.ts src/utils/networkOverview.test.ts src/components/GeographicNetworkOverview.tsx
git commit -m "feat: add geographic network overview"
```

### Task 4: Promote the overview and delete obsolete visualizations

**Files:**
- Modify: `src/pages/Index.tsx`
- Delete: `src/components/ThreatCharts.tsx`

**Interfaces:**
- Consumes: `<GeographicNetworkOverview vendorData={data.vendorData} />` from Task 3.
- Removes: `<ThreatCharts>` and all Leaflet script/style injection, Geolocation map, and provider Top 10 code.

- [x] **Step 1: Add a failing structural assertion**

Add `src/components/resultLayout.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("places network overview after summary and removes obsolete charts", () => {
  const source = readFileSync(new URL("../pages/Index.tsx", import.meta.url), "utf8");
  const summary = source.indexOf("<ThreatSummary");
  const overview = source.indexOf("<GeographicNetworkOverview");
  const timeline = source.indexOf("<IocTimeline");
  assert.ok(summary >= 0 && overview > summary && timeline > overview);
  assert.equal(source.includes("<ThreatCharts"), false);
});
```

- [x] **Step 2: Run the structural test and verify RED**

Run: `node --experimental-strip-types --test src/components/resultLayout.test.ts`

Expected: FAIL because the new overview is not rendered and `ThreatCharts` still exists.

- [x] **Step 3: Integrate the new top-level panel**

Import `GeographicNetworkOverview` in `Index.tsx`, render it immediately after `ThreatSummary`, and remove the `ThreatCharts` import and bottom render. Delete `src/components/ThreatCharts.tsx`, which removes the Geolocation map and provider Top 10 implementations together.

- [x] **Step 4: Verify structure, typecheck, and build**

Run: `npm run test:unit && npm run typecheck && npm run build`

Expected: all commands PASS and the Vite build contains no missing import.

- [x] **Step 5: Commit the result-page hierarchy**

```bash
git add src/pages/Index.tsx src/components/GeographicNetworkOverview.tsx src/components/resultLayout.test.ts
git add -u src/components/ThreatCharts.tsx
git commit -m "refactor: promote network data in IOC results"
```

### Task 5: Remove primary-search CVE copy and verify the complete change

**Files:**
- Modify: `src/pages/Index.tsx`
- Modify: `src/components/SearchForm.tsx`
- Modify: `README.md` only where it describes the primary analyzer
- Test: `src/**/*.test.ts`
- Test: `server/test/*.test.js`

**Interfaces:**
- Preserves: dedicated `/cves` navigation, CVE dashboard copy, advisory copy, and CVE backend endpoints.
- Removes: only primary-search claims, examples, and validation paths that advertise CVE.

- [x] **Step 1: Replace every primary-search CVE claim**

Change analyzer-specific Portuguese copy to `IP, domínio, URL ou hash` and English copy to `IP, domain, URL, or hash`. Remove `CVE-2024-3094` from analyzer example chips. Do not change CVE navigation cards, advisory prose, CVE dashboard routes, or report fields populated by provider vulnerability results.

- [x] **Step 2: Run targeted source audits**

Run: `rg -n 'IP, dominio, URL, hash ou CVE|IP, domain, URL, hash or CVE|CVE-2024-3094|cvePattern|cveRegex' src/pages/Index.tsx src/components/SearchForm.tsx src/utils/iocExtract.ts`

Expected: no matches.

Run: `rg -n -i "criminal.?ip|CRIMINALIP" src server README.md API_RESOURCES.md ENDPOINTS.txt`

Expected: no matches.

- [x] **Step 3: Run all local verification**

Run: `npm run test:unit && npm run lint && npm run typecheck && npm run build && npm run test:server && npm run ci:hunt`

Expected: every command exits 0. Existing warnings must be reported; new warnings or errors must be fixed before completion.

- [ ] **Step 4: Perform optional credentialed smoke checks when a configured local server is available**

Exercise one public IPv4, one public IPv6, one domain, one URL, one MD5, one SHA-1, and one SHA-256 through the running API. Record provider-level success, no-data, authentication, quota, and upstream failures separately. Do not expose keys or claim upstream health from contract tests alone.

Before the smoke check, add backend contract tests for public IPv6 acceptance, non-global IPv6 rejection, and provider routing. Providers that do not demonstrably accept IPv6 must be filtered before a request is made.

- [x] **Step 5: Commit final copy and verification adjustments**

```bash
git add src/pages/Index.tsx src/components/SearchForm.tsx README.md package.json
git commit -m "chore: align analyzer copy with supported searches"
```
