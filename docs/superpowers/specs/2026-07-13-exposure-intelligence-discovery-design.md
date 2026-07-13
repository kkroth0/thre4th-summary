# Exposure Intelligence Discovery Design

Date: 2026-07-13
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Add an Exposure Intelligence discovery workflow inside the existing Attack
Surface feature.

The feature should let an analyst create a company profile, run passive
discovery, review candidate assets with evidence and confidence scoring, and
approve selected candidates into the existing Attack Surface Monitor.

The product outcome is clear separation of three jobs in one hub:

- `Scan`: investigate a known target now.
- `Discovery`: find likely assets for a company profile.
- `Monitor`: track approved assets over time.

## Non-Goals

- Do not add a separate top-level Exposure Intelligence route for the MVP.
- Do not add active scanning or a new VPS worker in the MVP.
- Do not run Subfinder, Amass, httpx, dnsx, naabu, nmap, or similar active or
  semi-active tools in the MVP.
- Do not automatically save every discovered asset into monitoring.
- Do not fail the whole workflow when one provider is missing, rate-limited, or
  unavailable.
- Do not duplicate Shodan/Censys normalization logic separately from the
  existing Attack Surface feature.
- Do not migrate persistence to a database in this iteration.

## Current State

The project already has:

- `/attack-surface`, the canonical external exposure page.
- `Scan` and `Monitor` modes planned or implemented under Attack Surface.
- `/exposure-watchlist` redirected to `/attack-surface?mode=monitor`.
- `POST /api/attack-surface`, backed by `server/attackSurface.js`.
- Exposure Watchlist APIs and snapshot diffing backed by
  `server/exposureWatchlist.js`.
- Saved assets, manual snapshots, daily schedule flags, and change detection.
- Shodan as the primary exposure source and Censys as optional enrichment.
- BYOK support for Shodan and Censys.
- TXT import support for IP, CIDR, domain, ASN, and Shodan queries.
- XLSX export for Attack Surface results.

Discovery should reuse those foundations instead of creating a parallel product
surface.

## Recommended Approach

Add `Discovery` as a new top-level tab inside `/attack-surface`, beside `Scan`
and `Monitor`.

The MVP is passive/API-only and uses company profiles:

- primary domain is required;
- legal organization name is optional;
- known ASNs are optional;
- passive collectors produce candidate assets;
- each candidate includes confidence, risk, evidence, freshness, and provider
  status;
- candidates enter a review queue;
- the user chooses which candidates become Monitor assets.

This avoids redundant navigation, keeps the defensive authorization boundary
clear, and allows future collector expansion without changing the user model.

## Considered Approaches

### Recommended: Attack Surface Hub With `Scan | Discovery | Monitor`

Attack Surface becomes the single external exposure workspace. Discovery is a
mode, not a separate product.

Trade-off: the page becomes larger, so the implementation should split
Discovery UI and backend modules into focused components.

### Alternative: Separate Exposure Intelligence Page

Create a new `/exposure-intelligence` route and navigation item.

Trade-off: stronger marketing label, but it recreates the navigation
fragmentation already solved by merging Exposure Watchlist into Attack Surface.

### Alternative: Discovery Inside Monitor

Place company profiles and candidate review under Monitor.

Trade-off: lower navigation change, but Discovery is conceptually different
from monitoring. It would hide a valuable workflow and make Monitor do too
many jobs.

## User Workflow

1. User opens `/attack-surface`.
2. User selects the `Discovery` tab.
3. User creates or selects a company profile:
   - profile label;
   - primary domain, required;
   - legal organization name, optional;
   - known ASNs, optional list;
   - result limit, capped;
   - notes, optional.
4. User runs passive discovery manually.
5. Backend runs enabled passive collectors.
6. Backend normalizes evidence into candidate assets.
7. Backend merges fresh and cached provider evidence.
8. Backend creates a discovery snapshot.
9. UI shows:
   - candidate review queue;
   - confidence and risk;
   - evidence by source;
   - provider warnings;
   - new/removed/changed candidates compared with the previous snapshot.
10. User approves selected candidates.
11. Approved candidates become existing Monitor assets.

## Passive Collectors

MVP collectors:

- Shodan collector:
  - domain/hostname queries;
  - organization queries when legal name is present;
  - ASN queries when ASNs are present;
  - port, banner, product, version, CVE, ASN, organization, and hostname
    evidence.
- Censys collector:
  - host and certificate enrichment when configured;
  - optional and fail-soft.
- CT logs collector:
  - certificate transparency lookup for names related to the primary domain;
  - subject common names and SANs;
  - candidate subdomains and related hostnames.
- DNS/RDAP/ASN collector:
  - passive DNS resolution where available through safe APIs or standard DNS;
  - RDAP ownership evidence;
  - ASN ownership/name evidence.

Future collectors can be added behind the same interface, including a VPS-based
worker, but that is intentionally out of scope for the MVP.

## Collector Interface

Each collector should return a provider result instead of throwing user-facing
errors for normal provider failure.

Suggested normalized shape:

```ts
interface DiscoveryProviderResult<T> {
  provider: "shodan" | "censys" | "ct_logs" | "dns_rdap_asn";
  status:
    | "ok"
    | "partial"
    | "missing_key"
    | "quota_exceeded"
    | "timeout"
    | "provider_error"
    | "cache_only";
  fetchedAt: string | null;
  cacheAgeSeconds: number | null;
  warnings: string[];
  data: T[];
}
```

Provider results are runtime objects. Snapshots should persist provider status
metadata and normalized evidence/candidates, not raw upstream payloads.

The Discovery orchestrator should aggregate provider results and decide whether
the whole run is:

- `success`: enough live or cached sources produced useful evidence;
- `partial`: at least one source failed, but candidates can still be shown;
- `cache_only`: no live source responded, but previous usable evidence exists;
- `empty`: sources responded but no candidates were found;
- `failed`: no source responded and there is no cache.

Only `failed` should render an explicit blocking empty state. Provider-level
errors should usually render as warnings and badges.

## Graceful Degradation And Cache Behavior

The UI must not expose raw API errors or collapse the whole page because one
provider fails.

When API quota ends, keys are missing, providers time out, or upstream services
fail:

- show partial results from providers that did respond;
- combine fresh evidence with cached evidence when available;
- mark each evidence item with source and freshness;
- show warning badges such as `quota exceeded`, `missing key`, `timeout`,
  `provider unavailable`, or `from cache`;
- reduce candidate confidence when important evidence is stale or incomplete;
- keep the review queue usable;
- show an empty/blocking state only if no live source and no cache produced
  useful evidence.

The chosen fallback is mixed evidence:

- fresh provider evidence is preferred;
- cached evidence can supplement missing providers;
- each evidence item keeps its own source timestamp and cache status;
- final confidence reflects both evidence strength and freshness.

Example UI copy:

```txt
Partial discovery results. Censys quota is exhausted, so Censys evidence is
shown from the last successful snapshot where available.
```

## Discovery Profile Shape

```ts
interface DiscoveryProfile {
  id: string;
  ownerId: string;
  ownerLogin: string;
  label: string;
  primaryDomain: string;
  legalName: string | null;
  asns: string[];
  notes: string | null;
  limit: number;
  createdAt: string;
  updatedAt: string;
  lastRunAt: string | null;
  lastStatus: "never_run" | "running" | "success" | "partial" | "cache_only" | "empty" | "failed";
  lastError: string | null;
  lastSnapshotId: string | null;
  lastSummary: DiscoverySummary | null;
}
```

Summary shape:

```ts
interface DiscoverySummary {
  totalCandidates: number;
  byConfidence: Record<"high" | "medium" | "low", number>;
  byRisk: Record<"critical" | "high" | "medium" | "low" | "unknown", number>;
  newCandidates: number;
  changedCandidates: number;
  removedCandidates: number;
  approvedCandidates: number;
  providerStatuses: DiscoveryProviderStatus[];
}
```

Validation rules:

- primary domain is required and must be a valid domain;
- legal name is optional, trimmed, and length-limited;
- ASNs accept `AS12345` or `12345`, normalize to `AS12345`, and reject
  non-numeric content;
- result limit is clamped to a safe maximum, initially `100`;
- profile labels are required and length-limited.

## Candidate Asset Shape

```ts
interface DiscoveryCandidate {
  id: string;
  profileId: string;
  kind: "domain" | "subdomain" | "ip" | "cidr" | "asn" | "shodan_query";
  value: string;
  normalizedValue: string;
  confidence: number;
  confidenceLevel: "high" | "medium" | "low";
  risk: "critical" | "high" | "medium" | "low" | "unknown";
  riskScore: number;
  status: "new" | "seen" | "changed" | "removed" | "approved" | "ignored";
  evidence: DiscoveryEvidence[];
  reasons: string[];
  firstSeenAt: string;
  lastSeenAt: string;
  monitorAssetId: string | null;
}
```

Evidence shape:

```ts
interface DiscoveryEvidence {
  provider: "shodan" | "censys" | "ct_logs" | "dns_rdap_asn";
  type:
    | "hostname_match"
    | "certificate_match"
    | "org_match"
    | "asn_match"
    | "rdap_match"
    | "dns_resolution"
    | "open_service"
    | "cve"
    | "banner";
  value: string;
  observedAt: string | null;
  sourceStatus: "fresh" | "cached" | "partial";
  weight: number;
}
```

## Confidence Scoring

Confidence answers: "How likely is this candidate to belong to the company
profile?"

Initial deterministic rules:

- high confidence:
  - subdomain under the primary domain found in CT logs or Shodan;
  - IP with RDAP/ASN ownership matching a known ASN and Shodan/Censys service
    evidence;
  - host with certificate SAN matching the primary domain.
- medium confidence:
  - organization-name match from Shodan/Censys without domain evidence;
  - ASN match from a user-provided ASN without certificate or DNS evidence;
  - related hostname with reasonable but indirect evidence.
- low confidence:
  - legal-name match only;
  - cloud/provider organization ambiguity;
  - stale-only evidence;
  - evidence from one weak source.

Confidence should be reduced when:

- evidence is cache-only;
- provider failures remove important corroboration;
- organization strings match generic cloud providers;
- hostname/domain does not share the primary domain or certificate lineage.

The UI should show confidence reasons, not only a number.

## Risk Scoring

Risk answers: "How concerning is this candidate if it belongs to the company?"

Risk should reuse Attack Surface exposure logic where possible:

- CVEs raise risk to critical;
- sensitive services like RDP, SMB, Telnet, databases, VNC, and admin panels
  raise risk;
- exposed web services without known sensitive signals are lower risk;
- stale-only exposure evidence lowers confidence but does not erase known risk.

Discovery candidates can have `risk: "unknown"` if they were discovered by CT
or RDAP evidence but do not yet have service exposure data.

## Snapshot And Diff Logic

Discovery profiles use manual snapshots in the MVP.

Snapshot shape:

```ts
interface DiscoverySnapshot {
  id: string;
  profileId: string;
  ownerId: string;
  startedAt: string;
  completedAt: string | null;
  status: "success" | "partial" | "cache_only" | "empty" | "failed";
  error: string | null;
  providerStatuses: DiscoveryProviderStatus[];
  summary: DiscoverySummary;
  candidates: DiscoveryCandidate[];
  changes: DiscoveryChange[];
  warnings: string[];
}
```

Provider status shape persisted in snapshots:

```ts
interface DiscoveryProviderStatus {
  provider: "shodan" | "censys" | "ct_logs" | "dns_rdap_asn";
  status:
    | "ok"
    | "partial"
    | "missing_key"
    | "quota_exceeded"
    | "timeout"
    | "provider_error"
    | "cache_only";
  fetchedAt: string | null;
  cacheAgeSeconds: number | null;
  resultCount: number;
  warnings: string[];
}
```

Change types:

- `candidate_added`
- `candidate_removed`
- `candidate_changed`
- `confidence_increased`
- `confidence_decreased`
- `risk_increased`
- `risk_decreased`
- `evidence_added`
- `evidence_stale`
- `provider_status_changed`

Change shape:

```ts
interface DiscoveryChange {
  id: string;
  profileId: string;
  snapshotId: string;
  detectedAt: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  type:
    | "candidate_added"
    | "candidate_removed"
    | "candidate_changed"
    | "confidence_increased"
    | "confidence_decreased"
    | "risk_increased"
    | "risk_decreased"
    | "evidence_added"
    | "evidence_stale"
    | "provider_status_changed";
  title: string;
  description: string;
  candidateId: string | null;
  previous: unknown;
  current: unknown;
}
```

The first successful or partial snapshot creates a baseline change rather than
flooding the user with high-severity alerts.

Retention can mirror Exposure Watchlist initially: keep the latest 14 snapshots
per profile.

## Review Queue

Discovery does not auto-save candidates into Monitor.

The review queue should support:

- approve one candidate;
- approve selected candidates;
- ignore candidate;
- clear ignored filter;
- inspect evidence before approving;
- create Monitor assets using existing Exposure Watchlist asset types.

Candidate-to-monitor mapping:

- domain/subdomain candidate -> Monitor `domain`;
- IP candidate -> Monitor `ip`;
- CIDR candidate -> Monitor `cidr`;
- ASN candidate -> Monitor `asn`;
- complex Shodan query candidate -> Monitor `shodan_query`.

Approved candidates should store `monitorAssetId` to prevent duplicate Monitor
assets for the same profile candidate.

## UI Design

Add a third tab under `/attack-surface`:

- `Scan`
- `Discovery`
- `Monitor`

`Discovery` layout:

- profile selector and create/edit profile form;
- run discovery action;
- summary cards:
  - total candidates;
  - high-confidence candidates;
  - critical/high risk candidates;
  - new since previous snapshot;
  - provider health;
- provider status strip with fresh/cache/failure badges;
- candidate review table;
- expandable evidence drawer;
- snapshot history and changes feed.

The page should use the existing SOC-style dense visual language already used
by Attack Surface.

## Backend Design

Add a focused backend module:

- `server/exposureDiscovery.js`

Responsibilities:

- validate and normalize profiles;
- run passive collectors;
- manage provider result statuses;
- combine live and cached evidence;
- score confidence and risk;
- persist profile snapshots;
- diff snapshots;
- approve candidates into existing Exposure Watchlist assets.

Endpoints:

- `GET /api/exposure-discovery/profiles`
- `POST /api/exposure-discovery/profiles`
- `PATCH /api/exposure-discovery/profiles/:id`
- `DELETE /api/exposure-discovery/profiles/:id`
- `POST /api/exposure-discovery/profiles/:id/run`
- `GET /api/exposure-discovery/profiles/:id/snapshots`
- `GET /api/exposure-discovery/profiles/:id/candidates`
- `POST /api/exposure-discovery/profiles/:id/candidates/:candidateId/approve`
- `POST /api/exposure-discovery/profiles/:id/candidates/:candidateId/ignore`

All endpoints should require the same premium/user isolation model as Monitor.
One-off Scan can remain public if that is current product behavior.

## Persistence

Use JSON-backed persistence for the MVP, matching existing local storage
patterns:

- `.exposure-discovery-profiles.json`
- `.exposure-discovery-snapshots.json`

Do not store raw provider responses. Store only normalized provider status,
evidence, candidates, summaries, and warnings.

## Redundancy Decisions

The following become intentionally redundant and should be avoided:

- separate Exposure Intelligence route;
- separate Shadow IT page;
- duplicate Shodan/Censys query logic;
- duplicate snapshot/diff infrastructure where existing patterns can be reused;
- provider fallback handling inside each UI component;
- treating `org` scan as the main Shadow IT workflow.

The existing `org` target type in Scan can remain as an advanced quick search,
but Discovery becomes the guided workflow for organization-based Shadow IT
analysis.

## Error Handling

Backend:

- provider failures become provider result statuses when possible;
- unexpected coding errors still return sanitized API errors;
- quota and missing-key errors should not be logged with secrets;
- one provider failure should not stop other providers;
- per-profile owner isolation must be enforced before reading snapshots or
  approving candidates.

Frontend:

- render partial results and warnings;
- never show stack traces or raw provider JSON errors;
- show stale/cache badges close to evidence;
- disable approve actions only when no candidate is selected or candidate is
  already approved;
- keep the last successful UI state visible when a new run returns partial
  results.

## Testing Strategy

Backend unit tests:

- profile validation and ASN normalization;
- collector result status normalization;
- mixed fresh/cache provider aggregation;
- confidence scoring;
- risk scoring reuse for exposure evidence;
- snapshot diffing;
- candidate approval into Monitor asset shape;
- owner isolation for profiles and snapshots.

Frontend/unit tests:

- Discovery tab route state;
- profile form validation behavior;
- provider warning rendering;
- candidate table filtering;
- approve/ignore actions;
- stale evidence badges.

Regression tests:

- existing Attack Surface Scan tests continue passing;
- existing Exposure Watchlist/Monitor tests continue passing;
- `/exposure-watchlist` continues redirecting to `/attack-surface?mode=monitor`.

Manual verification:

- run Discovery with only Shodan configured;
- run Discovery with Censys missing;
- run Discovery with a simulated quota-exceeded provider;
- rerun Discovery and confirm diff behavior;
- approve candidates and confirm they appear in Monitor;
- confirm no raw provider error appears in the UI.

## Open Implementation Notes

- Prefer a collector registry so future VPS-based collectors can be added
  without changing the Discovery orchestrator.
- Keep scoring deterministic in the MVP. Do not use LLMs for ownership
  confidence until the deterministic model is understandable and auditable.
- Provider usage should respect user BYOK where available and fall back to
  environment keys according to existing server patterns.
- If a visual graph is added later, it should derive from normalized candidates
  and evidence rather than becoming the primary data model.
