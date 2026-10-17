# Patch Day interface and asset catalog — 2026-10-16

## Changes
- Shared monthly toolbar and tab navigation for OT/ICS, AI Tools, Microsoft Patch Tuesday and SAP Patch Day; SAP renamed in navigation and SEO.
- SAP supports an explicit month, durable 24-hour snapshots and request coalescing. An unavailable month cannot substitute another month. Officially linked GHSA advisories are preserved.
- OT equipment definitions moved to a sibling Asset glossary tab; AI glossary includes 150 purpose descriptions with official source links, searched by name/category/function. Static definitions require no additional ETL requests.
- OT reference catalog expanded from 20 to 47 manufacturers. Nine source-specific CERT@VDE CSAF feeds added (15 total source connectors). Reference entries are not claims of comprehensive coverage.
- Product/firmware base accumulates normalized evidence from cached advisories and bounded bootstrap documents. It retains literal version ranges, hardware/software relationships, per-product CVE statuses, source links and wildcard model distinctions. Observed products do not mutate reference models used for matching.
- Query caches reuse the accumulated product base and bootstrap selection. Existing unchanged CSAF documents are not redownloaded solely to extract version wording.

## Validation before deployment
- Final CI: 825 backend tests passed; 257 frontend unit tests and 7 brand tests passed (264 frontend total).
- TypeScript passed; lint passed with pre-existing warnings; production build passed.
- Live read-only checks of all nine new feeds and their latest documents succeeded. Document IDs match their index entries; 175 product records across these nine documents include affected/fixed evidence and version metadata.
- New tests cover SAP monthly isolation/single-flight/restart/stale behavior and GHSA links, product evidence deduplication, hardware/firmware relationships, version wording, exact model versus wildcard codes, source-host restrictions and complete seeded-tool glossary definitions.

## Production verification
First release `14f0d0fecc25f21cc4a16f73c827a9c91f4d6b7a` passed CI 38983123529 and deployed through VPS 38983329002 / Pages 38983328892 (release SHA verified).
- SAP browser: October has 22 notes, September has 20, with correct official monthly URLs. Actual downloaded `SAP-Security-Patch-Day-2026-09.xlsx` round-trips in ExcelJS: executive sheet plus 20 note rows.
- AI browser: seeded Ollama definition and official repository visible in the sibling glossary. NVD/KEV/EPSS healthy; GitHub continues to serve a stale snapshot during an upstream failure (388 monthly advisories preserved). No new external calls are introduced by glossary definitions.
- Production testing caught a large accumulated inventory payload. Follow-up separates it from monthly responses, loads it only on the product tab, and excludes ambiguous cached version-only leaves from equipment identities while retaining original advisory evidence.
- Screenshots remain local in the temporary `patch-day-unification` directory; profile images are not committed.

## Final release verification
- Functional SHA `2faf687ecc0b6eb8e5538d524768635c5b6d27bc`: CI 38984116519 succeeded; VPS 38984262807 and Pages 38984262707 succeeded. VPS release SHA verified exactly.
- Monthly OT payload now excludes the accumulated product inventory: 4,448,854 bytes in the observed response, versus approximately 14 MB with the inventory attached. Product data is fetched only from `/api/ot-patch-day/products` when its tab opens.
- Production: 73 October advisories, all 15 source connectors healthy, no pending or failed documents. Accumulated base: 7,681 product/version records, 2,538 with version information, 322 WAGO records, no truncation. Ambiguous version-only names `.0` and `12.6(1)ES1` no longer appear as product identities.
- Final browser: lazy-loaded products successfully filter WAGO firmware/OS and show 25 rows per page; source code patterns remain distinguished from exact models. Glossary has 14 equipment definitions and stays beside Catalog and coverage.
- Microsoft browser: monthly overview, source coverage, September navigation and 25-row advisory table verified. Final filter widths are 231px at the tested viewport and preserve complete labels.
- Separate dependency security scan continues to report the existing dependency findings; this change does not modify dependency manifests or lockfiles.
