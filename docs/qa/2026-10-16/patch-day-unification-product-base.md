# Patch Day interface and asset catalog — 2026-10-16

## Changes
- Shared monthly toolbar and tab navigation for OT/ICS, AI Tools, Microsoft Patch Tuesday and SAP Patch Day; SAP renamed in navigation and SEO.
- SAP supports an explicit month, durable 24-hour snapshots and request coalescing. An unavailable month cannot substitute another month. Officially linked GHSA advisories are preserved.
- OT equipment definitions moved to a sibling Asset glossary tab; AI glossary includes 150 purpose descriptions with official source links, searched by name/category/function. Static definitions require no additional ETL requests.
- OT reference catalog expanded from 20 to 47 manufacturers. Nine source-specific CERT@VDE CSAF feeds added (15 total source connectors). Reference entries are not claims of comprehensive coverage.
- Product/firmware base accumulates normalized evidence from cached advisories and bounded bootstrap documents. It retains literal version ranges, hardware/software relationships, per-product CVE statuses, source links and wildcard model distinctions. Observed products do not mutate reference models used for matching.
- Query caches reuse the accumulated product base and bootstrap selection. Existing unchanged CSAF documents are not redownloaded solely to extract version wording.

## Validation before deployment
- 823 backend tests passed. 264 bundled frontend tests and 7 brand tests passed.
- TypeScript passed; lint passed with pre-existing warnings; production build passed.
- Live read-only checks of all nine new feeds and their latest documents succeeded. Document IDs match their index entries; 175 product records across these nine documents include affected/fixed evidence and version metadata.
- New tests cover SAP monthly isolation/single-flight/restart/stale behavior and GHSA links, product evidence deduplication, hardware/firmware relationships, version wording, exact model versus wildcard codes, source-host restrictions and complete seeded-tool glossary definitions.

## Production verification
First release `14f0d0fecc25f21cc4a16f73c827a9c91f4d6b7a` passed CI 38983123529 and deployed through VPS 38983329002 / Pages 38983328892 (release SHA verified).
- SAP browser: October has 22 notes, September has 20, with correct official monthly URLs. Actual downloaded `SAP-Security-Patch-Day-2026-09.xlsx` round-trips in ExcelJS: executive sheet plus 20 note rows.
- AI browser: seeded Ollama definition and official repository visible in the sibling glossary. NVD/KEV/EPSS healthy; GitHub continues to serve a stale snapshot during an upstream failure (388 monthly advisories preserved). No new external calls are introduced by glossary definitions.
- Production testing caught a large accumulated inventory payload. Follow-up separates it from monthly responses, loads it only on the product tab, and excludes ambiguous cached version-only leaves from equipment identities while retaining original advisory evidence.
- Screenshots remain local in the temporary `patch-day-unification` directory; profile images are not committed.
