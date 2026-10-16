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
Pending deployment and authenticated browser checks.
