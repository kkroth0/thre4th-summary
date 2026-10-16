# OT/ICS coverage and equipment context — 2026-10-16

## Changes
- Added direct Siemens ProductCERT and ABB PSIRT CSAF ROLIE feeds alongside CISA, Rockwell, Schneider and Cisco. Official source URLs were verified live; no credentials or HTML portal scraping is required for the new feeds.
- Added Siemens and B&R to the reference catalog (20 manufacturers). Product families are kept separate from exact model/SKU matches. Five Siemens order numbers were verified against the official SIMATIC advisory SSA-019113.
- Preserved publication/revision dates, affected/fixed product entries, model numbers, remediation product groups and version comparison operators. A product affected by one CVE and fixed for another is marked as varying by CVE; advisories combining published fixes and `none_available` are labelled as partial fixes.
- Round-robin document batches prevent one manufacturer's large index from starving others. Existing daily ETag source caching, single-flight, durable restart, bounded batches and retry behavior remain. Revised documents use conditional ETags; cached records are re-normalized once using document version 2.
- Added 14 equipment-role explanations: PLC, RTU, HMI, SCADA, DCS, SIS, drives, industrial networking, gateways, protection relays, I/O, industrial PCs, engineering software and measurement instruments. The catalog shows explanations for roles recognized in its reference families/models, plus a full expandable glossary. Unknown types remain unclassified. NIST SP 800-82r3 is linked as general OT reference.
- Excel retains the dashboard/executive/action/evidence workflow and includes equipment explanations in Fontes e critérios. Family matching does not count as an exact model match. Partial fixes and mixed product states are explicit.
- Advisory detail contents now render only when opened, avoiding thousands of hidden CVE/remediation nodes in the initial monthly table.

## Validation
- Live official indexes: Siemens 858 entries (38 published/revised in October), ABB 75 entries (one in October). All 39 October CSAF documents fetched and normalized successfully: 1,957 distinct CVEs, 35 advisories with a published fix and 13 with partial fixes. These are point-in-time source facts, not a complete claim of client exposure or future counts.
- SSA-019113 retained all 431 CVEs, ten product/version entries, official HTML reference and five catalog SKUs. SSA-580366 retained its explicit absence of an available fix. ABB 7PAA025438 retained version 26.6 and restrictions on Edgenius upgrades in the source evidence.
- Tests cover source-specific URL limits, old advisories revised this month, groups and comparison operators, mixed product states, no-fix versus mitigation, family/model boundaries, starvation prevention, conditional requests, cache/restart and equipment-role classification. Report tests cover family applicability, mixed states and the equipment glossary.
- Deployment and browser verification are recorded below after release.
