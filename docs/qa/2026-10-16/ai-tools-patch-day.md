# AI Tools Patch Day and client Patch Day reports — 2026-10-16

## Scope
- Monthly AI security view alongside OT/ICS Patch Day, with catalog coverage across inference/LLMs, interfaces, agents, MCP, RAG/vector data, model libraries/MLOps, gateways/observability, coding assistants, and hosted services.
- Seed catalog plus evidence-based discovery of previously unknown AI/MCP components. Catalog inclusion is not a promise of exhaustive vendor disclosure coverage.
- GitHub global security advisories retain affected ranges, first patched versions, references and withdrawn status. Local NVD CVEs are joined by CVE with KEV/EPSS. A CVE alone does not confirm a patch.
- NVD candidate selection uses FTS and indexed publication/modification dates in the query worker, with five-minute monthly single-flight caching. No per-tool NVD HTTP fan-out on page views.
- Separate durable daily and historical GitHub cursors; 5 pages per batch, hourly continuation during backfill, daily incremental checks after completion. Twelve months of initial GHSA history, bounded cache and explicit partial coverage. Daily arrivals continue during the historical import.
- GitHub and NVD references are combined; separate GHSA/package advisories remain distinct even when they share a CVE.

## Report and monthly controls
- Prominent month toolbar with previous/next, current month, refresh and Excel actions. Export retains selected month and filters, source status and generation timestamp.
- Formatted Excel: Dashboard (two native editable charts and cached formulas), Resumo executivo, Plano de ação, Produtos e versões, Correções e evidências, Fontes e critérios, and complete technical base. Oversize evidence remains in ordered chunks.
- Priority policy is explicit: KEV, CVSS >= 7 or EPSS >= 50%, medium/unknown, low. This is editorial triage, not a client SLA or confirmed exposure. Missing values are not zero; mitigation is not a confirmed patch.
- Report generation and ZIP/chart serialization stay in the existing browser worker. No new runtime dependency.
- Human catalog description replaces the previous robotic OT copy.

## Validation before release
- Real production OT October snapshot: 32 advisories, 117 distinct CVEs, 4 KEV, 19 with fixes, 12 mitigations, 1 unconfirmed. Counts are snapshot facts, not constants.
- Real GitHub first-100 updated advisories initially exposed false positives from common words and credit text. Classification was tightened; six relevant records remained, including Jupyter, Claude Code, Unstructured and MCP components.
- Backend tests cover new-component discovery, exact package matching, non-AI false positives, unknown fixes, withdrawals, CVE joins, zero EPSS, persistence, rate failures, bounded/allowed pagination, daily collection during backfill, and monthly NVD filtering.
- Frontend/report tests cover year-boundary navigation, Fortaleza month, priority/unknown distinctions, full evidence, native-chart ZIP relationships/caches, report formulas and separate AI wording.
- Artifact Tool imported the real exported OT workbook, rendered all seven principal sheets, and found zero spreadsheet formula-error cells. Visual review caught and repaired narrow title clipping in technical tabs. Native rendering on Windows emitted an exit crash after writing the completed previews and successful inspection; ExcelJS ZIP round-trip tests also validated the workbook independently.
- Full checks and production release validation are recorded after deployment below.

- A live incremental request exposed GitHub's rejection of millisecond timestamp ranges (HTTP 422). Queries now use inclusive YYYY-MM-DD ranges with a one-day overlap; the corrected live request returned relevant AI/MCP advisories without an error. A regression test checks the wire format. Combined rows keep the latest revision date and both source revision origins.

- Production exposed GitHub's inclusion of unreviewed records when filters were present. The connector now explicitly requests reviewed advisories and prioritizes one batched query for the 155 known package identities before the discovery backfill. A live two-request validation returned 58 October advisories, 57 with published fixes; package ranges and patched versions were preserved. The 150-tool catalog remains the scope reference, not a claim of complete coverage of every product.
