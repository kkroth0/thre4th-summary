# AI Tools Patch Day and client Patch Day reports — 2026-10-16

## Scope
- Monthly AI security view alongside OT/ICS Patch Day, with catalog coverage across inference/LLMs, interfaces, agents, MCP, RAG/vector data, model libraries/MLOps, gateways/observability, coding assistants, and hosted services.
- Seed catalog plus evidence-based discovery of previously unknown AI/MCP components. Catalog inclusion is not a promise of exhaustive vendor disclosure coverage.
- GitHub global security advisories retain affected ranges, first patched versions, references and withdrawn status. Local NVD CVEs are joined by CVE with KEV/EPSS. A CVE alone does not confirm a patch.
- NVD ingestion maintains a compact AI index in the unified SQLite database. A resumable background worker prepares historical rows; monthly queries read this index and join current KEV/EPSS by CVE, with five-minute single-flight caching. No per-tool NVD HTTP fan-out on page views.
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

- Semantic review also separated third-party ChatGPT/Claude plugins from the underlying hosted products: the affected component name is retained, and the referenced AI product remains a related tool. A regression test rejects brand mentions that occur only in researcher credits.

- Final production validation found the large FTS/date intersection exceeding the catalog query timeout on the VPS. Date streaming was also insufficient on the 917 MB production catalog. The final implementation maintains a compact AI index during ingestion, with strict classification and a source-code revision fingerprint. A resumable background worker handles historical rows without holding page requests. Monthly reads are capped at 5,000 AI results, with an explicit partial-coverage flag. Catalog errors expire from the response cache after 15 seconds rather than poisoning it for five minutes.

- Historical index preparation persists a row cursor, yields between batches, resumes after restart and retries busy writers. Ingestion removes rejected/reclassified entries atomically. Tests verify those transitions and fresh KEV/EPSS signals, including a genuine zero EPSS, without rebuilding the index.

## Final release verification
- Functional production SHA: `aa4d330323b5a53be9d3306b0c8fa30cb452d862`.
- CI `38948292138`: success, 807 backend tests, 254 frontend unit tests and 7 brand tests. VPS deploy `38948594857` and Cloudflare Pages deploy `38948594989`: success; VPS release SHA confirmed in deployment logs.
- Production no longer timed out after moving classification into ingestion and the historical worker. Initial indexed snapshots grew from 97 to 310 monthly advisories while preparation continued; measured HTTP responses dropped from the failing 44–50 second window to 8.3, 4.3 and 1.6 seconds during warm-up. These are individual measurements, not a latency SLA.
- Latest inspected snapshot: 310 advisories, 308 distinct CVEs, 66 advisories with confirmed fixes and 7 advisories with a KEV signal; zero collection failures. NVD historical AI indexing and the GitHub discovery backfill were still running and explicitly marked partial. CISA KEV and EPSS were available.
- Browser checks: month navigation, current-month shortcut, MCP category filtering, published-fix filtering, catalog coverage, LiteLLM text search and details. LiteLLM retained affected range `>= 1.81.16, < 1.83.7` and fixed version `1.83.7`. Its CVE link opened the shared vulnerability record with CVSS 9.8, KEV and EPSS 5.77%.
- Browser-downloaded filtered Excel: 6 advisories, 1 KEV signal, 1 confirmed fix, preserved `Busca: LiteLLM` scope. Full monthly Excel: 310 advisories, 308 CVEs, 7 KEV signals, 66 fixes. Both contain two native charts and valid XML; all seven AI report sheets imported/rendered with zero spreadsheet formula errors. Partial coverage was preserved in the report.
- Production diagnostics `38949895378`: site active, `NRestarts=0`, no startup error or index failure in the inspected signals; 407 MiB available memory. Index preparation continued in the background. The earlier diagnostic also retained the 32 C2Agent hashes in the repository feed cache.
- Independent security scanning still reports existing dependency vulnerabilities (49 npm findings); no dependency versions changed in this feature. This is separate from the passing functional CI and deployment checks.
