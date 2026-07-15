# SAP Security Patch Day — Design

**Date:** 2026-07-15
**Status:** Approved (design)

## Summary

A new "SAP Patch" feature mirroring the existing Patch Tuesday page, showing the
latest **SAP Security Patch Day** (monthly SAP Security Notes). Full feature
parity with Patch Tuesday — KPIs, filters, and PDF/PPTX/Excel exports — but for
the **current (latest) month only**, with **no CVE enrichment** (shows only what
SAP publishes).

## Motivation

SAP releases security notes on its monthly Patch Day (second Tuesday). The notes
are published as a public HTML table at a predictable monthly URL:

```
https://support.sap.com/en/my-support/knowledge-base/security-notes-news/{month}-{year}.html
```

There is no SAP API or feed. The platform already has a Patch Tuesday feature
(Microsoft CVRF); this brings the same treatment to SAP. "Every month pull from
there" is satisfied by computing the latest patch day on each request.

## Decisions (from brainstorming)

- **Parity:** full (KPIs, filters, exports) — same UX as Patch Tuesday.
- **History:** current month only. No month selector.
- **Enrichment:** none. Only SAP's own fields (note, title, CVE, CVSS, priority).

## Data source (de-risked)

A raw server-side fetch (browser UA) of the monthly page returns HTTP 200 with
the notes table in the **static HTML** — no JS wall. The table:

```
Note# | Title | Priority | CVSS
```

- **Note#** → `<a href="https://me.sap.com/notes/{id}">{id}</a>`
- **Title** → text, embeds one or more CVE links (`cve.org/CVERecord?id=CVE-...`).
  Some rows are re-releases: "Update to Security Note released on {month} Patch Day".
- **Priority** → Critical / High / Medium / Low (SAP's top tier on this page reads
  "Critical"; treat "Hot News" as an alias if it appears).
- **CVSS** → link to first.org calculator; the numeric score is the link text
  (e.g. `">9.9</a>`), the vector is in the href.

Patch day date comes from the intro text ("On 14th of July 2026, SAP security
patch day…"), with the computed second-Tuesday date as fallback.

## Architecture

Mirrors the Patch Tuesday structure (server scraper/normalizer → cached API →
front page + exports).

### 1. Server scraper — `server/sapPatch.js` (new)

Pure, unit-testable functions:

- `latestPatchMonth(now = new Date())` → `{ year, month, url }`. SAP patch day =
  2nd Tuesday. If `now` is on/after this month's patch day, use the current month;
  otherwise the previous month. Builds the monthly URL.
- `parseSapNotes(html)` → `{ releaseDate, notes }` where each note is
  `{ note, noteUrl, title, cves: string[], priority, cvss: number|null, cvssVector, isUpdate }`.
  Uses cheerio; locates the table by its `Note#/Title/Priority/CVSS` header row.
- `PRIORITY_RANK` map (Critical/Hot News > High > Medium > Low) for sorting/KPIs.
- `summarize(notes)` → `{ total, byPriority, maxCvss, cveCount }`.

Exports the pure functions; parsing has no network, so it is tested against a
saved HTML fixture (the July 2026 page).

### 2. API route — `server/index.js`

- `GET /api/sap-patch` → `{ releaseDate, month, notes, summary }`.
- Fetches `latestPatchMonth().url` via axios (browser UA, timeout, redirects).
  If it 404s (month not published yet), falls back one month.
- Cached in `memoryCache` like `patchTuesday` (~6–12h TTL); serves cache within TTL.
- Errors degrade gracefully (return cached if present, else a clear error).

### 3. Front service — `src/services/sapApi.ts` (new)

`fetchSapPatch(): Promise<SapPatchSummary>` calling `/api/sap-patch`, plus the
TypeScript types (`SapNote`, `SapPatchSummary`).

### 4. Front page — `src/pages/SapPatch.tsx` (new)

Mirrors `PatchTuesday.tsx`:

- **KPIs:** total notes, Critical/Hot News count, High count, max CVSS, CVE count.
- **Filters:** priority (ALL/Critical/High/Medium/Low), min CVSS threshold, search
  (note#, title, CVE). Client-side, with pagination.
- **Table:** Note# (→ me.sap.com), Title (with CVE → cve.org), Priority badge,
  CVSS. "Update" rows flagged. Sorted by priority rank then CVSS desc.
- **Exports:** PDF / PPTX / Excel via a new `src/utils/sapPatchExport.ts` mirroring
  `patchTuesdayExport.ts`.
- Route `/sap-patch`, nav entry in the **Intel** group next to Patch Tuesday, and
  a `src/config/seo.ts` entry.

### 5. Exports — `src/utils/sapPatchExport.ts` (new)

`exportSapPatchPDF/PPTX/Excel(summary)`, mirroring the Patch Tuesday export util
(same libraries, brand styling).

## Data flow

```
request → /api/sap-patch → (cache hit? serve)
                         → latestPatchMonth() → fetch monthly HTML (fallback -1 month on 404)
                         → parseSapNotes() → summarize() → cache → JSON
front page → fetchSapPatch() → KPIs + filtered/paginated table → export utils
```

## Error handling

- Fetch failure / 404 on current month → try previous month; if both fail, return
  last cached payload or a clear error object the page renders as an empty state.
- `parseSapNotes` tolerant of layout drift: skips malformed rows, never throws;
  returns whatever valid notes it finds. A note with no CVSS keeps `cvss: null`.
- Priority not in the known set → ranked lowest, shown verbatim.

## Testing

- **Unit** (`server/test/sapPatch.test.js`): `parseSapNotes` against the saved
  July 2026 fixture — asserts note count, a known note's fields (number, CVE,
  priority, CVSS), `isUpdate` detection, and `latestPatchMonth` boundary (before
  vs. on/after the 2nd Tuesday).
- **Smoke:** the `/api/sap-patch` route returns the expected shape (mockable
  fetch), mirroring existing server route tests.

## Out of scope (YAGNI)

- Month/history selector.
- CVE enrichment (EPSS/KEV/NVD).
- Separate affected-component column (component stays in the title).
- Scheduled cron: not needed — the latest patch day is computed per request and
  cached.
