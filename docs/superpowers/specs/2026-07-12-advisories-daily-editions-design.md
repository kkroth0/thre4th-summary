# Advisories Daily Editions Design

Date: 2026-07-12
Branch: `main`

## Goal

Turn `/advisories` into a daily security publication. Each edition summarizes
one completed calendar day, uses AI to explain the important changes, preserves
the supporting events and remains available in a date-based history.

## Scope

This delivery will:

- Replace the moving 36-hour window with the previous calendar day from
  `00:00:00` through `23:59:59` in `America/Recife`.
- Generate one edition shortly after midnight.
- Ask OpenRouter for a structured Portuguese synthesis.
- Save each edition and expose a history by date.
- Reorganize `/advisories` around the approved hybrid editorial layout.
- Remove the KPI counters, standalone ransomware section, old critical
  highlights block and manual published-analysis section from this page.

The existing manual post API, admin tooling, post detail route and RSS behavior
remain in the codebase. This change only removes manual posts from the
`/advisories` listing.

## Daily Window

Each edition has a `date` in `YYYY-MM-DD` format and covers that date in the
`America/Recife` timezone. A request made on July 13 generates the July 12
edition. The server converts the local boundaries to instants before filtering
advisories and ransomware events.

An edition does not change after the server saves it. Late source updates enter
the next relevant edition only if their source timestamp falls in that next
window. Administrative regeneration is outside this delivery.

## Generation Flow

1. Shortly after local midnight, the server determines the previous date.
2. It fetches and normalizes advisory and ransomware sources.
3. It filters events to the closed 24-hour window.
4. It builds a compact fact set with titles, sources, timestamps, severity,
   scores, KEV status, CVEs and ransomware metadata.
5. It sends that fact set to `openrouter/free` with a strict JSON response
   contract.
6. It validates the response against the supplied facts and size limits.
7. It saves the edition to `.daily-summaries.json` using an atomic write.

The first request for a missing edition runs the same flow. This recovery path
covers process restarts or a missed timer without generating a second edition.
Concurrent requests share one in-flight generation promise.

## AI Contract

The model returns:

```ts
interface DailyNarrative {
  title: string;
  summary: string[];
  attentionTopics: Array<{
    title: string;
    assessment: string;
    eventIds: string[];
    recommendedAction?: string;
  }>;
}
```

The prompt asks for three to five factual summary points and two to four
attention topics. It prohibits unsupported numbers, CVEs, organizations and
claims. The model may mention ransomware only when the source events make it a
meaningful theme for that day.

The server rejects unknown event IDs and factual identifiers absent from the
input. It also enforces field counts and text length. It never exposes the
OpenRouter key to the browser.

Use `openrouter/free` for this feature, independent of the model configured for
other OpenRouter features. One successful generation per day has no inference
cost under the current free-router pricing and stays below the free request
limit. Availability can vary, so the product cannot depend on it exclusively.

## Fallback

If OpenRouter is missing, times out or returns invalid data, the server creates
a deterministic narrative from the same facts. The edition records
`narrativeSource: "openrouter" | "deterministic"` for diagnostics, but the
public interface does not present an error banner for a valid fallback edition.

The fallback remains concise and derives every count and identifier directly
from normalized events. A generation failure must not leave `/advisories`
without the previous day's edition.

## Persistence And API

Store editions in `server/.daily-summaries.json`, following the atomic JSON
storage pattern already used by the server. Deployment excludes this runtime
file so new releases preserve history.

Each record contains:

```ts
interface DailySummaryEdition {
  date: string;
  timezone: "America/Recife";
  windowStart: string;
  windowEnd: string;
  generatedAt: string;
  narrativeSource: "openrouter" | "deterministic";
  narrative: DailyNarrative;
  events: DailySummaryEvent[];
  sources: string[];
}
```

Public API:

- `GET /api/intel/daily-brief` returns the latest completed edition and a list
  of available dates for backward compatibility with the current frontend.
- `GET /api/intel/daily-brief?date=YYYY-MM-DD` returns a saved edition.
- Invalid or future dates return `400`; unavailable historical dates return
  `404` and do not trigger arbitrary backfills.

The server keeps saved editions without an automatic retention limit. The
expected JSON growth is small because each date stores only normalized display
fields, not full source documents.

## Page Layout

The approved layout is the hybrid editorial option C.

### Header

Show `Summ4ry diario`, the edition date, exact 24-hour period and a date selector
for saved editions. The latest completed date opens by default.

### In A Few Lines

Show the AI title and three to five summary points. This block answers what
changed, why it matters and what an analyst should do next.

### What Needs Attention

Render two to four thematic sections from `attentionTopics`. Each section links
to its supporting events and may show one recommended action. This replaces the
old `Destaques criticos` list. It consolidates related events instead of
repeating the feed.

### All Events

Rename `Feed organizado` to `Todos os eventos`. Provide compact filters for:

- Priority: critical, high and context.
- Category: vulnerability, active exploitation, ransomware and news.
- Source.

Sort matching events by operational priority and then timestamp. Each row shows
its category, severity or KEV status, source, time, title and CVEs when present.
Source links open in a new tab.

Ransomware remains an event category and can appear in an attention topic. The
page will not show a standalone ransomware panel because the product already
has a dedicated ransomware view.

### Removed From The Page

- KPI cards for advisories, critical, KEV, CVEs, ransomware and LATAM.
- `Ransomware nas ultimas 36h`.
- The current `Destaques criticos` implementation.
- `Analises publicadas`, its empty state and the new-publication button.

## Loading And Error States

The page shows a stable loading state while it requests an edition. A missing
historical date shows an inline message and retains the date selector. An empty
day still has a saved edition with a calm deterministic or AI narrative and an
empty events state.

If the latest edition request fails completely, show a compact service error
with a retry command. Do not refer users to manual analyses that no longer
appear on this page.

## Scheduling

Start an in-process timer when the server boots. It calculates the next local
midnight, adds a short delay for source publication, generates the previous
edition and schedules the next run. The on-demand recovery path remains the
source of reliability because VPS restarts can interrupt timers.

No GitHub Actions schedule or external worker is required for this delivery.

## Testing

Backend tests cover:

- Local-day boundaries and UTC conversion for `America/Recife`.
- Exclusion of events immediately outside the selected day.
- One stored edition per date and atomic persistence behavior.
- Deduplication of concurrent generation.
- Valid OpenRouter responses.
- Rejection of unsupported event IDs and malformed JSON.
- Deterministic fallback after timeout or invalid output.
- Latest and date-specific API behavior.

Frontend verification covers:

- Latest edition and historical date selection.
- Attention topics linked to supporting events.
- Priority, category and source filters.
- Empty, loading and error states.
- Desktop and mobile layout with long titles.

Run unit tests, type checking, lint and production build before deployment.

## Acceptance Criteria

- `/advisories` defaults to the previous completed calendar day in Recife.
- The server saves one immutable edition per date.
- OpenRouter generates the narrative when available; deterministic fallback
  keeps the page operational.
- Users can open saved daily editions by date.
- The page follows option C and contains no KPI strip, standalone ransomware
  panel or manual analyses section.
- Attention topics cite supporting events and the complete feed remains
  filterable.
- Runtime history survives application deployments.
- Tests, type checking, lint and build pass before the change reaches the site.

## Out Of Scope

- Editing or regenerating a published edition from the admin interface.
- Migrating the JSON history to a database.
- Email or push delivery of each Summ4ry.
- Generating missing editions for arbitrary old dates.
