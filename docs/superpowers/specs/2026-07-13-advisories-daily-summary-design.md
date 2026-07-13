# Advisories Daily Summary Design

Date: 2026-07-13
Branch: `main`
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Turn `/advisories` into a public "Summ4ry das ultimas 36h": a hybrid page with
an executive summary at the top and an organized feed of the relevant security
items from the same window below it.

The page should help an analyst understand what happened recently without
opening the full advisory feed first. It should surface the main signals,
metrics, critical items, and ransomware activity, then provide the full list of
items grouped by operational priority.

## Non-Goals

- Do not build a calendar-day report. The approved window is the last 36 hours.
- Do not add a new data pipeline or worker.
- Do not require login for the daily summary.
- Do not remove manual advisory posts or admin publishing.
- Do not add LLM-generated prose in this change. Use deterministic summary
  bullets from the existing normalized feed data.

## Current State

The page already loads two public data sources:

- `fetchDailyBrief()` calls `GET /api/intel/daily-brief`.
- `fetchPosts()` loads manual advisory posts.

The backend endpoint already aggregates RSS advisories, CISA KEV, FIRST EPSS,
and ransomware.live. It filters recent advisory items with a 36-hour moving
window and returns KPIs, top highlights, and ransomware victims.

The frontend currently presents this as "Boletim & Advisories" with a daily
brief block and a posts section. The copy and information architecture still
read as a mix of daily signal and blog posts instead of a daily summary product.

## User Workflow

1. User opens `/advisories`.
2. The page loads the 36-hour daily brief and manual posts in parallel.
3. User sees an executive summary titled around the 36-hour window.
4. User scans the verdict, KPIs, and deterministic bullets.
5. User reviews critical highlights and ransomware activity.
6. User scrolls to the organized feed, grouped by operational priority.
7. User can open source links for any feed item.
8. User can still read manual posts lower on the page.
9. Admin users can still create or edit manual posts.

## Backend Design

Keep `GET /api/intel/daily-brief` as the data source.

Extend its response in a backwards-compatible way:

- Add `windowHours: 36`.
- Add `executiveSummary: string[]`.
- Add `feedGroups`, an array of grouped feed items.

The endpoint should continue returning the existing fields:

- `generatedAt`
- `title`
- `verdict`
- `summary`
- `highlights`
- `ransomware`
- `sources`

### Executive Summary Rules

Generate 3 to 5 concise bullets from deterministic conditions:

- If KEV items exist, mention the count and that known-exploited CVEs need
  priority.
- If critical advisories exist, mention the count.
- If ransomware victims exist, mention the count and top group when available.
- If LATAM victims exist, mention the count.
- If no strong signal exists, say that no high-priority signal dominated the
  36-hour window.

### Feed Groups

Group recent items into these sections:

- `kev`: Known exploited or exploitation signal.
- `critical`: Critical advisories not already in `kev`.
- `ransomware`: Ransomware context. Start with ransomware victims from
  ransomware.live, then include relevant feed items if they exist.
- `other`: Remaining relevant items from the 36-hour window.

Each feed group should include:

```ts
interface DailyBriefFeedGroup {
  key: "kev" | "critical" | "ransomware" | "other";
  title: string;
  description: string;
  items: DailyBriefFeedItem[];
}
```

Feed items should use a stable shape:

```ts
interface DailyBriefFeedItem {
  id: string;
  kind: "advisory" | "ransomware";
  title: string;
  link?: string;
  source: string;
  pubDate?: string;
  score?: number;
  severity?: string;
  cves: string[];
  kev?: boolean;
  reasons: string[];
  group?: string;
  countryName?: string;
  sector?: string;
}
```

Use deterministic IDs from source fields, such as link plus source for advisory
items and victim name plus discovered date for ransomware items.

## Frontend Design

Keep the route and page component:

- Route: `/advisories`
- Component: `src/pages/Advisories.tsx`

Change the page structure:

- Header copy: "Summ4ry das ultimas 36h".
- Subtitle: explain that the page summarizes advisories, active exploitation,
  ransomware, CVEs, and relevant security news from the last 36 hours.
- Top brief block:
  - Verdict badge.
  - Generated timestamp or 36-hour window label.
  - Executive summary bullets.
  - KPI grid.
- Critical highlights:
  - Keep the top scored items visible.
  - Show source, severity, score, CVEs, and KEV marker.
- Ransomware:
  - Keep recent victims visible.
  - Include group and country data.
- Organized feed:
  - Render `feedGroups`.
  - Each group has title, description, count, and compact item rows.
  - Items link to original source when available.
- Manual posts:
  - Rename section to "Analises publicadas" in Portuguese.
  - Keep it below the automated summary.
  - Keep admin `PostEditor` behavior.

## Error Handling

- If `fetchDailyBrief()` fails but posts load, show posts and a muted warning
  about the temporary brief failure.
- If daily brief loads but has no highlights or feed items, show an empty state
  that says no strong signal was found in the last 36 hours.
- If posts fail, keep the daily summary visible and show the existing toast.

## Testing

Run the existing quality gates that fit this change:

- `npm run typecheck`
- `npm run build`
- `node --check server/index.js`
- `node --check server/ctiIntel.js`

Add focused test coverage only if the backend grouping logic becomes complex
enough to extract into a helper. Otherwise, keep the change scoped and verify
the endpoint shape manually through local build/typecheck.

## Acceptance Criteria

- `/advisories` clearly reads as a summary of the last 36 hours.
- The top of the page provides a verdict, KPIs, and 3 to 5 executive bullets.
- The page includes an organized feed with KEV, critical, ransomware, and other
  groups.
- Manual posts remain available below the automated summary.
- The daily summary remains public.
- Existing advisory post routes and RSS behavior continue to work.
