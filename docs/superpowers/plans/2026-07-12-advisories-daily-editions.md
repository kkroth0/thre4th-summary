# Advisories Daily Editions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish one saved, AI-assisted `/advisories` Summ4ry for each completed calendar day in Recife, with historical navigation and a cleaner hybrid editorial feed.

**Architecture:** A focused `dailyEditions` module will own local-day boundaries, normalized events, narrative validation, OpenRouter fallback, persistence and generation deduplication. Express will supply source data, expose latest/date-specific editions and schedule generation; React will render the selected edition and filter its supporting events.

**Tech Stack:** Node.js ESM, Express 5, Axios, atomic JSON files, Node test runner, React 18, TypeScript, Vite, Tailwind and shadcn/ui.

## Global Constraints

- Calendar boundaries use `America/Recife` and cover `00:00:00` through the next local midnight.
- Use `openrouter/free` specifically for daily narratives.
- Save runtime history in `server/.daily-summaries.json`; deployment must preserve it.
- A deterministic fallback must produce a valid edition when OpenRouter fails.
- Saved editions are immutable and unique by `YYYY-MM-DD` date.
- Remove KPI cards, standalone ransomware, old critical highlights and manual analyses from `/advisories`.
- Keep the existing posts API, detail route, admin screen and RSS implementation intact.

---

### Task 1: Calendar-Day Event Model

**Files:**
- Create: `server/dailyEditions.js`
- Create: `server/test/dailyEditions.test.js`
- Modify: `server/dailyBrief.js`

**Interfaces:**
- Produces: `getCompletedDate(now): string`, `getDateWindow(date): { windowStart, windowEnd }`, `buildEditionEvents({ feed, victims, date }): DailySummaryEvent[]`, `buildDeterministicNarrative(events): DailyNarrative`.
- Consumes: normalized newsletter feed entries and ransomware victims already returned by `server/index.js`.

- [x] **Step 1: Write failing boundary and normalization tests**

```js
test('uses the previous completed Recife calendar day', () => {
  assert.equal(getCompletedDate(new Date('2026-07-13T02:59:59Z')), '2026-07-11');
  assert.equal(getCompletedDate(new Date('2026-07-13T03:00:00Z')), '2026-07-12');
  assert.deepEqual(getDateWindow('2026-07-12'), {
    windowStart: '2026-07-12T03:00:00.000Z',
    windowEnd: '2026-07-13T03:00:00.000Z',
  });
});

test('includes only events inside the selected Recife day', () => {
  const events = buildEditionEvents({ feed, victims, date: '2026-07-12' });
  assert.deepEqual(events.map((event) => event.title), ['inside advisory', 'inside victim']);
});
```

- [x] **Step 2: Run tests and confirm RED**

Run: `node --test server/test/dailyEditions.test.js`

Expected: FAIL because `server/dailyEditions.js` does not exist.

- [x] **Step 3: Implement calendar helpers and normalized event records**

Use `Intl.DateTimeFormat(..., { timeZone: 'America/Recife' })` for completed-date selection. Since Recife has a fixed UTC-03 offset, parse validated `YYYY-MM-DD` dates as `${date}T03:00:00.000Z` and derive the exclusive next-midnight endpoint. Give each event a SHA-256 ID, `priority` (`critical`, `high`, `context`) and `category` (`vulnerability`, `active-exploitation`, `ransomware`, `news`).

```js
export function getDateWindow(date) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new TypeError('invalid date');
  const start = new Date(`${date}T03:00:00.000Z`);
  if (Number.isNaN(start.getTime())) throw new TypeError('invalid date');
  const end = new Date(start.getTime() + 86_400_000);
  return { windowStart: start.toISOString(), windowEnd: end.toISOString() };
}
```

- [x] **Step 4: Add deterministic narrative coverage and implementation**

Test that an empty day produces a calm summary and that critical/KEV/ransomware facts produce only counts and IDs found in the events. Implement three to five summary strings and two to four attention topics with supporting `eventIds`.

- [x] **Step 5: Run the focused tests and commit**

Run: `node --test server/test/dailyEditions.test.js server/test/dailyBrief.test.js`

Expected: all tests pass. Update the old `dailyBrief` tests or retire only assertions tied to the replaced 36-hour endpoint; retain helper coverage used elsewhere.

```bash
git add server/dailyEditions.js server/test/dailyEditions.test.js server/dailyBrief.js server/test/dailyBrief.test.js
git commit -m "feat: model daily advisory editions"
```

### Task 2: AI Validation And Persistent Edition Store

**Files:**
- Modify: `server/dailyEditions.js`
- Modify: `server/test/dailyEditions.test.js`
- Modify: `server/.env.example`
- Modify: `.github/workflows/deploy-vps.yml`

**Interfaces:**
- Produces: `validateNarrative(value, events)`, `createEditionStore({ filePath, writeJsonAtomic })`, `createEditionGenerator({ store, requestNarrative, getSourceData, now })`.
- Store methods: `listDates(): string[]`, `get(date)`, `save(edition)`.
- Generator method: `generate(date): Promise<DailySummaryEdition>`.

- [x] **Step 1: Write failing narrative validation tests**

```js
test('rejects attention topics that cite unknown events', () => {
  assert.throws(
    () => validateNarrative({ title: 'Dia', summary: ['Fato'], attentionTopics: [{ title: 'Tema', assessment: 'Texto', eventIds: ['missing'] }] }, events),
    /unknown event/i,
  );
});
```

Also test field limits: title 140 characters, each summary 320, three to five summary entries, two to four topics for non-empty days, and event IDs limited to the supplied set. Empty days may return one summary and no topic.

- [x] **Step 2: Run validation tests and confirm RED**

Run: `node --test server/test/dailyEditions.test.js --test-name-pattern="narrative"`

Expected: FAIL because `validateNarrative` is missing.

- [x] **Step 3: Implement strict validation and OpenRouter request adapter contract**

The module accepts an injected `requestNarrative` so tests do not call the network. `server/index.js` will provide an Axios adapter in Task 3. Reject prose outside parsed JSON, unsupported IDs and identifiers such as `CVE-...` absent from the event corpus.

- [x] **Step 4: Write failing store and generator tests**

Cover sorted dates, immutable duplicate saves, reload from disk, one in-flight promise for concurrent requests, validated AI output and deterministic fallback after a thrown timeout.

```js
const [first, second] = await Promise.all([generator.generate('2026-07-12'), generator.generate('2026-07-12')]);
assert.equal(sourceCalls, 1);
assert.deepEqual(first, second);
assert.equal(store.get('2026-07-12').narrativeSource, 'openrouter');
```

- [x] **Step 5: Implement store and generator, then verify GREEN**

Load a JSON array defensively, write a date-sorted array atomically and return an existing edition before fetching source data. Fall back on any OpenRouter error or invalid narrative.

Run: `node --test server/test/dailyEditions.test.js`

Expected: all tests pass.

- [x] **Step 6: Preserve runtime storage and document configuration**

Add `.daily-summaries.json` to every VPS rsync exclusion alongside `.posts.json`. Add:

```dotenv
OPENROUTER_DAILY_MODEL=openrouter/free
```

- [x] **Step 7: Commit**

```bash
git add server/dailyEditions.js server/test/dailyEditions.test.js server/.env.example .github/workflows/deploy-vps.yml
git commit -m "feat: persist AI-assisted daily summaries"
```

### Task 3: Public API And Automatic Generation

**Files:**
- Modify: `server/index.js`
- Modify: `server/test/smoke.test.js`
- Modify: `server/test/dailyEditions.test.js`

**Interfaces:**
- Consumes: edition store/generator from Task 2.
- Produces: `GET /api/intel/daily-brief` and `GET /api/intel/daily-brief?date=YYYY-MM-DD` responses shaped as `{ edition, availableDates }`.

- [x] **Step 1: Write failing route behavior tests**

Extract or inject the date-selection behavior so tests prove: no query selects `getCompletedDate(now)`, a valid saved historical date returns without generation, malformed/future dates return `400`, and an unavailable past date returns `404`.

- [x] **Step 2: Run tests and confirm RED**

Run: `node --test server/test/dailyEditions.test.js server/test/smoke.test.js`

Expected: route/selection assertions fail against the current 36-hour response.

- [x] **Step 3: Add the OpenRouter daily adapter**

Use the existing base URL and headers, but pin:

```js
const OPENROUTER_DAILY_MODEL = process.env.OPENROUTER_DAILY_MODEL || 'openrouter/free';
```

Send `temperature: 0.1`, `response_format: { type: 'json_object' }`, a 30-second timeout and only compact event facts. Return parsed JSON; throw on missing content or parse errors so the generator invokes fallback.

- [x] **Step 4: Replace the endpoint and add scheduler**

Initialize the store at `server/.daily-summaries.json`. The latest request generates only the previous completed day when missing. Date queries read saved history only.

Add a scheduler that calculates milliseconds until the next Recife midnight plus five minutes, invokes generation for the completed date, logs failures and reschedules with a new `setTimeout`. Call it from `app.listen` after source-cache priming.

- [x] **Step 5: Verify API tests and syntax, then commit**

Run:

```bash
node --test server/test/dailyEditions.test.js server/test/smoke.test.js
node --check server/index.js
```

Expected: tests pass and syntax check exits 0.

```bash
git add server/index.js server/test/dailyEditions.test.js server/test/smoke.test.js
git commit -m "feat: serve and schedule daily summary editions"
```

### Task 4: Hybrid Editorial Interface

**Files:**
- Modify: `src/services/threatApi.ts`
- Modify: `src/pages/Advisories.tsx`

**Interfaces:**
- Consumes: `{ edition, availableDates }` API response from Task 3.
- Produces: `fetchDailyBrief(date?: string)` and the option-C page with date selection and event filters.

- [x] **Step 1: Replace frontend contracts**

Define `DailyNarrative`, `DailySummaryEvent`, `DailySummaryEdition` and `DailyBriefResponse`. Add an optional date query with `URLSearchParams`.

```ts
export const fetchDailyBrief = async (date?: string): Promise<DailyBriefResponse> => {
  const query = date ? `?${new URLSearchParams({ date })}` : '';
  const response = await fetch(`/api/intel/daily-brief${query}`);
  if (!response.ok) return intelError(response);
  return response.json();
};
```

- [x] **Step 2: Rebuild the page around option C**

Remove post fetching, `PostEditor`, KPI grid, standalone ransomware panel and old highlights. Render:

- Header with edition date, exact period and RSS action.
- `Em poucas linhas` with title and narrative bullets.
- `O que merece sua atencao` cards resolved through `eventIds`.
- `Todos os eventos` with select controls for priority, category and source.
- A saved-date select that refetches the selected edition.

Use stable full-width sections rather than nested cards. Preserve source links and compact mobile rows.

- [x] **Step 3: Handle loading, empty and error states**

Keep the date selector available after historical fetch errors. Empty days show `Nenhum evento relevante foi registrado nesta edicao.` The service error offers a retry button and makes no reference to manual posts.

- [x] **Step 4: Run frontend verification and commit**

Run:

```bash
npm run typecheck
npm run lint
npm run build
```

Expected: typecheck/build exit 0 and lint has no new errors.

```bash
git add src/services/threatApi.ts src/pages/Advisories.tsx
git commit -m "feat: organize advisories as daily editions"
```

### Task 5: End-To-End Verification And Deployment

**Files:**
- Modify: `docs/superpowers/plans/2026-07-12-advisories-daily-editions.md` (checkbox status only)

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified `main` deployment on Cloudflare Pages and VPS.

- [x] **Step 1: Run the complete local quality gate**

```bash
node --test server/test/*.test.js
node --check server/index.js
node --check server/dailyEditions.js
npm run typecheck
npm run lint
npm run build
git diff --check
```

Expected: tests/typecheck/build/syntax checks pass; lint has no errors or new warnings.

- [x] **Step 2: Inspect the final diff and runtime-file exclusions**

Run: `git status --short && git diff HEAD~4 --stat && rg -n "daily-summaries" .github/workflows/deploy-vps.yml server/.env.example`

Expected: only planned files changed and every VPS sync path preserves `.daily-summaries.json`.

- [ ] **Step 3: Commit checklist updates and push**

```bash
git add docs/superpowers/plans/2026-07-12-advisories-daily-editions.md
git commit -m "docs: complete daily editions rollout"
git push origin main
```

- [ ] **Step 4: Verify deployments and public route**

Confirm the Cloudflare Pages and VPS workflows for the pushed SHA succeed. Request `https://threatsumm4ry.app/advisories` and its API, confirming HTTP 200 and a 24-hour edition response. If deployment fails, inspect logs, fix, rerun all affected checks and push the corrective commit.
