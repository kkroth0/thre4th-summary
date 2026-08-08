# Shodan Batch Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Process every supported Shodan target from a TXT/JSON import, paginate results without an application cap, and show remaining query credits in Attack Surface.

**Architecture:** Keep TXT/JSON parsing in `attackSurfaceImport.ts`. The Attack Surface page executes imported targets sequentially, requesting Shodan's fixed 100-item pages and merging deduplicated findings in memory. The backend keeps the Shodan key private, adds a sanitized credit endpoint, and exposes the requested page to the existing scanner.

**Tech Stack:** React, TypeScript, Vite, Node.js, Express, Axios, `node:test`.

## Global Constraints

- Do not add a dependency, worker, queue, or persistent job system.
- No application-defined import or total-result maximum; 100 is only Shodan's page size.
- Never expose `SHODAN_API_KEY` or raw Shodan account data to the browser.
- Preserve opt-in active TCP validation and its public-IP/observed-port safeguards.
- Stop paid pagination clearly when Shodan denies credits or rate limits; retain already collected results.

---

### Task 1: Parse every import target, including URLs

**Files:**
- Modify: `src/utils/attackSurfaceImport.ts`
- Modify: `src/utils/attackSurfaceImport.test.ts`

**Interfaces:**
- Produces: `parseAttackSurfaceTargets(text): AttackSurfaceImportResult`
- Produces: `AttackSurfaceImportedTarget` with `kind`, `value`, and `label`

- [ ] **Step 1: Write the failing parser test**

~~~
test("parses a URL as its hostname and keeps more than 100 targets", () => {
  const ips = Array.from({ length: 101 }, (_, index) =>
    "1.1." + Math.floor(index / 256) + "." + (index % 256),
  );
  const result = parseAttackSurfaceTargets(["https://Example.COM/a", ...ips].join("\n"));

  assert.deepEqual(
    [result.targets[0]?.kind, result.targets[0]?.value],
    ["domain", "example.com"],
  );
  assert.equal(result.targets.length, 102);
});
~~~

- [ ] **Step 2: Run the test to verify it fails**

Run:

~~~bash
npm run test:unit -- src/utils/attackSurfaceImport.test.ts
~~~

Expected: the URL is ignored because `classify()` only receives raw tokens.

- [ ] **Step 3: Implement the minimal URL normalization**

Add a helper that returns `new URL(raw).hostname` for `http:` and `https:`
inputs; invalid URLs and other protocols fall through to the existing classifier.
Call it from the shared collector before `classify()`, so TXT and JSON share
the behavior.

- [ ] **Step 4: Re-run the focused parser test**

Run:

~~~bash
npm run test:unit -- src/utils/attackSurfaceImport.test.ts
~~~

Expected: PASS.

- [ ] **Step 5: Commit the parser change**

~~~bash
git add src/utils/attackSurfaceImport.ts src/utils/attackSurfaceImport.test.ts
git commit -m "feat: parse Shodan batch URLs"
~~~

### Task 2: Page Shodan scans and expose sanitized credit status

**Files:**
- Modify: `server/attackSurface.js`
- Modify: `server/test/attackSurface.test.js`
- Modify: `server/index.js`

**Interfaces:**
- Produces: `runAttackSurfaceScan({ ..., page?: number }, deps)`; search calls
  include `page` and host lookups retain all returned services.
- Produces: `getShodanCreditStatus(deps): Promise<{ plan: string | null, queryCredits: number | null }>`.
- Produces: `GET /api/attack-surface/credits` with only that status shape.

- [ ] **Step 1: Write failing server tests**

~~~js
test('runAttackSurfaceScan requests the selected Shodan search page', async () => {
  const calls = [];
  await runAttackSurfaceScan({ mode: 'advanced', advancedQuery: 'apache', limit: 100, page: 3 }, {
    shodanApiKey: 'key',
    axiosClient: { get: async (url, options) => {
      calls.push({ url, options });
      return { data: { total: 0, matches: [] } };
    } },
  });
  assert.equal(calls[0].options.params.page, 3);
});

test('getShodanCreditStatus returns only plan and query credits', async () => {
  const result = await getShodanCreditStatus({
    shodanApiKey: 'key',
    axiosClient: { get: async () => ({
      data: { plan: 'member', query_credits: 99, scan_credits: 1, key: 'secret' },
    }) },
  });
  assert.deepEqual(result, { plan: 'member', queryCredits: 99 });
});
~~~

Also add a host fixture with 101 services and assert `findings.length === 101`;
this guards against reintroducing the old post-normalization `slice` cap.

- [ ] **Step 2: Run the focused server test and verify it fails**

Run:

~~~bash
node --test server/test/attackSurface.test.js
~~~

Expected: `page` is absent, `getShodanCreditStatus` is not exported, and host
findings remain capped.

- [ ] **Step 3: Implement the minimal backend behavior**

In `server/attackSurface.js`:

- validate `input.page` as a positive integer, defaulting to `1`;
- include `page` only on `/shodan/host/search` requests;
- remove the final `findings.slice(0, queryPlan.limit)` so host lookups retain
  every provider-observed service;
- export `getShodanCreditStatus`, call `/api-info` with the server key, and
  return only a cleaned plan and finite non-negative query-credit number.

In `server/index.js`, add `GET /api/attack-surface/credits` next to the scan
route. Pass Axios and the server-held Shodan key into the helper; return the
helper result and route errors through the existing public-error handling.

- [ ] **Step 4: Re-run server tests**

Run:

~~~bash
node --test server/test/attackSurface.test.js
~~~

Expected: PASS.

- [ ] **Step 5: Commit the backend change**

~~~bash
git add server/attackSurface.js server/test/attackSurface.test.js server/index.js
git commit -m "feat: page Shodan batch scans"
~~~

### Task 3: Merge paged results deterministically on the client

**Files:**
- Create: `src/utils/attackSurfaceBatch.ts`
- Create: `src/utils/attackSurfaceBatch.test.ts`

**Interfaces:**
- Consumes: `AttackSurfaceResponse` and `AttackSurfaceFinding` from
  `src/services/threatApi.ts`.
- Produces: `mergeAttackSurfaceResponses(responses: AttackSurfaceResponse[]): AttackSurfaceResponse | null`.

- [ ] **Step 1: Write a failing merge test**

~~~ts
test('merges pages, deduplicates a service, and rebuilds summary totals', () => {
  const result = mergeAttackSurfaceResponses([pageOne, pageTwo]);
  assert.equal(result?.findings.length, 3);
  assert.equal(result?.summary.totalAssets, 2);
  assert.equal(result?.summary.totalServices, 3);
  assert.equal(result?.summary.byRisk.critical, 1);
});
~~~

Make `pageOne` and `pageTwo` each contain the same `ip:port/transport`
once. Give them different risk levels and an explicit `activeValidation` value
so the test proves the function rebuilds display totals from final findings.

- [ ] **Step 2: Run it and verify it fails**

Run:

~~~bash
npm run test:unit -- src/utils/attackSurfaceBatch.test.ts
~~~

Expected: module/function missing.

- [ ] **Step 3: Implement the pure merger**

Deduplicate by `${ip}:${port}/${transport}`. Sort only by the existing risk
order and risk score, reassign stable IDs, union warnings, count unique IPs, and
reconstruct every `AttackSurfaceSummary` field from merged findings. Use the
last response for timestamp and validation flag; use `Batch: <response count>
requests` for the query and sum provider totals.

- [ ] **Step 4: Re-run the merge test**

Run:

~~~bash
npm run test:unit -- src/utils/attackSurfaceBatch.test.ts
~~~

Expected: PASS.

- [ ] **Step 5: Commit the merger**

~~~bash
git add src/utils/attackSurfaceBatch.ts src/utils/attackSurfaceBatch.test.ts
git commit -m "feat: merge Shodan batch results"
~~~

### Task 4: Run imported targets sequentially and display credits/progress

**Files:**
- Modify: `src/services/threatApi.ts`
- Modify: `src/pages/AttackSurface.tsx`

**Interfaces:**
- Produces: `fetchAttackSurfaceCredits(): Promise<{ plan: string | null, queryCredits: number | null }>`.
- Consumes: `mergeAttackSurfaceResponses()` and imported targets.

- [ ] **Step 1: Add the API helper**

Add a `ShodanCreditStatus` interface and this helper next to
`fetchAttackSurface`:

~~~ts
export const fetchAttackSurfaceCredits = async (): Promise<ShodanCreditStatus> => {
  const response = await fetch('/api/attack-surface/credits');
  if (!response.ok) throw new Error('Unable to load Shodan credits');
  return response.json();
};
~~~

Extend `AttackSurfaceInput` with optional `page?: number`.

- [ ] **Step 2: Replace the single-target submit path**

In `AttackSurface.tsx`, remove the user-facing `limit` state/control and stop
truncating the import preview. Build one input for every imported target; when
no file was imported, build one input from the guided or advanced controls.

For each input, call `fetchAttackSurface` with `limit: 100` and increasing
`page` values while `page * 100 < response.summary.totalObserved`. Append
each response to an array, call `mergeAttackSurfaceResponses(responses)` after
every page, and update result and progress text.

Before the first request and after each completed target, call
`fetchAttackSurfaceCredits()` and show `queryCredits` and plan. A
credit/rate-limit error stops later pages and targets, keeps the result, and
adds a warning. Other per-target failures add a warning and continue with the
next target. Keep opt-in validation and its authorization copy.

- [ ] **Step 3: Do a focused type check**

Run:

~~~bash
npm run typecheck
~~~

Expected: PASS.

- [ ] **Step 4: Manually verify the screen**

Run:

~~~bash
npm run dev
~~~

Check a TXT/JSON import with more than ten targets, progress updates, the credit
indicator, a manual single target, and an exhausted-credit error. Stop the dev
server afterward.

- [ ] **Step 5: Commit the page**

~~~bash
git add src/services/threatApi.ts src/pages/AttackSurface.tsx
git commit -m "feat: run Shodan imports in batches"
~~~

### Task 5: Verify the integrated feature

**Files:**
- Verify only.

- [ ] **Step 1: Run all automated checks**

~~~bash
npm run test:unit
npm run test:server
npm run lint
npm run typecheck
npm run build
~~~

Expected: all commands exit with status 0.

- [ ] **Step 2: Inspect the final change**

~~~bash
git diff --check HEAD~4..HEAD
git status --short
~~~

Expected: no whitespace errors and no uncommitted implementation files.

- [ ] **Step 3: Commit a verification-only repair, if needed**

If a verification command requires a code fix, write its focused failing test
first, rerun it red, make the smallest repair, rerun it green, then commit the
repair with the affected files.

