# Actors Dense Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace only the threat-actor result cards with the approved dense table layout and show how many of the signed-in user's private hunts cover each actor.

**Architecture:** Keep the public actor catalog, filters, summary cards, and detail panel intact. Add technique IDs to the existing slim public actor response, fetch the already owner-scoped `/api/hunts` collection when available, and derive per-actor hunt counts in a pure frontend helper. Render the existing fields with installed shadcn `Table`, `Avatar`, `Badge`, and `Button` primitives.

**Tech Stack:** Node.js, Express, `node:test`, React 18, TypeScript, existing shadcn/Radix components, Tailwind CSS.

## Global Constraints

- Change only the actor list presentation and the minimum data needed by it; preserve the page header, statistics, filters, 440px detail panel, and public actor detail flow.
- Do not add a dependency, endpoint, service, store, or actor-image pipeline.
- Private hunts remain owner-scoped by the existing authenticated `/api/hunts` endpoint; the public actor endpoint must not contain private counts.
- Use only catalog fields that exist today. The table uses `motivation` instead of inventing unsupported sector data.
- Match the supplied Groups reference with dense bordered rows, avatar fallback, sortable numeric headers, and a right-aligned action.
- Keep PT/EN copy and avoid page-level horizontal overflow; secondary columns may hide on narrow screens.
- Keep the existing `MAX_RESULTS = 180` cap.

---

### Task 1: Expose actor techniques and derive private hunt coverage

**Files:**
- Create: `src/pages/actorsView.ts`
- Create: `src/pages/actorsView.test.ts`
- Modify: `server/index.js:3566-3579`
- Modify: `server/test/smoke.test.js`

**Interfaces:**
- Consumes: public actor technique objects `{ id: string }[]` and private hunts `{ id: string, techniques: string[] }[]`.
- Produces: slim actor field `techniques: string[]`, `actorHuntCoverage(actors, hunts): Record<string, number>`, and `sortActors(actors, mode, coverage): actors`.

- [ ] **Step 1: Add the failing API contract assertion**

Add a smoke test that fetches `/api/actors`, chooses an actor with `technique_count > 0`, and asserts that its new `techniques` array has the same length and contains ATT&CK IDs:

```js
test('actor list exposes slim technique ids for local correlation', async () => {
    const response = await fetch(`${BASE}/api/actors`);
    assert.equal(response.status, 200);
    const body = await response.json();
    const mapped = body.actors.find((actor) => actor.technique_count > 0);
    assert.ok(mapped);
    assert.equal(mapped.techniques.length, mapped.technique_count);
    assert.match(mapped.techniques[0], /^T\d{4}(?:\.\d{3})?$/);
});
```

- [ ] **Step 2: Run the smoke test and confirm RED**

Run: `node --test server/test/smoke.test.js`

Expected: FAIL because `mapped.techniques` is absent.

- [ ] **Step 3: Add only slim technique IDs to the actor list response**

In the existing `/api/actors` mapping, add:

```js
techniques: (a.techniques || []).map((technique) => technique.id).filter(Boolean),
```

Do not join with `huntsStore` and keep the existing public cache header.

- [ ] **Step 4: Rerun the smoke test and confirm GREEN**

Run: `node --test server/test/smoke.test.js`

Expected: all smoke tests pass.

- [ ] **Step 5: Add failing pure-helper tests**

Create `src/pages/actorsView.test.ts` with literal fixtures proving that one hunt matching two actor techniques counts once, account-local hunts count independently, and `hunts` sorting is descending with a stable name tie-break:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { actorHuntCoverage, sortActors } from "./actorsView.ts";

const actors = [
  { id: "alpha", name: "Alpha", country: "BR", technique_count: 2, techniques: ["T1059", "T1078"] },
  { id: "bravo", name: "Bravo", country: "US", technique_count: 1, techniques: ["T1566"] },
  { id: "charlie", name: "Charlie", country: "US", technique_count: 1, techniques: ["T1078"] },
];

test("counts each private hunt once per actor even when two techniques match", () => {
  assert.deepEqual(actorHuntCoverage(actors, [
    { id: "h1", techniques: ["T1059", "T1078"] },
    { id: "h2", techniques: ["T1078"] },
  ]), { alpha: 2, bravo: 0, charlie: 2 });
});

test("sorts hunt coverage descending and breaks ties by actor name", () => {
  assert.deepEqual(
    sortActors(actors, "hunts", { alpha: 2, bravo: 0, charlie: 2 }).map((actor) => actor.id),
    ["alpha", "charlie", "bravo"],
  );
});
```

- [ ] **Step 6: Run the helper test and confirm RED**

Run:

```bash
npx esbuild src/pages/actorsView.test.ts --bundle --platform=node --format=esm --outfile=/tmp/actorsView.test.js
node --test /tmp/actorsView.test.js
```

Expected: FAIL because `actorsView.ts` does not exist.

- [ ] **Step 7: Implement the minimum pure helpers**

Create generic actor/hunt shapes, build a `Map<string, Set<string>>` from technique ID to hunt IDs, and union those IDs per actor so one hunt is never counted twice. `sortActors` must return a copied array and preserve the current `name`, `country`, and `techniques` modes while adding `hunts`.

- [ ] **Step 8: Run focused and full checks**

Run: `npm run test:unit && node --test server/test/smoke.test.js && npm run typecheck`

Expected: all pass.

- [ ] **Step 9: Commit Task 1**

```bash
git add server/index.js server/test/smoke.test.js src/pages/actorsView.ts src/pages/actorsView.test.ts
git commit -m "feat: relacionar atores às hunts privadas"
```

### Task 2: Render the dense actor table

**Files:**
- Modify: `src/pages/Actors.tsx`

**Interfaces:**
- Consumes: `ActorListItem.techniques`, `fetchHunts()`, `actorHuntCoverage`, and `sortActors` from Task 1.
- Produces: dense actor table with columns Actor, Country, Motivation, TTPs, Hunts, Source, and Action while preserving selection and detail loading.

- [ ] **Step 1: Record the visual RED state**

Start the current app, open `/atores` at 1440px width, and capture the list. Confirm the current result cards lack table headers, avatar treatment, numeric hunt coverage, and a dedicated action column.

- [ ] **Step 2: Load private hunts without making the public page fail**

Call existing `fetchHunts()` beside the actor request with `Promise.allSettled`. Store `PrivateHunt[] | null`: fulfilled means coverage is available, while anonymous/non-premium failure remains `null` and renders an em dash. Never display a failed request as zero coverage.

- [ ] **Step 3: Reuse the pure sorting and coverage helpers**

Extend `ActorListItem` with `techniques: string[]`, add `"hunts"` to `SortMode`, compute coverage with `useMemo`, and replace the inline sorting comparator with `sortActors(matches, sortMode, coverage)`.

- [ ] **Step 4: Replace only `ActorRow` and the list wrapper**

Use the installed components from `@/components/ui/table` and `@/components/ui/avatar`. The actor cell contains an `AvatarFallback` plus name and truncated aliases; numeric TTP/Hunts headers select their sort mode; a small outline/ghost `Button` opens the existing detail panel. Use `data-state="selected"` on the active row.

Desktop columns:

```text
ATOR | PAÍS | MOTIVAÇÃO | TTPS | HUNTS | FONTE | AÇÃO
```

At widths below `lg`, hide Motivation and Source; below `sm`, also hide Country and Hunts. Keep TTPs and the action visible.

- [ ] **Step 5: Verify interaction and responsiveness**

At desktop and mobile widths, verify search, country/source filters, Name/Country/TTP/Hunts sorting, opening an actor, retrying detail load, and selected-row state. Confirm the table scroll container does not create page-level horizontal overflow.

- [ ] **Step 6: Compare screenshots**

Capture the latest desktop render and compare it with `/home/mandrade/Pictures/Screenshots/Screenshot From 2026-08-01 03-44-08.png` using `view_image`. Fix only table density, hierarchy, alignment, clipping, and responsive issues; do not redesign the rest of the page.

- [ ] **Step 7: Run all verification**

Run:

```bash
npm run lint
npm run typecheck
npm run test:unit
npm run test:server
npm run build
git diff --check
```

Expected: all commands pass with no new warnings or errors.

- [ ] **Step 8: Commit Task 2**

```bash
git add src/pages/Actors.tsx docs/superpowers/plans/2026-08-03-actors-dense-table.md
git commit -m "feat: apresentar atores em tabela operacional"
```
