# Hunt Service Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the Hunt Pack microservice, API, page, embedded Newsletter controls, and active operational references while preserving unrelated OpenRouter and IOC workflows.

**Architecture:** Delete the complete request path from React through Express to FastAPI. Keep shared URL validation and document export dependencies that other features use. Add backend and source-level regression tests so the removed route and product links cannot return unnoticed.

**Tech Stack:** React 18, TypeScript, Vite, Express 5, Node test runner, GitHub Actions.

## Global Constraints

- Preserve all unrelated working-tree changes, including concurrent edits in `server/index.js` and `server/.env.example`.
- Do not alter Daily Editions, advisory enrichment, feed jobs, deterministic IOC extraction, Attack Surface, or other OpenRouter consumers.
- Keep `assertSafePublicUrl`, `isPrivateAddress`, and `pptxgenjs` because other live features use them.
- Leave historical documents under `docs/superpowers/` unchanged.
- Direct requests to `POST /api/newsletter/hunt-pack` must return HTTP 404.
- Direct navigation to `/threat-hunting` must render the existing not-found view.
- Do not stage or commit user-owned changes outside each task's file list.

---

### Task 1: Add Removal Regression Tests

**Files:**
- Modify: `server/test/smoke.test.js`
- Create: `src/huntRemoval.test.ts`

**Interfaces:**
- Consumes: the real Express server booted by `server/test/smoke.test.js` and repository files read through `node:fs/promises`.
- Produces: regression coverage for the retired API, frontend route, page, Newsletter client, service directory, CI job, scripts, and operational documentation.

- [ ] **Step 1: Add the failing backend regression test**

Append this test after the existing unknown-route test in `server/test/smoke.test.js`:

```js
test('removed hunt-pack endpoint yields 404', async () => {
    const r = await fetch(`${BASE}/api/newsletter/hunt-pack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com/report', lang: 'en' }),
    });
    assert.equal(r.status, 404);
});
```

- [ ] **Step 2: Run the backend test and verify RED**

Run: `npm run test:server`

Expected: FAIL only for `removed hunt-pack endpoint yields 404`; the current premium route returns 401 before it can reach the proxy.

- [ ] **Step 3: Add the failing source-level regression tests**

Create `src/huntRemoval.test.ts`:

```ts
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("removes the Hunt Pack frontend and dedicated route", async () => {
  const liveSources = await Promise.all([
    "src/App.tsx",
    "src/components/Header.tsx",
    "src/components/PremiumRoute.tsx",
    "src/pages/Index.tsx",
    "src/pages/Features.tsx",
    "src/pages/Newsletter.tsx",
  ].map(read));

  for (const source of liveSources) {
    assert.doesNotMatch(source, /\/threat-hunting|hunt-pack|HuntPack|huntPacks|getHuntPack/);
  }
  await assert.rejects(access("src/pages/ThreatHunting.tsx"), { code: "ENOENT" });
});

test("removes the Hunt service runtime and operational configuration", async () => {
  const activeFiles = await Promise.all([
    "server/index.js",
    "server/.env.example",
    "package.json",
    ".github/workflows/ci.yml",
    "README.md",
    "DEPLOYMENT.md",
    "ENDPOINTS.txt",
    "PRODUCT_IDEA.txt",
    ".gitignore",
  ].map(read));

  for (const source of activeFiles) {
    assert.doesNotMatch(source, /hunt-service|hunt-pack|HUNT_SERVICE|ci:hunt|\/threat-hunting/i);
  }
  await assert.rejects(access("hunt-service"), { code: "ENOENT" });
});
```

- [ ] **Step 4: Run the source-level tests and verify RED**

Run:

```bash
rm -rf /tmp/threatsumm4ry-unit-tests
npm run test:unit
```

Expected: the two new tests FAIL because the route, page, service directory, and operational references still exist. Existing unit tests remain green.

- [ ] **Step 5: Commit only the failing tests**

```bash
git add server/test/smoke.test.js src/huntRemoval.test.ts
git diff --cached --check
git commit -m "test: cover hunt service removal"
```

---

### Task 2: Remove The Backend Proxy And Python Service

**Files:**
- Delete: `hunt-service/.env.example`
- Delete: `hunt-service/.gitignore`
- Delete: `hunt-service/Dockerfile`
- Delete: `hunt-service/README.md`
- Delete: `hunt-service/analyzer.py`
- Delete: `hunt-service/main.py`
- Delete: `hunt-service/requirements.txt`
- Delete: `hunt-service/scraper.py`
- Modify: `server/index.js`
- Modify: `server/.env.example`

**Interfaces:**
- Consumes: the standard Express unknown-API handler already used by other removed endpoints.
- Produces: HTTP 404 for `POST /api/newsletter/hunt-pack` and no deployable Python Hunt service.

- [ ] **Step 1: Remove the Hunt Pack memory cache**

Delete only this member from `memoryCache` in `server/index.js`:

```js
// Guided Threat Hunting packs (from the Python hunt-service), keyed by `${lang}|${url}`.
huntPack: {
    store: new Map(),
    ttl: 7 * 24 * 60 * 60 * 1000 // 7 days
},
```

Keep the preceding `newsletterEnrich` member and following `recentCves` member intact.

- [ ] **Step 2: Remove the Hunt Pack API route**

Delete the complete block that starts with:

```js
// Guided Threat Hunting: proxy to the Python hunt-service which scrapes the
```

and ends after the closing `});` for:

```js
app.post('/api/newsletter/hunt-pack', requirePremium, scanLimiter, async (req, res) => {
```

Keep `isPrivateAddress` and `assertSafePublicUrl`; `/api/feed/generate` calls the latter.

- [ ] **Step 3: Remove service environment variables without overwriting concurrent edits**

Delete this block from `server/.env.example` and preserve `RANSOMWARE_LIVE_API_KEY` or any other user additions:

```dotenv
# Guided Threat Hunting microservice (hunt-service/). Base URL of the Python
# FastAPI service (e.g. a Hugging Face Space) and the shared secret it expects.
HUNT_SERVICE_URL=
HUNT_SERVICE_SECRET=
```

- [ ] **Step 4: Delete the service directory**

Delete all tracked files listed for this task and any generated `hunt-service/__pycache__/` content. Do not alter Python or OpenRouter references outside the deleted service unless another task names the file.

- [ ] **Step 5: Run the backend test and verify GREEN**

Run: `npm run test:server`

Expected: all tests PASS, including `removed hunt-pack endpoint yields 404`.

- [ ] **Step 6: Check syntax and focused references**

Run:

```bash
node --check server/index.js
rg -n -i "hunt-service|hunt-pack|HUNT_SERVICE" server hunt-service || true
```

Expected: syntax check exits 0. `rg` prints no match and may report that `hunt-service` does not exist.

- [ ] **Step 7: Commit only backend and service removal files**

```bash
git add -u hunt-service server/index.js server/.env.example
git diff --cached --check
git commit -m "fix: remove hunt service backend"
```

Before committing, inspect `git diff --cached` and unstage any user-owned hunks from `server/index.js` or `server/.env.example`; stage only the removal hunks.

---

### Task 3: Remove Hunt Pack From The Frontend

**Files:**
- Delete: `src/pages/ThreatHunting.tsx`
- Modify: `src/App.tsx`
- Modify: `src/components/Header.tsx`
- Modify: `src/components/PremiumRoute.tsx`
- Modify: `src/pages/Index.tsx`
- Modify: `src/pages/Features.tsx`
- Modify: `src/pages/Newsletter.tsx`

**Interfaces:**
- Consumes: the existing `NotFound` wildcard route and current Newsletter enrichment/IOC components.
- Produces: no `/threat-hunting` route or link and no Hunt Pack controls in Newsletter.

- [ ] **Step 1: Delete the dedicated page and route**

Delete `src/pages/ThreatHunting.tsx`. In `src/App.tsx`, delete:

```tsx
const ThreatHunting = lazy(() => import("./pages/ThreatHunting"));
```

and:

```tsx
<Route path="/threat-hunting" element={<PremiumRoute feature="threat-hunting"><ThreatHunting /></PremiumRoute>} />
```

The existing `<Route path="*" element={<NotFound />} />` becomes the direct-navigation fallback.

- [ ] **Step 2: Remove navigation and premium feature metadata**

In `src/components/Header.tsx`, remove `Crosshair` from the icon imports and delete the complete `Hunting` navigation group whose only item points to `/threat-hunting`.

In `src/components/PremiumRoute.tsx`, change the union to:

```ts
type Feature = "threat-brief" | "advisory-feed" | "exposure-watchlist";
```

Delete only the `"threat-hunting"` member from `COPY`. Keep the `Crosshair` import and generic benefit row because that icon still appears in the premium-access explanation.

- [ ] **Step 3: Remove links from product pages**

In `src/pages/Index.tsx`, delete the complete tool entry with `href: "/threat-hunting"`. Remove `Radar` from that file's imports only if no remaining entry uses it.

In `src/pages/Features.tsx`, delete `ctaHunt` from both language objects and remove:

```tsx
<Link to="/threat-hunting"><Button variant="outline" className="h-9 rounded-md font-semibold text-xs">{t.ctaHunt}</Button></Link>
```

- [ ] **Step 4: Remove the Newsletter Hunt Pack client**

In `src/pages/Newsletter.tsx`:

- Delete `Crosshair` from the Lucide import; retain `Copy` and `Loader2` for existing IOC and enrichment controls.
- Delete `HuntIoc`, `HuntDetectionQuery`, and `HuntPackData`.
- Delete the `huntPacks` state and `getHuntPack` function.
- Delete the JSX block beginning with `{/* Guided Threat Hunting Pack (on-demand) */}` and ending at its matching wrapper expression.

Do not change `hasIocs`, `defang`, `iocRows`, `getEnrichment`, or the existing IOC copy/CSV JSX immediately before the removed block.

- [ ] **Step 5: Run the frontend removal test and verify GREEN**

Run:

```bash
npx esbuild src/huntRemoval.test.ts --bundle --platform=node --format=esm \
  --outfile=/tmp/threatsumm4ry-hunt-removal-test.js
node --test --test-name-pattern="removes the Hunt Pack frontend" \
  /tmp/threatsumm4ry-hunt-removal-test.js
```

Expected: `removes the Hunt Pack frontend and dedicated route` PASS. Node skips
the operational-removal test until Task 4.

- [ ] **Step 6: Run typecheck and lint on the changed frontend**

Run:

```bash
npm run typecheck
npx eslint src/App.tsx src/components/Header.tsx src/components/PremiumRoute.tsx src/pages/Index.tsx src/pages/Features.tsx src/pages/Newsletter.tsx src/huntRemoval.test.ts
```

Expected: both commands exit 0, with no unused imports introduced by the deletion.

- [ ] **Step 7: Commit only frontend removal files**

```bash
git add src/App.tsx src/components/Header.tsx src/components/PremiumRoute.tsx \
  src/pages/Index.tsx src/pages/Features.tsx src/pages/Newsletter.tsx
git add -u src/pages/ThreatHunting.tsx
git diff --cached --check
git commit -m "fix: remove hunt pack frontend"
```

---

### Task 4: Remove Active Operational And Product References

**Files:**
- Modify: `package.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `DEPLOYMENT.md`
- Modify: `ENDPOINTS.txt`
- Modify: `PRODUCT_IDEA.txt`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: the frontend and backend removal completed in Tasks 2 and 3.
- Produces: scripts, CI, documentation, and future-product notes that no longer claim the Hunt service exists.

- [ ] **Step 1: Remove build and CI integration**

Delete this script from `package.json`:

```json
"ci:hunt": "python3 -m py_compile hunt-service/*.py",
```

Delete the complete `hunt-service` job from `.github/workflows/ci.yml`, from:

```yaml
hunt-service:
```

through its final `run: python -m py_compile hunt-service/*.py` line.

- [ ] **Step 2: Update active documentation**

In `README.md`, remove the Hunt service from the product summary, Stack list,
Quality Gates, and CI flow diagram. Keep the remaining Node frontend/backend
commands and deployment model accurate.

In `DEPLOYMENT.md`, remove the Hunt service compile-check bullet.

In `ENDPOINTS.txt`, remove both:

```text
POST    /api/newsletter/hunt-pack            [rl]
/threat-hunting   *   Threat Hunting
```

In `.gitignore`, remove `hunt-service-env.txt` and its now-orphaned local-secret
comment only if the next entry has its own explanatory comment.

- [ ] **Step 3: Correct future-product statements**

In `PRODUCT_IDEA.txt`, remove claims that an existing `hunt-service` provides
Hunt Packs, remove the Python Hunt microservice from the current/proposed stack,
and remove `hunt-service` from the list of code to port. Keep the proposed HEARTH
library and general threat-hunting product direction intact.

- [ ] **Step 4: Run source-level tests and verify GREEN**

Run:

```bash
rm -rf /tmp/threatsumm4ry-unit-tests
npm run test:unit
```

Expected: all unit tests PASS, including both tests in `src/huntRemoval.test.ts`.

- [ ] **Step 5: Check active references**

Run:

```bash
rg -n -i "hunt-service|hunt-pack|HUNT_SERVICE|/threat-hunting" \
  src server package.json README.md DEPLOYMENT.md ENDPOINTS.txt \
  PRODUCT_IDEA.txt .github .gitignore || true
```

Expected: no matches. References under `docs/superpowers/` remain as historical records.

- [ ] **Step 6: Commit operational cleanup**

```bash
git add package.json .github/workflows/ci.yml README.md DEPLOYMENT.md \
  ENDPOINTS.txt PRODUCT_IDEA.txt .gitignore
git diff --cached --check
git commit -m "chore: remove hunt service integration"
```

---

### Task 5: Full Verification And Working-Tree Audit

**Files:**
- No production files added or modified.

**Interfaces:**
- Consumes: all removal tasks.
- Produces: verification evidence and a clean separation between our commits and the user's concurrent work.

- [ ] **Step 1: Run the complete local test set**

```bash
npm run test:unit
npm run test:brand
npm run test:server
npm run ci
node --check server/index.js
```

Expected: every command exits 0. Existing lint warnings may remain, but no new warning may come from a changed file.

- [ ] **Step 2: Verify dependency and product integrity**

```bash
npm ls pptxgenjs
rg -n "OPENROUTER_API_KEY|OPENROUTER_MODEL|OPENROUTER_DAILY_MODEL" server src
rg -n -i "hunt-service|hunt-pack|HUNT_SERVICE|/threat-hunting" \
  src server package.json README.md DEPLOYMENT.md ENDPOINTS.txt \
  PRODUCT_IDEA.txt .github .gitignore || true
```

Expected: `pptxgenjs` remains installed; unrelated OpenRouter consumers remain; no live Hunt integration reference appears.

- [ ] **Step 3: Audit final Git state**

```bash
git status --short --branch
git log -5 --oneline
git diff --check
```

Expected: Hunt removal files are committed. User-owned modifications remain visible and uncommitted unless the user committed them during execution.

- [ ] **Step 4: Report results**

Report deleted surfaces, test counts, verification commands, commit hashes, and any residual user-owned working-tree changes. Do not claim the remaining security-audit findings are fixed.
