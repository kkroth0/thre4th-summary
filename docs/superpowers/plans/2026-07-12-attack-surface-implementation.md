# Attack Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dedicated `/attack-surface` workflow that searches Shodan, optionally enriches with Censys, ranks exposed services, and optionally validates observed TCP ports.

**Architecture:** Add a focused backend module for Attack Surface query building, normalization, scoring, provider orchestration, and TCP validation. Keep `server/index.js` as the route wiring layer. Add typed frontend API helpers and a React page that renders a guided/advanced search form, summary metrics, filters, and findings table.

**Tech Stack:** Node.js ES modules, Express, axios, node:test, React 18, TypeScript, Vite, Tailwind, shadcn/ui, lucide-react.

## Global Constraints

- Branch: `feature/attack-surface`.
- Do not modify `/home/mandrade/Dev/THREAT SUMMARY/thre4th-summary`.
- Shodan is required for the feature.
- Censys is optional and must fail soft.
- Active TCP validation is disabled by default and must be UI-controlled.
- Active TCP validation only attempts provider-observed public IPv4/port pairs.
- Active TCP validation does not scan arbitrary ports.
- Result limit maximum is 100.
- No new runtime dependency is required for the MVP.
- Use TDD for isolated backend logic.

---

## File Structure

- Create `server/attackSurface.js`
  - Owns request validation, Shodan query construction, risk scoring, provider response normalization, Censys enrichment merge, active TCP validation, and scan orchestration.
- Create `server/attackSurface.test.js`
  - Uses Node's built-in test runner for pure logic and dependency-injected orchestration tests.
- Modify `server/index.js`
  - Imports `runAttackSurfaceScan` and wires `POST /api/attack-surface` under `scanLimiter`.
- Modify `src/services/threatApi.ts`
  - Adds Attack Surface types and `fetchAttackSurface`.
- Create `src/pages/AttackSurface.tsx`
  - Renders the full page workflow.
- Modify `src/App.tsx`
  - Adds lazy route `/attack-surface`.
- Modify `src/components/Header.tsx`
  - Adds sidebar/mobile navigation item under `Analysis`.

---

### Task 1: Backend Logic Tests

**Files:**
- Create: `server/attackSurface.test.js`
- Create later in Task 2: `server/attackSurface.js`

**Interfaces:**
- Consumes: none.
- Produces test expectations for:
  - `buildAttackSurfaceQuery(input)`
  - `assessExposureRisk(service)`
  - `normalizeShodanHost(host, options)`
  - `isPublicIPv4(ip)`
  - `runAttackSurfaceScan(input, deps)`

- [ ] **Step 1: Write the failing test**

Add `server/attackSurface.test.js` with tests that import the functions that do not exist yet:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assessExposureRisk,
  buildAttackSurfaceQuery,
  isPublicIPv4,
  normalizeShodanHost,
  runAttackSurfaceScan,
} from './attackSurface.js';

test('buildAttackSurfaceQuery maps guided CIDR to Shodan net query', () => {
  assert.deepEqual(
    buildAttackSurfaceQuery({
      mode: 'guided',
      targetType: 'cidr',
      target: '203.0.113.0/24',
      limit: 250,
      activeValidation: false,
    }),
    {
      kind: 'search',
      query: 'net:"203.0.113.0/24"',
      limit: 100,
    },
  );
});

test('buildAttackSurfaceQuery maps guided IP to host lookup', () => {
  assert.deepEqual(
    buildAttackSurfaceQuery({
      mode: 'guided',
      targetType: 'ip',
      target: '8.8.8.8',
      limit: 10,
      activeValidation: false,
    }),
    {
      kind: 'host',
      ip: '8.8.8.8',
      limit: 10,
    },
  );
});

test('buildAttackSurfaceQuery validates advanced Shodan query', () => {
  assert.deepEqual(
    buildAttackSurfaceQuery({
      mode: 'advanced',
      advancedQuery: 'org:"Example" port:3389',
      limit: 20,
      activeValidation: true,
    }),
    {
      kind: 'search',
      query: 'org:"Example" port:3389',
      limit: 20,
    },
  );
});

test('assessExposureRisk marks CVEs and critical remote ports as critical', () => {
  assert.deepEqual(
    assessExposureRisk({ port: 3389, transport: 'tcp', cves: [], tags: [], product: 'RDP' }).risk,
    'critical',
  );
  const cveRisk = assessExposureRisk({ port: 443, transport: 'tcp', cves: ['CVE-2024-1234'], tags: [], product: 'nginx' });
  assert.equal(cveRisk.risk, 'critical');
  assert.match(cveRisk.riskReasons.join(' '), /CVE-2024-1234/);
});

test('assessExposureRisk detects admin-like web services as high', () => {
  const result = assessExposureRisk({
    port: 8443,
    transport: 'tcp',
    cves: [],
    tags: ['dashboard'],
    product: 'router management',
    httpTitle: 'Admin Login',
  });
  assert.equal(result.risk, 'high');
  assert.ok(result.riskReasons.some((reason) => reason.includes('Admin-like')));
});

test('isPublicIPv4 rejects private and reserved addresses', () => {
  assert.equal(isPublicIPv4('8.8.8.8'), true);
  assert.equal(isPublicIPv4('10.0.0.1'), false);
  assert.equal(isPublicIPv4('172.16.0.1'), false);
  assert.equal(isPublicIPv4('192.168.1.10'), false);
  assert.equal(isPublicIPv4('127.0.0.1'), false);
  assert.equal(isPublicIPv4('169.254.1.1'), false);
});

test('normalizeShodanHost returns one finding per exposed service', () => {
  const findings = normalizeShodanHost({
    ip_str: '8.8.8.8',
    org: 'Google LLC',
    asn: 'AS15169',
    country_name: 'United States',
    city: 'Mountain View',
    hostnames: ['dns.google'],
    data: [
      {
        ip_str: '8.8.8.8',
        port: 53,
        transport: 'udp',
        product: 'DNS',
        timestamp: '2026-07-12T10:00:00.000000',
        data: 'dns banner',
      },
      {
        ip_str: '8.8.8.8',
        port: 443,
        transport: 'tcp',
        product: 'Google Frontend',
        ssl: { cert: { subject: { CN: 'dns.google' } } },
        vulns: { 'CVE-2025-0001': {} },
      },
    ],
  });

  assert.equal(findings.length, 2);
  assert.equal(findings[0].ip, '8.8.8.8');
  assert.equal(findings[0].validation.status, 'not_requested');
  assert.equal(findings[1].risk, 'critical');
  assert.deepEqual(findings[1].cves, ['CVE-2025-0001']);
});

test('runAttackSurfaceScan uses Shodan search and fail-soft Censys enrichment', async () => {
  const calls = [];
  const axiosClient = {
    async get(url, options) {
      calls.push({ url, options });
      if (url.includes('/shodan/host/search')) {
        return {
          data: {
            total: 1,
            matches: [
              {
                ip_str: '8.8.8.8',
                port: 3389,
                transport: 'tcp',
                org: 'Example Org',
                data: 'rdp banner',
                timestamp: '2026-07-12T10:00:00.000000',
              },
            ],
          },
        };
      }
      throw new Error('censys unavailable');
    },
  };

  const result = await runAttackSurfaceScan(
    {
      mode: 'advanced',
      advancedQuery: 'org:"Example"',
      limit: 1,
      activeValidation: false,
    },
    {
      axiosClient,
      shodanApiKey: 'shodan-key',
      censysApiKey: 'censys-key',
      tcpConnect: async () => ({ status: 'open', detail: 'unused' }),
    },
  );

  assert.equal(result.summary.totalAssets, 1);
  assert.equal(result.summary.totalServices, 1);
  assert.equal(result.findings[0].risk, 'critical');
  assert.equal(result.warnings.length, 1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
node --test server/attackSurface.test.js
```

Expected: FAIL with `Cannot find module './attackSurface.js'` or missing exported functions.

---

### Task 2: Backend Logic Implementation

**Files:**
- Create: `server/attackSurface.js`
- Test: `server/attackSurface.test.js`

**Interfaces:**
- Produces:
  - `buildAttackSurfaceQuery(input: object): { kind: 'host', ip: string, limit: number } | { kind: 'search', query: string, limit: number }`
  - `assessExposureRisk(service: object): { risk: 'critical' | 'high' | 'medium' | 'low', riskScore: number, riskReasons: string[] }`
  - `isPublicIPv4(ip: string): boolean`
  - `normalizeShodanHost(host: object, options?: object): AttackSurfaceFinding[]`
  - `runAttackSurfaceScan(input: object, deps: object): Promise<AttackSurfaceResponse>`

- [ ] **Step 1: Implement minimal backend logic**

Create `server/attackSurface.js` with request validation, risk scoring, normalization, provider orchestration, and TCP validation. Use Node's `net` module only; do not add dependencies.

- [ ] **Step 2: Run test to verify it passes**

Run:

```bash
node --test server/attackSurface.test.js
```

Expected: PASS.

- [ ] **Step 3: Refactor while green**

Refactor only if the file has duplicated provider parsing or risk reason logic.

- [ ] **Step 4: Run backend logic tests again**

Run:

```bash
node --test server/attackSurface.test.js
```

Expected: PASS.

---

### Task 3: Express Endpoint Wiring

**Files:**
- Modify: `server/index.js`
- Test: `server/attackSurface.test.js`

**Interfaces:**
- Consumes: `runAttackSurfaceScan(input, deps)` from `server/attackSurface.js`.
- Produces: `POST /api/attack-surface`.

- [ ] **Step 1: Import backend helper**

Modify the imports near the top of `server/index.js`:

```js
import { runAttackSurfaceScan } from './attackSurface.js';
```

- [ ] **Step 2: Add route before vendor status**

Add this route before `GET /api/vendors/status`:

```js
app.post('/api/attack-surface', scanLimiter, async (req, res) => {
    try {
        const result = await runAttackSurfaceScan(req.body, {
            axiosClient: axios,
            shodanApiKey: process.env.SHODAN_API_KEY,
            censysApiKey: process.env.CENSYS_API_KEY,
        });
        res.json(result);
    } catch (error) {
        const status = error.status || 500;
        res.status(status).json({ error: error.publicMessage || error.message || 'Internal server error' });
    }
});
```

- [ ] **Step 3: Check syntax**

Run:

```bash
node --check server/index.js
node --check server/attackSurface.js
```

Expected: both commands exit 0.

---

### Task 4: Frontend API Types

**Files:**
- Modify: `src/services/threatApi.ts`

**Interfaces:**
- Produces:
  - `AttackSurfaceInput`
  - `AttackSurfaceFinding`
  - `AttackSurfaceResponse`
  - `fetchAttackSurface(input)`

- [ ] **Step 1: Add TypeScript interfaces**

Add the Attack Surface interfaces near the existing exported service types in `src/services/threatApi.ts`.

- [ ] **Step 2: Add fetch helper**

Add:

```ts
export const fetchAttackSurface = async (input: AttackSurfaceInput): Promise<AttackSurfaceResponse> => {
    const response = await fetch('/api/attack-surface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Attack Surface API error: ${response.status} ${response.statusText} - ${text}`);
    }
    return response.json();
};
```

---

### Task 5: Attack Surface Page

**Files:**
- Create: `src/pages/AttackSurface.tsx`

**Interfaces:**
- Consumes: `fetchAttackSurface`, `AttackSurfaceFinding`, `AttackSurfaceResponse`.
- Produces: default React page component for route `/attack-surface`.

- [ ] **Step 1: Create page**

Create a page with guided/advanced tabs, target type select, limit input, active validation checkbox, safety `Alert`, submit button, metric cards, risk/text filters, and findings table.

- [ ] **Step 2: Keep expensive derived values memoized**

Use `useMemo` for filtered findings and metric derivations from the response.

- [ ] **Step 3: Avoid new dependencies**

Use existing shadcn components already present in `src/components/ui`.

---

### Task 6: Route and Navigation

**Files:**
- Modify: `src/App.tsx`
- Modify: `src/components/Header.tsx`

**Interfaces:**
- Consumes: default export from `src/pages/AttackSurface.tsx`.
- Produces: reachable `/attack-surface` route and sidebar item.

- [ ] **Step 1: Add lazy route**

In `src/App.tsx`, add:

```tsx
const AttackSurface = lazy(() => import("./pages/AttackSurface"));
```

And add:

```tsx
<Route path="/attack-surface" element={<AttackSurface />} />
```

- [ ] **Step 2: Add navigation item**

In the `Analysis` group in `src/components/Header.tsx`, add an item:

```tsx
{
  path: "/attack-surface",
  label: "Attack Surface",
  description: pt ? "Shodan, Censys e validacao TCP controlada." : "Shodan, Censys and controlled TCP validation.",
  icon: Radar,
}
```

Import `Radar` from `lucide-react`.

---

### Task 7: Verification

**Files:**
- All changed implementation files.

**Interfaces:**
- Consumes: all prior task outputs.
- Produces: verified implementation commit.

- [ ] **Step 1: Run backend tests**

Run:

```bash
node --test server/attackSurface.test.js
```

Expected: PASS.

- [ ] **Step 2: Run syntax checks**

Run:

```bash
node --check server/index.js
node --check server/attackSurface.js
```

Expected: PASS.

- [ ] **Step 3: Run frontend checks**

Run:

```bash
npm run typecheck
npm run lint
npm run build
```

Expected: PASS or only pre-existing unrelated lint issues documented with file paths.

- [ ] **Step 4: Commit implementation**

Run:

```bash
git status --short
git add server/attackSurface.js server/attackSurface.test.js server/index.js src/services/threatApi.ts src/pages/AttackSurface.tsx src/App.tsx src/components/Header.tsx
git commit -m "feat: add attack surface workflow"
```

Expected: commit created on `feature/attack-surface`.

---

## Self-Review

- Spec coverage: route, hybrid input, Shodan required, Censys fail-soft, TCP UI control, public-IP/observed-port safety, risk scoring, table UI, and verification all map to tasks above.
- Placeholder scan: no placeholder tokens are intentionally left for implementers.
- Type consistency: backend and frontend both use `AttackSurfaceInput`, `AttackSurfaceFinding`, and `AttackSurfaceResponse`; route is consistently `/api/attack-surface` and page route is `/attack-surface`.
