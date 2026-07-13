# Exposure Watchlist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a premium Exposure Watchlist that saves manually entered external assets, runs manual and daily Attack Surface snapshots, and shows in-app changes between snapshots.

**Architecture:** Add a focused backend module for asset validation, JSON persistence, snapshot execution, diffing, retention, and due-schedule selection. Wire premium Express routes and a single-process scheduler in `server/index.js`, then add typed frontend API helpers and a compact `/exposure-watchlist` React page that reuses the existing Attack Surface contract.

**Tech Stack:** Node.js ES modules, Express 5, axios, node:test, React 18, TypeScript, Vite, Tailwind, shadcn/ui, lucide-react.

## Global Constraints

- Asset registration is manual in v1.
- Daily automatic snapshots are included.
- Manual "run snapshot now" is included.
- Active TCP validation is configurable per asset.
- Alerts are in-app only.
- Shodan remains the primary source through the existing Attack Surface logic.
- Censys enrichment remains optional and fail-soft.
- Do not add automatic subdomain, CIDR, ASN, or company discovery in v1.
- Do not add email, Slack, Discord, webhook, or SIEM notifications in v1.
- Do not scan arbitrary ports. TCP validation stays limited to provider-observed public IPv4 and port pairs.
- Do not build a new microservice.
- Do not migrate persistence to a database in v1.
- Maximum 25 assets per user.
- Maximum scan limit 100 per asset.
- Keep the latest 14 snapshots per asset.
- All watchlist endpoints require premium access.
- Production delivery remains the existing push-to-main CI/CD flow; after verification, merge to `main`, push, monitor deploy, and validate the site.

---

## File Structure

- Create `server/exposureWatchlist.js`
  - Owns asset validation, target-to-Attack-Surface conversion, persistence helpers, snapshot summaries, diff generation, retention, due asset selection, and snapshot orchestration.
- Create `server/test/exposureWatchlist.test.js`
  - Hermetic `node:test` coverage for validation, conversion, diffing, retention, and due scheduling.
- Modify `server/index.js`
  - Imports the watchlist helpers, creates JSON store paths, resolves BYOK/server keys, wires premium routes, and starts the daily scheduler inside `app.listen`.
- Modify `src/services/threatApi.ts`
  - Adds Exposure Watchlist types and API helpers.
- Create `src/pages/ExposureWatchlist.tsx`
  - Renders watchlist assets, create/edit form, changes feed, snapshot history, and run-now actions.
- Modify `src/App.tsx`
  - Adds lazy route `/exposure-watchlist` behind `PremiumRoute`.
- Modify `src/components/Header.tsx`
  - Adds navigation item near Attack Surface.
- Modify `ENDPOINTS.txt`
  - Documents the new premium endpoints.
- Modify this plan file as tasks complete.

---

### Task 1: Pure Watchlist Logic

**Files:**
- Create: `server/exposureWatchlist.js`
- Create: `server/test/exposureWatchlist.test.js`

**Interfaces:**
- Consumes: Attack Surface input shape from `server/attackSurface.js`.
- Produces:
  - `WATCHLIST_LIMITS`
  - `RISK_ORDER`
  - `normalizeExposureAssetInput(input, existingAsset?, now?, owner?)`
  - `assetToAttackSurfaceInput(asset)`
  - `summarizeFindings(findings)`
  - `diffSnapshots({ assetId, snapshotId, previous, current, detectedAt })`
  - `selectDueAssets(assets, now)`
  - `applySnapshotRetention(snapshots, assetId)`

- [x] **Step 1: Write failing tests for validation, conversion, summary, diff, due selection, and retention**

Create `server/test/exposureWatchlist.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  WATCHLIST_LIMITS,
  applySnapshotRetention,
  assetToAttackSurfaceInput,
  diffSnapshots,
  normalizeExposureAssetInput,
  selectDueAssets,
  summarizeFindings,
} from '../exposureWatchlist.js';

const owner = { sub: 'user-1', login: 'analyst' };
const now = '2026-07-13T12:00:00.000Z';

const baseFinding = (overrides = {}) => ({
  id: 'finding-1',
  ip: '8.8.8.8',
  port: 443,
  transport: 'tcp',
  risk: 'low',
  riskScore: 25,
  riskReasons: ['Standard web service exposed'],
  service: 'https',
  product: 'nginx',
  version: '1.24',
  organization: 'Example',
  asn: 'AS15169',
  hostnames: ['example.com'],
  country: 'US',
  city: 'Mountain View',
  source: { shodan: true, censys: false },
  observedAt: now,
  cves: [],
  tags: [],
  bannerSnippet: 'nginx',
  validation: { attempted: false, status: 'not_requested', detail: null },
  ...overrides,
});

test('normalizeExposureAssetInput validates and normalizes a domain asset', () => {
  const asset = normalizeExposureAssetInput({
    label: ' Main Web ',
    type: 'domain',
    value: 'Example.COM',
    limit: 250,
    activeValidation: true,
    scheduleEnabled: true,
  }, null, now, owner);

  assert.equal(asset.ownerId, 'user-1');
  assert.equal(asset.ownerLogin, 'analyst');
  assert.equal(asset.label, 'Main Web');
  assert.equal(asset.type, 'domain');
  assert.equal(asset.value, 'example.com');
  assert.equal(asset.limit, 100);
  assert.equal(asset.activeValidation, true);
  assert.equal(asset.scheduleEnabled, true);
  assert.equal(asset.lastStatus, 'never_run');
});

test('normalizeExposureAssetInput normalizes ASN values', () => {
  const asset = normalizeExposureAssetInput({
    label: 'ASN',
    type: 'asn',
    value: '15169',
    limit: 10,
    activeValidation: false,
    scheduleEnabled: false,
  }, null, now, owner);

  assert.equal(asset.value, 'AS15169');
});

test('normalizeExposureAssetInput rejects unsupported asset types', () => {
  assert.throws(
    () => normalizeExposureAssetInput({ label: 'Bad', type: 'company', value: 'Example' }, null, now, owner),
    /Invalid asset type/,
  );
});

test('assetToAttackSurfaceInput maps supported assets to Attack Surface inputs', () => {
  assert.deepEqual(
    assetToAttackSurfaceInput({ type: 'cidr', value: '8.8.8.0/24', limit: 30, activeValidation: false }),
    { mode: 'guided', targetType: 'cidr', target: '8.8.8.0/24', limit: 30, activeValidation: false },
  );
  assert.deepEqual(
    assetToAttackSurfaceInput({ type: 'asn', value: 'AS15169', limit: 30, activeValidation: true }),
    { mode: 'advanced', advancedQuery: 'asn:"AS15169"', limit: 30, activeValidation: true },
  );
  assert.deepEqual(
    assetToAttackSurfaceInput({ type: 'shodan_query', value: 'org:"Example"', limit: 20, activeValidation: false }),
    { mode: 'advanced', advancedQuery: 'org:"Example"', limit: 20, activeValidation: false },
  );
});

test('summarizeFindings returns service and risk counts', () => {
  const summary = summarizeFindings([
    baseFinding({ ip: '8.8.8.8', port: 443, risk: 'low' }),
    baseFinding({ ip: '1.1.1.1', port: 3389, risk: 'critical', validation: { attempted: true, status: 'open', detail: null } }),
  ]);

  assert.equal(summary.totalAssets, 2);
  assert.equal(summary.totalServices, 2);
  assert.equal(summary.criticalHighFindings, 1);
  assert.equal(summary.activelyConfirmedOpen, 1);
  assert.equal(summary.byRisk.critical, 1);
  assert.equal(summary.byRisk.low, 1);
  assert.equal(summary.highestRisk, 'critical');
});

test('diffSnapshots creates informational baseline changes on first snapshot', () => {
  const changes = diffSnapshots({
    assetId: 'asset-1',
    snapshotId: 'snap-1',
    previous: null,
    current: [baseFinding()],
    detectedAt: now,
  });

  assert.equal(changes.length, 1);
  assert.equal(changes[0].type, 'baseline_created');
  assert.equal(changes[0].severity, 'info');
});

test('diffSnapshots detects service, CVE, risk, banner and validation changes', () => {
  const previous = [
    baseFinding({ ip: '8.8.8.8', port: 443, risk: 'low', cves: [], bannerSnippet: 'nginx 1.24', validation: { attempted: true, status: 'open', detail: null } }),
    baseFinding({ ip: '8.8.4.4', port: 22, risk: 'high', cves: [], bannerSnippet: 'OpenSSH', validation: { attempted: false, status: 'not_requested', detail: null } }),
  ];
  const current = [
    baseFinding({ ip: '8.8.8.8', port: 443, risk: 'critical', cves: ['CVE-2026-0001'], bannerSnippet: 'nginx 1.25', validation: { attempted: true, status: 'closed', detail: null } }),
    baseFinding({ ip: '1.1.1.1', port: 3389, risk: 'critical', cves: [], bannerSnippet: 'rdp', validation: { attempted: true, status: 'open', detail: null } }),
  ];

  const changes = diffSnapshots({ assetId: 'asset-1', snapshotId: 'snap-2', previous, current, detectedAt: now });
  const types = changes.map((change) => change.type);

  assert.ok(types.includes('service_added'));
  assert.ok(types.includes('service_removed'));
  assert.ok(types.includes('cve_added'));
  assert.ok(types.includes('risk_increased'));
  assert.ok(types.includes('banner_changed'));
  assert.ok(types.includes('validation_changed'));
});

test('selectDueAssets returns scheduled assets older than 24 hours and skips running assets', () => {
  const assets = [
    { id: 'never', ownerId: 'u1', scheduleEnabled: true, lastRunAt: null, lastStatus: 'never_run' },
    { id: 'old', ownerId: 'u1', scheduleEnabled: true, lastRunAt: '2026-07-12T11:00:00.000Z', lastStatus: 'success' },
    { id: 'fresh', ownerId: 'u1', scheduleEnabled: true, lastRunAt: '2026-07-13T11:00:00.000Z', lastStatus: 'success' },
    { id: 'disabled', ownerId: 'u1', scheduleEnabled: false, lastRunAt: null, lastStatus: 'never_run' },
    { id: 'running', ownerId: 'u1', scheduleEnabled: true, lastRunAt: '2026-07-12T11:00:00.000Z', lastStatus: 'running' },
  ];

  assert.deepEqual(selectDueAssets(assets, new Date(now)).map((asset) => asset.id), ['never', 'old']);
});

test('applySnapshotRetention keeps latest snapshots for an asset', () => {
  const snapshots = Array.from({ length: WATCHLIST_LIMITS.snapshotsPerAsset + 3 }, (_, index) => ({
    id: `snap-${index}`,
    assetId: 'asset-1',
    ownerId: 'user-1',
    startedAt: new Date(Date.UTC(2026, 6, 1, index)).toISOString(),
  }));

  const retained = applySnapshotRetention(snapshots, 'asset-1');
  assert.equal(retained.length, WATCHLIST_LIMITS.snapshotsPerAsset);
  assert.equal(retained[0].id, 'snap-16');
  assert.equal(retained.at(-1).id, 'snap-3');
});
```

- [x] **Step 2: Run tests to verify failure**

Run:

```bash
node --test server/test/exposureWatchlist.test.js
```

Expected: FAIL with `Cannot find module '../exposureWatchlist.js'`.

- [x] **Step 3: Implement pure logic**

Create `server/exposureWatchlist.js` with these exports and behavior:

```js
import crypto from 'crypto';
import net from 'net';

export const WATCHLIST_LIMITS = {
  assetsPerUser: 25,
  scanLimit: 100,
  labelLength: 80,
  valueLength: 512,
  snapshotsPerAsset: 14,
};

export const RISK_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
const VALID_TYPES = new Set(['domain', 'ip', 'cidr', 'asn', 'shodan_query']);
const CONTROL_CHARS = /[\x00-\x1F\x7F]/;
const SAFE_DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SAFE_CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

export const createExposureError = (status, publicMessage) => {
  const error = new Error(publicMessage);
  error.status = status;
  error.publicMessage = publicMessage;
  return error;
};

const cleanText = (value, max) => String(value || '').replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const newId = (prefix) => `${prefix}_${crypto.randomBytes(8).toString('hex')}`;
const riskRank = (risk) => RISK_ORDER[risk] || 0;

const isValidIPv4 = (ip) => net.isIP(ip) === 4 && ip.split('.').every((octet) => {
  const n = Number(octet);
  return Number.isInteger(n) && n >= 0 && n <= 255;
});

const normalizeValue = (type, raw) => {
  const value = cleanText(raw, WATCHLIST_LIMITS.valueLength);
  if (!value) throw createExposureError(400, 'Asset value is required');
  if (CONTROL_CHARS.test(String(raw || ''))) throw createExposureError(400, 'Asset value contains invalid characters');
  if (String(raw || '').trim().length > WATCHLIST_LIMITS.valueLength) throw createExposureError(400, 'Asset value is too long');

  if (type === 'domain') {
    const domain = value.toLowerCase();
    if (!SAFE_DOMAIN_REGEX.test(domain)) throw createExposureError(400, 'Invalid domain format');
    return domain;
  }
  if (type === 'ip') {
    if (!isValidIPv4(value)) throw createExposureError(400, 'Invalid IP format');
    return value;
  }
  if (type === 'cidr') {
    if (!SAFE_CIDR_REGEX.test(value)) throw createExposureError(400, 'Invalid CIDR format');
    const [ip, maskValue] = value.split('/');
    const mask = Number(maskValue);
    if (!isValidIPv4(ip) || !Number.isInteger(mask) || mask < 0 || mask > 32) throw createExposureError(400, 'Invalid CIDR format');
    return value;
  }
  if (type === 'asn') {
    const digits = value.toUpperCase().replace(/^AS/, '');
    if (!/^\d{1,10}$/.test(digits)) throw createExposureError(400, 'Invalid ASN format');
    return `AS${digits}`;
  }
  return value;
};

export function normalizeExposureAssetInput(input = {}, existingAsset = null, now = new Date().toISOString(), owner = {}) {
  const type = cleanText(input.type || existingAsset?.type, 32);
  if (!VALID_TYPES.has(type)) throw createExposureError(400, 'Invalid asset type');
  const label = cleanText(input.label ?? existingAsset?.label, WATCHLIST_LIMITS.labelLength);
  if (!label) throw createExposureError(400, 'Asset label is required');
  const value = normalizeValue(type, input.value ?? existingAsset?.value);
  const limit = Math.min(Math.max(Number.parseInt(input.limit ?? existingAsset?.limit ?? 50, 10) || 50, 1), WATCHLIST_LIMITS.scanLimit);

  return {
    id: existingAsset?.id || newId('asset'),
    ownerId: existingAsset?.ownerId || owner.sub,
    ownerLogin: existingAsset?.ownerLogin || owner.login,
    label,
    type,
    value,
    limit,
    activeValidation: Boolean(input.activeValidation ?? existingAsset?.activeValidation),
    scheduleEnabled: Boolean(input.scheduleEnabled ?? existingAsset?.scheduleEnabled),
    createdAt: existingAsset?.createdAt || now,
    updatedAt: now,
    lastRunAt: existingAsset?.lastRunAt || null,
    lastStatus: existingAsset?.lastStatus || 'never_run',
    lastError: existingAsset?.lastError || null,
    lastSnapshotId: existingAsset?.lastSnapshotId || null,
    lastRisk: existingAsset?.lastRisk || null,
    lastSummary: existingAsset?.lastSummary || null,
  };
}

export function assetToAttackSurfaceInput(asset) {
  if (asset.type === 'shodan_query') return { mode: 'advanced', advancedQuery: asset.value, limit: asset.limit, activeValidation: asset.activeValidation };
  if (asset.type === 'asn') return { mode: 'advanced', advancedQuery: `asn:"${asset.value}"`, limit: asset.limit, activeValidation: asset.activeValidation };
  return { mode: 'guided', targetType: asset.type, target: asset.value, limit: asset.limit, activeValidation: asset.activeValidation };
}

export function summarizeFindings(findings = []) {
  const byRisk = { critical: 0, high: 0, medium: 0, low: 0 };
  const assets = new Set();
  let activelyConfirmedOpen = 0;
  for (const finding of findings) {
    if (finding.ip) assets.add(finding.ip);
    if (byRisk[finding.risk] !== undefined) byRisk[finding.risk] += 1;
    if (finding.validation?.status === 'open') activelyConfirmedOpen += 1;
  }
  const highestRisk = ['critical', 'high', 'medium', 'low'].find((risk) => byRisk[risk] > 0) || null;
  return {
    totalAssets: assets.size,
    totalServices: findings.length,
    criticalHighFindings: byRisk.critical + byRisk.high,
    activelyConfirmedOpen,
    byRisk,
    highestRisk,
  };
}

const serviceKey = (finding) => `${finding.ip}:${String(finding.transport || 'tcp').toLowerCase()}/${Number(finding.port)}`;
const serviceLabel = (finding) => `${finding.ip}:${finding.port}/${finding.transport || 'tcp'}`;
const comparableBanner = (finding) => [finding.service, finding.product, finding.version, finding.bannerSnippet].map((v) => v || '').join('|');

function change({ assetId, snapshotId, detectedAt, type, severity, finding, previous, current, title, description }) {
  return {
    id: newId('chg'),
    assetId,
    snapshotId,
    detectedAt,
    severity,
    type,
    title,
    description,
    ip: finding?.ip || null,
    port: finding?.port || null,
    transport: finding?.transport || null,
    previous,
    current,
  };
}

export function diffSnapshots({ assetId, snapshotId, previous, current, detectedAt = new Date().toISOString() }) {
  if (!previous) {
    return current.length
      ? [change({ assetId, snapshotId, detectedAt, type: 'baseline_created', severity: 'info', finding: null, previous: null, current: { services: current.length }, title: 'Baseline snapshot created', description: `${current.length} exposed services captured as the initial baseline.` })]
      : [];
  }

  const changes = [];
  const prevMap = new Map(previous.map((finding) => [serviceKey(finding), finding]));
  const currMap = new Map(current.map((finding) => [serviceKey(finding), finding]));

  for (const [key, curr] of currMap) {
    const prev = prevMap.get(key);
    if (!prev) {
      const severity = curr.risk === 'critical' ? 'critical' : curr.risk === 'high' ? 'high' : curr.risk === 'medium' ? 'medium' : 'info';
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'service_added', severity, finding: curr, previous: null, current: curr, title: 'Service added', description: `${serviceLabel(curr)} appeared with ${curr.risk} risk.` }));
      continue;
    }

    for (const cve of (curr.cves || []).filter((id) => !(prev.cves || []).includes(id))) {
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'cve_added', severity: 'critical', finding: curr, previous: prev.cves || [], current: curr.cves || [], title: 'CVE added', description: `${cve} appeared on ${serviceLabel(curr)}.` }));
    }
    for (const cve of (prev.cves || []).filter((id) => !(curr.cves || []).includes(id))) {
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'cve_removed', severity: 'low', finding: curr, previous: prev.cves || [], current: curr.cves || [], title: 'CVE removed', description: `${cve} no longer appears on ${serviceLabel(curr)}.` }));
    }
    if (riskRank(curr.risk) > riskRank(prev.risk)) {
      const severity = curr.risk === 'critical' ? 'critical' : curr.risk === 'high' ? 'high' : 'medium';
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'risk_increased', severity, finding: curr, previous: prev.risk, current: curr.risk, title: 'Risk increased', description: `${serviceLabel(curr)} changed from ${prev.risk} to ${curr.risk}.` }));
    }
    if (riskRank(curr.risk) < riskRank(prev.risk)) {
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'risk_decreased', severity: 'low', finding: curr, previous: prev.risk, current: curr.risk, title: 'Risk decreased', description: `${serviceLabel(curr)} changed from ${prev.risk} to ${curr.risk}.` }));
    }
    if (comparableBanner(curr) !== comparableBanner(prev)) {
      const severity = riskRank(curr.risk) >= riskRank('high') ? 'medium' : 'info';
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'banner_changed', severity, finding: curr, previous: comparableBanner(prev), current: comparableBanner(curr), title: 'Banner changed', description: `${serviceLabel(curr)} service metadata changed.` }));
    }
    if ((curr.validation?.status || 'not_requested') !== (prev.validation?.status || 'not_requested')) {
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'validation_changed', severity: 'info', finding: curr, previous: prev.validation?.status || 'not_requested', current: curr.validation?.status || 'not_requested', title: 'Validation changed', description: `${serviceLabel(curr)} validation changed from ${prev.validation?.status || 'not_requested'} to ${curr.validation?.status || 'not_requested'}.` }));
    }
  }

  for (const [key, prev] of prevMap) {
    if (!currMap.has(key)) {
      changes.push(change({ assetId, snapshotId, detectedAt, type: 'service_removed', severity: 'low', finding: prev, previous: prev, current: null, title: 'Service removed', description: `${serviceLabel(prev)} is no longer observed.` }));
    }
  }

  return changes;
}

export function selectDueAssets(assets = [], now = new Date()) {
  const cutoff = now.getTime() - 24 * 60 * 60 * 1000;
  return assets.filter((asset) => {
    if (!asset.scheduleEnabled || asset.lastStatus === 'running') return false;
    if (!asset.lastRunAt) return true;
    const last = new Date(asset.lastRunAt).getTime();
    return Number.isFinite(last) && last <= cutoff;
  });
}

export function applySnapshotRetention(snapshots = [], assetId) {
  const target = snapshots
    .filter((snapshot) => snapshot.assetId === assetId)
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, WATCHLIST_LIMITS.snapshotsPerAsset);
  const keepIds = new Set(target.map((snapshot) => snapshot.id));
  return snapshots
    .filter((snapshot) => snapshot.assetId !== assetId || keepIds.has(snapshot.id))
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
}
```

- [x] **Step 4: Run tests to verify pure logic passes**

Run:

```bash
node --test server/test/exposureWatchlist.test.js
```

Expected: PASS for all Task 1 tests.

- [x] **Step 5: Commit Task 1**

```bash
git add server/exposureWatchlist.js server/test/exposureWatchlist.test.js docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md
git commit -m "feat: add exposure watchlist core logic"
```

---

### Task 2: Persistence and Snapshot Runner

**Files:**
- Modify: `server/exposureWatchlist.js`
- Modify: `server/test/exposureWatchlist.test.js`

**Interfaces:**
- Consumes:
  - `normalizeExposureAssetInput(input, existingAsset, now, owner)`
  - `assetToAttackSurfaceInput(asset)`
  - `summarizeFindings(findings)`
  - `diffSnapshots({ assetId, snapshotId, previous, current, detectedAt })`
- Produces:
  - `createWatchlistStore({ assetsPath, snapshotsPath, readFileSync, writeJsonAtomic })`
  - `runExposureSnapshot({ store, assetId, ownerId, now, runAttackSurfaceScan, scanDeps })`
  - Store methods: `listAssets(ownerId)`, `createAsset(owner, input)`, `updateAsset(ownerId, assetId, input)`, `deleteAsset(ownerId, assetId)`, `getAsset(ownerId, assetId)`, `listSnapshots(ownerId, assetId)`, `listChanges(ownerId, limit)`

- [x] **Step 1: Add failing persistence and snapshot runner tests**

Append to `server/test/exposureWatchlist.test.js`:

```js
import {
  createWatchlistStore,
  runExposureSnapshot,
} from '../exposureWatchlist.js';

function memoryStore() {
  const files = new Map();
  return createWatchlistStore({
    assetsPath: 'assets.json',
    snapshotsPath: 'snapshots.json',
    readFileSync(path) {
      if (!files.has(path)) throw new Error('missing');
      return files.get(path);
    },
    writeJsonAtomic(path, data) {
      files.set(path, JSON.stringify(data));
    },
  });
}

test('createWatchlistStore creates, updates, lists and deletes owner assets', () => {
  const store = memoryStore();
  const asset = store.createAsset(owner, {
    label: 'Edge',
    type: 'domain',
    value: 'example.com',
    limit: 20,
    activeValidation: false,
    scheduleEnabled: true,
  }, now);

  assert.equal(store.listAssets('user-1').length, 1);
  assert.equal(store.listAssets('other-user').length, 0);

  const updated = store.updateAsset('user-1', asset.id, { label: 'Edge Updated', scheduleEnabled: false }, now);
  assert.equal(updated.label, 'Edge Updated');
  assert.equal(updated.scheduleEnabled, false);

  assert.equal(store.deleteAsset('user-1', asset.id), true);
  assert.equal(store.listAssets('user-1').length, 0);
});

test('runExposureSnapshot executes scan, stores snapshot and computes changes', async () => {
  const store = memoryStore();
  const asset = store.createAsset(owner, {
    label: 'Edge',
    type: 'domain',
    value: 'example.com',
    limit: 20,
    activeValidation: false,
    scheduleEnabled: true,
  }, now);

  let runCount = 0;
  const runAttackSurfaceScan = async () => {
    runCount += 1;
    return {
      summary: { warnings: [] },
      findings: runCount === 1
        ? [baseFinding({ ip: '8.8.8.8', port: 443, risk: 'low', cves: [] })]
        : [baseFinding({ ip: '8.8.8.8', port: 443, risk: 'critical', cves: ['CVE-2026-0001'] })],
      warnings: [],
    };
  };

  const first = await runExposureSnapshot({ store, assetId: asset.id, ownerId: 'user-1', now: new Date(now), runAttackSurfaceScan, scanDeps: {} });
  assert.equal(first.status, 'success');
  assert.equal(first.changes[0].type, 'baseline_created');

  const second = await runExposureSnapshot({ store, assetId: asset.id, ownerId: 'user-1', now: new Date('2026-07-13T13:00:00.000Z'), runAttackSurfaceScan, scanDeps: {} });
  assert.equal(second.status, 'success');
  assert.ok(second.changes.some((change) => change.type === 'cve_added'));
  assert.equal(store.getAsset('user-1', asset.id).lastRisk, 'critical');
  assert.equal(store.listChanges('user-1', 10).length >= 2, true);
});

test('runExposureSnapshot stores sanitized config errors', async () => {
  const store = memoryStore();
  const asset = store.createAsset(owner, {
    label: 'Edge',
    type: 'domain',
    value: 'example.com',
    limit: 20,
    activeValidation: false,
    scheduleEnabled: true,
  }, now);

  const error = new Error('Shodan API Key missing');
  error.status = 503;
  error.publicMessage = 'Shodan API key is not configured';

  const snapshot = await runExposureSnapshot({
    store,
    assetId: asset.id,
    ownerId: 'user-1',
    now: new Date(now),
    runAttackSurfaceScan: async () => { throw error; },
    scanDeps: {},
  });

  assert.equal(snapshot.status, 'config_error');
  assert.equal(store.getAsset('user-1', asset.id).lastStatus, 'config_error');
  assert.match(store.getAsset('user-1', asset.id).lastError, /Shodan API key/);
});
```

- [x] **Step 2: Run tests to verify failure**

Run:

```bash
node --test server/test/exposureWatchlist.test.js
```

Expected: FAIL because `createWatchlistStore` and `runExposureSnapshot` are not exported.

- [x] **Step 3: Implement store and snapshot runner**

Extend `server/exposureWatchlist.js`:

```js
const loadJson = (readFileSync, path, fallback) => {
  try {
    const data = JSON.parse(readFileSync(path, 'utf8'));
    return data && typeof data === 'object' ? data : fallback;
  } catch {
    return fallback;
  }
};

export function createWatchlistStore({ assetsPath, snapshotsPath, readFileSync, writeJsonAtomic }) {
  let assets = loadJson(readFileSync, assetsPath, []);
  let snapshots = loadJson(readFileSync, snapshotsPath, []);

  const saveAssets = () => writeJsonAtomic(assetsPath, assets);
  const saveSnapshots = () => writeJsonAtomic(snapshotsPath, snapshots);
  const assertAsset = (ownerId, assetId) => {
    const asset = assets.find((item) => item.id === assetId && item.ownerId === ownerId);
    if (!asset) throw createExposureError(404, 'Asset not found');
    return asset;
  };

  return {
    listAssets(ownerId) {
      return assets.filter((asset) => asset.ownerId === ownerId).sort((a, b) => String(a.label).localeCompare(String(b.label)));
    },
    allAssets() {
      return [...assets];
    },
    getAsset(ownerId, assetId) {
      return assertAsset(ownerId, assetId);
    },
    createAsset(owner, input, now = new Date().toISOString()) {
      if (assets.filter((asset) => asset.ownerId === owner.sub).length >= WATCHLIST_LIMITS.assetsPerUser) {
        throw createExposureError(409, 'Asset limit reached');
      }
      const asset = normalizeExposureAssetInput(input, null, now, owner);
      assets.unshift(asset);
      saveAssets();
      return asset;
    },
    updateAsset(ownerId, assetId, input, now = new Date().toISOString()) {
      const index = assets.findIndex((asset) => asset.id === assetId && asset.ownerId === ownerId);
      if (index < 0) throw createExposureError(404, 'Asset not found');
      assets[index] = normalizeExposureAssetInput(input, assets[index], now, { sub: ownerId, login: assets[index].ownerLogin });
      saveAssets();
      return assets[index];
    },
    updateAssetState(ownerId, assetId, patch) {
      const asset = assertAsset(ownerId, assetId);
      Object.assign(asset, patch, { updatedAt: new Date().toISOString() });
      saveAssets();
      return asset;
    },
    deleteAsset(ownerId, assetId) {
      const before = assets.length;
      assets = assets.filter((asset) => !(asset.id === assetId && asset.ownerId === ownerId));
      snapshots = snapshots.filter((snapshot) => !(snapshot.assetId === assetId && snapshot.ownerId === ownerId));
      if (assets.length !== before) {
        saveAssets();
        saveSnapshots();
        return true;
      }
      return false;
    },
    listSnapshots(ownerId, assetId) {
      assertAsset(ownerId, assetId);
      return snapshots.filter((snapshot) => snapshot.ownerId === ownerId && snapshot.assetId === assetId)
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
    },
    previousSuccessfulSnapshot(ownerId, assetId) {
      return snapshots.filter((snapshot) => snapshot.ownerId === ownerId && snapshot.assetId === assetId && snapshot.status === 'success')
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())[0] || null;
    },
    addSnapshot(snapshot) {
      snapshots.unshift(snapshot);
      snapshots = applySnapshotRetention(snapshots, snapshot.assetId);
      saveSnapshots();
      return snapshot;
    },
    listChanges(ownerId, limit = 100) {
      return snapshots
        .filter((snapshot) => snapshot.ownerId === ownerId)
        .flatMap((snapshot) => snapshot.changes || [])
        .sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime())
        .slice(0, Math.min(Math.max(Number(limit) || 100, 1), 200));
    },
  };
}

const sanitizeRunError = (error) => error.publicMessage || (error.status === 503 ? 'Provider configuration error' : 'Snapshot failed');
const snapshotStatusFor = (error) => error.status === 503 || /key|configured/i.test(error.publicMessage || error.message || '') ? 'config_error' : 'error';

export async function runExposureSnapshot({ store, assetId, ownerId, now = new Date(), runAttackSurfaceScan, scanDeps }) {
  const asset = store.getAsset(ownerId, assetId);
  const startedAt = now.toISOString();
  store.updateAssetState(ownerId, assetId, { lastStatus: 'running', lastError: null });

  const input = assetToAttackSurfaceInput(asset);
  const snapshotId = newId('snap');

  try {
    const previous = store.previousSuccessfulSnapshot(ownerId, assetId);
    const result = await runAttackSurfaceScan(input, scanDeps);
    const findings = result.findings || [];
    const summary = summarizeFindings(findings);
    const changes = diffSnapshots({
      assetId,
      snapshotId,
      previous: previous?.findings || null,
      current: findings,
      detectedAt: new Date().toISOString(),
    });
    const snapshot = {
      id: snapshotId,
      assetId,
      ownerId,
      startedAt,
      completedAt: new Date().toISOString(),
      status: 'success',
      error: null,
      input,
      summary,
      findings,
      changes,
      warnings: result.warnings || result.summary?.warnings || [],
    };
    store.addSnapshot(snapshot);
    store.updateAssetState(ownerId, assetId, {
      lastRunAt: snapshot.completedAt,
      lastStatus: 'success',
      lastError: null,
      lastSnapshotId: snapshot.id,
      lastRisk: summary.highestRisk,
      lastSummary: summary,
    });
    return snapshot;
  } catch (error) {
    const status = snapshotStatusFor(error);
    const message = sanitizeRunError(error);
    const snapshot = {
      id: snapshotId,
      assetId,
      ownerId,
      startedAt,
      completedAt: new Date().toISOString(),
      status,
      error: message,
      input,
      summary: summarizeFindings([]),
      findings: [],
      changes: [],
      warnings: [],
    };
    store.addSnapshot(snapshot);
    store.updateAssetState(ownerId, assetId, {
      lastRunAt: snapshot.completedAt,
      lastStatus: status,
      lastError: message,
      lastSnapshotId: snapshot.id,
    });
    return snapshot;
  }
}
```

- [x] **Step 4: Run tests to verify persistence passes**

Run:

```bash
node --test server/test/exposureWatchlist.test.js
```

Expected: PASS for Task 1 and Task 2 tests.

- [x] **Step 5: Commit Task 2**

```bash
git add server/exposureWatchlist.js server/test/exposureWatchlist.test.js docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md
git commit -m "feat: persist exposure watchlist snapshots"
```

---

### Task 3: Premium Routes, Key Resolution, and Daily Scheduler

**Files:**
- Modify: `server/index.js`
- Modify: `server/exposureWatchlist.js`
- Modify: `server/test/smoke.test.js`

**Interfaces:**
- Consumes:
  - `createWatchlistStore(...)`
  - `runExposureSnapshot(...)`
  - `selectDueAssets(assets, now)`
- Produces:
  - `buildExposureScanDeps(ownerId)`
  - `runDueExposureSnapshots({ store, runOne, now })`
  - Express endpoints under `/api/exposure-watchlist/*`

- [x] **Step 1: Add focused scheduler test**

Append to `server/test/exposureWatchlist.test.js`:

```js
import { runDueExposureSnapshots } from '../exposureWatchlist.js';

test('runDueExposureSnapshots runs due assets sequentially and continues after failure', async () => {
  const assets = [
    { id: 'old-1', ownerId: 'user-1', scheduleEnabled: true, lastRunAt: '2026-07-12T10:00:00.000Z', lastStatus: 'success' },
    { id: 'old-2', ownerId: 'user-2', scheduleEnabled: true, lastRunAt: '2026-07-12T10:00:00.000Z', lastStatus: 'success' },
  ];
  const calls = [];
  const result = await runDueExposureSnapshots({
    store: { allAssets: () => assets },
    now: new Date(now),
    runOne: async (asset) => {
      calls.push(asset.id);
      if (asset.id === 'old-1') throw new Error('provider down');
      return { id: 'snap-ok' };
    },
  });

  assert.deepEqual(calls, ['old-1', 'old-2']);
  assert.equal(result.attempted, 2);
  assert.equal(result.failed, 1);
  assert.equal(result.completed, 1);
});
```

- [x] **Step 2: Implement scheduler helper**

Add to `server/exposureWatchlist.js`:

```js
export async function runDueExposureSnapshots({ store, now = new Date(), runOne }) {
  const due = selectDueAssets(store.allAssets(), now);
  const result = { attempted: 0, completed: 0, failed: 0 };
  for (const asset of due) {
    result.attempted += 1;
    try {
      await runOne(asset);
      result.completed += 1;
    } catch (error) {
      result.failed += 1;
      console.error('exposure watchlist scheduled run failed:', error.message || error);
    }
  }
  return result;
}
```

- [x] **Step 3: Wire store, key resolution, and routes in `server/index.js`**

Modify imports:

```js
import {
    createWatchlistStore,
    runDueExposureSnapshots,
    runExposureSnapshot,
} from './exposureWatchlist.js';
```

Create the store near the saved scans store:

```js
const EXPOSURE_ASSETS_PATH = path.join(__dirname, '.exposure-watchlist.json');
const EXPOSURE_SNAPSHOTS_PATH = path.join(__dirname, '.exposure-snapshots.json');
const exposureStore = createWatchlistStore({
    assetsPath: EXPOSURE_ASSETS_PATH,
    snapshotsPath: EXPOSURE_SNAPSHOTS_PATH,
    readFileSync: fs.readFileSync,
    writeJsonAtomic,
});
```

Add helper functions after BYOK functions:

```js
function getUserApiKey(userId, provider) {
    const encrypted = usersStore[userId]?.apiKeysEnc?.[provider];
    if (!encrypted) return '';
    try { return decryptSecret(encrypted); }
    catch (error) {
        console.error(`failed to decrypt ${provider} key for user:`, error.message);
        return '';
    }
}

function buildExposureScanDeps(ownerId) {
    return {
        axiosClient: axios,
        shodanApiKey: getUserApiKey(ownerId, 'shodan') || process.env.SHODAN_API_KEY,
        censysApiKey: getUserApiKey(ownerId, 'censys') || process.env.CENSYS_API_KEY,
    };
}

async function runExposureForAsset(asset) {
    return runExposureSnapshot({
        store: exposureStore,
        assetId: asset.id,
        ownerId: asset.ownerId,
        runAttackSurfaceScan,
        scanDeps: buildExposureScanDeps(asset.ownerId),
    });
}

async function runExposureSchedulerTick() {
    if (process.env.EXPOSURE_WATCHLIST_DISABLE_DAILY === 'true' || process.env.NODE_ENV === 'test') return;
    await runDueExposureSnapshots({
        store: exposureStore,
        now: new Date(),
        runOne: runExposureForAsset,
    });
}
```

Add premium routes before production static serving:

```js
app.get('/api/exposure-watchlist/assets', requirePremium, (req, res) => {
    res.json({ assets: exposureStore.listAssets(req.user.sub) });
});

app.post('/api/exposure-watchlist/assets', requirePremium, (req, res) => {
    try {
        const asset = exposureStore.createAsset(req.user, req.body || {});
        res.status(201).json({ asset });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.patch('/api/exposure-watchlist/assets/:id', requirePremium, (req, res) => {
    try {
        const asset = exposureStore.updateAsset(req.user.sub, req.params.id, req.body || {});
        res.json({ asset });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.delete('/api/exposure-watchlist/assets/:id', requirePremium, (req, res) => {
    const deleted = exposureStore.deleteAsset(req.user.sub, req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Asset not found' });
    res.json({ ok: true });
});

app.post('/api/exposure-watchlist/assets/:id/run', requirePremium, scanLimiter, async (req, res) => {
    try {
        const snapshot = await runExposureSnapshot({
            store: exposureStore,
            assetId: req.params.id,
            ownerId: req.user.sub,
            runAttackSurfaceScan,
            scanDeps: buildExposureScanDeps(req.user.sub),
        });
        res.json({ snapshot, asset: exposureStore.getAsset(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-watchlist/assets/:id/snapshots', requirePremium, (req, res) => {
    try {
        res.json({ snapshots: exposureStore.listSnapshots(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-watchlist/changes', requirePremium, (req, res) => {
    res.json({ changes: exposureStore.listChanges(req.user.sub, req.query.limit) });
});
```

Start scheduler in `app.listen`:

```js
    if (process.env.NODE_ENV !== 'test' && process.env.EXPOSURE_WATCHLIST_DISABLE_DAILY !== 'true') {
        setTimeout(runExposureSchedulerTick, 30_000);
        setInterval(runExposureSchedulerTick, 15 * 60 * 1000);
    }
```

- [x] **Step 4: Add smoke test for anonymous route protection**

Append to `server/test/smoke.test.js`:

```js
test('exposure watchlist requires authentication', async () => {
  const r = await fetch(`${baseUrl}/api/exposure-watchlist/assets`);
  assert.equal(r.status, 401);
  const body = await r.json();
  assert.equal(body.needAuth, true);
});
```

- [x] **Step 5: Run backend tests and syntax checks**

Run:

```bash
npm run test:server
node --check server/index.js
node --check server/exposureWatchlist.js
```

Expected: all pass.

- [x] **Step 6: Commit Task 3**

```bash
git add server/index.js server/exposureWatchlist.js server/test/exposureWatchlist.test.js server/test/smoke.test.js docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md
git commit -m "feat: add exposure watchlist api"
```

---

### Task 4: Frontend API Contract

**Files:**
- Modify: `src/services/threatApi.ts`

**Interfaces:**
- Consumes: backend endpoint contracts from Task 3.
- Produces:
  - `ExposureAsset`
  - `ExposureSnapshot`
  - `ExposureChange`
  - `ExposureAssetInput`
  - `fetchExposureAssets()`
  - `createExposureAsset(input)`
  - `updateExposureAsset(id, input)`
  - `deleteExposureAsset(id)`
  - `runExposureAsset(id)`
  - `fetchExposureSnapshots(id)`
  - `fetchExposureChanges(limit?)`

- [x] **Step 1: Add TypeScript types and API helpers**

Append near the Attack Surface exports in `src/services/threatApi.ts`:

```ts
export type ExposureAssetType = 'domain' | 'ip' | 'cidr' | 'asn' | 'shodan_query';
export type ExposureStatus = 'never_run' | 'running' | 'success' | 'error' | 'config_error';
export type ExposureChangeSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ExposureChangeType =
    | 'baseline_created'
    | 'service_added'
    | 'service_removed'
    | 'cve_added'
    | 'cve_removed'
    | 'risk_increased'
    | 'risk_decreased'
    | 'banner_changed'
    | 'validation_changed';

export interface ExposureSnapshotSummary {
    totalAssets: number;
    totalServices: number;
    criticalHighFindings: number;
    activelyConfirmedOpen: number;
    byRisk: Record<AttackSurfaceRisk, number>;
    highestRisk: AttackSurfaceRisk | null;
}

export interface ExposureAsset {
    id: string;
    ownerId: string;
    ownerLogin: string;
    label: string;
    type: ExposureAssetType;
    value: string;
    limit: number;
    activeValidation: boolean;
    scheduleEnabled: boolean;
    createdAt: string;
    updatedAt: string;
    lastRunAt: string | null;
    lastStatus: ExposureStatus;
    lastError: string | null;
    lastSnapshotId: string | null;
    lastRisk: AttackSurfaceRisk | null;
    lastSummary: ExposureSnapshotSummary | null;
}

export interface ExposureChange {
    id: string;
    assetId: string;
    snapshotId: string;
    detectedAt: string;
    severity: ExposureChangeSeverity;
    type: ExposureChangeType;
    title: string;
    description: string;
    ip: string | null;
    port: number | null;
    transport: 'tcp' | 'udp' | null;
    previous: unknown;
    current: unknown;
}

export interface ExposureSnapshot {
    id: string;
    assetId: string;
    ownerId: string;
    startedAt: string;
    completedAt: string | null;
    status: 'success' | 'error' | 'config_error';
    error: string | null;
    input: AttackSurfaceInput;
    summary: ExposureSnapshotSummary;
    findings: AttackSurfaceFinding[];
    changes: ExposureChange[];
    warnings: string[];
}

export interface ExposureAssetInput {
    label: string;
    type: ExposureAssetType;
    value: string;
    limit: number;
    activeValidation: boolean;
    scheduleEnabled: boolean;
}

const exposureError = async (response: Response): Promise<never> => {
    const body = await response.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `Exposure Watchlist API error: ${response.status}`);
};

export const fetchExposureAssets = async (): Promise<ExposureAsset[]> => {
    const response = await fetch('/api/exposure-watchlist/assets');
    if (!response.ok) return exposureError(response);
    return (await response.json()).assets;
};

export const createExposureAsset = async (input: ExposureAssetInput): Promise<ExposureAsset> => {
    const response = await fetch('/api/exposure-watchlist/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!response.ok) return exposureError(response);
    return (await response.json()).asset;
};

export const updateExposureAsset = async (id: string, input: ExposureAssetInput): Promise<ExposureAsset> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
    });
    if (!response.ok) return exposureError(response);
    return (await response.json()).asset;
};

export const deleteExposureAsset = async (id: string): Promise<void> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!response.ok) return exposureError(response);
};

export const runExposureAsset = async (id: string): Promise<{ asset: ExposureAsset; snapshot: ExposureSnapshot }> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}/run`, { method: 'POST' });
    if (!response.ok) return exposureError(response);
    return response.json();
};

export const fetchExposureSnapshots = async (id: string): Promise<ExposureSnapshot[]> => {
    const response = await fetch(`/api/exposure-watchlist/assets/${encodeURIComponent(id)}/snapshots`);
    if (!response.ok) return exposureError(response);
    return (await response.json()).snapshots;
};

export const fetchExposureChanges = async (limit = 100): Promise<ExposureChange[]> => {
    const response = await fetch(`/api/exposure-watchlist/changes?limit=${encodeURIComponent(String(limit))}`);
    if (!response.ok) return exposureError(response);
    return (await response.json()).changes;
};
```

- [x] **Step 2: Run TypeScript check**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [x] **Step 3: Commit Task 4**

```bash
git add src/services/threatApi.ts docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md
git commit -m "feat: add exposure watchlist client api"
```

---

### Task 5: Exposure Watchlist UI and Navigation

**Files:**
- Create: `src/pages/ExposureWatchlist.tsx`
- Modify: `src/App.tsx`
- Modify: `src/components/Header.tsx`

**Interfaces:**
- Consumes frontend API helpers from Task 4.
- Produces route `/exposure-watchlist` behind `PremiumRoute`.

- [ ] **Step 1: Create the page component**

Create `src/pages/ExposureWatchlist.tsx`. Keep the page compact and table-first:

```tsx
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Clock,
  Loader2,
  Play,
  Plus,
  Radar,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { PageLayout } from "@/components/PageLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";
import {
  createExposureAsset,
  deleteExposureAsset,
  fetchExposureAssets,
  fetchExposureChanges,
  fetchExposureSnapshots,
  runExposureAsset,
  updateExposureAsset,
  type ExposureAsset,
  type ExposureAssetInput,
  type ExposureAssetType,
  type ExposureChange,
  type ExposureSnapshot,
} from "@/services/threatApi";
import { useLanguage } from "@/contexts/LanguageContext";

const emptyForm: ExposureAssetInput = {
  label: "",
  type: "domain",
  value: "",
  limit: 50,
  activeValidation: false,
  scheduleEnabled: true,
};

const riskTone: Record<string, string> = {
  critical: "bg-red-500/10 text-red-600 border-red-500/30",
  high: "bg-orange-500/10 text-orange-600 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-700 border-amber-500/30",
  low: "bg-emerald-500/10 text-emerald-700 border-emerald-500/30",
  info: "bg-blue-500/10 text-blue-700 border-blue-500/30",
  null: "bg-muted text-muted-foreground",
};

const statusLabel = (status: string) => ({
  never_run: "Never run",
  running: "Running",
  success: "OK",
  error: "Error",
  config_error: "Config",
}[status] || status);

export default function ExposureWatchlist() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [assets, setAssets] = useState<ExposureAsset[]>([]);
  const [changes, setChanges] = useState<ExposureChange[]>([]);
  const [snapshots, setSnapshots] = useState<ExposureSnapshot[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [form, setForm] = useState<ExposureAssetInput>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);

  const selectedAsset = useMemo(() => assets.find((asset) => asset.id === selectedAssetId) || null, [assets, selectedAssetId]);
  const totals = useMemo(() => assets.reduce(
    (acc, asset) => {
      acc.services += asset.lastSummary?.totalServices || 0;
      acc.criticalHigh += asset.lastSummary?.criticalHighFindings || 0;
      if (asset.lastStatus === "error" || asset.lastStatus === "config_error") acc.errors += 1;
      return acc;
    },
    { services: 0, criticalHigh: 0, errors: 0 },
  ), [assets]);

  const load = async () => {
    setLoading(true);
    try {
      const [assetList, changeList] = await Promise.all([fetchExposureAssets(), fetchExposureChanges(100)]);
      setAssets(assetList);
      setChanges(changeList);
      if (!selectedAssetId && assetList[0]) setSelectedAssetId(assetList[0].id);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Exposure Watchlist API error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  useEffect(() => {
    if (!selectedAssetId) {
      setSnapshots([]);
      return;
    }
    fetchExposureSnapshots(selectedAssetId)
      .then(setSnapshots)
      .catch((error) => toast.error(error instanceof Error ? error.message : "Snapshot API error"));
  }, [selectedAssetId]);

  const submit = async () => {
    try {
      const saved = editingId ? await updateExposureAsset(editingId, form) : await createExposureAsset(form);
      toast.success(pt ? "Ativo salvo" : "Asset saved");
      setForm(emptyForm);
      setEditingId(null);
      setSelectedAssetId(saved.id);
      await load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to save asset");
    }
  };

  const edit = (asset: ExposureAsset) => {
    setEditingId(asset.id);
    setForm({
      label: asset.label,
      type: asset.type,
      value: asset.value,
      limit: asset.limit,
      activeValidation: asset.activeValidation,
      scheduleEnabled: asset.scheduleEnabled,
    });
  };

  const runNow = async (asset: ExposureAsset) => {
    setBusyId(asset.id);
    try {
      await runExposureAsset(asset.id);
      toast.success(pt ? "Snapshot finalizado" : "Snapshot complete");
      await load();
      setSelectedAssetId(asset.id);
      setSnapshots(await fetchExposureSnapshots(asset.id));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Snapshot failed");
    } finally {
      setBusyId(null);
    }
  };

  const remove = async (asset: ExposureAsset) => {
    setBusyId(asset.id);
    try {
      await deleteExposureAsset(asset.id);
      toast.success(pt ? "Ativo removido" : "Asset removed");
      if (selectedAssetId === asset.id) setSelectedAssetId(null);
      await load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Delete failed");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <PageLayout>
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <Badge variant="outline" className="gap-1"><Radar className="h-3 w-3" /> {pt ? "Monitoramento diario" : "Daily monitoring"}</Badge>
              <Badge variant="secondary">{pt ? "In-app alerts" : "In-app alerts"}</Badge>
            </div>
            <h1 className="text-3xl font-bold tracking-tight">Exposure Watchlist</h1>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {pt
                ? "Cadastre ativos externos, rode snapshots e acompanhe mudancas de servicos, CVEs, risco e validacao TCP."
                : "Save external assets, run snapshots, and track service, CVE, risk, and TCP validation changes."}
            </p>
          </div>
          <Button variant="outline" onClick={load} disabled={loading} className="gap-2">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            {pt ? "Atualizar" : "Refresh"}
          </Button>
        </div>

        <div className="grid gap-3 md:grid-cols-4">
          <Card><CardContent className="p-4"><div className="text-xs text-muted-foreground">Assets</div><div className="text-2xl font-bold">{assets.length}</div></CardContent></Card>
          <Card><CardContent className="p-4"><div className="text-xs text-muted-foreground">Services</div><div className="text-2xl font-bold">{totals.services}</div></CardContent></Card>
          <Card><CardContent className="p-4"><div className="text-xs text-muted-foreground">Critical/High</div><div className="text-2xl font-bold">{totals.criticalHigh}</div></CardContent></Card>
          <Card><CardContent className="p-4"><div className="text-xs text-muted-foreground">Errors</div><div className="text-2xl font-bold">{totals.errors}</div></CardContent></Card>
        </div>

        <div className="grid gap-5 lg:grid-cols-[360px_1fr]">
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Plus className="h-4 w-4" /> {editingId ? (pt ? "Editar ativo" : "Edit asset") : (pt ? "Novo ativo" : "New asset")}</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1"><Label>Label</Label><Input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} /></div>
              <div className="space-y-1">
                <Label>Type</Label>
                <Select value={form.type} onValueChange={(value) => setForm({ ...form, type: value as ExposureAssetType })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="domain">Domain</SelectItem>
                    <SelectItem value="ip">IP</SelectItem>
                    <SelectItem value="cidr">CIDR</SelectItem>
                    <SelectItem value="asn">ASN</SelectItem>
                    <SelectItem value="shodan_query">Shodan query</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>Value</Label>
                {form.type === "shodan_query"
                  ? <Textarea rows={4} value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
                  : <Input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />}
              </div>
              <div className="space-y-1"><Label>Limit</Label><Input type="number" min={1} max={100} value={form.limit} onChange={(e) => setForm({ ...form, limit: Number(e.target.value) || 50 })} /></div>
              <div className="flex items-center justify-between rounded-md border p-3"><Label>Daily</Label><Switch checked={form.scheduleEnabled} onCheckedChange={(value) => setForm({ ...form, scheduleEnabled: value })} /></div>
              <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
                <div className="flex items-center justify-between gap-3"><Label>Active TCP</Label><Switch checked={form.activeValidation} onCheckedChange={(value) => setForm({ ...form, activeValidation: value })} /></div>
                <p className="mt-2 text-xs text-muted-foreground">{pt ? "Somente pares IP/porta publicos observados pelos providers." : "Only provider-observed public IP/port pairs."}</p>
              </div>
              <Button onClick={submit} className="w-full">{editingId ? (pt ? "Salvar alteracoes" : "Save changes") : (pt ? "Adicionar ativo" : "Add asset")}</Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-base">{pt ? "Watchlist" : "Watchlist"}</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Services</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => (
                    <TableRow key={asset.id} className={selectedAssetId === asset.id ? "bg-muted/50" : ""}>
                      <TableCell>
                        <button className="text-left" onClick={() => setSelectedAssetId(asset.id)}>
                          <div className="font-medium">{asset.label}</div>
                          <div className="text-xs text-muted-foreground">{asset.type} · {asset.value}</div>
                        </button>
                      </TableCell>
                      <TableCell><Badge variant="outline" className={riskTone[asset.lastRisk || "null"]}>{asset.lastRisk || "none"}</Badge></TableCell>
                      <TableCell>{asset.lastSummary?.totalServices || 0}</TableCell>
                      <TableCell><Badge variant="secondary">{statusLabel(asset.lastStatus)}</Badge></TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button size="icon" variant="ghost" onClick={() => runNow(asset)} disabled={busyId === asset.id}>{busyId === asset.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}</Button>
                          <Button size="sm" variant="ghost" onClick={() => edit(asset)}>{pt ? "Editar" : "Edit"}</Button>
                          <Button size="icon" variant="ghost" onClick={() => remove(asset)} disabled={busyId === asset.id}><Trash2 className="h-4 w-4" /></Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {!assets.length && <TableRow><TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">{pt ? "Nenhum ativo cadastrado." : "No assets saved."}</TableCell></TableRow>}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><AlertTriangle className="h-4 w-4" /> {pt ? "Mudancas recentes" : "Recent changes"}</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {changes.slice(0, 12).map((change) => (
                <div key={change.id} className="rounded-md border p-3">
                  <div className="flex items-center justify-between gap-2"><Badge variant="outline" className={riskTone[change.severity]}>{change.severity}</Badge><span className="text-xs text-muted-foreground">{new Date(change.detectedAt).toLocaleString()}</span></div>
                  <div className="mt-2 text-sm font-medium">{change.title}</div>
                  <div className="text-xs text-muted-foreground">{change.description}</div>
                </div>
              ))}
              {!changes.length && <div className="py-8 text-center text-sm text-muted-foreground">{pt ? "Sem mudancas ainda." : "No changes yet."}</div>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Clock className="h-4 w-4" /> {selectedAsset?.label || (pt ? "Historico" : "History")}</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {selectedAsset?.lastError && <div className="rounded-md border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-700">{selectedAsset.lastError}</div>}
              {snapshots.slice(0, 8).map((snapshot) => (
                <div key={snapshot.id} className="rounded-md border p-3">
                  <div className="flex items-center justify-between gap-2"><Badge variant="secondary">{snapshot.status}</Badge><span className="text-xs text-muted-foreground">{snapshot.completedAt ? new Date(snapshot.completedAt).toLocaleString() : "running"}</span></div>
                  <div className="mt-2 grid grid-cols-3 gap-2 text-sm">
                    <div><div className="text-xs text-muted-foreground">Services</div><div className="font-semibold">{snapshot.summary.totalServices}</div></div>
                    <div><div className="text-xs text-muted-foreground">Critical/High</div><div className="font-semibold">{snapshot.summary.criticalHighFindings}</div></div>
                    <div><div className="text-xs text-muted-foreground">Changes</div><div className="font-semibold">{snapshot.changes.length}</div></div>
                  </div>
                </div>
              ))}
              {!snapshots.length && <div className="py-8 text-center text-sm text-muted-foreground">{pt ? "Selecione um ativo ou rode o primeiro snapshot." : "Select an asset or run the first snapshot."}</div>}
            </CardContent>
          </Card>
        </div>
      </div>
    </PageLayout>
  );
}
```

- [ ] **Step 2: Add the route**

Modify `src/App.tsx`:

```tsx
const ExposureWatchlist = lazy(() => import("./pages/ExposureWatchlist"));
```

Add the route near Attack Surface:

```tsx
<Route path="/exposure-watchlist" element={<PremiumRoute feature="exposure-watchlist"><ExposureWatchlist /></PremiumRoute>} />
```

- [ ] **Step 3: Add navigation**

Modify `src/components/Header.tsx` in the Analysis/Tools group near Attack Surface:

```tsx
{
  label: "Exposure Watchlist",
  href: "/exposure-watchlist",
  icon: Radar,
  description: pt ? "Monitore mudancas na superficie exposta." : "Monitor exposed surface changes.",
}
```

Ensure `Radar` is imported from `lucide-react`.

- [ ] **Step 4: Run frontend checks**

Run:

```bash
npm run typecheck
npm run build
```

Expected: both pass.

- [ ] **Step 5: Commit Task 5**

```bash
git add src/pages/ExposureWatchlist.tsx src/App.tsx src/components/Header.tsx docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md
git commit -m "feat: add exposure watchlist ui"
```

---

### Task 6: Endpoint Docs, Verification, Merge, Push, and Deploy Validation

**Files:**
- Modify: `ENDPOINTS.txt`
- Modify: `docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md`

**Interfaces:**
- Consumes all previous tasks.
- Produces verified production deployment on `main`.

- [ ] **Step 1: Document endpoints**

Add to `ENDPOINTS.txt` after Attack Surface or Tool sections:

```txt
====================================================================
EXPOSURE WATCHLIST
====================================================================
  GET     /api/exposure-watchlist/assets                 [auth] premium list assets
  POST    /api/exposure-watchlist/assets                 [auth] premium create asset
  PATCH   /api/exposure-watchlist/assets/:id             [auth] premium update asset
  DELETE  /api/exposure-watchlist/assets/:id             [auth] premium delete asset
  POST    /api/exposure-watchlist/assets/:id/run         [auth] [rl] premium run snapshot
  GET     /api/exposure-watchlist/assets/:id/snapshots   [auth] premium snapshot history
  GET     /api/exposure-watchlist/changes                [auth] premium changes feed
```

Add route list entry:

```txt
  /exposure-watchlist *  Exposure Watchlist
```

- [ ] **Step 2: Run full local verification**

Run from `/home/mandrade/Dev/thre4th-summary`:

```bash
npm run lint
npm run typecheck
npm run build
npm run test:server
node --check server/index.js
node --check server/attackSurface.js
node --check server/exposureWatchlist.js
python3 -m py_compile hunt-service/*.py
```

Expected:

- All commands exit `0`.
- `npm run lint` may report existing warnings, but no errors.
- `npm run build` may report existing Browserslist/chunk warnings, but exits `0`.

- [ ] **Step 3: Commit docs and checklist updates**

```bash
git add ENDPOINTS.txt docs/superpowers/plans/2026-07-13-exposure-watchlist-implementation.md
git commit -m "docs: document exposure watchlist"
```

- [ ] **Step 4: Merge to main if work was done on a feature branch**

If implementation used `feature/exposure-watchlist`:

```bash
git switch main
git fetch origin
git merge --no-ff feature/exposure-watchlist
```

If implementation was already done on `main`, run:

```bash
git status --short --branch
git log --oneline --decorate origin/main..main
```

Expected: local `main` contains the Exposure Watchlist implementation commits.

- [ ] **Step 5: Push `main`**

```bash
git push origin main
```

Expected: GitHub accepts the push and starts CI.

- [ ] **Step 6: Monitor GitHub Actions**

Run:

```bash
gh run list --repo kkroth0/thre4th-summary --branch main --limit 10
gh run watch <ci-run-id> --repo kkroth0/thre4th-summary --exit-status
gh run watch <deploy-pages-run-id> --repo kkroth0/thre4th-summary --exit-status
gh run watch <deploy-vps-run-id> --repo kkroth0/thre4th-summary --exit-status
```

Expected:

- CI completes with `success`.
- Continuous Security Scan completes with `success`, unless GitHub reports a pre-existing infrastructure issue unrelated to this change.
- Deploy to Cloudflare Pages completes with `success`.
- Deploy to VPS completes with `success`.

- [ ] **Step 7: Validate production**

Run:

```bash
curl -sS -o /tmp/threatsumm4ry-home.html -w "%{http_code}\n" --max-time 20 https://threatsumm4ry.app/
curl -sS -o /tmp/threatsumm4ry-exposure-watchlist.html -w "%{http_code}\n" --max-time 20 https://threatsumm4ry.app/exposure-watchlist
curl -sS -o /tmp/threatsumm4ry-api-status.json -w "%{http_code}\n" --max-time 20 https://threatsumm4ry.app/api/vendors/status
```

Expected:

```txt
200
200
200
```

The `/exposure-watchlist` route may show the premium login gate when unauthenticated, but it must load the SPA route with HTTP 200.

- [ ] **Step 8: Final status report**

Report:

- final `origin/main` commit hash
- CI status
- Cloudflare Pages deploy status
- VPS deploy status
- production HTTP checks
- any residual warnings, such as pre-existing lint warnings
