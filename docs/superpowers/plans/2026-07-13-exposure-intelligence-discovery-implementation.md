# Exposure Intelligence Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a passive Exposure Intelligence Discovery workflow inside `/attack-surface` so premium users can create company profiles, run passive discovery snapshots, review candidate assets, and approve selected candidates into Monitor.

**Architecture:** Add a focused backend module, `server/exposureDiscovery.js`, for profile validation, passive collector orchestration, graceful provider degradation, candidate scoring, snapshot diffing, and JSON-backed persistence. Expose premium-gated discovery APIs from `server/index.js`, then add typed frontend API helpers and a new `ExposureDiscoveryPanel` tab inside the existing Attack Surface hub.

**Tech Stack:** Node.js ESM, Express, `node:test`, React 18, TypeScript, Vite, shadcn/ui, Tailwind, existing JSON persistence helpers, existing BYOK key lookup, existing Attack Surface and Exposure Watchlist modules.

## Global Constraints

- Do not add a separate top-level Exposure Intelligence route for the MVP.
- Do not add active scanning or a new VPS worker in the MVP.
- Do not run Subfinder, Amass, httpx, dnsx, naabu, nmap, or similar active or semi-active tools in the MVP.
- Do not automatically save every discovered asset into monitoring.
- Do not fail the whole workflow when one provider is missing, rate-limited, or unavailable.
- Do not duplicate Shodan/Censys normalization logic separately from the existing Attack Surface feature.
- Do not migrate persistence to a database in this iteration.
- Primary domain is required for a Discovery profile.
- Legal organization name and known ASNs are optional.
- Discovery profiles use manual snapshots in the MVP.
- The fallback behavior is mixed evidence: combine fresh provider evidence with cached evidence and mark source freshness.
- Store normalized provider status, evidence, candidates, summaries, and warnings; do not store raw provider responses.
- Discovery endpoints require the same premium/user isolation model as Monitor.
- Approved candidates become existing Exposure Watchlist assets.

---

## File Structure

Create:

- `server/exposureDiscovery.js` — backend Discovery domain module: validation, stores, collectors, scoring, diffing, snapshot runs, candidate approval mapping.
- `server/test/exposureDiscovery.test.js` — backend unit tests for profile validation, provider status handling, scoring, diffing, snapshots, store isolation, and monitor approval mapping.
- `src/components/attack-surface/ExposureDiscoveryPanel.tsx` — Discovery tab UI for profiles, provider health, candidate queue, snapshots, and approve/ignore actions.
- `src/utils/exposureDiscovery.ts` — frontend display utilities for candidate sorting, provider status copy, and compact warning text.
- `src/utils/exposureDiscovery.test.ts` — frontend utility tests.

Modify:

- `server/index.js` — wire JSON stores, dependency builder, and premium discovery routes.
- `src/services/threatApi.ts` — add Discovery types and API functions.
- `src/pages/AttackSurface.tsx` — add `Discovery` tab and route mode support.

Do not modify:

- `src/pages/ExposureWatchlist.tsx` — it already redirects to `/attack-surface?mode=monitor`.
- `server/attackSurface.js` — use existing risk logic where needed, but keep Discovery-specific orchestration in `server/exposureDiscovery.js`.

---

### Task 1: Backend Profile Validation And JSON Store

**Files:**

- Create: `server/exposureDiscovery.js`
- Create: `server/test/exposureDiscovery.test.js`

**Interfaces:**

- Produces:
  - `DISCOVERY_LIMITS`
  - `createDiscoveryError(status: number, publicMessage: string): Error`
  - `normalizeDiscoveryProfileInput(input, existingProfile, now, owner): DiscoveryProfile`
  - `createDiscoveryStore({ profilesPath, snapshotsPath, readFileSync, writeJsonAtomic })`
- Consumes: none from other new tasks.

- [ ] **Step 1: Write failing validation and store tests**

Add this initial content to `server/test/exposureDiscovery.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DISCOVERY_LIMITS,
  createDiscoveryStore,
  normalizeDiscoveryProfileInput,
} from '../exposureDiscovery.js';

const owner = { sub: 'user-1', login: 'analyst' };
const now = '2026-07-13T12:00:00.000Z';

function memoryDiscoveryStore() {
  const files = new Map();
  return createDiscoveryStore({
    profilesPath: 'profiles.json',
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

test('normalizeDiscoveryProfileInput validates and normalizes profile fields', () => {
  const profile = normalizeDiscoveryProfileInput({
    label: ' Example Bank ',
    primaryDomain: 'Example.COM.BR',
    legalName: ' Example Banco S.A. ',
    asns: ['15169', 'AS13335', 'as15169'],
    notes: ' External perimeter ',
    limit: 250,
  }, null, now, owner);

  assert.equal(profile.ownerId, 'user-1');
  assert.equal(profile.ownerLogin, 'analyst');
  assert.equal(profile.label, 'Example Bank');
  assert.equal(profile.primaryDomain, 'example.com.br');
  assert.equal(profile.legalName, 'Example Banco S.A.');
  assert.deepEqual(profile.asns, ['AS15169', 'AS13335']);
  assert.equal(profile.notes, 'External perimeter');
  assert.equal(profile.limit, DISCOVERY_LIMITS.scanLimit);
  assert.equal(profile.lastStatus, 'never_run');
  assert.equal(profile.lastSnapshotId, null);
});

test('normalizeDiscoveryProfileInput rejects invalid required fields', () => {
  assert.throws(
    () => normalizeDiscoveryProfileInput({ label: '', primaryDomain: 'example.com' }, null, now, owner),
    /Profile label is required/,
  );
  assert.throws(
    () => normalizeDiscoveryProfileInput({ label: 'Bad', primaryDomain: 'not a domain' }, null, now, owner),
    /Invalid primary domain format/,
  );
  assert.throws(
    () => normalizeDiscoveryProfileInput({ label: 'Bad', primaryDomain: 'example.com', asns: ['ASABC'] }, null, now, owner),
    /Invalid ASN format/,
  );
});

test('createDiscoveryStore isolates profiles by owner and supports CRUD', () => {
  const store = memoryDiscoveryStore();
  const profile = store.createProfile(owner, {
    label: 'Example',
    primaryDomain: 'example.com',
    legalName: 'Example Inc',
    asns: ['AS15169'],
    notes: '',
    limit: 50,
  }, now);

  assert.equal(store.listProfiles('user-1').length, 1);
  assert.equal(store.listProfiles('user-2').length, 0);
  assert.equal(store.getProfile('user-1', profile.id).primaryDomain, 'example.com');
  assert.throws(() => store.getProfile('user-2', profile.id), /Profile not found/);

  const updated = store.updateProfile('user-1', profile.id, {
    label: 'Example Updated',
    primaryDomain: 'example.org',
    legalName: '',
    asns: ['13335'],
    notes: 'changed',
    limit: 10,
  }, '2026-07-13T13:00:00.000Z');

  assert.equal(updated.label, 'Example Updated');
  assert.equal(updated.primaryDomain, 'example.org');
  assert.equal(updated.legalName, null);
  assert.deepEqual(updated.asns, ['AS13335']);
  assert.equal(store.deleteProfile('user-2', profile.id), false);
  assert.equal(store.deleteProfile('user-1', profile.id), true);
  assert.equal(store.listProfiles('user-1').length, 0);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: FAIL with an import error for `../exposureDiscovery.js`.

- [ ] **Step 3: Create the validation and store implementation**

Create `server/exposureDiscovery.js` with this implementation:

```js
import crypto from 'crypto';

export const DISCOVERY_LIMITS = {
  profilesPerUser: 10,
  profileLabelLength: 80,
  domainLength: 253,
  legalNameLength: 160,
  notesLength: 500,
  asnsPerProfile: 20,
  scanLimit: 100,
  snapshotsPerProfile: 14,
};

const CONTROL_CHARS = /[\x00-\x1F\x7F]/;
const SAFE_DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const createDiscoveryError = (status, publicMessage) => Object.assign(new Error(publicMessage), {
  status,
  publicMessage,
});

const newId = (prefix) => `${prefix}_${crypto.randomBytes(8).toString('hex')}`;

const cleanText = (value, max) => String(value || '')
  .replace(CONTROL_CHARS, ' ')
  .replace(/\s+/g, ' ')
  .trim()
  .slice(0, max);

const requiredText = (value, label, max) => {
  if (CONTROL_CHARS.test(String(value || ''))) throw createDiscoveryError(400, `${label} contains invalid characters`);
  const cleaned = cleanText(value, max);
  if (!cleaned) throw createDiscoveryError(400, `${label} is required`);
  if (String(value || '').trim().length > max) throw createDiscoveryError(400, `${label} is too long`);
  return cleaned;
};

const optionalText = (value, label, max) => {
  if (value === undefined || value === null) return null;
  if (CONTROL_CHARS.test(String(value || ''))) throw createDiscoveryError(400, `${label} contains invalid characters`);
  const cleaned = cleanText(value, max);
  if (String(value || '').trim().length > max) throw createDiscoveryError(400, `${label} is too long`);
  return cleaned || null;
};

export const normalizeDomain = (value) => {
  const domain = requiredText(value, 'Primary domain', DISCOVERY_LIMITS.domainLength).toLowerCase();
  if (!SAFE_DOMAIN_REGEX.test(domain)) throw createDiscoveryError(400, 'Invalid primary domain format');
  return domain;
};

export const normalizeAsn = (value) => {
  const raw = cleanText(value, 24).toUpperCase().replace(/^AS/, '');
  if (!/^\d{1,10}$/.test(raw)) throw createDiscoveryError(400, 'Invalid ASN format');
  return `AS${raw}`;
};

export const normalizeAsns = (values = []) => {
  const input = Array.isArray(values) ? values : String(values || '').split(/[,\s]+/);
  return Array.from(new Set(input.filter(Boolean).map(normalizeAsn))).slice(0, DISCOVERY_LIMITS.asnsPerProfile);
};

const clampLimit = (value) => {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return 50;
  return Math.min(parsed, DISCOVERY_LIMITS.scanLimit);
};

export function normalizeDiscoveryProfileInput(input = {}, existingProfile = null, now = new Date().toISOString(), owner = {}) {
  const label = requiredText(input.label ?? existingProfile?.label, 'Profile label', DISCOVERY_LIMITS.profileLabelLength);
  const primaryDomain = normalizeDomain(input.primaryDomain ?? existingProfile?.primaryDomain);
  const legalName = optionalText(input.legalName ?? existingProfile?.legalName, 'Legal name', DISCOVERY_LIMITS.legalNameLength);
  const notes = optionalText(input.notes ?? existingProfile?.notes, 'Notes', DISCOVERY_LIMITS.notesLength);
  const asns = normalizeAsns(input.asns ?? existingProfile?.asns ?? []);
  const limit = clampLimit(input.limit ?? existingProfile?.limit ?? 50);

  return {
    id: existingProfile?.id || newId('profile'),
    ownerId: existingProfile?.ownerId || owner.sub,
    ownerLogin: existingProfile?.ownerLogin || owner.login,
    label,
    primaryDomain,
    legalName,
    asns,
    notes,
    limit,
    createdAt: existingProfile?.createdAt || now,
    updatedAt: now,
    lastRunAt: existingProfile?.lastRunAt || null,
    lastStatus: existingProfile?.lastStatus || 'never_run',
    lastError: existingProfile?.lastError || null,
    lastSnapshotId: existingProfile?.lastSnapshotId || null,
    lastSummary: existingProfile?.lastSummary || null,
  };
}

const loadJson = (readFileSync, path, fallback) => {
  try {
    const data = JSON.parse(readFileSync(path, 'utf8'));
    return Array.isArray(data) ? data : fallback;
  } catch {
    return fallback;
  }
};

export function createDiscoveryStore({ profilesPath, snapshotsPath, readFileSync, writeJsonAtomic }) {
  let profiles = loadJson(readFileSync, profilesPath, []);
  let snapshots = loadJson(readFileSync, snapshotsPath, []);
  const saveProfiles = () => writeJsonAtomic(profilesPath, profiles);
  const saveSnapshots = () => writeJsonAtomic(snapshotsPath, snapshots);
  const assertProfile = (ownerId, profileId) => {
    const profile = profiles.find((item) => item.id === profileId && item.ownerId === ownerId);
    if (!profile) throw createDiscoveryError(404, 'Profile not found');
    return profile;
  };

  return {
    listProfiles(ownerId) {
      return profiles
        .filter((profile) => profile.ownerId === ownerId)
        .sort((a, b) => String(a.label).localeCompare(String(b.label)));
    },
    getProfile(ownerId, profileId) {
      return assertProfile(ownerId, profileId);
    },
    createProfile(owner, input, now = new Date().toISOString()) {
      if (profiles.filter((profile) => profile.ownerId === owner.sub).length >= DISCOVERY_LIMITS.profilesPerUser) {
        throw createDiscoveryError(409, 'Discovery profile limit reached');
      }
      const profile = normalizeDiscoveryProfileInput(input, null, now, owner);
      profiles.unshift(profile);
      saveProfiles();
      return profile;
    },
    updateProfile(ownerId, profileId, input, now = new Date().toISOString()) {
      const index = profiles.findIndex((profile) => profile.id === profileId && profile.ownerId === ownerId);
      if (index < 0) throw createDiscoveryError(404, 'Profile not found');
      profiles[index] = normalizeDiscoveryProfileInput(input, profiles[index], now, {
        sub: ownerId,
        login: profiles[index].ownerLogin,
      });
      saveProfiles();
      return profiles[index];
    },
    updateProfileState(ownerId, profileId, patch) {
      const profile = assertProfile(ownerId, profileId);
      Object.assign(profile, patch, { updatedAt: new Date().toISOString() });
      saveProfiles();
      return profile;
    },
    deleteProfile(ownerId, profileId) {
      const before = profiles.length;
      profiles = profiles.filter((profile) => !(profile.id === profileId && profile.ownerId === ownerId));
      snapshots = snapshots.filter((snapshot) => !(snapshot.profileId === profileId && snapshot.ownerId === ownerId));
      if (profiles.length === before) return false;
      saveProfiles();
      saveSnapshots();
      return true;
    },
    listSnapshots(ownerId, profileId) {
      assertProfile(ownerId, profileId);
      return snapshots
        .filter((snapshot) => snapshot.ownerId === ownerId && snapshot.profileId === profileId)
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
    },
    latestSnapshot(ownerId, profileId) {
      return this.listSnapshots(ownerId, profileId)[0] || null;
    },
    addSnapshot(snapshot) {
      snapshots.unshift(snapshot);
      const retained = snapshots
        .filter((item) => item.profileId === snapshot.profileId)
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
        .slice(0, DISCOVERY_LIMITS.snapshotsPerProfile);
      const keepIds = new Set(retained.map((item) => item.id));
      snapshots = snapshots
        .filter((item) => item.profileId !== snapshot.profileId || keepIds.has(item.id))
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
      saveSnapshots();
      return snapshot;
    },
  };
}
```

- [ ] **Step 4: Run backend tests**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: PASS for the three tests in `server/test/exposureDiscovery.test.js`.

- [ ] **Step 5: Commit**

```bash
git add server/exposureDiscovery.js server/test/exposureDiscovery.test.js
git commit -m "feat: add exposure discovery profile store"
```

---

### Task 2: Backend Evidence, Scoring, Diffing, And Provider Status

**Files:**

- Modify: `server/exposureDiscovery.js`
- Modify: `server/test/exposureDiscovery.test.js`

**Interfaces:**

- Consumes:
  - `createDiscoveryError`
  - `createDiscoveryStore`
- Produces:
  - `providerResult(provider, status, data, options): DiscoveryProviderResult`
  - `providerStatusFromResult(result): DiscoveryProviderStatus`
  - `buildCandidatesFromProviderResults(profile, providerResults, previousSnapshot, now): DiscoveryCandidate[]`
  - `summarizeDiscoveryCandidates(candidates, providerStatuses): DiscoverySummary`
  - `diffDiscoverySnapshots({ profileId, snapshotId, previous, current, providerStatuses, previousProviderStatuses, detectedAt }): DiscoveryChange[]`
  - `candidateToMonitorAssetInput(candidate): ExposureAssetInput`

- [ ] **Step 1: Add failing tests for provider status, mixed cache evidence, scoring, diffing, and monitor mapping**

Append these tests to `server/test/exposureDiscovery.test.js`:

```js
import {
  buildCandidatesFromProviderResults,
  candidateToMonitorAssetInput,
  diffDiscoverySnapshots,
  providerResult,
  providerStatusFromResult,
  summarizeDiscoveryCandidates,
} from '../exposureDiscovery.js';

const profileFixture = {
  id: 'profile-1',
  ownerId: 'user-1',
  ownerLogin: 'analyst',
  label: 'Example',
  primaryDomain: 'example.com',
  legalName: 'Example Inc',
  asns: ['AS15169'],
  limit: 50,
};

test('providerStatusFromResult keeps status metadata without raw data', () => {
  const result = providerResult('censys', 'quota_exceeded', [{ raw: 'not persisted' }], {
    fetchedAt: now,
    cacheAgeSeconds: 3600,
    warnings: ['Censys quota exceeded'],
  });

  assert.deepEqual(providerStatusFromResult(result), {
    provider: 'censys',
    status: 'quota_exceeded',
    fetchedAt: now,
    cacheAgeSeconds: 3600,
    resultCount: 1,
    warnings: ['Censys quota exceeded'],
  });
});

test('buildCandidatesFromProviderResults merges fresh and cached evidence into scored candidates', () => {
  const providerResults = [
    providerResult('ct_logs', 'ok', [{
      kind: 'subdomain',
      value: 'vpn.example.com',
      evidence: [{ type: 'certificate_match', value: 'vpn.example.com', observedAt: now }],
    }], { fetchedAt: now }),
    providerResult('shodan', 'ok', [{
      kind: 'ip',
      value: '8.8.8.8',
      evidence: [
        { type: 'hostname_match', value: 'vpn.example.com', observedAt: now },
        { type: 'asn_match', value: 'AS15169', observedAt: now },
        { type: 'open_service', value: '8.8.8.8:3389/tcp Microsoft RDP', observedAt: now },
      ],
    }], { fetchedAt: now }),
    providerResult('censys', 'cache_only', [{
      kind: 'ip',
      value: '8.8.8.8',
      evidence: [{ type: 'cve', value: 'CVE-2026-0001', observedAt: '2026-07-12T12:00:00.000Z' }],
    }], { fetchedAt: '2026-07-12T12:00:00.000Z', cacheAgeSeconds: 86400 }),
  ];

  const candidates = buildCandidatesFromProviderResults(profileFixture, providerResults, null, now);
  const vpn = candidates.find((candidate) => candidate.normalizedValue === 'vpn.example.com');
  const ip = candidates.find((candidate) => candidate.normalizedValue === '8.8.8.8');

  assert.equal(vpn.kind, 'subdomain');
  assert.equal(vpn.confidenceLevel, 'high');
  assert.equal(vpn.status, 'new');
  assert.equal(ip.risk, 'critical');
  assert.equal(ip.confidenceLevel, 'high');
  assert.ok(ip.evidence.some((item) => item.sourceStatus === 'cached'));
  assert.ok(ip.reasons.some((reason) => reason.includes('cached evidence')));
});

test('summarizeDiscoveryCandidates counts confidence, risk, status and provider health', () => {
  const providerStatuses = [
    providerStatusFromResult(providerResult('shodan', 'ok', [1, 2], { fetchedAt: now })),
    providerStatusFromResult(providerResult('censys', 'missing_key', [], { warnings: ['Censys key missing'] })),
  ];
  const candidates = buildCandidatesFromProviderResults(profileFixture, [
    providerResult('ct_logs', 'ok', [{
      kind: 'subdomain',
      value: 'login.example.com',
      evidence: [{ type: 'certificate_match', value: 'login.example.com', observedAt: now }],
    }], { fetchedAt: now }),
  ], null, now);

  const summary = summarizeDiscoveryCandidates(candidates, providerStatuses);
  assert.equal(summary.totalCandidates, 1);
  assert.equal(summary.byConfidence.high, 1);
  assert.equal(summary.byRisk.unknown, 1);
  assert.equal(summary.newCandidates, 1);
  assert.equal(summary.providerStatuses[1].status, 'missing_key');
});

test('diffDiscoverySnapshots detects candidate and provider status changes', () => {
  const previous = [{
    id: 'cand-old',
    kind: 'subdomain',
    normalizedValue: 'old.example.com',
    confidence: 80,
    risk: 'low',
    evidence: [],
  }, {
    id: 'cand-risk',
    kind: 'ip',
    normalizedValue: '8.8.8.8',
    confidence: 60,
    risk: 'low',
    evidence: [],
  }];
  const current = [{
    id: 'cand-risk',
    kind: 'ip',
    normalizedValue: '8.8.8.8',
    confidence: 85,
    risk: 'critical',
    evidence: [{ provider: 'shodan', type: 'cve', value: 'CVE-2026-0001' }],
  }, {
    id: 'cand-new',
    kind: 'subdomain',
    normalizedValue: 'new.example.com',
    confidence: 70,
    risk: 'unknown',
    evidence: [],
  }];

  const changes = diffDiscoverySnapshots({
    profileId: 'profile-1',
    snapshotId: 'snap-1',
    previous,
    current,
    providerStatuses: [providerStatusFromResult(providerResult('censys', 'quota_exceeded', [], { fetchedAt: now }))],
    previousProviderStatuses: [providerStatusFromResult(providerResult('censys', 'ok', [1], { fetchedAt: now }))],
    detectedAt: now,
  });
  const types = changes.map((change) => change.type);

  assert.ok(types.includes('candidate_added'));
  assert.ok(types.includes('candidate_removed'));
  assert.ok(types.includes('risk_increased'));
  assert.ok(types.includes('confidence_increased'));
  assert.ok(types.includes('evidence_added'));
  assert.ok(types.includes('provider_status_changed'));
});

test('candidateToMonitorAssetInput maps candidates to Exposure Watchlist assets', () => {
  assert.deepEqual(candidateToMonitorAssetInput({
    kind: 'subdomain',
    value: 'vpn.example.com',
    normalizedValue: 'vpn.example.com',
    risk: 'high',
  }), {
    label: 'vpn.example.com',
    type: 'domain',
    value: 'vpn.example.com',
    limit: 50,
    activeValidation: false,
    scheduleEnabled: true,
  });

  assert.deepEqual(candidateToMonitorAssetInput({
    kind: 'asn',
    value: 'AS15169',
    normalizedValue: 'AS15169',
    risk: 'unknown',
  }).type, 'asn');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: FAIL with named export errors for `providerResult` and the other new functions.

- [ ] **Step 3: Add provider result, candidate, scoring, summary, diff, and monitor mapping functions**

Append these exports to `server/exposureDiscovery.js` after `createDiscoveryStore`:

```js
const PROVIDERS = new Set(['shodan', 'censys', 'ct_logs', 'dns_rdap_asn']);
const STATUSES = new Set(['ok', 'partial', 'missing_key', 'quota_exceeded', 'timeout', 'provider_error', 'cache_only']);
const RISK_ORDER = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

const hashId = (prefix, value) => `${prefix}_${crypto.createHash('sha256').update(value).digest('hex').slice(0, 16)}`;

export function providerResult(provider, status, data = [], options = {}) {
  if (!PROVIDERS.has(provider)) throw createDiscoveryError(500, `Unsupported discovery provider: ${provider}`);
  if (!STATUSES.has(status)) throw createDiscoveryError(500, `Unsupported discovery status: ${status}`);
  return {
    provider,
    status,
    fetchedAt: options.fetchedAt || null,
    cacheAgeSeconds: Number.isFinite(options.cacheAgeSeconds) ? options.cacheAgeSeconds : null,
    warnings: Array.isArray(options.warnings) ? options.warnings.map(String).slice(0, 10) : [],
    data: Array.isArray(data) ? data : [],
  };
}

export function providerStatusFromResult(result) {
  return {
    provider: result.provider,
    status: result.status,
    fetchedAt: result.fetchedAt || null,
    cacheAgeSeconds: result.cacheAgeSeconds ?? null,
    resultCount: Array.isArray(result.data) ? result.data.length : 0,
    warnings: Array.isArray(result.warnings) ? result.warnings : [],
  };
}

const normalizeCandidateValue = (kind, value) => {
  const text = cleanText(value, 512);
  if (kind === 'domain' || kind === 'subdomain') return text.toLowerCase();
  if (kind === 'asn') return normalizeAsn(text);
  return text;
};

const evidenceWeight = (evidence) => ({
  certificate_match: 45,
  hostname_match: 40,
  rdap_match: 30,
  asn_match: 25,
  org_match: 20,
  dns_resolution: 15,
  open_service: 10,
  cve: 5,
  banner: 5,
}[evidence.type] || 5);

const sourceMultiplier = (sourceStatus) => {
  if (sourceStatus === 'cached') return 0.75;
  if (sourceStatus === 'partial') return 0.9;
  return 1;
};

const confidenceLevel = (score) => {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
};

const riskFromEvidence = (evidence = []) => {
  const text = evidence.map((item) => `${item.type} ${item.value}`).join(' ').toLowerCase();
  if (/\bcve-\d{4}-\d+\b/i.test(text)) return { risk: 'critical', riskScore: 95 };
  if (/(3389|445|23)\/tcp|rdp|smb|telnet/.test(text)) return { risk: 'critical', riskScore: 90 };
  if (/(21|22|1433|3306|5900)\/tcp|ftp|ssh|mssql|mysql|vnc/.test(text)) return { risk: 'high', riskScore: 75 };
  if (/admin|login|dashboard|management|router|camera|printer|database/.test(text)) return { risk: 'high', riskScore: 72 };
  if (/open_service/.test(text)) return { risk: 'low', riskScore: 25 };
  return { risk: 'unknown', riskScore: 0 };
};

const candidateIdentity = (candidate) => `${candidate.kind}:${candidate.normalizedValue}`;

export function buildCandidatesFromProviderResults(profile, providerResults = [], previousSnapshot = null, now = new Date().toISOString()) {
  const previousCandidates = previousSnapshot?.candidates || [];
  const previousByIdentity = new Map(previousCandidates.map((candidate) => [candidateIdentity(candidate), candidate]));
  const byIdentity = new Map();

  for (const result of providerResults) {
    const sourceStatus = result.status === 'cache_only' ? 'cached' : result.status === 'partial' ? 'partial' : 'fresh';
    for (const item of result.data || []) {
      const kind = item.kind === 'domain' ? 'domain'
        : item.kind === 'subdomain' ? 'subdomain'
          : item.kind === 'cidr' ? 'cidr'
            : item.kind === 'asn' ? 'asn'
              : item.kind === 'shodan_query' ? 'shodan_query'
                : 'ip';
      const normalizedValue = normalizeCandidateValue(kind, item.value);
      const identity = `${kind}:${normalizedValue}`;
      const candidate = byIdentity.get(identity) || {
        id: previousByIdentity.get(identity)?.id || hashId('cand', `${profile.id}:${identity}`),
        profileId: profile.id,
        kind,
        value: String(item.value || normalizedValue),
        normalizedValue,
        confidence: 0,
        confidenceLevel: 'low',
        risk: 'unknown',
        riskScore: 0,
        status: previousByIdentity.has(identity) ? 'seen' : 'new',
        evidence: [],
        reasons: [],
        firstSeenAt: previousByIdentity.get(identity)?.firstSeenAt || now,
        lastSeenAt: now,
        monitorAssetId: previousByIdentity.get(identity)?.monitorAssetId || null,
      };

      for (const rawEvidence of item.evidence || []) {
        const evidence = {
          provider: result.provider,
          type: rawEvidence.type,
          value: String(rawEvidence.value || ''),
          observedAt: rawEvidence.observedAt || result.fetchedAt || null,
          sourceStatus,
          weight: Math.round(evidenceWeight(rawEvidence) * sourceMultiplier(sourceStatus)),
        };
        candidate.evidence.push(evidence);
      }
      byIdentity.set(identity, candidate);
    }
  }

  return Array.from(byIdentity.values()).map((candidate) => {
    const confidence = Math.min(100, candidate.evidence.reduce((sum, evidence) => sum + evidence.weight, 0));
    const risk = riskFromEvidence(candidate.evidence);
    const reasons = [];
    if (candidate.evidence.some((item) => item.type === 'certificate_match')) reasons.push('Certificate evidence links this asset to the profile domain.');
    if (candidate.evidence.some((item) => item.type === 'hostname_match')) reasons.push('Hostname evidence links this asset to the profile domain.');
    if (candidate.evidence.some((item) => item.type === 'asn_match')) reasons.push('ASN evidence matches the profile.');
    if (candidate.evidence.some((item) => item.sourceStatus === 'cached')) reasons.push('Confidence reduced because some evidence is cached evidence.');
    if (candidate.evidence.length === 1) reasons.push('Single-source evidence requires analyst review.');
    if (risk.risk !== 'unknown') reasons.push(`Exposure risk is ${risk.risk}.`);

    return {
      ...candidate,
      confidence,
      confidenceLevel: confidenceLevel(confidence),
      risk: risk.risk,
      riskScore: risk.riskScore,
      reasons,
    };
  }).sort((a, b) => {
    const statusDelta = Number(b.status === 'new') - Number(a.status === 'new');
    if (statusDelta !== 0) return statusDelta;
    const riskDelta = RISK_ORDER[b.risk] - RISK_ORDER[a.risk];
    if (riskDelta !== 0) return riskDelta;
    return b.confidence - a.confidence;
  });
}

export function summarizeDiscoveryCandidates(candidates = [], providerStatuses = []) {
  const byConfidence = { high: 0, medium: 0, low: 0 };
  const byRisk = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const candidate of candidates) {
    if (byConfidence[candidate.confidenceLevel] !== undefined) byConfidence[candidate.confidenceLevel] += 1;
    if (byRisk[candidate.risk] !== undefined) byRisk[candidate.risk] += 1;
  }
  return {
    totalCandidates: candidates.length,
    byConfidence,
    byRisk,
    newCandidates: candidates.filter((candidate) => candidate.status === 'new').length,
    changedCandidates: candidates.filter((candidate) => candidate.status === 'changed').length,
    removedCandidates: candidates.filter((candidate) => candidate.status === 'removed').length,
    approvedCandidates: candidates.filter((candidate) => candidate.status === 'approved').length,
    providerStatuses,
  };
}

const change = ({ profileId, snapshotId, detectedAt, severity, type, title, description, candidateId = null, previous = null, current = null }) => ({
  id: newId('dchg'),
  profileId,
  snapshotId,
  detectedAt,
  severity,
  type,
  title,
  description,
  candidateId,
  previous,
  current,
});

export function diffDiscoverySnapshots({
  profileId,
  snapshotId,
  previous,
  current,
  providerStatuses = [],
  previousProviderStatuses = [],
  detectedAt = new Date().toISOString(),
}) {
  if (!previous) {
    return current.length ? [change({
      profileId,
      snapshotId,
      detectedAt,
      severity: 'info',
      type: 'candidate_changed',
      title: 'Baseline discovery snapshot created',
      description: `${current.length} candidate assets captured as the initial discovery baseline.`,
      current: { candidates: current.length },
    })] : [];
  }

  const changes = [];
  const previousMap = new Map(previous.map((candidate) => [candidateIdentity(candidate), candidate]));
  const currentMap = new Map(current.map((candidate) => [candidateIdentity(candidate), candidate]));

  for (const [identity, currentCandidate] of currentMap) {
    const previousCandidate = previousMap.get(identity);
    if (!previousCandidate) {
      changes.push(change({
        profileId,
        snapshotId,
        detectedAt,
        severity: currentCandidate.risk === 'critical' ? 'critical' : currentCandidate.risk === 'high' ? 'high' : 'info',
        type: 'candidate_added',
        title: 'Candidate added',
        description: `${currentCandidate.normalizedValue} appeared in discovery results.`,
        candidateId: currentCandidate.id,
        current: currentCandidate,
      }));
      continue;
    }
    if (RISK_ORDER[currentCandidate.risk] > RISK_ORDER[previousCandidate.risk]) {
      changes.push(change({
        profileId,
        snapshotId,
        detectedAt,
        severity: currentCandidate.risk === 'critical' ? 'critical' : 'high',
        type: 'risk_increased',
        title: 'Candidate risk increased',
        description: `${currentCandidate.normalizedValue} changed from ${previousCandidate.risk} to ${currentCandidate.risk}.`,
        candidateId: currentCandidate.id,
        previous: previousCandidate.risk,
        current: currentCandidate.risk,
      }));
    }
    if (currentCandidate.confidence > previousCandidate.confidence) {
      changes.push(change({
        profileId,
        snapshotId,
        detectedAt,
        severity: 'info',
        type: 'confidence_increased',
        title: 'Candidate confidence increased',
        description: `${currentCandidate.normalizedValue} confidence changed from ${previousCandidate.confidence} to ${currentCandidate.confidence}.`,
        candidateId: currentCandidate.id,
        previous: previousCandidate.confidence,
        current: currentCandidate.confidence,
      }));
    } else if (currentCandidate.confidence < previousCandidate.confidence) {
      changes.push(change({
        profileId,
        snapshotId,
        detectedAt,
        severity: 'low',
        type: 'confidence_decreased',
        title: 'Candidate confidence decreased',
        description: `${currentCandidate.normalizedValue} confidence changed from ${previousCandidate.confidence} to ${currentCandidate.confidence}.`,
        candidateId: currentCandidate.id,
        previous: previousCandidate.confidence,
        current: currentCandidate.confidence,
      }));
    }
    const previousEvidence = new Set((previousCandidate.evidence || []).map((item) => `${item.provider}:${item.type}:${item.value}`));
    for (const evidence of currentCandidate.evidence || []) {
      const key = `${evidence.provider}:${evidence.type}:${evidence.value}`;
      if (!previousEvidence.has(key)) {
        changes.push(change({
          profileId,
          snapshotId,
          detectedAt,
          severity: evidence.type === 'cve' ? 'critical' : 'info',
          type: evidence.sourceStatus === 'cached' ? 'evidence_stale' : 'evidence_added',
          title: evidence.sourceStatus === 'cached' ? 'Cached evidence used' : 'Evidence added',
          description: `${evidence.provider} ${evidence.type} evidence recorded for ${currentCandidate.normalizedValue}.`,
          candidateId: currentCandidate.id,
          current: evidence,
        }));
      }
    }
  }

  for (const [identity, previousCandidate] of previousMap) {
    if (!currentMap.has(identity)) {
      changes.push(change({
        profileId,
        snapshotId,
        detectedAt,
        severity: 'low',
        type: 'candidate_removed',
        title: 'Candidate removed',
        description: `${previousCandidate.normalizedValue} no longer appears in discovery results.`,
        candidateId: previousCandidate.id,
        previous: previousCandidate,
      }));
    }
  }

  const previousStatusByProvider = new Map(previousProviderStatuses.map((status) => [status.provider, status.status]));
  for (const status of providerStatuses) {
    if (previousStatusByProvider.has(status.provider) && previousStatusByProvider.get(status.provider) !== status.status) {
      changes.push(change({
        profileId,
        snapshotId,
        detectedAt,
        severity: status.status === 'ok' ? 'info' : 'low',
        type: 'provider_status_changed',
        title: 'Provider status changed',
        description: `${status.provider} changed from ${previousStatusByProvider.get(status.provider)} to ${status.status}.`,
        previous: previousStatusByProvider.get(status.provider),
        current: status.status,
      }));
    }
  }

  return changes;
}

export function candidateToMonitorAssetInput(candidate) {
  const value = candidate.normalizedValue || candidate.value;
  const type = candidate.kind === 'subdomain' ? 'domain' : candidate.kind;
  return {
    label: String(value).slice(0, 80),
    type,
    value,
    limit: 50,
    activeValidation: false,
    scheduleEnabled: true,
  };
}
```

- [ ] **Step 4: Run targeted backend tests**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: PASS for all tests in `server/test/exposureDiscovery.test.js`.

- [ ] **Step 5: Commit**

```bash
git add server/exposureDiscovery.js server/test/exposureDiscovery.test.js
git commit -m "feat: score exposure discovery candidates"
```

---

### Task 3: Passive Collectors And Discovery Snapshot Runs

**Files:**

- Modify: `server/exposureDiscovery.js`
- Modify: `server/test/exposureDiscovery.test.js`

**Interfaces:**

- Consumes:
  - `providerResult`
  - `providerStatusFromResult`
  - `buildCandidatesFromProviderResults`
  - `diffDiscoverySnapshots`
  - `summarizeDiscoveryCandidates`
- Produces:
  - `collectShodanDiscovery(profile, deps): Promise<DiscoveryProviderResult>`
  - `collectCensysDiscovery(profile, deps): Promise<DiscoveryProviderResult>`
  - `collectCtLogsDiscovery(profile, deps): Promise<DiscoveryProviderResult>`
  - `collectDnsRdapAsnDiscovery(profile, deps): Promise<DiscoveryProviderResult>`
  - `runDiscoverySnapshot({ store, profileId, ownerId, now, deps, collectors }): Promise<DiscoverySnapshot>`

- [ ] **Step 1: Add failing collector and snapshot tests**

Append these tests to `server/test/exposureDiscovery.test.js`:

```js
import {
  collectCensysDiscovery,
  collectCtLogsDiscovery,
  collectDnsRdapAsnDiscovery,
  collectShodanDiscovery,
  runDiscoverySnapshot,
} from '../exposureDiscovery.js';

test('collectShodanDiscovery returns partial data when one query fails', async () => {
  const calls = [];
  const axiosClient = {
    async get(url, options) {
      calls.push({ url, options });
      if (options.params.query.includes('org:')) {
        const error = new Error('quota');
        error.response = { status: 429 };
        throw error;
      }
      return {
        data: {
          matches: [{
            ip_str: '8.8.8.8',
            hostnames: ['vpn.example.com'],
            org: 'Example Inc',
            asn: 'AS15169',
            port: 3389,
            transport: 'tcp',
            product: 'Microsoft RDP',
            vulns: { 'CVE-2026-0001': {} },
            timestamp: now,
          }],
        },
      };
    },
  };

  const result = await collectShodanDiscovery(profileFixture, { axiosClient, shodanApiKey: 'key' });
  assert.equal(result.provider, 'shodan');
  assert.equal(result.status, 'partial');
  assert.equal(result.data.length > 0, true);
  assert.ok(result.warnings.some((warning) => warning.includes('quota')));
  assert.equal(calls.length >= 2, true);
});

test('collectShodanDiscovery returns missing_key without throwing', async () => {
  const result = await collectShodanDiscovery(profileFixture, { axiosClient: { get: async () => ({}) }, shodanApiKey: '' });
  assert.equal(result.status, 'missing_key');
  assert.equal(result.data.length, 0);
});

test('collectCensysDiscovery is fail-soft when key is missing', async () => {
  const result = await collectCensysDiscovery(profileFixture, { axiosClient: { get: async () => ({}) }, censysApiKey: '' });
  assert.equal(result.provider, 'censys');
  assert.equal(result.status, 'missing_key');
});

test('collectCtLogsDiscovery parses crt.sh name_value records', async () => {
  const axiosClient = {
    async get(url) {
      assert.equal(url, 'https://crt.sh/');
      return {
        data: [
          { name_value: 'www.example.com\\napi.example.com', entry_timestamp: now },
          { name_value: '*.ignored.example.com', entry_timestamp: now },
        ],
      };
    },
  };

  const result = await collectCtLogsDiscovery(profileFixture, { axiosClient });
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.data.map((item) => item.value).sort(), ['api.example.com', 'www.example.com']);
});

test('collectDnsRdapAsnDiscovery resolves primary domain and records ASN evidence', async () => {
  const dnsClient = {
    async resolve4(domain) {
      assert.equal(domain, 'example.com');
      return ['8.8.8.8'];
    },
    async resolve6() {
      return [];
    },
  };
  const result = await collectDnsRdapAsnDiscovery(profileFixture, { dnsClient });
  assert.equal(result.status, 'ok');
  assert.ok(result.data.some((item) => item.kind === 'ip' && item.value === '8.8.8.8'));
  assert.ok(result.data.some((item) => item.kind === 'asn' && item.value === 'AS15169'));
});

test('runDiscoverySnapshot stores partial snapshots and reuses previous snapshot evidence when collectors fail', async () => {
  const store = memoryDiscoveryStore();
  const profile = store.createProfile(owner, {
    label: 'Example',
    primaryDomain: 'example.com',
    legalName: 'Example Inc',
    asns: ['AS15169'],
    notes: '',
    limit: 50,
  }, now);

  const first = await runDiscoverySnapshot({
    store,
    profileId: profile.id,
    ownerId: 'user-1',
    now: new Date(now),
    deps: {},
    collectors: [
      async () => providerResult('ct_logs', 'ok', [{
        kind: 'subdomain',
        value: 'vpn.example.com',
        evidence: [{ type: 'certificate_match', value: 'vpn.example.com', observedAt: now }],
      }], { fetchedAt: now }),
    ],
  });

  assert.equal(first.status, 'success');
  assert.equal(first.candidates.length, 1);

  const second = await runDiscoverySnapshot({
    store,
    profileId: profile.id,
    ownerId: 'user-1',
    now: new Date('2026-07-13T13:00:00.000Z'),
    deps: {},
    collectors: [
      async () => providerResult('ct_logs', 'timeout', [], { warnings: ['CT logs timeout'] }),
    ],
  });

  assert.equal(second.status, 'cache_only');
  assert.equal(second.candidates.length, 1);
  assert.equal(second.candidates[0].evidence[0].sourceStatus, 'cached');
  assert.equal(store.getProfile('user-1', profile.id).lastStatus, 'cache_only');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: FAIL with named export errors for `collectShodanDiscovery`.

- [ ] **Step 3: Implement collectors and snapshot orchestration**

Append these functions to `server/exposureDiscovery.js`:

```js
const providerErrorStatus = (error) => {
  const status = error?.response?.status;
  if (status === 401 || status === 403) return 'missing_key';
  if (status === 402 || status === 429) return 'quota_exceeded';
  if (error?.code === 'ECONNABORTED' || /timeout/i.test(error?.message || '')) return 'timeout';
  return 'provider_error';
};

const quoteShodan = (value) => String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

const shodanQueriesForProfile = (profile) => {
  const queries = [
    `hostname:"${quoteShodan(profile.primaryDomain)}"`,
    `ssl.cert.subject.cn:"${quoteShodan(profile.primaryDomain)}"`,
  ];
  if (profile.legalName) queries.push(`org:"${quoteShodan(profile.legalName)}"`);
  for (const asn of profile.asns || []) queries.push(`asn:"${quoteShodan(asn)}"`);
  return Array.from(new Set(queries));
};

const cveIds = (value) => {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === 'object') return Object.keys(value);
  return [];
};

const shodanMatchToDiscoveryItems = (match, profile) => {
  const ip = match.ip_str || match.ip;
  const hostnames = Array.isArray(match.hostnames) ? match.hostnames : [];
  const items = [];
  for (const hostname of hostnames.filter((name) => String(name).endsWith(profile.primaryDomain))) {
    items.push({
      kind: hostname === profile.primaryDomain ? 'domain' : 'subdomain',
      value: hostname,
      evidence: [{ type: 'hostname_match', value: hostname, observedAt: match.timestamp || null }],
    });
  }
  if (ip) {
    const evidence = [];
    for (const hostname of hostnames) evidence.push({ type: 'hostname_match', value: hostname, observedAt: match.timestamp || null });
    if (match.asn && profile.asns?.includes(match.asn)) evidence.push({ type: 'asn_match', value: match.asn, observedAt: match.timestamp || null });
    if (profile.legalName && match.org && String(match.org).toLowerCase().includes(profile.legalName.toLowerCase())) {
      evidence.push({ type: 'org_match', value: match.org, observedAt: match.timestamp || null });
    }
    if (match.port) {
      evidence.push({
        type: 'open_service',
        value: `${ip}:${match.port}/${match.transport || 'tcp'} ${match.product || match._shodan?.module || ''}`.trim(),
        observedAt: match.timestamp || null,
      });
    }
    for (const cve of cveIds(match.vulns)) evidence.push({ type: 'cve', value: cve, observedAt: match.timestamp || null });
    if (match.data) evidence.push({ type: 'banner', value: String(match.data).slice(0, 200), observedAt: match.timestamp || null });
    items.push({ kind: 'ip', value: ip, evidence });
  }
  return items;
};

export async function collectShodanDiscovery(profile, deps = {}) {
  const { axiosClient, shodanApiKey } = deps;
  if (!shodanApiKey) return providerResult('shodan', 'missing_key', [], { warnings: ['Shodan API key missing'] });
  if (!axiosClient?.get) return providerResult('shodan', 'provider_error', [], { warnings: ['HTTP client unavailable'] });

  const data = [];
  const warnings = [];
  const failureStatuses = [];
  const fetchedAt = new Date().toISOString();
  const perQueryLimit = Math.max(1, Math.ceil(profile.limit / shodanQueriesForProfile(profile).length));

  for (const query of shodanQueriesForProfile(profile)) {
    try {
      const response = await axiosClient.get('https://api.shodan.io/shodan/host/search', {
        params: { key: shodanApiKey, query, limit: perQueryLimit },
        timeout: 15000,
      });
      for (const match of response.data?.matches || []) data.push(...shodanMatchToDiscoveryItems(match, profile));
    } catch (error) {
      const failureStatus = providerErrorStatus(error);
      failureStatuses.push(failureStatus);
      warnings.push(`Shodan ${failureStatus} for ${query}`);
    }
  }

  const failedStatus = failureStatuses.includes('quota_exceeded') ? 'quota_exceeded'
    : failureStatuses.includes('timeout') ? 'timeout'
      : failureStatuses.includes('missing_key') ? 'missing_key'
        : failureStatuses[0] || 'provider_error';
  const status = warnings.length && data.length ? 'partial' : warnings.length ? failedStatus : 'ok';
  return providerResult('shodan', status, data.slice(0, profile.limit), { fetchedAt, warnings });
}

export async function collectCensysDiscovery(profile, deps = {}) {
  const { axiosClient, censysApiKey } = deps;
  if (!censysApiKey) return providerResult('censys', 'missing_key', [], { warnings: ['Censys API key missing'] });
  if (!axiosClient?.get) return providerResult('censys', 'provider_error', [], { warnings: ['HTTP client unavailable'] });

  const fetchedAt = new Date().toISOString();
  try {
    const response = await axiosClient.get('https://api.platform.censys.io/v3/global/search/query', {
      headers: { Authorization: `Bearer ${censysApiKey}`, Accept: 'application/json' },
      params: { q: `dns.names: ${profile.primaryDomain}`, per_page: Math.min(profile.limit, 100) },
      timeout: 15000,
    });
    const hits = response.data?.result?.hits || response.data?.hits || [];
    const data = hits.flatMap((hit) => {
      const ip = hit.ip || hit.resource?.ip;
      const names = hit.dns?.names || hit.resource?.dns?.names || [];
      const evidence = names.map((name) => ({ type: 'hostname_match', value: name, observedAt: fetchedAt }));
      if (ip) evidence.push({ type: 'dns_resolution', value: ip, observedAt: fetchedAt });
      return ip ? [{ kind: 'ip', value: ip, evidence }] : names.map((name) => ({
        kind: String(name).endsWith(profile.primaryDomain) && name !== profile.primaryDomain ? 'subdomain' : 'domain',
        value: name,
        evidence: [{ type: 'hostname_match', value: name, observedAt: fetchedAt }],
      }));
    });
    return providerResult('censys', 'ok', data.slice(0, profile.limit), { fetchedAt });
  } catch (error) {
    return providerResult('censys', providerErrorStatus(error), [], {
      fetchedAt,
      warnings: [`Censys ${providerErrorStatus(error)}`],
    });
  }
}

export async function collectCtLogsDiscovery(profile, deps = {}) {
  const { axiosClient } = deps;
  if (!axiosClient?.get) return providerResult('ct_logs', 'provider_error', [], { warnings: ['HTTP client unavailable'] });
  const fetchedAt = new Date().toISOString();
  try {
    const response = await axiosClient.get('https://crt.sh/', {
      params: { q: `%.${profile.primaryDomain}`, output: 'json' },
      timeout: 15000,
    });
    const names = new Set();
    for (const cert of Array.isArray(response.data) ? response.data : []) {
      for (const rawName of String(cert.name_value || '').split(/\n+/)) {
        const name = rawName.trim().toLowerCase();
        if (!name || name.startsWith('*.')) continue;
        if (name === profile.primaryDomain || name.endsWith(`.${profile.primaryDomain}`)) names.add(name);
      }
    }
    const data = Array.from(names).slice(0, profile.limit).map((name) => ({
      kind: name === profile.primaryDomain ? 'domain' : 'subdomain',
      value: name,
      evidence: [{ type: 'certificate_match', value: name, observedAt: fetchedAt }],
    }));
    return providerResult('ct_logs', 'ok', data, { fetchedAt });
  } catch (error) {
    return providerResult('ct_logs', providerErrorStatus(error), [], {
      fetchedAt,
      warnings: [`CT logs ${providerErrorStatus(error)}`],
    });
  }
}

export async function collectDnsRdapAsnDiscovery(profile, deps = {}) {
  const dnsClient = deps.dnsClient;
  if (!dnsClient?.resolve4) return providerResult('dns_rdap_asn', 'provider_error', [], { warnings: ['DNS client unavailable'] });
  const fetchedAt = new Date().toISOString();
  const data = [];
  const warnings = [];
  try {
    const [aRecords, aaaaRecords] = await Promise.all([
      dnsClient.resolve4(profile.primaryDomain).catch((error) => {
        warnings.push(`DNS A lookup failed: ${error.message}`);
        return [];
      }),
      dnsClient.resolve6 ? dnsClient.resolve6(profile.primaryDomain).catch(() => []) : Promise.resolve([]),
    ]);
    for (const ip of [...aRecords, ...aaaaRecords]) {
      data.push({
        kind: 'ip',
        value: ip,
        evidence: [
          { type: 'dns_resolution', value: `${profile.primaryDomain} -> ${ip}`, observedAt: fetchedAt },
        ],
      });
    }
    for (const asn of profile.asns || []) {
      data.push({
        kind: 'asn',
        value: asn,
        evidence: [{ type: 'asn_match', value: asn, observedAt: fetchedAt }],
      });
    }
    return providerResult('dns_rdap_asn', warnings.length && data.length ? 'partial' : 'ok', data, { fetchedAt, warnings });
  } catch (error) {
    return providerResult('dns_rdap_asn', providerErrorStatus(error), [], {
      fetchedAt,
      warnings: [`DNS/RDAP/ASN ${providerErrorStatus(error)}`],
    });
  }
}

const defaultCollectors = [
  collectShodanDiscovery,
  collectCensysDiscovery,
  collectCtLogsDiscovery,
  collectDnsRdapAsnDiscovery,
];

const snapshotStatus = (providerResults, candidates, cacheUsed) => {
  const hasLive = providerResults.some((result) => ['ok', 'partial'].includes(result.status) && result.data.length > 0);
  const hasFailure = providerResults.some((result) => !['ok'].includes(result.status));
  if (hasLive && hasFailure) return 'partial';
  if (hasLive) return candidates.length ? 'success' : 'empty';
  if (cacheUsed && candidates.length) return 'cache_only';
  if (providerResults.some((result) => ['ok', 'partial'].includes(result.status))) return 'empty';
  return 'failed';
};

const cachedProviderResultsFromSnapshot = (snapshot, failedProviders) => {
  if (!snapshot?.candidates?.length) return [];
  const snapshotTime = snapshot.completedAt || snapshot.startedAt;
  const cacheAgeSeconds = Math.max(0, Math.floor((Date.now() - new Date(snapshotTime).getTime()) / 1000));
  const results = [];
  for (const provider of failedProviders) {
    const cachedData = snapshot.candidates
      .filter((candidate) => candidate.evidence?.some((evidence) => evidence.provider === provider))
      .map((candidate) => ({
        kind: candidate.kind,
        value: candidate.normalizedValue,
        evidence: candidate.evidence
          .filter((evidence) => evidence.provider === provider)
          .map((evidence) => ({
            type: evidence.type,
            value: evidence.value,
            observedAt: evidence.observedAt,
          })),
      }));
    if (cachedData.length) {
      results.push(providerResult(provider, 'cache_only', cachedData, {
        fetchedAt: snapshotTime,
        cacheAgeSeconds,
        warnings: [`Using cached ${provider} discovery evidence from previous snapshot`],
      }));
    }
  }
  return results;
};

export async function runDiscoverySnapshot({
  store,
  profileId,
  ownerId,
  now = new Date(),
  deps = {},
  collectors = defaultCollectors,
}) {
  const profile = store.getProfile(ownerId, profileId);
  const startedAt = now.toISOString();
  const snapshotId = newId('dsnap');
  store.updateProfileState(ownerId, profileId, { lastStatus: 'running', lastError: null });
  const previousSnapshot = store.latestSnapshot(ownerId, profileId);
  const providerResults = [];

  for (const collector of collectors) {
    try {
      providerResults.push(await collector(profile, deps));
    } catch (error) {
      providerResults.push(providerResult('ct_logs', 'provider_error', [], { warnings: [error.message || 'Discovery collector failed'] }));
    }
  }

  const failedProviders = new Set(providerResults.filter((result) => !['ok', 'partial'].includes(result.status)).map((result) => result.provider));
  const cachedResults = cachedProviderResultsFromSnapshot(previousSnapshot, failedProviders);
  const effectiveResults = [...providerResults, ...cachedResults];
  const candidates = buildCandidatesFromProviderResults(profile, effectiveResults, previousSnapshot, startedAt);
  const providerStatuses = effectiveResults.map(providerStatusFromResult);
  const previousProviderStatuses = previousSnapshot?.providerStatuses || [];
  const status = snapshotStatus(providerResults, candidates, cachedResults.length > 0);
  const summary = summarizeDiscoveryCandidates(candidates, providerStatuses);
  const changes = diffDiscoverySnapshots({
    profileId,
    snapshotId,
    previous: previousSnapshot?.candidates || null,
    current: candidates,
    providerStatuses,
    previousProviderStatuses,
    detectedAt: new Date().toISOString(),
  });
  const warnings = effectiveResults.flatMap((result) => result.warnings || []);
  const completedAt = new Date().toISOString();
  const snapshot = {
    id: snapshotId,
    profileId,
    ownerId,
    startedAt,
    completedAt,
    status,
    error: status === 'failed' ? 'No discovery provider returned data and no cached evidence is available' : null,
    providerStatuses,
    summary,
    candidates,
    changes,
    warnings,
  };

  store.addSnapshot(snapshot);
  store.updateProfileState(ownerId, profileId, {
    lastRunAt: completedAt,
    lastStatus: status,
    lastError: snapshot.error,
    lastSnapshotId: snapshot.id,
    lastSummary: summary,
  });
  return snapshot;
}
```

- [ ] **Step 4: Run targeted backend tests**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: PASS for all Discovery tests.

- [ ] **Step 5: Run existing backend regression tests**

Run:

```bash
npm run test:server
```

Expected: PASS for all `server/test/*.test.js` files.

- [ ] **Step 6: Commit**

```bash
git add server/exposureDiscovery.js server/test/exposureDiscovery.test.js
git commit -m "feat: run passive exposure discovery snapshots"
```

---

### Task 4: Premium Discovery API Routes And Candidate Approval

**Files:**

- Modify: `server/exposureDiscovery.js`
- Modify: `server/test/exposureDiscovery.test.js`
- Modify: `server/index.js`

**Interfaces:**

- Consumes:
  - `createDiscoveryStore`
  - `runDiscoverySnapshot`
  - `candidateToMonitorAssetInput`
  - existing `createWatchlistStore().createAsset(owner, input)`
- Produces:
  - `createDiscoveryStore().latestCandidates(ownerId, profileId): DiscoveryCandidate[]`
  - `createDiscoveryStore().updateCandidateStatus(ownerId, profileId, candidateId, patch): DiscoveryCandidate`
  - Express routes under `/api/exposure-discovery/*`

- [ ] **Step 1: Add failing store tests for candidate approval state**

Append this test to `server/test/exposureDiscovery.test.js`:

```js
test('createDiscoveryStore updates latest candidate status with owner isolation', () => {
  const store = memoryDiscoveryStore();
  const profile = store.createProfile(owner, {
    label: 'Example',
    primaryDomain: 'example.com',
    legalName: '',
    asns: [],
    notes: '',
    limit: 50,
  }, now);

  store.addSnapshot({
    id: 'snap-1',
    profileId: profile.id,
    ownerId: 'user-1',
    startedAt: now,
    completedAt: now,
    status: 'success',
    error: null,
    providerStatuses: [],
    summary: { totalCandidates: 1, byConfidence: { high: 1, medium: 0, low: 0 }, byRisk: { critical: 0, high: 0, medium: 0, low: 0, unknown: 1 }, newCandidates: 1, changedCandidates: 0, removedCandidates: 0, approvedCandidates: 0, providerStatuses: [] },
    candidates: [{
      id: 'cand-1',
      profileId: profile.id,
      kind: 'subdomain',
      value: 'vpn.example.com',
      normalizedValue: 'vpn.example.com',
      confidence: 80,
      confidenceLevel: 'high',
      risk: 'unknown',
      riskScore: 0,
      status: 'new',
      evidence: [],
      reasons: [],
      firstSeenAt: now,
      lastSeenAt: now,
      monitorAssetId: null,
    }],
    changes: [],
    warnings: [],
  });

  assert.throws(() => store.updateCandidateStatus('user-2', profile.id, 'cand-1', { status: 'approved' }), /Profile not found/);
  const updated = store.updateCandidateStatus('user-1', profile.id, 'cand-1', { status: 'approved', monitorAssetId: 'asset-1' });
  assert.equal(updated.status, 'approved');
  assert.equal(updated.monitorAssetId, 'asset-1');
  assert.equal(store.latestCandidates('user-1', profile.id)[0].status, 'approved');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: FAIL with `store.updateCandidateStatus is not a function`.

- [ ] **Step 3: Add latest candidate store methods**

Inside the object returned by `createDiscoveryStore()` in `server/exposureDiscovery.js`, add these methods after `latestSnapshot(ownerId, profileId)`:

```js
    latestCandidates(ownerId, profileId) {
      return this.latestSnapshot(ownerId, profileId)?.candidates || [];
    },
    updateCandidateStatus(ownerId, profileId, candidateId, patch) {
      assertProfile(ownerId, profileId);
      const snapshot = this.latestSnapshot(ownerId, profileId);
      if (!snapshot) throw createDiscoveryError(404, 'Discovery snapshot not found');
      const candidate = (snapshot.candidates || []).find((item) => item.id === candidateId);
      if (!candidate) throw createDiscoveryError(404, 'Discovery candidate not found');
      Object.assign(candidate, {
        status: patch.status || candidate.status,
        monitorAssetId: patch.monitorAssetId === undefined ? candidate.monitorAssetId : patch.monitorAssetId,
      });
      snapshot.summary = summarizeDiscoveryCandidates(snapshot.candidates || [], snapshot.providerStatuses || []);
      saveSnapshots();
      return candidate;
    },
```

- [ ] **Step 4: Run Discovery store tests**

Run:

```bash
node --test server/test/exposureDiscovery.test.js
```

Expected: PASS.

- [ ] **Step 5: Wire Discovery imports, store, deps, and routes in `server/index.js`**

Modify the imports at the top of `server/index.js`:

```js
import { createDiscoveryStore, runDiscoverySnapshot, candidateToMonitorAssetInput } from './exposureDiscovery.js';
```

Add store paths after the Exposure Watchlist store:

```js
const DISCOVERY_PROFILES_PATH = path.join(__dirname, '.exposure-discovery-profiles.json');
const DISCOVERY_SNAPSHOTS_PATH = path.join(__dirname, '.exposure-discovery-snapshots.json');
const discoveryStore = createDiscoveryStore({
    profilesPath: DISCOVERY_PROFILES_PATH,
    snapshotsPath: DISCOVERY_SNAPSHOTS_PATH,
    readFileSync: fs.readFileSync,
    writeJsonAtomic,
});
```

Add this dependency builder after `buildExposureScanDeps(ownerId)`:

```js
function buildDiscoveryDeps(ownerId) {
    return {
        axiosClient: axios,
        dnsClient: dns.promises,
        shodanApiKey: getUserApiKey(ownerId, 'shodan') || process.env.SHODAN_API_KEY,
        censysApiKey: getUserApiKey(ownerId, 'censys') || process.env.CENSYS_API_KEY,
    };
}
```

Add these routes after the `/api/exposure-watchlist/changes` route:

```js
app.get('/api/exposure-discovery/profiles', requirePremium, (req, res) => {
    res.json({ profiles: discoveryStore.listProfiles(req.user.sub) });
});

app.post('/api/exposure-discovery/profiles', requirePremium, (req, res) => {
    try {
        const profile = discoveryStore.createProfile(req.user, req.body || {});
        res.status(201).json({ profile });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.patch('/api/exposure-discovery/profiles/:id', requirePremium, (req, res) => {
    try {
        const profile = discoveryStore.updateProfile(req.user.sub, req.params.id, req.body || {});
        res.json({ profile });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.delete('/api/exposure-discovery/profiles/:id', requirePremium, (req, res) => {
    const deleted = discoveryStore.deleteProfile(req.user.sub, req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Profile not found' });
    res.json({ ok: true });
});

app.post('/api/exposure-discovery/profiles/:id/run', requirePremium, scanLimiter, async (req, res) => {
    try {
        const snapshot = await runDiscoverySnapshot({
            store: discoveryStore,
            profileId: req.params.id,
            ownerId: req.user.sub,
            deps: buildDiscoveryDeps(req.user.sub),
        });
        res.json({ snapshot, profile: discoveryStore.getProfile(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-discovery/profiles/:id/snapshots', requirePremium, (req, res) => {
    try {
        res.json({ snapshots: discoveryStore.listSnapshots(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-discovery/profiles/:id/candidates', requirePremium, (req, res) => {
    try {
        res.json({ candidates: discoveryStore.latestCandidates(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.post('/api/exposure-discovery/profiles/:id/candidates/:candidateId/approve', requirePremium, (req, res) => {
    try {
        const candidate = discoveryStore.latestCandidates(req.user.sub, req.params.id)
            .find((item) => item.id === req.params.candidateId);
        if (!candidate) return res.status(404).json({ error: 'Discovery candidate not found' });
        if (candidate.monitorAssetId) {
            return res.json({ candidate, asset: exposureStore.getAsset(req.user.sub, candidate.monitorAssetId) });
        }
        const asset = exposureStore.createAsset(req.user, candidateToMonitorAssetInput(candidate));
        const updated = discoveryStore.updateCandidateStatus(req.user.sub, req.params.id, req.params.candidateId, {
            status: 'approved',
            monitorAssetId: asset.id,
        });
        res.status(201).json({ candidate: updated, asset });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.post('/api/exposure-discovery/profiles/:id/candidates/:candidateId/ignore', requirePremium, (req, res) => {
    try {
        const candidate = discoveryStore.updateCandidateStatus(req.user.sub, req.params.id, req.params.candidateId, {
            status: 'ignored',
        });
        res.json({ candidate });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});
```

- [ ] **Step 6: Run syntax and backend regression checks**

Run:

```bash
node --check server/index.js
npm run test:server
```

Expected:

- `node --check server/index.js`: no output and exit code 0.
- `npm run test:server`: PASS.

- [ ] **Step 7: Commit**

```bash
git add server/index.js server/exposureDiscovery.js server/test/exposureDiscovery.test.js
git commit -m "feat: expose discovery profile APIs"
```

---

### Task 5: Frontend API Types And Discovery Utilities

**Files:**

- Modify: `src/services/threatApi.ts`
- Create: `src/utils/exposureDiscovery.ts`
- Create: `src/utils/exposureDiscovery.test.ts`

**Interfaces:**

- Consumes: backend routes from Task 4.
- Produces:
  - `DiscoveryProfile`, `DiscoveryProfileInput`, `DiscoveryCandidate`, `DiscoverySnapshot`, `DiscoveryProviderStatus`, `DiscoverySummary`
  - `fetchDiscoveryProfiles()`
  - `createDiscoveryProfile(input)`
  - `updateDiscoveryProfile(id, input)`
  - `deleteDiscoveryProfile(id)`
  - `runDiscoveryProfile(id)`
  - `fetchDiscoverySnapshots(id)`
  - `fetchDiscoveryCandidates(id)`
  - `approveDiscoveryCandidate(profileId, candidateId)`
  - `ignoreDiscoveryCandidate(profileId, candidateId)`
  - `sortDiscoveryCandidates(candidates)`
  - `providerStatusLabel(status)`
  - `compactProviderWarnings(statuses)`

- [ ] **Step 1: Write failing frontend utility tests**

Create `src/utils/exposureDiscovery.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import {
  compactProviderWarnings,
  providerStatusLabel,
  sortDiscoveryCandidates,
} from "./exposureDiscovery";
import type { DiscoveryCandidate, DiscoveryProviderStatus } from "@/services/threatApi";

const candidate = (overrides: Partial<DiscoveryCandidate>): DiscoveryCandidate => ({
  id: "cand",
  profileId: "profile",
  kind: "ip",
  value: "8.8.8.8",
  normalizedValue: "8.8.8.8",
  confidence: 50,
  confidenceLevel: "medium",
  risk: "low",
  riskScore: 25,
  status: "seen",
  evidence: [],
  reasons: [],
  firstSeenAt: "2026-07-13T12:00:00.000Z",
  lastSeenAt: "2026-07-13T12:00:00.000Z",
  monitorAssetId: null,
  ...overrides,
});

test("sortDiscoveryCandidates prioritizes new critical high-confidence candidates", () => {
  const sorted = sortDiscoveryCandidates([
    candidate({ id: "low", status: "seen", risk: "low", confidence: 90 }),
    candidate({ id: "new-critical", status: "new", risk: "critical", confidence: 70 }),
    candidate({ id: "new-medium", status: "new", risk: "medium", confidence: 40 }),
  ]);

  assert.deepEqual(sorted.map((item) => item.id), ["new-critical", "new-medium", "low"]);
});

test("providerStatusLabel returns user-facing labels", () => {
  assert.equal(providerStatusLabel("ok"), "OK");
  assert.equal(providerStatusLabel("quota_exceeded"), "Quota exceeded");
  assert.equal(providerStatusLabel("missing_key"), "Missing key");
  assert.equal(providerStatusLabel("cache_only"), "Cache only");
});

test("compactProviderWarnings joins only non-ok provider statuses", () => {
  const statuses: DiscoveryProviderStatus[] = [
    { provider: "shodan", status: "ok", fetchedAt: null, cacheAgeSeconds: null, resultCount: 2, warnings: [] },
    { provider: "censys", status: "quota_exceeded", fetchedAt: null, cacheAgeSeconds: null, resultCount: 0, warnings: ["quota"] },
    { provider: "ct_logs", status: "timeout", fetchedAt: null, cacheAgeSeconds: null, resultCount: 0, warnings: [] },
  ];

  assert.equal(compactProviderWarnings(statuses), "censys: Quota exceeded | ct_logs: Timeout");
});
```

- [ ] **Step 2: Run utility test to verify it fails**

Run:

```bash
./node_modules/.bin/esbuild src/utils/exposureDiscovery.test.ts --bundle --platform=node --format=esm --outfile=/tmp/threatsumm4ry-exposure-discovery-test.js
node --test /tmp/threatsumm4ry-exposure-discovery-test.js
```

Expected: FAIL with an import error for `./exposureDiscovery`.

- [ ] **Step 3: Add frontend Discovery types and API helpers**

Append this section to `src/services/threatApi.ts` after the Exposure Watchlist API helpers:

```ts
export type DiscoveryProvider = "shodan" | "censys" | "ct_logs" | "dns_rdap_asn";
export type DiscoveryProviderResultStatus = "ok" | "partial" | "missing_key" | "quota_exceeded" | "timeout" | "provider_error" | "cache_only";
export type DiscoveryRunStatus = "never_run" | "running" | "success" | "partial" | "cache_only" | "empty" | "failed";
export type DiscoveryConfidenceLevel = "high" | "medium" | "low";
export type DiscoveryCandidateKind = "domain" | "subdomain" | "ip" | "cidr" | "asn" | "shodan_query";
export type DiscoveryCandidateStatus = "new" | "seen" | "changed" | "removed" | "approved" | "ignored";
export type DiscoveryRisk = AttackSurfaceRisk | "unknown";
export type DiscoveryEvidenceType = "hostname_match" | "certificate_match" | "org_match" | "asn_match" | "rdap_match" | "dns_resolution" | "open_service" | "cve" | "banner";
export type DiscoveryChangeType = "candidate_added" | "candidate_removed" | "candidate_changed" | "confidence_increased" | "confidence_decreased" | "risk_increased" | "risk_decreased" | "evidence_added" | "evidence_stale" | "provider_status_changed";

export interface DiscoveryProviderStatus {
    provider: DiscoveryProvider;
    status: DiscoveryProviderResultStatus;
    fetchedAt: string | null;
    cacheAgeSeconds: number | null;
    resultCount: number;
    warnings: string[];
}

export interface DiscoverySummary {
    totalCandidates: number;
    byConfidence: Record<DiscoveryConfidenceLevel, number>;
    byRisk: Record<DiscoveryRisk, number>;
    newCandidates: number;
    changedCandidates: number;
    removedCandidates: number;
    approvedCandidates: number;
    providerStatuses: DiscoveryProviderStatus[];
}

export interface DiscoveryProfile {
    id: string;
    ownerId: string;
    ownerLogin: string;
    label: string;
    primaryDomain: string;
    legalName: string | null;
    asns: string[];
    notes: string | null;
    limit: number;
    createdAt: string;
    updatedAt: string;
    lastRunAt: string | null;
    lastStatus: DiscoveryRunStatus;
    lastError: string | null;
    lastSnapshotId: string | null;
    lastSummary: DiscoverySummary | null;
}

export interface DiscoveryProfileInput {
    label: string;
    primaryDomain: string;
    legalName: string;
    asns: string[];
    notes: string;
    limit: number;
}

export interface DiscoveryEvidence {
    provider: DiscoveryProvider;
    type: DiscoveryEvidenceType;
    value: string;
    observedAt: string | null;
    sourceStatus: "fresh" | "cached" | "partial";
    weight: number;
}

export interface DiscoveryCandidate {
    id: string;
    profileId: string;
    kind: DiscoveryCandidateKind;
    value: string;
    normalizedValue: string;
    confidence: number;
    confidenceLevel: DiscoveryConfidenceLevel;
    risk: DiscoveryRisk;
    riskScore: number;
    status: DiscoveryCandidateStatus;
    evidence: DiscoveryEvidence[];
    reasons: string[];
    firstSeenAt: string;
    lastSeenAt: string;
    monitorAssetId: string | null;
}

export interface DiscoveryChange {
    id: string;
    profileId: string;
    snapshotId: string;
    detectedAt: string;
    severity: ExposureChangeSeverity;
    type: DiscoveryChangeType;
    title: string;
    description: string;
    candidateId: string | null;
    previous: unknown;
    current: unknown;
}

export interface DiscoverySnapshot {
    id: string;
    profileId: string;
    ownerId: string;
    startedAt: string;
    completedAt: string | null;
    status: Exclude<DiscoveryRunStatus, "never_run" | "running">;
    error: string | null;
    providerStatuses: DiscoveryProviderStatus[];
    summary: DiscoverySummary;
    candidates: DiscoveryCandidate[];
    changes: DiscoveryChange[];
    warnings: string[];
}

const discoveryError = async (response: Response): Promise<never> => {
    const body = await response.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `Exposure Discovery API error: ${response.status}`);
};

export const fetchDiscoveryProfiles = async (): Promise<DiscoveryProfile[]> => {
    const response = await fetch("/api/exposure-discovery/profiles");
    if (!response.ok) return discoveryError(response);
    return (await response.json()).profiles;
};

export const createDiscoveryProfile = async (input: DiscoveryProfileInput): Promise<DiscoveryProfile> => {
    const response = await fetch("/api/exposure-discovery/profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
    });
    if (!response.ok) return discoveryError(response);
    return (await response.json()).profile;
};

export const updateDiscoveryProfile = async (id: string, input: DiscoveryProfileInput): Promise<DiscoveryProfile> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
    });
    if (!response.ok) return discoveryError(response);
    return (await response.json()).profile;
};

export const deleteDiscoveryProfile = async (id: string): Promise<void> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) return discoveryError(response);
};

export const runDiscoveryProfile = async (id: string): Promise<{ snapshot: DiscoverySnapshot; profile: DiscoveryProfile }> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(id)}/run`, { method: "POST" });
    if (!response.ok) return discoveryError(response);
    return response.json();
};

export const fetchDiscoverySnapshots = async (id: string): Promise<DiscoverySnapshot[]> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(id)}/snapshots`);
    if (!response.ok) return discoveryError(response);
    return (await response.json()).snapshots;
};

export const fetchDiscoveryCandidates = async (id: string): Promise<DiscoveryCandidate[]> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(id)}/candidates`);
    if (!response.ok) return discoveryError(response);
    return (await response.json()).candidates;
};

export const approveDiscoveryCandidate = async (profileId: string, candidateId: string): Promise<{ candidate: DiscoveryCandidate; asset: ExposureAsset }> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(profileId)}/candidates/${encodeURIComponent(candidateId)}/approve`, { method: "POST" });
    if (!response.ok) return discoveryError(response);
    return response.json();
};

export const ignoreDiscoveryCandidate = async (profileId: string, candidateId: string): Promise<DiscoveryCandidate> => {
    const response = await fetch(`/api/exposure-discovery/profiles/${encodeURIComponent(profileId)}/candidates/${encodeURIComponent(candidateId)}/ignore`, { method: "POST" });
    if (!response.ok) return discoveryError(response);
    return (await response.json()).candidate;
};
```

- [ ] **Step 4: Add frontend Discovery utility implementation**

Create `src/utils/exposureDiscovery.ts`:

```ts
import type {
  DiscoveryCandidate,
  DiscoveryProviderResultStatus,
  DiscoveryProviderStatus,
  DiscoveryRisk,
} from "@/services/threatApi";

const riskRank: Record<DiscoveryRisk, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
};

const statusRank: Record<DiscoveryCandidate["status"], number> = {
  new: 5,
  changed: 4,
  seen: 3,
  removed: 2,
  ignored: 1,
  approved: 0,
};

export const sortDiscoveryCandidates = (candidates: DiscoveryCandidate[]): DiscoveryCandidate[] => (
  [...candidates].sort((a, b) => {
    const statusDelta = statusRank[b.status] - statusRank[a.status];
    if (statusDelta !== 0) return statusDelta;
    const riskDelta = riskRank[b.risk] - riskRank[a.risk];
    if (riskDelta !== 0) return riskDelta;
    return b.confidence - a.confidence;
  })
);

export const providerStatusLabel = (status: DiscoveryProviderResultStatus): string => ({
  ok: "OK",
  partial: "Partial",
  missing_key: "Missing key",
  quota_exceeded: "Quota exceeded",
  timeout: "Timeout",
  provider_error: "Provider error",
  cache_only: "Cache only",
}[status]);

export const compactProviderWarnings = (statuses: DiscoveryProviderStatus[]): string => (
  statuses
    .filter((status) => status.status !== "ok")
    .map((status) => `${status.provider}: ${providerStatusLabel(status.status)}`)
    .join(" | ")
);
```

- [ ] **Step 5: Run frontend utility tests**

Run:

```bash
./node_modules/.bin/esbuild src/utils/exposureDiscovery.test.ts --bundle --platform=node --format=esm --outfile=/tmp/threatsumm4ry-exposure-discovery-test.js
node --test /tmp/threatsumm4ry-exposure-discovery-test.js
```

Expected: PASS.

- [ ] **Step 6: Run typecheck**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/threatApi.ts src/utils/exposureDiscovery.ts src/utils/exposureDiscovery.test.ts
git commit -m "feat: add exposure discovery frontend API"
```

---

### Task 6: Discovery Tab UI And Attack Surface Hub Integration

**Files:**

- Create: `src/components/attack-surface/ExposureDiscoveryPanel.tsx`
- Modify: `src/pages/AttackSurface.tsx`

**Interfaces:**

- Consumes:
  - `fetchDiscoveryProfiles`
  - `createDiscoveryProfile`
  - `updateDiscoveryProfile`
  - `deleteDiscoveryProfile`
  - `runDiscoveryProfile`
  - `fetchDiscoverySnapshots`
  - `fetchDiscoveryCandidates`
  - `approveDiscoveryCandidate`
  - `ignoreDiscoveryCandidate`
  - `sortDiscoveryCandidates`
  - `providerStatusLabel`
  - `compactProviderWarnings`
- Produces:
  - `ExposureDiscoveryPanel` React component.
  - `/attack-surface?mode=discovery` tab state.

- [ ] **Step 1: Create `ExposureDiscoveryPanel.tsx`**

Create `src/components/attack-surface/ExposureDiscoveryPanel.tsx` with this component:

```tsx
import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, Check, Clock, Loader2, Lock, Play, Plus, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
import {
  approveDiscoveryCandidate,
  createDiscoveryProfile,
  deleteDiscoveryProfile,
  fetchDiscoveryCandidates,
  fetchDiscoveryProfiles,
  fetchDiscoverySnapshots,
  ignoreDiscoveryCandidate,
  runDiscoveryProfile,
  updateDiscoveryProfile,
  type DiscoveryCandidate,
  type DiscoveryProfile,
  type DiscoveryProfileInput,
  type DiscoverySnapshot,
} from "@/services/threatApi";
import {
  compactProviderWarnings,
  providerStatusLabel,
  sortDiscoveryCandidates,
} from "@/utils/exposureDiscovery";

const emptyProfile: DiscoveryProfileInput = {
  label: "",
  primaryDomain: "",
  legalName: "",
  asns: [],
  notes: "",
  limit: 50,
};

const riskTone: Record<string, string> = {
  critical: "border-destructive/40 bg-destructive/10 text-destructive",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-500",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-500",
  unknown: "border-border bg-muted text-muted-foreground",
};

const confidenceTone: Record<string, string> = {
  high: "border-emerald-500/40 bg-emerald-500/10 text-emerald-500",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  low: "border-muted bg-muted text-muted-foreground",
};

const parseAsns = (value: string) => value
  .split(/[,\s]+/)
  .map((item) => item.trim())
  .filter(Boolean);

const formatDate = (value: string | null) => {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

function DiscoveryMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="soc-panel rounded-lg p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-2 font-mono text-2xl font-bold tabular-nums">{value}</p>
    </div>
  );
}

export function ExposureDiscoveryPanel() {
  const { auth, loading: authLoading } = useAuth();
  const { language } = useLanguage();
  const pt = language === "pt";
  const canUseDiscovery = !authLoading && auth.authenticated && auth.isPremium;

  const [profiles, setProfiles] = useState<DiscoveryProfile[]>([]);
  const [snapshots, setSnapshots] = useState<DiscoverySnapshot[]>([]);
  const [candidates, setCandidates] = useState<DiscoveryCandidate[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [form, setForm] = useState<DiscoveryProfileInput>(emptyProfile);
  const [asnText, setAsnText] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [busyCandidateId, setBusyCandidateId] = useState<string | null>(null);

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.id === selectedProfileId) || null,
    [profiles, selectedProfileId],
  );

  const latestSnapshot = snapshots[0] || null;
  const sortedCandidates = useMemo(() => sortDiscoveryCandidates(candidates), [candidates]);
  const providerWarnings = latestSnapshot ? compactProviderWarnings(latestSnapshot.providerStatuses) : "";

  const loadProfiles = useCallback(async () => {
    if (!canUseDiscovery) return;
    setLoading(true);
    try {
      const profileList = await fetchDiscoveryProfiles();
      setProfiles(profileList);
      setSelectedProfileId((current) => current || profileList[0]?.id || null);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Exposure Discovery API error");
    } finally {
      setLoading(false);
    }
  }, [canUseDiscovery]);

  const loadProfileDetails = useCallback(async (profileId: string | null) => {
    if (!canUseDiscovery || !profileId) {
      setSnapshots([]);
      setCandidates([]);
      return;
    }
    try {
      const [snapshotList, candidateList] = await Promise.all([
        fetchDiscoverySnapshots(profileId),
        fetchDiscoveryCandidates(profileId),
      ]);
      setSnapshots(snapshotList);
      setCandidates(candidateList);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Discovery profile API error");
    }
  }, [canUseDiscovery]);

  useEffect(() => {
    if (!canUseDiscovery) {
      setProfiles([]);
      setSnapshots([]);
      setCandidates([]);
      setSelectedProfileId(null);
      return;
    }
    void loadProfiles();
  }, [canUseDiscovery, loadProfiles]);

  useEffect(() => {
    void loadProfileDetails(selectedProfileId);
  }, [selectedProfileId, loadProfileDetails]);

  const saveProfile = async () => {
    const input = { ...form, asns: parseAsns(asnText) };
    try {
      const saved = editingId
        ? await updateDiscoveryProfile(editingId, input)
        : await createDiscoveryProfile(input);
      toast.success(pt ? "Perfil salvo" : "Profile saved");
      setForm(emptyProfile);
      setAsnText("");
      setEditingId(null);
      setSelectedProfileId(saved.id);
      await loadProfiles();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to save discovery profile");
    }
  };

  const editProfile = (profile: DiscoveryProfile) => {
    setEditingId(profile.id);
    setForm({
      label: profile.label,
      primaryDomain: profile.primaryDomain,
      legalName: profile.legalName || "",
      asns: profile.asns,
      notes: profile.notes || "",
      limit: profile.limit,
    });
    setAsnText(profile.asns.join(", "));
  };

  const removeProfile = async (profile: DiscoveryProfile) => {
    try {
      await deleteDiscoveryProfile(profile.id);
      toast.success(pt ? "Perfil removido" : "Profile removed");
      setSelectedProfileId(null);
      await loadProfiles();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to delete profile");
    }
  };

  const runNow = async () => {
    if (!selectedProfileId) return;
    setRunning(true);
    try {
      const { snapshot, profile } = await runDiscoveryProfile(selectedProfileId);
      setProfiles((current) => current.map((item) => (item.id === profile.id ? profile : item)));
      await loadProfileDetails(selectedProfileId);
      if (snapshot.status === "partial" || snapshot.status === "cache_only") {
        toast.warning(pt ? "Discovery concluido com dados parciais/cache." : "Discovery completed with partial/cache data.");
      } else if (snapshot.status === "failed") {
        toast.error(snapshot.error || "Discovery failed");
      } else {
        toast.success(pt ? "Discovery finalizado" : "Discovery complete");
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Discovery failed");
    } finally {
      setRunning(false);
    }
  };

  const approve = async (candidate: DiscoveryCandidate) => {
    if (!selectedProfileId) return;
    setBusyCandidateId(candidate.id);
    try {
      const result = await approveDiscoveryCandidate(selectedProfileId, candidate.id);
      setCandidates((current) => current.map((item) => (item.id === candidate.id ? result.candidate : item)));
      toast.success(pt ? "Candidato adicionado ao Monitor" : "Candidate added to Monitor");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to approve candidate");
    } finally {
      setBusyCandidateId(null);
    }
  };

  const ignore = async (candidate: DiscoveryCandidate) => {
    if (!selectedProfileId) return;
    setBusyCandidateId(candidate.id);
    try {
      const updated = await ignoreDiscoveryCandidate(selectedProfileId, candidate.id);
      setCandidates((current) => current.map((item) => (item.id === candidate.id ? updated : item)));
      toast.success(pt ? "Candidato ignorado" : "Candidate ignored");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to ignore candidate");
    } finally {
      setBusyCandidateId(null);
    }
  };

  if (authLoading) {
    return (
      <div className="soc-panel rounded-lg p-6 text-sm text-muted-foreground">
        <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />
        {pt ? "Verificando acesso..." : "Checking access..."}
      </div>
    );
  }

  if (!canUseDiscovery) {
    return (
      <div className="soc-panel rounded-lg p-8 text-center">
        <Lock className="mx-auto h-9 w-9 text-muted-foreground/60" />
        <h2 className="mt-4 text-lg font-semibold">{pt ? "Discovery premium" : "Premium discovery"}</h2>
        <p className="mx-auto mt-2 max-w-xl text-sm text-muted-foreground">
          {pt
            ? "Entre com uma conta premium para criar perfis de empresa, rodar discovery passivo e revisar possivel Shadow IT."
            : "Sign in with premium access to create company profiles, run passive discovery, and review possible Shadow IT."}
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">Exposure Intelligence Discovery</h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            {pt
              ? "Crie perfis de empresa, rode discovery passivo e aprove candidatos antes de envia-los ao Monitor."
              : "Create company profiles, run passive discovery, and approve candidates before sending them to Monitor."}
          </p>
        </div>
        <div className="flex gap-2">
          <Button type="button" variant="outline" onClick={() => void loadProfiles()} disabled={loading} className="gap-2">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            {pt ? "Atualizar" : "Refresh"}
          </Button>
          <Button type="button" onClick={() => void runNow()} disabled={!selectedProfileId || running} className="gap-2">
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {pt ? "Rodar discovery" : "Run discovery"}
          </Button>
        </div>
      </div>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <DiscoveryMetric label={pt ? "Perfis" : "Profiles"} value={profiles.length} />
        <DiscoveryMetric label={pt ? "Candidatos" : "Candidates"} value={latestSnapshot?.summary.totalCandidates || 0} />
        <DiscoveryMetric label={pt ? "Alta confianca" : "High confidence"} value={latestSnapshot?.summary.byConfidence.high || 0} />
        <DiscoveryMetric label="Critical / High" value={(latestSnapshot?.summary.byRisk.critical || 0) + (latestSnapshot?.summary.byRisk.high || 0)} />
        <DiscoveryMetric label={pt ? "Novos" : "New"} value={latestSnapshot?.summary.newCandidates || 0} />
      </section>

      {providerWarnings && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-700 dark:text-amber-300">
          <AlertTriangle className="mr-2 inline h-4 w-4" />
          {providerWarnings}
        </div>
      )}

      <section className="grid gap-5 lg:grid-cols-[360px_1fr]">
        <div className="soc-panel rounded-lg p-4">
          <h3 className="flex items-center gap-2 text-base font-semibold">
            <Plus className="h-4 w-4 text-primary" />
            {editingId ? (pt ? "Editar perfil" : "Edit profile") : (pt ? "Novo perfil" : "New profile")}
          </h3>
          <div className="mt-4 flex flex-col gap-4">
            <label className="flex flex-col gap-1.5">
              <Label>Label</Label>
              <Input value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} />
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>{pt ? "Dominio principal" : "Primary domain"}</Label>
              <Input value={form.primaryDomain} placeholder="example.com" onChange={(event) => setForm({ ...form, primaryDomain: event.target.value })} />
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>{pt ? "Nome legal" : "Legal name"}</Label>
              <Input value={form.legalName} placeholder="Example Inc" onChange={(event) => setForm({ ...form, legalName: event.target.value })} />
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>ASNs</Label>
              <Input value={asnText} placeholder="AS15169, AS13335" onChange={(event) => setAsnText(event.target.value)} />
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>Limit</Label>
              <Input type="number" min={1} max={100} value={form.limit} onChange={(event) => setForm({ ...form, limit: Number(event.target.value) || 50 })} />
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>Notes</Label>
              <Textarea rows={3} value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} />
            </label>
            <Button type="button" onClick={() => void saveProfile()} disabled={!form.label.trim() || !form.primaryDomain.trim()}>
              {editingId ? (pt ? "Salvar alteracoes" : "Save changes") : (pt ? "Criar perfil" : "Create profile")}
            </Button>
          </div>
        </div>

        <div className="soc-panel min-w-0 rounded-lg">
          <div className="border-b border-border p-4">
            <h3 className="text-base font-semibold">{pt ? "Perfis salvos" : "Saved profiles"}</h3>
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Profile</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last run</TableHead>
                  <TableHead>Providers</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {profiles.map((profile) => (
                  <TableRow key={profile.id} className={cn(selectedProfileId === profile.id && "bg-muted/50")}>
                    <TableCell>
                      <button type="button" className="text-left" onClick={() => setSelectedProfileId(profile.id)}>
                        <span className="block font-medium">{profile.label}</span>
                        <span className="block max-w-64 truncate text-xs text-muted-foreground">{profile.primaryDomain}</span>
                      </button>
                    </TableCell>
                    <TableCell><Badge variant="secondary">{profile.lastStatus}</Badge></TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatDate(profile.lastRunAt)}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(profile.lastSummary?.providerStatuses || []).slice(0, 4).map((status) => (
                          <Badge key={status.provider} variant={status.status === "ok" ? "outline" : "secondary"} className="text-[10px]">
                            {status.provider}: {providerStatusLabel(status.status)}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button type="button" size="sm" variant="ghost" onClick={() => editProfile(profile)}>{pt ? "Editar" : "Edit"}</Button>
                        <Button type="button" size="icon" variant="ghost" aria-label="Delete profile" onClick={() => void removeProfile(profile)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {profiles.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">
                      {pt ? "Nenhum perfil cadastrado." : "No profiles saved."}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      </section>

      <section className="soc-panel rounded-lg">
        <div className="border-b border-border p-4">
          <h3 className="text-base font-semibold">{pt ? "Fila de revisao" : "Review queue"}</h3>
        </div>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Candidate</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Evidence</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedCandidates.map((candidate) => (
                <TableRow key={candidate.id} className="align-top">
                  <TableCell>
                    <div className="font-mono text-sm font-semibold">{candidate.normalizedValue}</div>
                    <div className="mt-1 text-xs uppercase text-muted-foreground">{candidate.kind}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={confidenceTone[candidate.confidenceLevel]}>{candidate.confidenceLevel}</Badge>
                    <div className="mt-1 font-mono text-[11px] text-muted-foreground">{candidate.confidence}/100</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={riskTone[candidate.risk]}>{candidate.risk}</Badge>
                    <div className="mt-1 font-mono text-[11px] text-muted-foreground">{candidate.riskScore}/100</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex max-w-xl flex-col gap-1">
                      {candidate.evidence.slice(0, 4).map((evidence) => (
                        <div key={`${candidate.id}:${evidence.provider}:${evidence.type}:${evidence.value}`} className="text-xs text-muted-foreground">
                          <Badge variant="outline" className="mr-1 text-[10px]">{evidence.provider}</Badge>
                          {evidence.type}: {evidence.value}
                          {evidence.sourceStatus !== "fresh" && <Badge variant="secondary" className="ml-1 text-[10px]">{evidence.sourceStatus}</Badge>}
                        </div>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell><Badge variant="secondary">{candidate.status}</Badge></TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      <Button type="button" size="sm" variant="outline" onClick={() => void approve(candidate)} disabled={candidate.status === "approved" || busyCandidateId === candidate.id}>
                        {busyCandidateId === candidate.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
                      </Button>
                      <Button type="button" size="sm" variant="ghost" onClick={() => void ignore(candidate)} disabled={candidate.status === "ignored" || busyCandidateId === candidate.id}>
                        {pt ? "Ignorar" : "Ignore"}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {sortedCandidates.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">
                    {pt ? "Rode discovery para gerar candidatos." : "Run discovery to generate candidates."}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="soc-panel rounded-lg">
          <div className="border-b border-border p-4">
            <h3 className="flex items-center gap-2 text-base font-semibold">
              <Clock className="h-4 w-4 text-primary" />
              {pt ? "Snapshots" : "Snapshots"}
            </h3>
          </div>
          <div className="flex flex-col gap-3 p-4">
            {snapshots.slice(0, 8).map((snapshot) => (
              <article key={snapshot.id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="secondary">{snapshot.status}</Badge>
                  <time className="text-xs text-muted-foreground">{formatDate(snapshot.completedAt)}</time>
                </div>
                <dl className="mt-3 grid grid-cols-3 gap-2 text-sm">
                  <div>
                    <dt className="text-xs text-muted-foreground">Candidates</dt>
                    <dd className="font-semibold">{snapshot.summary.totalCandidates}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">New</dt>
                    <dd className="font-semibold">{snapshot.summary.newCandidates}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">Changes</dt>
                    <dd className="font-semibold">{snapshot.changes.length}</dd>
                  </div>
                </dl>
              </article>
            ))}
            {snapshots.length === 0 && (
              <p className="py-8 text-center text-sm text-muted-foreground">
                {pt ? "Sem snapshots ainda." : "No snapshots yet."}
              </p>
            )}
          </div>
        </div>

        <div className="soc-panel rounded-lg">
          <div className="border-b border-border p-4">
            <h3 className="flex items-center gap-2 text-base font-semibold">
              <AlertTriangle className="h-4 w-4 text-primary" />
              {pt ? "Mudancas do ultimo snapshot" : "Latest snapshot changes"}
            </h3>
          </div>
          <div className="flex flex-col gap-2 p-4">
            {(latestSnapshot?.changes || []).slice(0, 12).map((change) => (
              <article key={change.id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="outline" className={riskTone[change.severity] || riskTone.unknown}>{change.severity}</Badge>
                  <time className="text-xs text-muted-foreground">{formatDate(change.detectedAt)}</time>
                </div>
                <p className="mt-2 text-sm font-medium">{change.title}</p>
                <p className="text-xs text-muted-foreground">{change.description}</p>
              </article>
            ))}
            {(!latestSnapshot || latestSnapshot.changes.length === 0) && (
              <p className="py-8 text-center text-sm text-muted-foreground">{pt ? "Sem mudancas ainda." : "No changes yet."}</p>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
```

- [ ] **Step 2: Update `AttackSurface.tsx` to add Discovery route state and tab**

Modify imports in `src/pages/AttackSurface.tsx`:

```tsx
import { ExposureDiscoveryPanel } from "@/components/attack-surface/ExposureDiscoveryPanel";
```

Change route mode and feature mode state:

```tsx
const routeMode = searchParams.get("mode") === "monitor"
  ? "monitor"
  : searchParams.get("mode") === "discovery"
    ? "discovery"
    : "scan";

const [featureMode, setFeatureMode] = useState<"scan" | "discovery" | "monitor">(routeMode);
```

Change `switchFeatureMode`:

```tsx
const switchFeatureMode = (value: string) => {
  const next = value === "monitor" ? "monitor" : value === "discovery" ? "discovery" : "scan";
  setFeatureMode(next);
  setSearchParams(next === "scan" ? {} : { mode: next });
};
```

Add a Discovery trigger between Scan and Monitor in the top-level `TabsList`:

```tsx
<TabsTrigger value="discovery">Discovery</TabsTrigger>
```

Add a Discovery tab content between Scan and Monitor:

```tsx
<TabsContent value="discovery" className="mt-0">
  <ExposureDiscoveryPanel />
</TabsContent>
```

- [ ] **Step 3: Run typecheck**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 4: Run production build**

Run:

```bash
npm run build
```

Expected: PASS and Vite emits `dist/`.

- [ ] **Step 5: Commit**

```bash
git add src/components/attack-surface/ExposureDiscoveryPanel.tsx src/pages/AttackSurface.tsx
git commit -m "feat: add attack surface discovery tab"
```

---

### Task 7: End-To-End Verification, Copy Tightening, And Final Regression

**Files:**

- Modify only files changed by earlier tasks if verification reveals concrete defects.

**Interfaces:**

- Consumes all tasks.
- Produces verified implementation ready for review.

- [ ] **Step 1: Run backend tests**

Run:

```bash
npm run test:server
```

Expected: PASS for all server tests.

- [ ] **Step 2: Run frontend unit tests**

Run:

```bash
npm run test:unit
```

Expected: PASS for all bundled frontend unit tests.

- [ ] **Step 3: Run static quality gates**

Run:

```bash
npm run lint
npm run typecheck
npm run build
```

Expected:

- `npm run lint`: PASS.
- `npm run typecheck`: PASS.
- `npm run build`: PASS.

- [ ] **Step 4: Run server syntax check**

Run:

```bash
node --check server/index.js
node --check server/exposureDiscovery.js
```

Expected: both commands exit 0 with no syntax errors.

- [ ] **Step 5: Manual local verification**

Run the API and frontend in separate terminals:

```bash
npm run server
```

```bash
npm run dev
```

Verify in the browser:

- `/attack-surface` opens Scan.
- `/attack-surface?mode=discovery` opens Discovery.
- `/attack-surface?mode=monitor` opens Monitor.
- Unauthenticated or non-premium Discovery shows the premium gate.
- Premium Discovery can create a profile with `example.com`, `Example Inc`, and `AS15169`.
- Running Discovery with only Shodan configured shows provider badges and does not show a raw stack trace.
- Running Discovery with Censys missing shows `Missing key` as a provider badge and still shows any Shodan/CT/DNS candidates.
- Approving a candidate adds it to Monitor.
- Ignoring a candidate changes its status to `ignored`.

- [ ] **Step 6: Commit verification fixes if any were required**

If Step 1-5 required code fixes, commit only those fixes:

```bash
git add server/exposureDiscovery.js server/index.js src/services/threatApi.ts src/utils/exposureDiscovery.ts src/components/attack-surface/ExposureDiscoveryPanel.tsx src/pages/AttackSurface.tsx
git commit -m "fix: stabilize exposure discovery workflow"
```

If no fixes were required, do not create an empty commit.
