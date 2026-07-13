import test from 'node:test';
import assert from 'node:assert/strict';
import {
    WATCHLIST_LIMITS,
    applySnapshotRetention,
    assetToAttackSurfaceInput,
    createWatchlistStore,
    diffSnapshots,
    normalizeExposureAssetInput,
    runExposureSnapshot,
    runDueExposureSnapshots,
    selectDueAssets,
    summarizeFindings,
} from '../exposureWatchlist.js';

const owner = { sub: 'user-1', login: 'analyst' };
const now = '2026-07-13T12:00:00.000Z';

const baseFinding = (overrides = {}) => ({
    id: 'finding-1', ip: '8.8.8.8', port: 443, transport: 'tcp', risk: 'low', riskScore: 25,
    riskReasons: ['Standard web service exposed'], service: 'https', product: 'nginx', version: '1.24',
    organization: 'Example', asn: 'AS15169', hostnames: ['example.com'], country: 'US', city: 'Mountain View',
    source: { shodan: true }, observedAt: now, cves: [], tags: [], bannerSnippet: 'nginx',
    validation: { attempted: false, status: 'not_requested', detail: null }, ...overrides,
});

function memoryStore() {
    const files = new Map();
    return createWatchlistStore({
        assetsPath: 'assets.json', snapshotsPath: 'snapshots.json',
        readFileSync(path) {
            if (!files.has(path)) throw new Error('missing');
            return files.get(path);
        },
        writeJsonAtomic(path, data) { files.set(path, JSON.stringify(data)); },
    });
}

test('normalizeExposureAssetInput validates and normalizes a domain asset', () => {
    const asset = normalizeExposureAssetInput({
        label: ' Main Web ', type: 'domain', value: 'Example.COM', limit: 250,
        activeValidation: true, scheduleEnabled: true,
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
        label: 'ASN', type: 'asn', value: '15169', limit: 10,
        activeValidation: false, scheduleEnabled: false,
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
    const changes = diffSnapshots({ assetId: 'asset-1', snapshotId: 'snap-1', previous: null, current: [baseFinding()], detectedAt: now });
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
    const types = diffSnapshots({ assetId: 'asset-1', snapshotId: 'snap-2', previous, current, detectedAt: now }).map((change) => change.type);
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
        id: `snap-${index}`, assetId: 'asset-1', ownerId: 'user-1',
        startedAt: new Date(Date.UTC(2026, 6, 1, index)).toISOString(),
    }));
    const retained = applySnapshotRetention(snapshots, 'asset-1');
    assert.equal(retained.length, WATCHLIST_LIMITS.snapshotsPerAsset);
    assert.equal(retained[0].id, 'snap-16');
    assert.equal(retained.at(-1).id, 'snap-3');
});

test('createWatchlistStore creates, updates, lists and deletes owner assets', () => {
    const store = memoryStore();
    const asset = store.createAsset(owner, {
        label: 'Edge', type: 'domain', value: 'example.com', limit: 20,
        activeValidation: false, scheduleEnabled: true,
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
        label: 'Edge', type: 'domain', value: 'example.com', limit: 20,
        activeValidation: false, scheduleEnabled: true,
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
        label: 'Edge', type: 'domain', value: 'example.com', limit: 20,
        activeValidation: false, scheduleEnabled: true,
    }, now);
    const error = Object.assign(new Error('Shodan API Key missing'), {
        status: 503, publicMessage: 'Shodan API key is not configured',
    });
    const snapshot = await runExposureSnapshot({
        store, assetId: asset.id, ownerId: 'user-1', now: new Date(now),
        runAttackSurfaceScan: async () => { throw error; }, scanDeps: {},
    });
    assert.equal(snapshot.status, 'config_error');
    assert.equal(store.getAsset('user-1', asset.id).lastStatus, 'config_error');
    assert.match(store.getAsset('user-1', asset.id).lastError, /Shodan API key/);
});

test('runDueExposureSnapshots runs due assets sequentially and continues after failure', async () => {
    const assets = [
        { id: 'old-1', ownerId: 'user-1', scheduleEnabled: true, lastRunAt: '2026-07-12T10:00:00.000Z', lastStatus: 'success' },
        { id: 'old-2', ownerId: 'user-2', scheduleEnabled: true, lastRunAt: '2026-07-12T10:00:00.000Z', lastStatus: 'success' },
    ];
    const calls = [];
    const result = await runDueExposureSnapshots({
        store: { allAssets: () => assets }, now: new Date(now),
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
