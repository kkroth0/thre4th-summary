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
    id: 'finding-1', ip: '8.8.8.8', port: 443, transport: 'tcp', risk: 'low', riskScore: 25,
    riskReasons: ['Standard web service exposed'], service: 'https', product: 'nginx', version: '1.24',
    organization: 'Example', asn: 'AS15169', hostnames: ['example.com'], country: 'US', city: 'Mountain View',
    source: { shodan: true, censys: false }, observedAt: now, cves: [], tags: [], bannerSnippet: 'nginx',
    validation: { attempted: false, status: 'not_requested', detail: null }, ...overrides,
});

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
