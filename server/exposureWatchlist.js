import crypto from 'crypto';
import net from 'net';

export const WATCHLIST_LIMITS = { assetsPerUser: 25, scanLimit: 100, labelLength: 80, valueLength: 512, snapshotsPerAsset: 14 };
export const RISK_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

const VALID_TYPES = new Set(['domain', 'ip', 'cidr', 'asn', 'shodan_query']);
const CONTROL_CHARS = /[\x00-\x1F\x7F]/;
const SAFE_DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SAFE_CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

export const createExposureError = (status, publicMessage) => Object.assign(new Error(publicMessage), { status, publicMessage });
const cleanText = (value, max) => String(value || '').replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const newId = (prefix) => `${prefix}_${crypto.randomBytes(8).toString('hex')}`;
const riskRank = (risk) => RISK_ORDER[risk] || 0;
const isValidIPv4 = (ip) => net.isIP(ip) === 4 && ip.split('.').every((octet) => {
    const value = Number(octet);
    return Number.isInteger(value) && value >= 0 && value <= 255;
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
        const [ip, rawMask] = value.split('/');
        const mask = Number(rawMask);
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
        id: existingAsset?.id || newId('asset'), ownerId: existingAsset?.ownerId || owner.sub,
        ownerLogin: existingAsset?.ownerLogin || owner.login, label, type, value, limit,
        activeValidation: Boolean(input.activeValidation ?? existingAsset?.activeValidation),
        scheduleEnabled: Boolean(input.scheduleEnabled ?? existingAsset?.scheduleEnabled),
        createdAt: existingAsset?.createdAt || now, updatedAt: now,
        lastRunAt: existingAsset?.lastRunAt || null, lastStatus: existingAsset?.lastStatus || 'never_run',
        lastError: existingAsset?.lastError || null, lastSnapshotId: existingAsset?.lastSnapshotId || null,
        lastRisk: existingAsset?.lastRisk || null, lastSummary: existingAsset?.lastSummary || null,
    };
}

export function assetToAttackSurfaceInput(asset) {
    const common = { limit: asset.limit, activeValidation: asset.activeValidation };
    if (asset.type === 'shodan_query') return { mode: 'advanced', advancedQuery: asset.value, ...common };
    if (asset.type === 'asn') return { mode: 'advanced', advancedQuery: `asn:"${asset.value}"`, ...common };
    return { mode: 'guided', targetType: asset.type, target: asset.value, ...common };
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
    return {
        totalAssets: assets.size, totalServices: findings.length,
        criticalHighFindings: byRisk.critical + byRisk.high, activelyConfirmedOpen, byRisk,
        highestRisk: ['critical', 'high', 'medium', 'low'].find((risk) => byRisk[risk] > 0) || null,
    };
}

const serviceKey = (finding) => `${finding.ip}:${String(finding.transport || 'tcp').toLowerCase()}/${Number(finding.port)}`;
const serviceLabel = (finding) => `${finding.ip}:${finding.port}/${finding.transport || 'tcp'}`;
const comparableBanner = (finding) => [finding.service, finding.product, finding.version, finding.bannerSnippet].map((value) => value || '').join('|');
const change = ({ assetId, snapshotId, detectedAt, type, severity, finding, previous, current, title, description }) => ({
    id: newId('chg'), assetId, snapshotId, detectedAt, severity, type, title, description,
    ip: finding?.ip || null, port: finding?.port || null, transport: finding?.transport || null, previous, current,
});

export function diffSnapshots({ assetId, snapshotId, previous, current, detectedAt = new Date().toISOString() }) {
    if (!previous) {
        return current.length ? [change({
            assetId, snapshotId, detectedAt, type: 'baseline_created', severity: 'info', finding: null,
            previous: null, current: { services: current.length }, title: 'Baseline snapshot created',
            description: `${current.length} exposed services captured as the initial baseline.`,
        })] : [];
    }
    const changes = [];
    const previousMap = new Map(previous.map((finding) => [serviceKey(finding), finding]));
    const currentMap = new Map(current.map((finding) => [serviceKey(finding), finding]));
    for (const [key, currentFinding] of currentMap) {
        const previousFinding = previousMap.get(key);
        if (!previousFinding) {
            const severity = currentFinding.risk === 'critical' ? 'critical' : currentFinding.risk === 'high' ? 'high' : currentFinding.risk === 'medium' ? 'medium' : 'info';
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'service_added', severity, finding: currentFinding, previous: null, current: currentFinding, title: 'Service added', description: `${serviceLabel(currentFinding)} appeared with ${currentFinding.risk} risk.` }));
            continue;
        }
        for (const cve of (currentFinding.cves || []).filter((id) => !(previousFinding.cves || []).includes(id))) {
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'cve_added', severity: 'critical', finding: currentFinding, previous: previousFinding.cves || [], current: currentFinding.cves || [], title: 'CVE added', description: `${cve} appeared on ${serviceLabel(currentFinding)}.` }));
        }
        for (const cve of (previousFinding.cves || []).filter((id) => !(currentFinding.cves || []).includes(id))) {
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'cve_removed', severity: 'low', finding: currentFinding, previous: previousFinding.cves || [], current: currentFinding.cves || [], title: 'CVE removed', description: `${cve} no longer appears on ${serviceLabel(currentFinding)}.` }));
        }
        if (riskRank(currentFinding.risk) > riskRank(previousFinding.risk)) {
            const severity = currentFinding.risk === 'critical' ? 'critical' : currentFinding.risk === 'high' ? 'high' : 'medium';
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'risk_increased', severity, finding: currentFinding, previous: previousFinding.risk, current: currentFinding.risk, title: 'Risk increased', description: `${serviceLabel(currentFinding)} changed from ${previousFinding.risk} to ${currentFinding.risk}.` }));
        } else if (riskRank(currentFinding.risk) < riskRank(previousFinding.risk)) {
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'risk_decreased', severity: 'low', finding: currentFinding, previous: previousFinding.risk, current: currentFinding.risk, title: 'Risk decreased', description: `${serviceLabel(currentFinding)} changed from ${previousFinding.risk} to ${currentFinding.risk}.` }));
        }
        if (comparableBanner(currentFinding) !== comparableBanner(previousFinding)) {
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'banner_changed', severity: riskRank(currentFinding.risk) >= riskRank('high') ? 'medium' : 'info', finding: currentFinding, previous: comparableBanner(previousFinding), current: comparableBanner(currentFinding), title: 'Banner changed', description: `${serviceLabel(currentFinding)} service metadata changed.` }));
        }
        const currentValidation = currentFinding.validation?.status || 'not_requested';
        const previousValidation = previousFinding.validation?.status || 'not_requested';
        if (currentValidation !== previousValidation) {
            changes.push(change({ assetId, snapshotId, detectedAt, type: 'validation_changed', severity: 'info', finding: currentFinding, previous: previousValidation, current: currentValidation, title: 'Validation changed', description: `${serviceLabel(currentFinding)} validation changed from ${previousValidation} to ${currentValidation}.` }));
        }
    }
    for (const [key, previousFinding] of previousMap) {
        if (!currentMap.has(key)) changes.push(change({ assetId, snapshotId, detectedAt, type: 'service_removed', severity: 'low', finding: previousFinding, previous: previousFinding, current: null, title: 'Service removed', description: `${serviceLabel(previousFinding)} is no longer observed.` }));
    }
    return changes;
}

export function selectDueAssets(assets = [], now = new Date()) {
    const cutoff = now.getTime() - 24 * 60 * 60 * 1000;
    return assets.filter((asset) => {
        if (!asset.scheduleEnabled || asset.lastStatus === 'running') return false;
        if (!asset.lastRunAt) return true;
        const lastRun = new Date(asset.lastRunAt).getTime();
        return Number.isFinite(lastRun) && lastRun <= cutoff;
    });
}

export function applySnapshotRetention(snapshots = [], assetId) {
    const target = snapshots.filter((snapshot) => snapshot.assetId === assetId)
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
        .slice(0, WATCHLIST_LIMITS.snapshotsPerAsset);
    const keepIds = new Set(target.map((snapshot) => snapshot.id));
    return snapshots.filter((snapshot) => snapshot.assetId !== assetId || keepIds.has(snapshot.id))
        .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
}
