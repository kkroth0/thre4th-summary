import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assessExposureRisk,
  buildAttackSurfaceQuery,
  isPublicIPv4,
  normalizeShodanHost,
  runAttackSurfaceScan,
} from '../attackSurface.js';

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

test('buildAttackSurfaceQuery rejects invalid modes', () => {
  assert.throws(
    () => buildAttackSurfaceQuery({
      mode: 'legacy',
      targetType: 'cidr',
      target: '8.8.8.0/24',
      limit: 10,
      activeValidation: false,
    }),
    /Invalid mode/,
  );
});

test('assessExposureRisk marks CVEs and critical remote ports as critical', () => {
  assert.deepEqual(
    assessExposureRisk({ port: 3389, transport: 'tcp', cves: [], tags: [], product: 'RDP' }).risk,
    'critical',
  );
  const cveRisk = assessExposureRisk({
    port: 443,
    transport: 'tcp',
    cves: ['CVE-2024-1234'],
    tags: [],
    product: 'nginx',
  });
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

test('assessExposureRisk does not apply TCP port rules to UDP services', () => {
  const result = assessExposureRisk({
    port: 3389,
    transport: 'udp',
    cves: [],
    tags: [],
    product: 'udp service',
  });

  assert.equal(result.risk, 'low');
});

test('isPublicIPv4 rejects private and reserved addresses', () => {
  assert.equal(isPublicIPv4('8.8.8.8'), true);
  assert.equal(isPublicIPv4('10.0.0.1'), false);
  assert.equal(isPublicIPv4('172.16.0.1'), false);
  assert.equal(isPublicIPv4('192.168.1.10'), false);
  assert.equal(isPublicIPv4('127.0.0.1'), false);
  assert.equal(isPublicIPv4('169.254.1.1'), false);
  assert.equal(isPublicIPv4('192.0.0.10'), false);
  assert.equal(isPublicIPv4('192.0.2.10'), false);
  assert.equal(isPublicIPv4('198.18.0.1'), false);
  assert.equal(isPublicIPv4('198.51.100.10'), false);
  assert.equal(isPublicIPv4('203.0.113.10'), false);
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

test('runAttackSurfaceScan caps host lookup findings before active validation', async () => {
  let tcpAttempts = 0;
  const axiosClient = {
    async get(url) {
      if (url.includes('/shodan/host/')) {
        return {
          data: {
            ip_str: '8.8.8.8',
            org: 'Example Org',
            data: Array.from({ length: 5 }, (_, index) => ({
              ip_str: '8.8.8.8',
              port: 8000 + index,
              transport: 'tcp',
              product: 'HTTP',
              timestamp: '2026-07-12T10:00:00.000000',
            })),
          },
        };
      }
      throw new Error('unexpected request');
    },
  };

  const result = await runAttackSurfaceScan(
    {
      mode: 'guided',
      targetType: 'ip',
      target: '8.8.8.8',
      limit: 2,
      activeValidation: true,
    },
    {
      axiosClient,
      shodanApiKey: 'shodan-key',
      tcpConnect: async () => {
        tcpAttempts += 1;
        return { status: 'open', detail: 'accepted' };
      },
    },
  );

  assert.equal(result.findings.length, 2);
  assert.equal(tcpAttempts, 2);
  assert.equal(result.summary.activelyConfirmedOpen, 2);
});
