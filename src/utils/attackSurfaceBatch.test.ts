import test from "node:test";
import assert from "node:assert/strict";
import type { AttackSurfaceFinding, AttackSurfaceResponse, AttackSurfaceRisk } from "@/services/threatApi";
import { mergeAttackSurfaceResponses } from "./attackSurfaceBatch";

const finding = (ip: string, port: number, risk: AttackSurfaceRisk): AttackSurfaceFinding => ({
  id: `${ip}:${port}/tcp:0`,
  ip,
  port,
  transport: "tcp",
  risk,
  riskScore: risk === "critical" ? 95 : risk === "high" ? 75 : 25,
  riskReasons: [],
  service: "HTTP",
  product: "nginx",
  version: null,
  organization: null,
  asn: null,
  hostnames: [],
  country: null,
  city: null,
  source: { shodan: true },
  observedAt: null,
  cves: [],
  tags: [],
  bannerSnippet: null,
  validation: { attempted: false, status: "not_requested", detail: null },
});

const response = (findings: AttackSurfaceFinding[], totalObserved: number): AttackSurfaceResponse => ({
  generatedAt: "2026-08-08T00:00:00.000Z",
  query: "example",
  queryKind: "search",
  limit: 100,
  activeValidation: false,
  summary: {
    totalAssets: 0,
    totalServices: findings.length,
    criticalHighFindings: 0,
    activelyConfirmedOpen: 0,
    byRisk: { critical: 0, high: 0, medium: 0, low: 0 },
    providers: { shodan: true },
    warnings: [],
    totalObserved,
  },
  findings,
  warnings: [],
});

test("merges pages, deduplicates services, and rebuilds summary totals", () => {
  const result = mergeAttackSurfaceResponses([
    response([finding("1.1.1.1", 443, "critical"), finding("2.2.2.2", 80, "low")], 2),
    response([finding("1.1.1.1", 443, "high"), finding("1.1.1.1", 22, "high")], 2),
  ]);

  assert.equal(result?.findings.length, 3);
  assert.equal(result?.summary.totalAssets, 2);
  assert.equal(result?.summary.totalServices, 3);
  assert.equal(result?.summary.criticalHighFindings, 2);
  assert.deepEqual(result?.summary.byRisk, { critical: 1, high: 1, medium: 0, low: 1 });
  assert.equal(result?.summary.totalObserved, 4);
});
