# Unified Attack Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge one-off Attack Surface scanning and Exposure Watchlist monitoring into a single `/attack-surface` feature with TXT import and XLSX export.

**Architecture:** Keep the existing backend APIs unchanged. Add focused frontend utilities for TXT parsing and XLSX workbook generation, move monitoring UI into an Attack Surface subcomponent, and make `src/pages/AttackSurface.tsx` the canonical route with top-level `Scan` and `Monitor` tabs. `/exposure-watchlist` becomes a redirect to `/attack-surface?mode=monitor`.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind, shadcn/ui, lucide-react, node:test, esbuild test bundling, lazy-loaded `exceljs`.

## Global Constraints

- The feature is one product surface: Attack Surface.
- Monitoring remains implemented through existing Exposure Watchlist APIs for now.
- `/attack-surface` renders the unified feature.
- `/attack-surface?mode=monitor` opens monitoring mode.
- `/exposure-watchlist` redirects to `/attack-surface?mode=monitor`.
- Header/sidebar navigation exposes one Attack Surface item only.
- One-off scan mode stays as accessible as it is today.
- Monitoring mode must not call watchlist APIs unless the user is authenticated and premium.
- XLSX export belongs to one-off scan results first.
- TXT import supports both scan target fill and monitor target drafts.
- The XLSX exporter must lazy-load `exceljs`.
- Do not replace the existing Attack Surface backend provider logic.
- Do not migrate JSON persistence to a database.
- Do not add new notification channels.
- Do not add automatic asset discovery.
- Do not run active TCP validation unless the user explicitly enables it.
- Do not scan arbitrary ports. Validation stays limited to provider-observed public IP and port pairs.

---

## File Structure

- Create `src/utils/attackSurfaceImport.ts`
  - Owns TXT parsing and conversion of recognized lines into typed Attack Surface import targets.
- Create `src/utils/attackSurfaceImport.test.ts`
  - Tests parser classification, normalization, dedupe, query prefixes, and ignored-line counts.
- Create `src/utils/attackSurfaceExport.ts`
  - Owns lazy `exceljs` workbook generation and browser download for `AttackSurfaceResponse`.
- Create `src/utils/attackSurfaceExport.test.ts`
  - Tests workbook sheet names and key row values without triggering browser download.
- Create `src/components/attack-surface/ExposureMonitorPanel.tsx`
  - Owns saved asset CRUD, run snapshot, recent changes, history, premium gating, and monitor-mode TXT import drafts.
- Modify `src/pages/AttackSurface.tsx`
  - Adds top-level Scan/Monitor tabs, URL query synchronization, scan-mode TXT import, Excel export action, and imports `ExposureMonitorPanel`.
- Modify `src/pages/ExposureWatchlist.tsx`
  - Replace the old standalone page with a redirect component.
- Modify `src/App.tsx`
  - Remove `PremiumRoute` around `/exposure-watchlist` so the redirect can always run.
- Modify `src/components/Header.tsx`
  - Remove the separate Exposure Watchlist navigation item and update Attack Surface copy to include monitoring.
- Modify `ENDPOINTS.txt`
  - Keep backend endpoint docs, but rename the frontend route note to Attack Surface monitoring.

---

### Task 1: TXT Import Parser

**Files:**
- Create: `src/utils/attackSurfaceImport.ts`
- Create: `src/utils/attackSurfaceImport.test.ts`

**Interfaces:**
- Produces:
  - `type AttackSurfaceImportedKind = "ip" | "cidr" | "domain" | "asn" | "shodan_query"`
  - `interface AttackSurfaceImportedTarget { kind: AttackSurfaceImportedKind; value: string; raw: string; line: number; label: string }`
  - `interface AttackSurfaceImportResult { targets: AttackSurfaceImportedTarget[]; ignored: number }`
  - `parseAttackSurfaceTargets(text: string): AttackSurfaceImportResult`
  - `targetToMonitorDraft(target: AttackSurfaceImportedTarget): { type: "domain" | "ip" | "cidr" | "asn" | "shodan_query"; value: string; label: string }`

- [ ] **Step 1: Write failing parser tests**

Create `src/utils/attackSurfaceImport.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import {
  parseAttackSurfaceTargets,
  targetToMonitorDraft,
} from "./attackSurfaceImport.ts";

test("parses supported attack surface targets from TXT content", () => {
  const result = parseAttackSurfaceTargets([
    "# customer perimeter",
    "8.8.8.8",
    "8.8.4.0/24",
    "Example.COM",
    "AS15169",
    "15170",
    "shodan: org:\"Example\" port:3389",
    "query: ssl.cert.subject.cn:example.com",
    "not a target",
  ].join("\n"));

  assert.deepEqual(
    result.targets.map(({ kind, value, label }) => [kind, value, label]),
    [
      ["ip", "8.8.8.8", "8.8.8.8"],
      ["cidr", "8.8.4.0/24", "8.8.4.0/24"],
      ["domain", "example.com", "example.com"],
      ["asn", "AS15169", "AS15169"],
      ["asn", "AS15170", "AS15170"],
      ["shodan_query", "org:\"Example\" port:3389", "Shodan query"],
      ["shodan_query", "ssl.cert.subject.cn:example.com", "Shodan query"],
    ],
  );
  assert.equal(result.ignored, 2);
});

test("deduplicates normalized targets while keeping first occurrence order", () => {
  const result = parseAttackSurfaceTargets("Example.COM\nexample.com\nAS15169\n15169\n");

  assert.deepEqual(
    result.targets.map(({ kind, value }) => [kind, value]),
    [
      ["domain", "example.com"],
      ["asn", "AS15169"],
    ],
  );
  assert.equal(result.ignored, 0);
});

test("converts imported targets to monitor drafts", () => {
  const [target] = parseAttackSurfaceTargets("query: org:\"Example\"").targets;

  assert.deepEqual(targetToMonitorDraft(target), {
    type: "shodan_query",
    value: "org:\"Example\"",
    label: "Shodan query",
  });
});
```

- [ ] **Step 2: Run parser tests and verify failure**

Run:

```bash
npm run test:unit -- --test-name-pattern "attack surface targets"
```

Expected: FAIL because `src/utils/attackSurfaceImport.ts` does not exist.

- [ ] **Step 3: Implement parser utility**

Create `src/utils/attackSurfaceImport.ts`:

```ts
export type AttackSurfaceImportedKind = "ip" | "cidr" | "domain" | "asn" | "shodan_query";

export interface AttackSurfaceImportedTarget {
  kind: AttackSurfaceImportedKind;
  value: string;
  raw: string;
  line: number;
  label: string;
}

export interface AttackSurfaceImportResult {
  targets: AttackSurfaceImportedTarget[];
  ignored: number;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CIDR = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
const DOMAIN = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const ASN = /^(?:AS)?(\d{1,10})$/i;
const QUERY_PREFIX = /^(?:shodan|query)\s*:\s*(.+)$/i;

const clean = (value: string) => value.replace(/[\x00-\x1F\x7F]/g, " ").replace(/\s+/g, " ").trim();

const normalizeLine = (line: string) => clean(line.replace(/^\uFEFF/, ""));

const parsedTarget = (kind: AttackSurfaceImportedKind, value: string, raw: string, line: number): AttackSurfaceImportedTarget => ({
  kind,
  value,
  raw,
  line,
  label: kind === "shodan_query" ? "Shodan query" : value,
});

export const parseAttackSurfaceTargets = (text: string): AttackSurfaceImportResult => {
  const targets: AttackSurfaceImportedTarget[] = [];
  const seen = new Set<string>();
  let ignored = 0;

  text.split(/\r?\n/).forEach((sourceLine, index) => {
    const raw = normalizeLine(sourceLine);
    if (!raw || raw.startsWith("#")) {
      ignored += raw ? 1 : 0;
      return;
    }

    let target: AttackSurfaceImportedTarget | null = null;
    const query = raw.match(QUERY_PREFIX);
    if (query?.[1]?.trim()) {
      target = parsedTarget("shodan_query", clean(query[1]), raw, index + 1);
    } else if (CIDR.test(raw)) {
      target = parsedTarget("cidr", raw, raw, index + 1);
    } else if (IPV4.test(raw)) {
      target = parsedTarget("ip", raw, raw, index + 1);
    } else {
      const asn = raw.match(ASN);
      if (asn) target = parsedTarget("asn", `AS${asn[1]}`, raw, index + 1);
      else if (DOMAIN.test(raw)) target = parsedTarget("domain", raw.toLowerCase(), raw, index + 1);
    }

    if (!target) {
      ignored += 1;
      return;
    }

    const key = `${target.kind}:${target.value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(target);
  });

  return { targets, ignored };
};

export const targetToMonitorDraft = (target: AttackSurfaceImportedTarget) => ({
  type: target.kind,
  value: target.value,
  label: target.label,
});
```

- [ ] **Step 4: Run parser tests and unit suite**

Run:

```bash
npm run test:unit
```

Expected: PASS for all bundled unit tests.

- [ ] **Step 5: Commit parser utility**

```bash
git add src/utils/attackSurfaceImport.ts src/utils/attackSurfaceImport.test.ts
git commit -m "feat: parse attack surface TXT targets"
```

---

### Task 2: Attack Surface XLSX Exporter

**Files:**
- Create: `src/utils/attackSurfaceExport.ts`
- Create: `src/utils/attackSurfaceExport.test.ts`

**Interfaces:**
- Consumes:
  - `AttackSurfaceResponse` from `src/services/threatApi.ts`
- Produces:
  - `buildAttackSurfaceWorkbook(result: AttackSurfaceResponse): Promise<ExcelJS.Workbook>`
  - `exportAttackSurfaceExcel(result: AttackSurfaceResponse): Promise<void>`

- [ ] **Step 1: Write failing exporter tests**

Create `src/utils/attackSurfaceExport.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { buildAttackSurfaceWorkbook } from "./attackSurfaceExport.ts";
import type { AttackSurfaceResponse } from "@/services/threatApi";

const sample: AttackSurfaceResponse = {
  generatedAt: "2026-07-13T12:00:00.000Z",
  query: "net:\"8.8.8.0/24\"",
  queryKind: "search",
  limit: 50,
  activeValidation: true,
  warnings: ["Censys unavailable"],
  summary: {
    totalAssets: 1,
    totalServices: 1,
    criticalHighFindings: 1,
    activelyConfirmedOpen: 1,
    byRisk: { critical: 1, high: 0, medium: 0, low: 0 },
    providers: { shodan: true, censys: false },
    warnings: ["Censys unavailable"],
    totalObserved: 1,
  },
  findings: [{
    id: "finding-1",
    ip: "8.8.8.8",
    port: 443,
    transport: "tcp",
    risk: "critical",
    riskScore: 95,
    riskReasons: ["Known vulnerabilities reported: CVE-2026-0001"],
    service: "https",
    product: "nginx",
    version: "1.25",
    organization: "Example",
    asn: "AS15169",
    hostnames: ["example.com"],
    country: "US",
    city: "Mountain View",
    source: { shodan: true, censys: false },
    observedAt: "2026-07-13T11:00:00.000Z",
    cves: ["CVE-2026-0001"],
    tags: ["cloud"],
    bannerSnippet: "nginx",
    validation: { attempted: true, status: "open", detail: "connected" },
  }],
};

test("builds an Attack Surface workbook with overview, findings and risk summary sheets", async () => {
  const workbook = await buildAttackSurfaceWorkbook(sample);

  assert.deepEqual(workbook.worksheets.map((sheet) => sheet.name), ["Overview", "Findings", "Risk Summary"]);
  assert.equal(workbook.getWorksheet("Overview")?.getCell("A1").value, "ThreatSumm4ry Attack Surface");
  assert.equal(workbook.getWorksheet("Findings")?.getRow(2).getCell(1).value, "critical");
  assert.equal(workbook.getWorksheet("Findings")?.getRow(2).getCell(3).value, "8.8.8.8");
  assert.equal(workbook.getWorksheet("Risk Summary")?.getRow(2).getCell(1).value, "critical");
  assert.equal(workbook.getWorksheet("Risk Summary")?.getRow(2).getCell(2).value, 1);
});
```

- [ ] **Step 2: Run exporter tests and verify failure**

Run:

```bash
npm run test:unit -- --test-name-pattern "Attack Surface workbook"
```

Expected: FAIL because `src/utils/attackSurfaceExport.ts` does not exist.

- [ ] **Step 3: Implement exporter utility**

Create `src/utils/attackSurfaceExport.ts`:

```ts
import type ExcelJS from "exceljs";
import type { AttackSurfaceResponse, AttackSurfaceRisk } from "@/services/threatApi";

const INK = "0F172A";
const BRAND = "2563EB";
const RISK_HEX: Record<AttackSurfaceRisk, string> = {
  critical: "DC2626",
  high: "EA580C",
  medium: "CA8A04",
  low: "16A34A",
};

const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");

const triggerDownload = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const headerFill = (worksheet: ExcelJS.Worksheet, rowNumber: number, lastCol: number, color = INK) => {
  const row = worksheet.getRow(rowNumber);
  for (let column = 1; column <= lastCol; column += 1) {
    const cell = row.getCell(column);
    cell.font = { bold: true, color: { argb: "FFFFFFFF" } };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${color}` } };
    cell.alignment = { vertical: "middle" };
    cell.border = { bottom: { style: "thin", color: { argb: "FFCBD5E1" } } };
  }
  row.height = 20;
};

export async function buildAttackSurfaceWorkbook(result: AttackSurfaceResponse): Promise<ExcelJS.Workbook> {
  const { default: ExcelLib } = await import("exceljs");
  const workbook = new ExcelLib.Workbook();
  workbook.creator = "ThreatSumm4ry";
  workbook.created = new Date();

  const overview = workbook.addWorksheet("Overview", { properties: { tabColor: { argb: `FF${BRAND}` } } });
  overview.mergeCells("A1:D1");
  overview.getCell("A1").value = "ThreatSumm4ry Attack Surface";
  overview.getCell("A1").font = { bold: true, size: 18, color: { argb: `FF${INK}` } };
  overview.mergeCells("A2:D2");
  overview.getCell("A2").value = `Generated ${result.generatedAt} · Query ${result.query}`;
  overview.getCell("A2").font = { size: 10, color: { argb: "FF64748B" } };
  overview.getRow(4).values = ["Metric", "Value"];
  headerFill(overview, 4, 2);
  [
    ["Query kind", result.queryKind],
    ["Limit", result.limit],
    ["Active validation", result.activeValidation ? "Yes" : "No"],
    ["Assets", result.summary.totalAssets],
    ["Services", result.summary.totalServices],
    ["Critical / High", result.summary.criticalHighFindings],
    ["TCP open", result.summary.activelyConfirmedOpen],
    ["Warnings", result.warnings.join(" | ") || "-"],
  ].forEach((row) => overview.addRow(row));
  overview.getColumn(1).width = 24;
  overview.getColumn(2).width = 70;

  const findings = workbook.addWorksheet("Findings", {
    properties: { tabColor: { argb: `FF${INK}` } },
    views: [{ state: "frozen", ySplit: 1 }],
  });
  const columns = [
    { header: "Risk", key: "risk", width: 12 },
    { header: "Score", key: "riskScore", width: 8 },
    { header: "IP", key: "ip", width: 16 },
    { header: "Port", key: "port", width: 8 },
    { header: "Transport", key: "transport", width: 10 },
    { header: "Service", key: "service", width: 18 },
    { header: "Product", key: "product", width: 22 },
    { header: "Version", key: "version", width: 18 },
    { header: "CVEs", key: "cves", width: 34 },
    { header: "Organization", key: "organization", width: 28 },
    { header: "ASN", key: "asn", width: 14 },
    { header: "Location", key: "location", width: 24 },
    { header: "Sources", key: "sources", width: 18 },
    { header: "Observed", key: "observedAt", width: 24 },
    { header: "TCP", key: "validation", width: 18 },
    { header: "Reasons", key: "riskReasons", width: 60 },
  ];
  findings.columns = columns;
  headerFill(findings, 1, columns.length);
  result.findings.forEach((finding) => {
    const row = findings.addRow({
      risk: finding.risk,
      riskScore: finding.riskScore,
      ip: finding.ip,
      port: finding.port,
      transport: finding.transport,
      service: finding.service || "",
      product: finding.product || "",
      version: finding.version || "",
      cves: finding.cves.join(", "),
      organization: finding.organization || "",
      asn: finding.asn || "",
      location: [finding.city, finding.country].filter(Boolean).join(", "),
      sources: [finding.source.shodan && "Shodan", finding.source.censys && "Censys"].filter(Boolean).join(", "),
      observedAt: finding.observedAt || "",
      validation: finding.validation.status,
      riskReasons: finding.riskReasons.join(" | "),
    });
    row.getCell("risk").font = { bold: true, color: { argb: `FF${RISK_HEX[finding.risk]}` } };
  });
  findings.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };

  const risks = workbook.addWorksheet("Risk Summary");
  risks.getRow(1).values = ["Risk", "Count"];
  headerFill(risks, 1, 2, BRAND);
  (["critical", "high", "medium", "low"] as AttackSurfaceRisk[]).forEach((risk) => {
    const row = risks.addRow([risk, result.summary.byRisk[risk] || 0]);
    row.getCell(1).font = { bold: true, color: { argb: `FF${RISK_HEX[risk]}` } };
  });
  risks.getColumn(1).width = 14;
  risks.getColumn(2).width = 12;

  return workbook;
}

export async function exportAttackSurfaceExcel(result: AttackSurfaceResponse): Promise<void> {
  const workbook = await buildAttackSurfaceWorkbook(result);
  const buffer = await workbook.xlsx.writeBuffer();
  triggerDownload(
    new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }),
    `ThreatSumm4ry-Attack-Surface-${stamp()}.xlsx`,
  );
}
```

- [ ] **Step 4: Run exporter tests and unit suite**

Run:

```bash
npm run test:unit
```

Expected: PASS for all bundled unit tests.

- [ ] **Step 5: Commit exporter utility**

```bash
git add src/utils/attackSurfaceExport.ts src/utils/attackSurfaceExport.test.ts
git commit -m "feat: export attack surface results to xlsx"
```

---

### Task 3: Monitor Panel Component

**Files:**
- Create: `src/components/attack-surface/ExposureMonitorPanel.tsx`
- Modify: `src/pages/ExposureWatchlist.tsx`

**Interfaces:**
- Consumes:
  - `parseAttackSurfaceTargets(text)` and `targetToMonitorDraft(target)` from Task 1
  - existing exposure watchlist API helpers from `src/services/threatApi.ts`
  - `useAuth()` for premium gating
- Produces:
  - `ExposureMonitorPanel` React component

- [ ] **Step 1: Create the monitor component from the existing watchlist behavior**

Create `src/components/attack-surface/ExposureMonitorPanel.tsx` from the current `src/pages/ExposureWatchlist.tsx` behavior. The completed component must:

- remove `PageLayout`, `Card`, `CardContent`, `CardHeader`, and `CardTitle` usage;
- use `soc-panel rounded-lg` containers directly;
- import `useAuth` and never call watchlist APIs unless `auth.authenticated && auth.isPremium`;
- keep hooks unconditionally at the top of the component;
- add TXT import drafts with `parseAttackSurfaceTargets` and `targetToMonitorDraft`;
- preserve asset list, create/edit/delete, run snapshot, recent changes, and snapshot history behavior.

Use this component skeleton and fill every marked section with the exact current watchlist logic from `src/pages/ExposureWatchlist.tsx`:

```tsx
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Clock, Loader2, Lock, Play, Plus, RefreshCw, Trash2, Upload } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
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
import { parseAttackSurfaceTargets, targetToMonitorDraft, type AttackSurfaceImportedTarget } from "@/utils/attackSurfaceImport";
import { toast } from "sonner";

const emptyForm: ExposureAssetInput = {
  label: "",
  type: "domain",
  value: "",
  limit: 50,
  activeValidation: false,
  scheduleEnabled: true,
};

const riskTone: Record<string, string> = {
  critical: "border-destructive/40 bg-destructive/10 text-destructive",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-500",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-500",
  info: "border-primary/40 bg-primary/10 text-primary",
  none: "border-border bg-muted text-muted-foreground",
};

const statusLabel = (status: string) => ({
  never_run: "Never run",
  running: "Running",
  success: "OK",
  error: "Error",
  config_error: "Config",
}[status] || status);

function MonitorMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="soc-panel rounded-lg p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-2 font-mono text-2xl font-bold tabular-nums">{value}</p>
    </div>
  );
}

export function ExposureMonitorPanel() {
  const { auth, loading: authLoading } = useAuth();
  const { language } = useLanguage();
  const pt = language === "pt";
  const canUseMonitor = !authLoading && auth.authenticated && auth.isPremium;
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [assets, setAssets] = useState<ExposureAsset[]>([]);
  const [changes, setChanges] = useState<ExposureChange[]>([]);
  const [snapshots, setSnapshots] = useState<ExposureSnapshot[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [form, setForm] = useState<ExposureAssetInput>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [importTargets, setImportTargets] = useState<AttackSurfaceImportedTarget[]>([]);

  const selectedAsset = useMemo(
    () => assets.find((asset) => asset.id === selectedAssetId) || null,
    [assets, selectedAssetId],
  );

  const totals = useMemo(() => assets.reduce((acc, asset) => {
    acc.services += asset.lastSummary?.totalServices || 0;
    acc.criticalHigh += asset.lastSummary?.criticalHighFindings || 0;
    if (["error", "config_error"].includes(asset.lastStatus)) acc.errors += 1;
    return acc;
  }, { services: 0, criticalHigh: 0, errors: 0 }), [assets]);

  const load = useCallback(async () => {
    if (!canUseMonitor) return;
    setLoading(true);
    try {
      const [assetList, changeList] = await Promise.all([fetchExposureAssets(), fetchExposureChanges(100)]);
      setAssets(assetList);
      setChanges(changeList);
      setSelectedAssetId((current) => current || assetList[0]?.id || null);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Exposure Watchlist API error");
    } finally {
      setLoading(false);
    }
  }, [canUseMonitor]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    if (!canUseMonitor || !selectedAssetId) {
      setSnapshots([]);
      return;
    }
    void fetchExposureSnapshots(selectedAssetId).then(setSnapshots).catch((error) => {
      toast.error(error instanceof Error ? error.message : "Snapshot API error");
    });
  }, [canUseMonitor, selectedAssetId]);

  const importTxt = async (file: File | undefined) => {
    if (!file) return;
    try {
      const parsed = parseAttackSurfaceTargets(await file.text());
      setImportTargets(parsed.targets);
      if (parsed.targets.length === 0) toast.warning(pt ? "Nenhum alvo reconhecido no TXT." : "No supported targets found in TXT.");
      else toast.success(pt ? `${parsed.targets.length} alvo(s) importado(s).` : `${parsed.targets.length} target(s) imported.`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : pt ? "Falha ao ler TXT." : "Failed to read TXT.");
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const useDraft = (target: AttackSurfaceImportedTarget) => {
    const draft = targetToMonitorDraft(target);
    setForm((current) => ({ ...current, ...draft }));
  };

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
      await load();
      setSelectedAssetId(asset.id);
      setSnapshots(await fetchExposureSnapshots(asset.id));
      toast.success(pt ? "Snapshot finalizado" : "Snapshot complete");
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
      if (selectedAssetId === asset.id) setSelectedAssetId(null);
      await load();
      toast.success(pt ? "Ativo removido" : "Asset removed");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Delete failed");
    } finally {
      setBusyId(null);
    }
  };

  if (authLoading) {
    return <div className="soc-panel rounded-lg p-6 text-sm text-muted-foreground"><Loader2 className="mr-2 inline h-4 w-4 animate-spin" />{pt ? "Verificando acesso..." : "Checking access..."}</div>;
  }

  if (!canUseMonitor) {
    return (
      <div className="soc-panel rounded-lg p-8 text-center">
        <Lock className="mx-auto h-9 w-9 text-muted-foreground/60" />
        <h2 className="mt-4 text-lg font-semibold">{pt ? "Monitoramento premium" : "Premium monitoring"}</h2>
        <p className="mx-auto mt-2 max-w-xl text-sm text-muted-foreground">
          {pt
            ? "O scan manual continua disponivel. Entre com uma conta premium para salvar ativos, rodar snapshots e acompanhar mudancas."
            : "Manual scan remains available. Sign in with premium access to save assets, run snapshots, and track changes."}
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Metrics grid, saved target form, import drafts, watchlist table, recent changes, and history panels go here. */}
    </div>
  );
}
```

Replace the JSX comment in the returned `<div>` with the current `ExposureWatchlist` sections translated to `soc-panel` containers:

- metrics grid with `MonitorMetric`;
- saved target form and import drafts;
- watchlist table with run/edit/delete actions;
- recent changes panel;
- selected asset history panel.

- [ ] **Step 2: Replace standalone ExposureWatchlist page with redirect**

Replace `src/pages/ExposureWatchlist.tsx` with:

```tsx
import { Navigate } from "react-router-dom";

export default function ExposureWatchlist() {
  return <Navigate to="/attack-surface?mode=monitor" replace />;
}
```

- [ ] **Step 3: Run typecheck**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 4: Commit monitor panel**

```bash
git add src/components/attack-surface/ExposureMonitorPanel.tsx src/pages/ExposureWatchlist.tsx
git commit -m "feat: move exposure monitoring into attack surface"
```

---

### Task 4: Unified Attack Surface Page

**Files:**
- Modify: `src/pages/AttackSurface.tsx`

**Interfaces:**
- Consumes:
  - `ExposureMonitorPanel` from Task 3
  - `parseAttackSurfaceTargets` from Task 1
  - `exportAttackSurfaceExcel` from Task 2

- [ ] **Step 1: Add top-level mode state synchronized to query string**

Modify imports in `src/pages/AttackSurface.tsx`:

```tsx
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Download, FileSpreadsheet, Upload } from "lucide-react";
import { ExposureMonitorPanel } from "@/components/attack-surface/ExposureMonitorPanel";
import { parseAttackSurfaceTargets, type AttackSurfaceImportedTarget } from "@/utils/attackSurfaceImport";
import { exportAttackSurfaceExcel } from "@/utils/attackSurfaceExport";
```

Inside `AttackSurface()` add:

```tsx
const [searchParams, setSearchParams] = useSearchParams();
const routeMode = searchParams.get("mode") === "monitor" ? "monitor" : "scan";
const [featureMode, setFeatureMode] = useState<"scan" | "monitor">(routeMode);
const fileInputRef = useRef<HTMLInputElement | null>(null);
const [importTargets, setImportTargets] = useState<AttackSurfaceImportedTarget[]>([]);
const [exporting, setExporting] = useState(false);

useEffect(() => {
  setFeatureMode(routeMode);
}, [routeMode]);

const switchFeatureMode = (value: string) => {
  const next = value === "monitor" ? "monitor" : "scan";
  setFeatureMode(next);
  setSearchParams(next === "monitor" ? { mode: "monitor" } : {});
};
```

- [ ] **Step 2: Add scan TXT import handlers**

Inside `AttackSurface()` add:

```tsx
const applyImportedTarget = (imported: AttackSurfaceImportedTarget) => {
  if (imported.kind === "shodan_query") {
    setMode("advanced");
    setAdvancedQuery(imported.value);
    return;
  }
  if (imported.kind === "asn") {
    setMode("advanced");
    setAdvancedQuery(`asn:"${imported.value}"`);
    return;
  }
  setMode("guided");
  setTargetType(imported.kind);
  setTarget(imported.value);
};

const importTxt = async (file: File | undefined) => {
  if (!file) return;
  try {
    const parsed = parseAttackSurfaceTargets(await file.text());
    setImportTargets(parsed.targets);
    if (parsed.targets[0]) applyImportedTarget(parsed.targets[0]);
    if (parsed.targets.length === 0) {
      toast.warning(pt ? "Nenhum alvo reconhecido no TXT." : "No supported targets found in TXT.");
    } else {
      toast.success(pt ? `${parsed.targets.length} alvo(s) importado(s).` : `${parsed.targets.length} target(s) imported.`);
    }
  } catch (error) {
    toast.error(error instanceof Error ? error.message : pt ? "Falha ao ler TXT." : "Failed to read TXT.");
  } finally {
    if (fileInputRef.current) fileInputRef.current.value = "";
  }
};
```

- [ ] **Step 3: Add Excel export handler**

Inside `AttackSurface()` add:

```tsx
const exportExcel = async () => {
  if (!result) return;
  setExporting(true);
  try {
    await exportAttackSurfaceExcel(result);
    toast.success(pt ? "XLSX gerado." : "XLSX generated.");
  } catch (error) {
    toast.error(error instanceof Error ? error.message : pt ? "Falha ao gerar XLSX." : "Failed to generate XLSX.");
  } finally {
    setExporting(false);
  }
};
```

- [ ] **Step 4: Wrap page body in top-level tabs**

Use existing shadcn `Tabs`:

```tsx
<Tabs value={featureMode} onValueChange={switchFeatureMode} className="flex flex-col gap-6">
  <div className="flex flex-col gap-3 border-b border-border pb-4 md:flex-row md:items-center md:justify-between">
    <TabsList>
      <TabsTrigger value="scan">{pt ? "Scan" : "Scan"}</TabsTrigger>
      <TabsTrigger value="monitor">{pt ? "Monitoramento" : "Monitor"}</TabsTrigger>
    </TabsList>
  </div>
  <TabsContent value="scan" className="mt-0">
    {/* existing scan form, metrics, filters, table, empty state */}
  </TabsContent>
  <TabsContent value="monitor" className="mt-0">
    <ExposureMonitorPanel />
  </TabsContent>
</Tabs>
```

Keep the existing scan form and results markup inside the `scan` content.

- [ ] **Step 5: Add TXT import and XLSX controls to scan UI**

In the scan form action row, add:

```tsx
<input
  ref={fileInputRef}
  type="file"
  accept=".txt,text/plain"
  className="hidden"
  onChange={(event) => void importTxt(event.target.files?.[0])}
/>
<Button type="button" variant="outline" className="h-9 gap-2" onClick={() => fileInputRef.current?.click()}>
  <Upload className="h-4 w-4" />
  TXT
</Button>
```

Above the warning alert, render imported target chips when present:

```tsx
{importTargets.length > 0 && (
  <div className="mt-4 flex flex-wrap gap-2">
    {importTargets.slice(0, 10).map((imported) => (
      <Button
        key={`${imported.kind}:${imported.value}`}
        type="button"
        variant="outline"
        size="sm"
        className="h-8 gap-2"
        onClick={() => applyImportedTarget(imported)}
      >
        <Badge variant="secondary" className="px-1.5 py-0 text-[10px] uppercase">{imported.kind.replace("_", " ")}</Badge>
        <span className="max-w-52 truncate font-mono text-xs">{imported.value}</span>
      </Button>
    ))}
  </div>
)}
```

In the results filter/action header, add:

```tsx
<Button type="button" variant="outline" size="sm" className="h-9 gap-2" onClick={() => void exportExcel()} disabled={!result || exporting}>
  {exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileSpreadsheet className="h-4 w-4" />}
  Excel
</Button>
```

- [ ] **Step 6: Run typecheck**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit unified page**

```bash
git add src/pages/AttackSurface.tsx
git commit -m "feat: unify attack surface scan and monitoring"
```

---

### Task 5: Route, Navigation, And Docs Cleanup

**Files:**
- Modify: `src/App.tsx`
- Modify: `src/components/Header.tsx`
- Modify: `ENDPOINTS.txt`

**Interfaces:**
- Consumes:
  - `src/pages/ExposureWatchlist.tsx` redirect from Task 3

- [ ] **Step 1: Let `/exposure-watchlist` redirect without premium wrapper**

Modify the route in `src/App.tsx`:

```tsx
<Route path="/exposure-watchlist" element={<ExposureWatchlist />} />
```

Keep `/attack-surface` unchanged:

```tsx
<Route path="/attack-surface" element={<AttackSurface />} />
```

- [ ] **Step 2: Remove separate Exposure Watchlist nav item**

In `src/components/Header.tsx`, update the Attack Surface nav item:

```tsx
{
  path: "/attack-surface",
  label: "Attack Surface",
  description: pt
    ? "Scan externo, XLSX e monitoramento de exposicao."
    : "External scan, XLSX export, and exposure monitoring.",
  icon: Radar,
},
```

Remove the object with `path: "/exposure-watchlist"`.

- [ ] **Step 3: Update endpoint route note**

In `ENDPOINTS.txt`, keep the backend watchlist API lines and change the frontend route line from:

```txt
/exposure-watchlist * Exposure Watchlist
```

to:

```txt
/attack-surface?mode=monitor * Attack Surface monitoring (legacy /exposure-watchlist redirects here)
```

- [ ] **Step 4: Run typecheck**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit route cleanup**

```bash
git add src/App.tsx src/components/Header.tsx ENDPOINTS.txt
git commit -m "refactor: route exposure watchlist through attack surface"
```

---

### Task 6: Verification

**Files:**
- No source changes expected unless verification finds defects.

- [ ] **Step 1: Run frontend unit tests**

Run:

```bash
npm run test:unit
```

Expected: PASS.

- [ ] **Step 2: Run frontend typecheck**

Run:

```bash
npm run typecheck
```

Expected: PASS.

- [ ] **Step 3: Run production build**

Run:

```bash
npm run build
```

Expected: PASS.

- [ ] **Step 4: Run server tests**

Run:

```bash
npm run test:server
```

Expected: PASS.

- [ ] **Step 5: Start dev server for manual browser check**

Run:

```bash
npm run dev -- --host 127.0.0.1
```

Expected: Vite prints a local URL, usually `http://127.0.0.1:5173/`.

Manual checks:

- `/attack-surface` opens in Scan mode.
- TXT import fills the scan form.
- Excel export button is disabled before results and enabled after a result exists.
- `/attack-surface?mode=monitor` opens Monitor mode.
- Non-premium users see the monitor gate without watchlist API calls.
- Premium users can list assets, create/edit a draft from TXT, run a snapshot, and see changes/history.
- `/exposure-watchlist` redirects to `/attack-surface?mode=monitor`.
- Mobile width keeps controls readable and tables horizontally scrollable.

- [ ] **Step 6: Final status**

Run:

```bash
git status --short
```

Expected: only unrelated pre-existing files remain dirty. Do not revert unrelated files.
