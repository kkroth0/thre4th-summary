# Threat Map Operational Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/threat-map` useful as an operational ransomware desk where recent victims are visible first and the map is supporting context.

**Architecture:** Keep `src/pages/ThreatMap.tsx` as the single page. Reuse the existing `fetchThreatMap` response, `ThreatWorldMap`, `PageLayout`, shadcn primitives, and local state; add small local helpers/components in the same file for victim filtering, evidence badges, the victim table, situation panel, rankings, and compact map.

**Tech Stack:** React 18, Vite, TypeScript, Tailwind, shadcn/ui, lucide-react, Node built-in test runner with esbuild bundling.

## Global Constraints

- Do not alter backend endpoints or `ThreatMapData`.
- Do not alter unrelated dirty files in the worktree.
- The first desktop viewport must prioritize recent victims over the map.
- Keep the map present, but contextual and smaller.
- Keep window selector and refresh behavior.
- Provide local search plus quick filters for group, country, and sector.
- Keep copy utilitarian, dense, and SOC-oriented.

---

### Task 1: Operational Structure Test

**Files:**
- Create: `src/pages/threatMapOperational.test.ts`

**Interfaces:**
- Consumes: source text from `src/pages/ThreatMap.tsx`.
- Produces: test expectations that lock the page hierarchy: victim table before map, operational copy, victim fields, search, filters, and contextual map.

- [ ] **Step 1: Write the failing structural test**

Create `src/pages/threatMapOperational.test.ts`:

```ts
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("threat map prioritizes recent ransomware victims before map context", async () => {
  const source = await read("src/pages/ThreatMap.tsx");

  const victimTable = source.indexOf("VictimTable");
  const mapContext = source.indexOf("ContextMapPanel");

  assert.ok(victimTable > -1, "VictimTable component should exist");
  assert.ok(mapContext > -1, "ContextMapPanel component should exist");
  assert.ok(victimTable < mapContext, "victim table should be defined before map context");
  assert.match(source, /Ransomware operation desk/);
  assert.match(source, /Vitimas recentes/);
  assert.match(source, /Situacao agora/);
  assert.match(source, /Fonte/);
  assert.match(source, /Evidencia/);
});

test("threat map exposes local triage controls for victims", async () => {
  const source = await read("src/pages/ThreatMap.tsx");

  assert.match(source, /victimSearch/);
  assert.match(source, /groupFilter/);
  assert.match(source, /countryFilter/);
  assert.match(source, /sectorFilter/);
  assert.match(source, /filteredVictims/);
  assert.match(source, /placeholder=\{pt \? "Buscar vitima, grupo, pais ou setor"/);
});
```

- [ ] **Step 2: Run unit tests to verify RED**

Run:

```bash
npm run test:unit
```

Expected: FAIL because `VictimTable`, `ContextMapPanel`, operational copy, and local triage state do not exist yet.

- [ ] **Step 3: Commit the RED test**

Do not commit a failing test separately. Keep it staged only after GREEN in Task 2.

---

### Task 2: Operational Threat Map UI

**Files:**
- Modify: `src/pages/ThreatMap.tsx`
- Test: `src/pages/threatMapOperational.test.ts`

**Interfaces:**
- Consumes: `ThreatMapData`, `RansomwareVictim`, `CountItem` from `src/services/threatApi.ts`.
- Produces: `VictimTable`, `ContextMapPanel`, `SituationPanel`, `RankingList`, `EvidenceBadges` local components in `src/pages/ThreatMap.tsx`.

- [ ] **Step 1: Update imports and state**

Modify `src/pages/ThreatMap.tsx`:

```ts
import { Search, SlidersHorizontal } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { fetchThreatMap, type CountItem, type RansomwareVictim, type ThreatMapData } from "@/services/threatApi";
```

Add page state:

```ts
const [victimSearch, setVictimSearch] = useState("");
const [groupFilter, setGroupFilter] = useState("all");
const [countryFilter, setCountryFilter] = useState("all");
const [sectorFilter, setSectorFilter] = useState("all");
```

- [ ] **Step 2: Add filter helpers**

Add these helpers above `ThreatMap`:

```ts
const uniqueValues = (values: Array<string | undefined | null>) =>
  Array.from(new Set(values.map((value) => value?.trim()).filter(Boolean) as string[])).sort((a, b) => a.localeCompare(b));

const matchesVictimSearch = (victim: RansomwareVictim, query: string) => {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [
    victim.name,
    victim.group,
    victim.countryName,
    victim.country,
    victim.sector,
    victim.website,
  ].some((value) => value?.toLowerCase().includes(needle));
};

const hasEvidence = (victim: RansomwareVictim) =>
  Boolean(victim.screenshot || victim.press?.length || victim.infostealer || victim.permalink);
```

- [ ] **Step 3: Add `EvidenceBadges`**

Add:

```tsx
function EvidenceBadges({ victim }: { victim: RansomwareVictim }) {
  const badges = [
    victim.screenshot && "screenshot",
    victim.press?.length ? "press" : null,
    victim.infostealer ? "infostealer" : null,
    victim.permalink ? "source" : null,
  ].filter(Boolean) as string[];

  if (!badges.length) return <span className="text-xs text-muted-foreground">-</span>;

  return (
    <div className="flex flex-wrap gap-1.5">
      {badges.map((badge) => (
        <Badge key={badge} variant="outline" className="h-5 px-1.5 text-[10px] uppercase tracking-wide">
          {badge}
        </Badge>
      ))}
    </div>
  );
}
```

- [ ] **Step 4: Add `VictimTable`**

Add a `VictimTable` component that receives `victims`, `totalVictims`, `pt`, `victimSearch`, `setVictimSearch`, `groupFilter`, `setGroupFilter`, `countryFilter`, `setCountryFilter`, `sectorFilter`, `setSectorFilter`, `groupOptions`, `countryOptions`, and `sectorOptions`.

It must render:

```tsx
<h2>{pt ? "Vitimas recentes" : "Recent victims"}</h2>
<Input placeholder={pt ? "Buscar vitima, grupo, pais ou setor" : "Search victim, crew, country, or sector"} />
```

It must render desktop table headers:

```tsx
{pt ? "Vitima" : "Victim"}
{pt ? "Grupo" : "Crew"}
{pt ? "Pais" : "Country"}
{pt ? "Setor" : "Sector"}
{pt ? "Descoberto" : "Discovered"}
{pt ? "Evidencia" : "Evidence"}
{pt ? "Fonte" : "Source"}
```

It must render mobile compact cards using the same victim fields. Empty state text:

```tsx
{pt ? "Nenhuma vitima encontrada nesse filtro." : "No victims found for this filter."}
```

- [ ] **Step 5: Add `SituationPanel`**

Add `SituationPanel` using existing `signal`, `priority`, `delta`, `deltaTone`, `data.generatedAt`, and `fmtDate`. The title must be:

```tsx
{pt ? "Situacao agora" : "Current situation"}
```

It must show: pressure, delta, previous window, updated, top country, top crew, top sector, LATAM, and latest victim.

- [ ] **Step 6: Add `ContextMapPanel`**

Add a compact map component:

```tsx
function ContextMapPanel({ data, pt }: { data: ThreatMapData; pt: boolean }) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="p-0">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <MapPinned className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-black tracking-tight">{pt ? "Mapa contextual" : "Map context"}</h2>
          </div>
          <Badge variant="outline">{data.countries.length} {pt ? "paises" : "countries"}</Badge>
        </div>
        <div className="bg-[linear-gradient(180deg,#0a1120,#0d1a2f)] p-2">
          <ThreatWorldMap countries={data.countries} />
        </div>
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 7: Add `RankingList` and reorder lower sections**

Keep the timeline, rankings, and insights below the first operational grid. Render rankings as compact list panels for countries, groups, and sectors. Timeline remains below the main grid.

- [ ] **Step 8: Replace the page layout**

In `ThreatMap`, compute:

```ts
const filteredVictims = useMemo(() => {
  return (data?.victims || []).filter((victim) => (
    matchesVictimSearch(victim, victimSearch)
    && (groupFilter === "all" || victim.group === groupFilter)
    && (countryFilter === "all" || victim.countryName === countryFilter || victim.country === countryFilter)
    && (sectorFilter === "all" || victim.sector === sectorFilter)
  ));
}, [countryFilter, data?.victims, groupFilter, sectorFilter, victimSearch]);

const groupOptions = useMemo(() => uniqueValues(data?.victims.map((victim) => victim.group) || []), [data?.victims]);
const countryOptions = useMemo(() => uniqueValues(data?.victims.map((victim) => victim.countryName || victim.country) || []), [data?.victims]);
const sectorOptions = useMemo(() => uniqueValues(data?.victims.map((victim) => victim.sector) || []), [data?.victims]);
```

Use this visible hierarchy:

```tsx
<Header />
<Kpis />
<div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
  <VictimTable />
  <div className="space-y-5">
    <SituationPanel />
    <ContextMapPanel />
  </div>
</div>
<TimelineAndRankings />
```

- [ ] **Step 9: Run verification**

Run:

```bash
npx esbuild src/pages/threatMapOperational.test.ts --bundle --platform=node --format=esm --outfile=/tmp/threat-map-operational-test.js && node --test /tmp/threat-map-operational-test.js
npm run typecheck
npm run build
```

Expected: all PASS. `npm run test:unit` may fail because the current worktree already contains unrelated changes outside this task; record that if it happens.

- [ ] **Step 10: Commit**

```bash
git add src/pages/ThreatMap.tsx src/pages/threatMapOperational.test.ts
git commit -m "feat: make threat map operational"
```

---

## Self-Review

- Spec coverage: the plan covers first-viewport victim priority, compact KPIs, local search/filter controls, situation panel, map as context, lower rankings/timeline, and validation.
- Marker scan: no pending markers or unspecified validation.
- Type consistency: `RansomwareVictim`, `ThreatMapData`, `CountItem`, `VictimTable`, `SituationPanel`, `ContextMapPanel`, `RankingList`, and `EvidenceBadges` are all defined in the plan.
