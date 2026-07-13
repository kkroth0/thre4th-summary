# Advisories Daily Summary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `/advisories` into a public "Summ4ry das ultimas 36h" with deterministic executive bullets and an organized feed.

**Architecture:** Extract daily brief shaping logic into a focused backend helper, test it with `node:test`, then wire the existing endpoint to the helper. Extend the frontend API types and update `src/pages/Advisories.tsx` to render the summary-first page without changing route behavior or admin post publishing.

**Tech Stack:** Express 5, Node ESM, React 18, Vite, TypeScript, Tailwind, shadcn/ui, lucide-react, node:test.

## Global Constraints

- The approved summary window is the last 36 hours.
- Do not add a new data pipeline or worker.
- Do not require login for the daily summary.
- Do not remove manual advisory posts or admin publishing.
- Do not add LLM-generated prose in this change.
- Use deterministic summary bullets from normalized feed data.
- Run `npm run typecheck`, `npm run build`, `node --check server/index.js`, and `node --check server/ctiIntel.js`.
- When the change is complete and verification passes, commit and `git push` to trigger deployment.

---

## File Structure

- Create `server/dailyBrief.js`: pure helpers for executive bullets, feed item normalization, feed grouping, and full daily brief response shaping.
- Create `server/test/dailyBrief.test.js`: hermetic unit tests for the new helper behavior.
- Modify `server/index.js`: import `buildDailyBrief` and replace inline `/api/intel/daily-brief` response shaping.
- Modify `src/services/threatApi.ts`: add `windowHours`, `executiveSummary`, and `feedGroups` to the `DailyBrief` contract.
- Modify `src/pages/Advisories.tsx`: render the summary-first page and organized feed.
- Modify `docs/superpowers/plans/2026-07-13-advisories-daily-summary-implementation.md`: update task checkboxes as work completes.

---

### Task 1: Backend Daily Brief Helper

**Files:**
- Create: `server/dailyBrief.js`
- Create: `server/test/dailyBrief.test.js`

**Interfaces:**
- Consumes: normalized feed items from `refreshNewsletterFeed()`, ransomware victims from `getRecentRansomwareVictims()`, `countBy`, and `LATAM_COUNTRIES`.
- Produces:
  - `buildDailyBrief({ feed, victims, now, countBy, latamCountries }): DailyBriefResponse`
  - `buildExecutiveSummary({ kev, critical, victims, latamVictims, cves, highSignal }): string[]`
  - `buildFeedGroups({ recent, victims }): DailyBriefFeedGroup[]`

- [ ] **Step 1: Write failing helper tests**

Create `server/test/dailyBrief.test.js` with this structure:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDailyBrief,
  buildExecutiveSummary,
  buildFeedGroups,
} from '../dailyBrief.js';

const now = new Date('2026-07-13T12:00:00.000Z').getTime();
const countBy = (arr, fn) => {
  const map = new Map();
  for (const item of arr) {
    const key = fn(item) || 'Unknown';
    map.set(key, (map.get(key) || 0) + 1);
  }
  return [...map.entries()].map(([name, count]) => ({ name, count }));
};

const feed = [
  {
    title: 'CVE-2026-1111 exploited in the wild',
    link: 'https://example.com/kev',
    source: 'CISA Advisories',
    pubDate: '2026-07-13T08:00:00.000Z',
    score: 95,
    severity: 'Critical',
    cves: ['CVE-2026-1111'],
    kev: true,
    reasons: ['CISA KEV - Actively Exploited (CVE-2026-1111)'],
  },
  {
    title: 'Critical firewall advisory',
    link: 'https://example.com/critical',
    source: 'Vendor PSIRT',
    pubDate: '2026-07-13T07:00:00.000Z',
    score: 82,
    severity: 'Critical',
    cves: ['CVE-2026-2222'],
    reasons: ['CVSS Critical (9.8)'],
  },
  {
    title: 'Low priority product update',
    link: 'https://example.com/low',
    source: 'Vendor Blog',
    pubDate: '2026-07-13T06:00:00.000Z',
    score: 15,
    severity: 'Low',
    cves: [],
    reasons: [],
  },
  {
    title: 'Old advisory outside the window',
    link: 'https://example.com/old',
    source: 'Vendor Blog',
    pubDate: '2026-07-10T06:00:00.000Z',
    score: 100,
    severity: 'Critical',
    cves: ['CVE-2026-9999'],
    kev: true,
    reasons: ['old'],
  },
];

const victims = [
  {
    name: 'Example SA',
    group: 'LockExample',
    country: 'BR',
    countryName: 'Brazil',
    sector: 'Manufacturing',
    discovered: '2026-07-13T03:00:00.000Z',
    source: 'ransomware.live',
  },
];

test('buildExecutiveSummary creates deterministic bullets for strong signals', () => {
  const bullets = buildExecutiveSummary({
    kev: [feed[0]],
    critical: [feed[0], feed[1]],
    victims,
    latamVictims: victims,
    cves: ['CVE-2026-1111', 'CVE-2026-2222'],
    highSignal: [feed[0], feed[1]],
  });

  assert.ok(bullets.length >= 3);
  assert.ok(bullets.some((text) => text.includes('1 KEV')));
  assert.ok(bullets.some((text) => text.includes('2 advisories criticos')));
  assert.ok(bullets.some((text) => text.includes('1 vitima de ransomware')));
});

test('buildFeedGroups separates KEV, critical, ransomware and other items', () => {
  const groups = buildFeedGroups({ recent: feed.slice(0, 3), victims });
  assert.deepEqual(groups.map((g) => g.key), ['kev', 'critical', 'ransomware', 'other']);
  assert.equal(groups.find((g) => g.key === 'kev').items.length, 1);
  assert.equal(groups.find((g) => g.key === 'critical').items.length, 1);
  assert.equal(groups.find((g) => g.key === 'ransomware').items.length, 1);
  assert.equal(groups.find((g) => g.key === 'other').items.length, 1);
});

test('buildDailyBrief filters the last 36 hours and returns the new contract', () => {
  const brief = buildDailyBrief({
    feed,
    victims,
    now,
    countBy,
    latamCountries: new Set(['BR']),
  });

  assert.equal(brief.windowHours, 36);
  assert.equal(brief.summary.totalAdvisories, 3);
  assert.equal(brief.summary.kev, 1);
  assert.equal(brief.summary.critical, 2);
  assert.equal(brief.summary.cves, 2);
  assert.equal(brief.summary.ransomwareVictims, 1);
  assert.equal(brief.summary.latamVictims, 1);
  assert.ok(Array.isArray(brief.executiveSummary));
  assert.ok(Array.isArray(brief.feedGroups));
  assert.equal(brief.highlights.some((item) => item.link === 'https://example.com/old'), false);
});
```

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test server/test/dailyBrief.test.js`

Expected: FAIL with module-not-found for `server/dailyBrief.js`.

- [ ] **Step 3: Implement helper**

Create `server/dailyBrief.js` with pure ESM exports:

```js
const WINDOW_HOURS = 36;
const DAY_MS = 24 * 60 * 60 * 1000;
const WINDOW_MS = WINDOW_HOURS * 60 * 60 * 1000;

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

const itemId = (item) => {
  const base = item.link || `${item.source || 'source'}:${item.title || 'untitled'}`;
  return Buffer.from(String(base)).toString('base64url').slice(0, 24);
};

export function buildExecutiveSummary({ kev, critical, victims, latamVictims, cves, highSignal }) {
  const bullets = [];
  if (kev.length) bullets.push(`${plural(kev.length, 'KEV', 'KEVs')} nas ultimas 36h: priorize CVEs com exploracao conhecida.`);
  if (critical.length) bullets.push(`${plural(critical.length, 'advisory critico', 'advisories criticos')} no periodo, com foco em patching e exposicao externa.`);
  if (victims.length) {
    const topGroup = victims.reduce((acc, victim) => {
      const group = victim.group || 'Unknown';
      acc.set(group, (acc.get(group) || 0) + 1);
      return acc;
    }, new Map());
    const [group] = [...topGroup.entries()].sort((a, b) => b[1] - a[1])[0] || [];
    bullets.push(`${plural(victims.length, 'vitima de ransomware', 'vitimas de ransomware')} reportada${victims.length === 1 ? '' : 's'}${group ? `; grupo mais recorrente: ${group}.` : '.'}`);
  }
  if (latamVictims.length) bullets.push(`${plural(latamVictims.length, 'caso LATAM', 'casos LATAM')} no recorte de ransomware.`);
  if (cves.length && !kev.length) bullets.push(`${plural(cves.length, 'CVE unica', 'CVEs unicas')} apareceu${cves.length === 1 ? '' : 'ram'} no feed recente.`);
  if (!bullets.length || !highSignal.length) bullets.push('Nenhum sinal de alta prioridade dominou a janela de 36h.');
  return bullets.slice(0, 5);
}

const advisoryItem = (item) => ({
  id: itemId(item),
  kind: 'advisory',
  title: item.title,
  link: item.link,
  source: item.source,
  pubDate: item.pubDate,
  score: item.score || 0,
  severity: item.severity || 'Low',
  cves: item.cves || [],
  kev: !!item.kev,
  reasons: item.reasons || [],
});

const ransomwareItem = (victim) => ({
  id: itemId({ link: `${victim.name}:${victim.group}:${victim.discovered}`, source: victim.source, title: victim.name }),
  kind: 'ransomware',
  title: victim.name,
  source: victim.source || 'ransomware.live',
  pubDate: victim.discovered || victim.published || null,
  cves: [],
  reasons: [],
  group: victim.group,
  countryName: victim.countryName,
  sector: victim.sector,
});

export function buildFeedGroups({ recent, victims }) {
  const used = new Set();
  const pick = (predicate) => recent.filter((item) => {
    const id = itemId(item);
    if (used.has(id) || !predicate(item)) return false;
    used.add(id);
    return true;
  }).map(advisoryItem);

  const groups = [
    {
      key: 'kev',
      title: 'Exploracao ativa / KEV',
      description: 'Itens com CVEs conhecidas como exploradas ou sinal forte de exploracao.',
      items: pick((item) => item.kev || (item.reasons || []).some((reason) => /exploited|explor/i.test(reason))),
    },
    {
      key: 'critical',
      title: 'Criticas',
      description: 'Advisories criticos que ainda nao entraram no grupo KEV.',
      items: pick((item) => String(item.severity || '').toLowerCase() === 'critical'),
    },
    {
      key: 'ransomware',
      title: 'Ransomware',
      description: 'Vitimas e noticias relacionadas a ransomware no recorte recente.',
      items: [
        ...victims.map(ransomwareItem),
        ...pick((item) => /ransomware|extortion|leak site/i.test(`${item.title} ${item.description || ''} ${(item.reasons || []).join(' ')}`)),
      ],
    },
    {
      key: 'other',
      title: 'Outras noticias relevantes',
      description: 'Demais itens do feed das ultimas 36h.',
      items: pick(() => true),
    },
  ];

  return groups;
}

export function buildDailyBrief({ feed, victims, now = Date.now(), countBy, latamCountries }) {
  const recent = (feed || []).filter((item) => {
    const t = new Date(item.pubDate || item.date || 0).getTime();
    return Number.isFinite(t) && now - t <= WINDOW_MS;
  });
  const recentVictims = (victims || [])
    .filter((victim) => !victim.discovered || now - new Date(victim.discovered).getTime() <= DAY_MS)
    .slice(0, 12);
  const highSignal = recent.filter((item) => (item.score || 0) >= 65 || item.kev);
  const kev = recent.filter((item) => item.kev);
  const cves = [...new Set(recent.flatMap((item) => item.cves || []))];
  const critical = recent.filter((item) => String(item.severity || '').toLowerCase() === 'critical');
  const latamVictims = recentVictims.filter((victim) => latamCountries.has(victim.country));
  const verdict = kev.length || highSignal.length >= 6 || recentVictims.length >= 8 ? 'hot'
    : highSignal.length || recentVictims.length ? 'watch'
    : 'calm';
  const top = [...recent]
    .sort((a, b) => (b.kev ? 25 : 0) + (b.score || 0) - ((a.kev ? 25 : 0) + (a.score || 0)))
    .slice(0, 10);

  return {
    generatedAt: new Date(now).toISOString(),
    windowHours: WINDOW_HOURS,
    title: verdict === 'hot'
      ? 'Dia quente: priorize exploracao ativa, ransomware e advisories criticos'
      : verdict === 'watch'
        ? 'Dia de atencao: sinais relevantes em advisories e ransomware'
        : 'Dia calmo: monitore CVEs novas e mantenha correcoes planejadas',
    verdict,
    executiveSummary: buildExecutiveSummary({ kev, critical, victims: recentVictims, latamVictims, cves, highSignal }),
    summary: {
      totalAdvisories: recent.length,
      critical: critical.length,
      kev: kev.length,
      cves: cves.length,
      ransomwareVictims: recentVictims.length,
      latamVictims: latamVictims.length,
    },
    highlights: top.map(advisoryItem),
    ransomware: {
      victims: recentVictims,
      groups: countBy(recentVictims, (victim) => victim.group).slice(0, 8),
      latam: latamVictims,
    },
    feedGroups: buildFeedGroups({ recent, victims: recentVictims }),
    sources: ['RSS advisories', 'CISA KEV', 'FIRST EPSS', 'ransomware.live'],
  };
}
```

- [ ] **Step 4: Run helper tests**

Run: `node --test server/test/dailyBrief.test.js`

Expected: PASS for all tests in `dailyBrief.test.js`.

- [ ] **Step 5: Commit backend helper**

Run:

```bash
git add server/dailyBrief.js server/test/dailyBrief.test.js docs/superpowers/plans/2026-07-13-advisories-daily-summary-implementation.md
git commit -m "feat: add daily brief summary helper"
```

Expected: commit succeeds.

---

### Task 2: Wire Daily Brief Endpoint And Types

**Files:**
- Modify: `server/index.js`
- Modify: `src/services/threatApi.ts`

**Interfaces:**
- Consumes: `buildDailyBrief({ feed, victims, now, countBy, latamCountries })` from `server/dailyBrief.js`.
- Produces: `DailyBrief` frontend type with `windowHours`, `executiveSummary`, and `feedGroups`.

- [ ] **Step 1: Import helper**

In `server/index.js`, add:

```js
import { buildDailyBrief } from './dailyBrief.js';
```

- [ ] **Step 2: Replace inline endpoint shaping**

Inside `GET /api/intel/daily-brief`, keep feed refresh and victim fetch, then return:

```js
const victims = await getRecentRansomwareVictims().catch(() => []);
res.json(buildDailyBrief({
  feed,
  victims,
  now: Date.now(),
  countBy,
  latamCountries: LATAM_COUNTRIES,
}));
```

- [ ] **Step 3: Extend TypeScript contract**

In `src/services/threatApi.ts`, add:

```ts
export interface DailyBriefFeedItem {
    id: string;
    kind: "advisory" | "ransomware";
    title: string;
    link?: string;
    source: string;
    pubDate?: string | null;
    score?: number;
    severity?: string;
    cves: string[];
    kev?: boolean;
    reasons: string[];
    group?: string;
    countryName?: string;
    sector?: string;
}

export interface DailyBriefFeedGroup {
    key: "kev" | "critical" | "ransomware" | "other";
    title: string;
    description: string;
    items: DailyBriefFeedItem[];
}
```

Extend `DailyBrief`:

```ts
windowHours: number;
executiveSummary: string[];
feedGroups: DailyBriefFeedGroup[];
```

- [ ] **Step 4: Run endpoint/type checks**

Run:

```bash
node --check server/index.js
node --check server/dailyBrief.js
npm run typecheck
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit endpoint and contract**

Run:

```bash
git add server/index.js src/services/threatApi.ts docs/superpowers/plans/2026-07-13-advisories-daily-summary-implementation.md
git commit -m "feat: expose organized daily brief data"
```

Expected: commit succeeds.

---

### Task 3: Redesign Advisories Page Around The 36h Summary

**Files:**
- Modify: `src/pages/Advisories.tsx`

**Interfaces:**
- Consumes: `DailyBrief.windowHours`, `DailyBrief.executiveSummary`, `DailyBrief.feedGroups`, existing `highlights`, `summary`, `ransomware`, and manual posts.
- Produces: public `/advisories` page that reads as "Summ4ry das ultimas 36h" with manual posts below.

- [ ] **Step 1: Add display helpers**

Add helper functions near the existing `fmtDate`:

```ts
const fmtDateTime = (iso: string | null | undefined, lang: string) =>
    iso ? new Date(iso).toLocaleString(LOCALE[lang] || "en-US", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
    }) : "";

const groupTone: Record<string, string> = {
    kev: "border-red-500/30 bg-red-500/5",
    critical: "border-orange-500/30 bg-orange-500/5",
    ransomware: "border-purple-500/30 bg-purple-500/5",
    other: "border-border bg-card",
};
```

- [ ] **Step 2: Change page header copy**

Change the page title to:

```tsx
{tr({ pt: "Summ4ry das ultimas 36h", en: "Last 36h Summ4ry", es: "Summ4ry de las ultimas 36h", fr: "Summ4ry des dernieres 36 h" })}
```

Change subtitle to mention advisories, exploração ativa, ransomware, CVEs, and security news from the last 36 hours.

- [ ] **Step 3: Render executive summary in the top block**

Inside the `brief &&` section, add a compact executive summary column:

```tsx
<div className="rounded-lg border border-border bg-background p-4">
    <div className="mb-3 text-xs font-bold uppercase tracking-wide text-muted-foreground">
        {tr({ pt: "Resumo executivo", en: "Executive summary", es: "Resumen ejecutivo", fr: "Resume executif" })}
    </div>
    <ul className="space-y-2">
        {(brief.executiveSummary || []).map((line) => (
            <li key={line} className="flex gap-2 text-sm leading-relaxed text-foreground">
                <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                <span>{line}</span>
            </li>
        ))}
    </ul>
</div>
```

Also show the generated timestamp:

```tsx
<span>{tr({ pt: "Janela", en: "Window", es: "Ventana", fr: "Fenetre" })}: {brief.windowHours || 36}h</span>
<span>{fmtDateTime(brief.generatedAt, language)}</span>
```

- [ ] **Step 4: Render organized feed groups below highlights/ransomware**

Add a new section after the top brief grid:

```tsx
<section>
    <div className="mb-4 flex items-center justify-between gap-4 border-b border-border pb-4">
        <div>
            <h2 className="text-2xl font-black tracking-tight">
                {tr({ pt: "Feed organizado", en: "Organized feed", es: "Feed organizado", fr: "Flux organise" })}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
                {tr({ pt: "Itens das ultimas 36h agrupados por prioridade operacional.", en: "Last 36h items grouped by operational priority.", es: "Items de las ultimas 36h agrupados por prioridad.", fr: "Elements des dernieres 36 h groupes par priorite." })}
            </p>
        </div>
    </div>
    <div className="space-y-4">
        {(brief.feedGroups || []).map((group) => (
            <div key={group.key} className={`rounded-lg border p-4 ${groupTone[group.key] || groupTone.other}`}>
                <div className="mb-3 flex items-start justify-between gap-3">
                    <div>
                        <h3 className="font-bold">{group.title}</h3>
                        <p className="text-sm text-muted-foreground">{group.description}</p>
                    </div>
                    <Badge variant="secondary">{group.items.length}</Badge>
                </div>
                {group.items.length ? (
                    <div className="divide-y divide-border/70">
                        {group.items.map((item) => (
                            <div key={item.id} className="py-3 first:pt-0 last:pb-0">
                                <div className="flex flex-wrap items-center gap-2">
                                    {item.kind === "ransomware" ? <Badge variant="outline">ransomware</Badge> : null}
                                    {item.kev ? <Badge variant="destructive">KEV</Badge> : null}
                                    {item.severity ? <Badge variant="secondary">{item.severity}</Badge> : null}
                                    {typeof item.score === "number" ? <span className="font-mono text-xs text-muted-foreground">{item.score}/100</span> : null}
                                    <span className="text-xs text-muted-foreground">{item.source}</span>
                                    {item.pubDate ? <span className="text-xs text-muted-foreground">{fmtDateTime(item.pubDate, language)}</span> : null}
                                </div>
                                {item.link ? (
                                    <a href={item.link} target="_blank" rel="noreferrer" className="mt-1 block font-semibold text-foreground hover:text-primary">
                                        {item.title}
                                    </a>
                                ) : (
                                    <div className="mt-1 font-semibold text-foreground">{item.title}</div>
                                )}
                                {item.kind === "ransomware" ? (
                                    <p className="mt-1 text-xs text-muted-foreground">{[item.group, item.countryName, item.sector].filter(Boolean).join(" · ")}</p>
                                ) : item.cves.length ? (
                                    <p className="mt-1 font-mono text-xs text-muted-foreground">{item.cves.slice(0, 6).join(" · ")}</p>
                                ) : null}
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="py-4 text-sm text-muted-foreground">
                        {tr({ pt: "Nenhum item neste grupo.", en: "No items in this group.", es: "Sin items en este grupo.", fr: "Aucun element dans ce groupe." })}
                    </p>
                )}
            </div>
        ))}
    </div>
</section>
```

- [ ] **Step 5: Rename manual posts section**

Change section title from "Publicações" to "Analises publicadas" in Portuguese and equivalent copy in other languages. Keep `PostEditor`, post cards, RSS button, and post links unchanged.

- [ ] **Step 6: Run frontend checks**

Run:

```bash
npm run typecheck
npm run build
```

Expected: both commands exit 0.

- [ ] **Step 7: Commit frontend page**

Run:

```bash
git add src/pages/Advisories.tsx docs/superpowers/plans/2026-07-13-advisories-daily-summary-implementation.md
git commit -m "feat: make advisories a 36h daily summary"
```

Expected: commit succeeds.

---

### Task 4: Final Verification And Deploy

**Files:**
- Modify: `docs/superpowers/plans/2026-07-13-advisories-daily-summary-implementation.md`

**Interfaces:**
- Consumes: all implementation commits from Tasks 1-3.
- Produces: pushed `main` branch so the configured CI/CD deploys the site.

- [ ] **Step 1: Run full relevant verification**

Run:

```bash
node --test server/test/dailyBrief.test.js
npm run typecheck
npm run build
node --check server/index.js
node --check server/ctiIntel.js
node --check server/dailyBrief.js
```

Expected: all commands exit 0.

- [ ] **Step 2: Check git state**

Run: `git status --short --branch`

Expected: branch is `main`; only the plan checkbox file may be modified.

- [ ] **Step 3: Commit final plan checkbox updates if needed**

If the plan file has checkbox updates after the last feature commit, run:

```bash
git add docs/superpowers/plans/2026-07-13-advisories-daily-summary-implementation.md
git commit -m "docs: mark advisories summary plan complete"
```

Expected: commit succeeds, or no commit is needed if the plan was already clean.

- [ ] **Step 4: Push to deploy**

Run: `git push origin main`

Expected: push succeeds and the existing deployment pipeline starts from `main`.

- [ ] **Step 5: Report deploy status**

Check local push output and report the pushed commit SHA. If the repository exposes deployment status locally or through existing tooling, include it. If not, report that the push was completed and CI/CD should publish from `main`.
