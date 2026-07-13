# Newsletter Date and Digest Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the newsletter month selector with today's date, show the stored history across months, and remove the digest-selection workflow.

**Architecture:** A small pure utility will own locale-aware date formatting and advisory filtering so Node tests can verify the behavior without rendering React. `Newsletter.tsx` will compose that utility with the existing page and remove month, selection, dialog, and print state.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind, shadcn/ui, Node test runner.

## Global Constraints

- Keep `/api/newsletter`, polling, cache merging, the 400-item cache limit, and source management unchanged.
- Search, layer, severity, relevance, and KEV filters apply to the complete cached history.
- Portuguese date copy uses `Hoje, 13 de julho de 2026`; English, Spanish, and French use locale-aware equivalents.
- Remove digest generation, bulk selection, article checkboxes, and selected-row styling.
- Keep advisory enrichment, sharing, threat hunting, feed refresh, and card details intact.

---

### Task 1: Date and History Utilities

**Files:**
- Create: `src/pages/newsletterView.ts`
- Create: `src/pages/newsletterView.test.ts`

**Interfaces:**
- Produces: `formatNewsletterDate(date: Date, language: Language): string`.
- Produces: `filterNewsletterAdvisories<T extends NewsletterFilterItem>(advisories: T[], options: NewsletterFilterOptions): T[]`.
- Consumes: `Language` from `src/utils/translations.ts`.

- [ ] **Step 1: Write failing date and cross-month history tests**

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { filterNewsletterAdvisories, formatNewsletterDate } from "./newsletterView.ts";

test("formats today's full date in the selected language", () => {
  const date = new Date("2026-07-13T12:00:00-03:00");
  assert.equal(formatNewsletterDate(date, "pt"), "Hoje, 13 de julho de 2026");
  assert.match(formatNewsletterDate(date, "en"), /^Today, July 13, 2026$/);
});

test("keeps matching advisories from different months", () => {
  const advisories = [
    { title: "July item", description: "alpha", source: "CISA", pubDate: "2026-07-01", layer: 1, severity: "High" },
    { title: "June item", description: "alpha", source: "Vendor", pubDate: "2026-06-01", layer: 2, severity: "Medium" },
  ];
  const result = filterNewsletterAdvisories(advisories, {
    search: "alpha", layer: "all", severity: "all", kevOnly: false, sortByRelevance: false,
  });
  assert.deepEqual(result.map((item) => item.title), ["July item", "June item"]);
});
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `npm run test:unit -- --test-name-pattern="full date|different months"`

Expected: FAIL because `src/pages/newsletterView.ts` does not exist.

- [ ] **Step 3: Implement locale-aware formatting and non-calendar filtering**

```ts
import type { Language } from "../utils/translations";

export interface NewsletterFilterItem {
  title: string;
  description: string;
  source: string;
  pubDate: string;
  layer?: number;
  severity?: string;
  kev?: boolean;
  score?: number;
}

export interface NewsletterFilterOptions {
  search: string;
  layer: string;
  severity: string;
  kevOnly: boolean;
  sortByRelevance: boolean;
}

const LOCALES: Record<Language, string> = { pt: "pt-BR", en: "en-US", es: "es-ES", fr: "fr-FR" };
const TODAY: Record<Language, string> = { pt: "Hoje", en: "Today", es: "Hoy", fr: "Aujourd’hui" };

export const formatNewsletterDate = (date: Date, language: Language): string => {
  const formatted = new Intl.DateTimeFormat(LOCALES[language], {
    day: "numeric", month: "long", year: "numeric",
  }).format(date);
  return `${TODAY[language]}, ${formatted}`;
};

export const filterNewsletterAdvisories = <T extends NewsletterFilterItem>(
  advisories: T[],
  options: NewsletterFilterOptions,
): T[] => {
  const query = options.search.toLowerCase();
  const filtered = advisories.filter((item) => {
    const matchesSearch = item.title.toLowerCase().includes(query)
      || item.description.toLowerCase().includes(query)
      || item.source.toLowerCase().includes(query);
    if (!matchesSearch) return false;
    if (options.severity !== "all" && item.severity !== options.severity) return false;
    if (options.kevOnly && !item.kev) return false;
    if (options.layer === "l1" && item.layer !== 1) return false;
    if (options.layer === "l2" && item.layer !== 2) return false;
    if (options.layer === "l3" && (item.layer ?? 0) < 3) return false;
    return true;
  });
  return options.sortByRelevance
    ? [...filtered].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)
      || new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
    : filtered;
};
```

`NewsletterFilterOptions` has no month or year fields.

- [ ] **Step 4: Run the utility tests and confirm GREEN**

Run: `npm run test:unit -- --test-name-pattern="full date|different months"`

Expected: both newsletter utility tests pass.

- [ ] **Step 5: Commit the tested utility**

```bash
git add src/pages/newsletterView.ts src/pages/newsletterView.test.ts
git commit -m "feat: support newsletter history view"
```

### Task 2: Newsletter Interface Cleanup

**Files:**
- Modify: `src/pages/Newsletter.tsx`

**Interfaces:**
- Consumes: `formatNewsletterDate` and `filterNewsletterAdvisories` from `src/pages/newsletterView.ts`.
- Preserves: the existing `Advisory` feed model and enrichment, hunt-pack, refresh, search, and filter handlers.

- [ ] **Step 1: Connect the history filter and current-date banner**

Import both utilities. Replace the month/year state, navigation handlers, names, and selector markup with:

```tsx
<div className="flex items-center gap-2.5 bg-card border rounded-lg p-3">
  <Calendar className="h-4 w-4 text-primary shrink-0" />
  <span className="text-sm font-semibold text-foreground capitalize">
    {formatNewsletterDate(new Date(), language)}
  </span>
</div>
```

Build `filteredAdvisories` by calling `filterNewsletterAdvisories(advisories, { search: searchNews, layer: selectedLayer, severity: selectedSeverity, kevOnly, sortByRelevance })` and remove month/year dependencies.

- [ ] **Step 2: Remove digest and selection code**

Delete `selectedNews`, `isDigestOpen`, selection handlers, `handlePrintDigest`, selected-item derived values, the digest preload effect, the digest card/dialog, `Selecionar Visíveis`, article checkboxes, and selected-row classes. Remove imports used only by those paths, including `Checkbox`, dialog components, `CardDescription`, `DialogTrigger`, `Download`, `Layers`, `ChevronLeft`, and `ChevronRight` when TypeScript confirms they have no remaining use.

- [ ] **Step 3: Make the empty state history-aware**

Use copy that does not mention a month:

```tsx
<p className="text-muted-foreground font-medium">
  {language === "pt" ? "Nenhuma notícia encontrada no histórico" : "No threat advisories found in the stored history"}
</p>
<p className="text-xs text-muted-foreground mt-1">
  {language === "pt" ? "Ajuste a busca ou os filtros, ou atualize os feeds" : "Adjust the search or filters, or refresh the feeds"}
</p>
```

- [ ] **Step 4: Run automated verification**

Run: `npm run test:unit && npm run lint && npm run typecheck && npm run build`

Expected: all commands exit with code 0, no unused imports remain, and Vite produces the production bundle.

- [ ] **Step 5: Verify the rendered page**

Run the local application and inspect `/newsletter` at desktop and mobile widths. Confirm the current-date banner, multi-month history, search/filter behavior, refresh button, expanded advisory details, and absence of month selectors, digest actions, bulk selection, and checkboxes.

- [ ] **Step 6: Commit the page cleanup**

```bash
git add src/pages/Newsletter.tsx
git commit -m "refactor: simplify newsletter history"
```
