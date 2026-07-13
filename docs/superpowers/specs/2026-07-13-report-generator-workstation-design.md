# Report Generator Workstation Redesign — Design

**Date:** 2026-07-13
**Page:** `/daily-bulletin` (`src/pages/DailyBulletin.tsx`, "Gerador de Relatorios")
**Direction:** approved via visual mockups — "Workstation split-view".

## Goal

Turn the single-column Report Generator into a full-width, two-pane CTI
workstation: work column (generate, queue, suggestions) on the left, a
persistent report reading pane on the right. No backend changes.

## Layout

- `PageLayout` gets `width="max-w-7xl"` (prop already exists). Site header,
  sidebar, and footer unchanged.
- Desktop (`lg+`): CSS grid `lg:grid-cols-[400px,1fr]` with a hairline divider
  between columns.
- Below `lg`: columns stack — generator, then report list, then suggestions;
  the report pane renders below the list when a report is selected.

### Left column (top to bottom)

1. **Generator input** — the existing rounded input group (URL field, deck-type
   `Select` with vuln/campaign, "Gerar" button) plus the existing auth footer
   row (`login · pronto para gerar` / link to Settings). The signed-out gate
   card is unchanged and replaces the input group when not authenticated.
2. **"Seus relatórios"** — job list. Each job is a rounded card row (not a
   hairline row) with these states:
   - **pending:** pulsing amber dot, title, elapsed seconds, indeterminate
     progress bar, phase label (existing `PHASES` copy) or queue position.
   - **done:** emerald dot, title, deck-type chip, "Pronto · relative time ·
     source host" meta line. Clickable.
   - **done + selected:** same, with blue border + tinted background
     (`bg-primary/5 border-primary/40`-style).
   - **error:** red dot, muted title, error text, and a new **"tentar de novo"**
     action that re-submits the same URL/type/title via the existing
     `generate()`.
   - Header row keeps the count and the "Limpar" action with its existing
     `AlertDialog` confirmation.
3. **"Sugestões do dia"** — compact hairline rows (severity dot, title, CVE or
   source, "Gerar" action). Keeps existing refresh button and loading/empty
   states. On touch/small screens the "Gerar" action stays always visible
   (current hover-reveal only applies `sm:`+).

### Right column — report pane

New component `src/components/ReportPane.tsx`:

- **Empty state** (no report selected): centered `BrandMark` + "Nenhum
  relatório aberto — selecione um relatório pronto ou gere um novo."
- **Selected report:**
  - Toolbar: TLP badge, deck-type chip, generated date, source link (host +
    external-link icon), then right-aligned actions: "Salvar como Advisory"
    (admin only, existing `PostEditor` trigger with `boletimToDraft`) and
    "Baixar JSON" (existing `download`).
  - Title: the job's `title` (falling back to its URL, as the list row does
    today) in larger type.
  - Body: `BoletimView` sections.
- On `lg+` the pane is sticky (`lg:sticky lg:top-20`, tuned to clear the fixed
  header) with its own `max-height` + `overflow-y-auto` so long reports scroll
  inside the pane.

### `BoletimView` adjustment

The meta row (TLP badge, date, source link) and the `mt-3 border-t pt-3`
wrapper move out of `BoletimView` into the `ReportPane` toolbar. `BoletimView`
keeps only the content sections and stays tolerant of missing fields.
`DailyBulletin` is its only consumer, so no other call sites change.

## Behavior

- `expandedId` becomes `selectedId` (same `useState<string | null>`); clicking
  a done job selects it, clicking the selected job deselects (empty state).
- **Auto-select:** when a pending job transitions to `done` and no report is
  currently selected, it becomes selected. Implemented inside the existing
  poll-update `setJobs` flow.
- **Mobile:** on `<lg`, selecting a job scrolls the report pane into view
  (`scrollIntoView({ behavior: "smooth" })` on a ref).
- Unchanged: 3s polling, `CLIENT_TIMEOUT_MS` (25 min), `ts-bulletins-v1`
  localStorage persistence, `MAX_HISTORY` (40), phase estimation, toasts,
  auth gating, all `threatApi` calls.

## Code structure

- `src/pages/DailyBulletin.tsx` — keeps all state/effects; renders the grid;
  job rows stay as a local `JobListItem` component in the same file.
- `src/components/ReportPane.tsx` — new; props: `{ job: BoletimJob | null,
  isAdmin: boolean, onDownload: (job: BoletimJob) => void }`; renders the
  empty state when `job` is `null`. Owns toolbar + `BoletimView`.
- `src/components/BoletimView.tsx` — meta row and top-border wrapper removed.
- All user-facing strings keep the existing `pt`/`en` dual-language pattern.

## Error handling

- Retry keeps the failed entry in history (new job is prepended, as
  `generate()` already does) — no dedupe needed at `MAX_HISTORY=40`.
- Jobs persisted before this change (with the old shape) load fine: the render
  only reads fields that already exist.

## Verification

- `npm run lint && npm run typecheck && npm run build` all exit 0.
- Rendered QA at desktop and mobile widths (local Vite + Playwright if
  available): generate flow, select/deselect, auto-select on completion,
  retry, JSON download, admin draft button visibility, empty state, dark and
  light themes.
- No new unit tests: the only new logic (auto-select, retry) is thin UI glue
  over existing tested flows.

## Out of scope

- Backend/API, job queue, LLM pipeline.
- `PremiumRoute`, `Features`, `Index` copy about the generator.
- Toolkit brand assets (already handled by the brand integration plan).
