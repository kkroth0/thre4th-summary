# Newsletter Date and Digest Cleanup Design

## Objective

Simplify `/newsletter` so the page presents the stored news history without a month selector or compilation workflow.

## Date banner

Replace the month navigation, month dropdown, and year dropdown with a read-only banner containing a calendar icon and the current local date. In Portuguese, the banner uses the format `Hoje, 13 de julho de 2026`. Other supported languages use their locale-aware equivalent.

The banner reads the browser's current date. It does not change feed collection, polling, caching, or server requests.

## News history

Remove the selected month and year from the client-side advisory filter. Search, layer, severity, relevance, and KEV filters continue to work across the complete set of advisories held in memory and local storage.

The client keeps the existing cache limit and newest-first ordering. This change does not alter how the server collects news or how the client merges new entries into its cache.

Update the empty state so it refers to the active filters or available history instead of a selected month.

## Compilation removal

Remove the complete digest workflow from `/newsletter`:

- the `Gerar Compilado` banner and dialog;
- the `Selecionar Visíveis` action;
- article checkboxes and selected-row styling;
- selected-article state, derived values, preload effect, print handler, and unused imports.

Article enrichment and the advisory details shown in the feed remain available. Translation keys may stay in the shared translation file if another surface could consume them; this change removes their use from `/newsletter`.

## Responsive behavior

The date banner uses the page's existing card and border styles. Its content stays on one line on mobile and desktop. Removing selection controls gives the search and filter toolbar more room at narrow widths.

## Verification

Automated checks must confirm that TypeScript compiles, lint passes for the edited code, and the production build succeeds. Rendered-page verification must confirm:

- the date banner shows today's date;
- month and year controls are absent;
- advisories from different months can appear in the same list;
- search and existing filters still work;
- compilation controls and article checkboxes are absent;
- feed refresh and advisory details still work on desktop and mobile widths.

## Out of scope

- changing newsletter API endpoints or collection schedules;
- changing the cache capacity or retention policy;
- redesigning advisory cards, enrichment, or source management;
- adding a replacement export or compilation feature.
