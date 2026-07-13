# Unified Attack Surface Design

Date: 2026-07-13
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Merge the current Attack Surface and Exposure Watchlist workflows into one clear
feature at `/attack-surface`.

The unified feature will let an analyst:

- run a one-off external exposure search;
- upload a `.txt` file and auto-fill IP, CIDR, domain, ASN, or Shodan-query
  targets;
- save targets for scheduled exposure monitoring;
- review snapshots and changes without leaving Attack Surface;
- export the current Attack Surface findings to XLSX.

The main product outcome is less ambiguity: "Attack Surface" becomes the single
place for external exposure discovery and monitoring. "Exposure Watchlist"
becomes a monitoring mode inside that feature, not a separate product surface.

## Non-Goals

- Do not replace the existing Attack Surface backend provider logic.
- Do not migrate JSON persistence to a database.
- Do not add new notification channels.
- Do not add automatic asset discovery.
- Do not run active TCP validation unless the user explicitly enables it.
- Do not scan arbitrary ports. Validation stays limited to provider-observed
  public IP and port pairs.

## Current State

The project already has:

- `/attack-surface`, a public one-off external exposure scan page.
- `POST /api/attack-surface`, backed by `server/attackSurface.js`.
- `/exposure-watchlist`, a premium saved-assets and snapshots page.
- Exposure Watchlist backend routes under `/api/exposure-watchlist`.
- Watchlist snapshots that reuse the normalized Attack Surface finding shape.
- `exceljs` already installed and used lazily by Patch Tuesday exports.

This means the change is primarily a frontend product consolidation plus a small
export/import utility layer. The backend can remain mostly unchanged.

## Considered Approaches

### Recommended: One Route, Two Modes

Keep `/attack-surface` as the canonical page and add two top-level modes:

- `Scan`: one-off search, upload TXT, results, filters, XLSX export.
- `Monitor`: saved assets, run snapshot, recent changes, snapshot history.

Redirect `/exposure-watchlist` to `/attack-surface?mode=monitor`.

Trade-off: this is the clearest user model and preserves existing backend work.
The page becomes larger, so the implementation can split UI helpers where it
keeps the file understandable.

### Alternative: Keep Two Routes With Better Naming

Rename Exposure Watchlist to something like "Attack Surface Monitoring" and
visually restyle it.

Trade-off: lower implementation cost, but it does not fully solve the ambiguity
the user called out.

### Alternative: Fully Merge Backend Endpoints

Create new `/api/attack-surface/assets` monitoring endpoints and deprecate
`/api/exposure-watchlist`.

Trade-off: cleaner API naming, but unnecessary migration risk for this request.
The existing watchlist backend already works and uses the right domain objects.

## User Experience

The unified page uses the existing `PageLayout`, `soc-panel`, compact badges,
metric cards, and dense tables from Attack Surface rather than the generic card
layout currently used by Exposure Watchlist.

### Header

The page title remains Attack Surface. The header explains that the feature
covers discovery and monitoring. Source badges remain visible: Shodan primary,
Censys optional, TCP validation opt-in.

### Top-Level Mode

Use the existing shadcn `Tabs` pattern as the top-level mode switch:

- `Scan`
- `Monitor`

The selected mode must be reflected in the URL query string so
`/attack-surface?mode=monitor` deep-links to monitoring.

### Scan Mode

Scan mode keeps the current guided and advanced search controls:

- Guided target type: CIDR, domain, IP, organization.
- Advanced Shodan query.
- Limit.
- Active TCP validation checkbox and warning.
- Submit button.

Add an import control for `.txt` files. The import reads the file client-side,
extracts supported target lines, and fills the scan controls with a preview.

The import behavior:

- one recognized target fills the corresponding guided or advanced field;
- multiple recognized targets populate an import preview list;
- the first target becomes the active scan target;
- the user can select a different imported target before running the scan;
- invalid or unsupported lines are shown as ignored count, not fatal errors.

Supported TXT patterns:

- IPv4: `8.8.8.8`
- CIDR: `8.8.8.0/24`
- domain: `example.com`
- ASN: `AS15169` or `15169`
- advanced Shodan query: lines prefixed with `shodan:` or `query:`

### Results And XLSX Export

When scan results exist, show the current metrics, filters, top ports, warnings,
and findings table.

Add an `Excel` export button near the results filter/action area. The button is
disabled until a result exists. It exports the current scan response, including:

- Overview sheet: generated time, query, limit, validation flag, summary counts.
- Findings sheet: risk, score, IP, port, transport, service, product, version,
  CVEs, organization, ASN, location, source flags, observed time, TCP validation.
- Risk Summary sheet: counts by critical, high, medium, low.

The XLSX exporter must lazy-load `exceljs`, following the Patch Tuesday export
pattern so the route chunk does not eagerly load Excel code.

### Monitor Mode

Monitor mode replaces the separate Exposure Watchlist page. It uses the same
`soc-panel` look as Scan mode.

Primary layout:

- left panel: saved target form and TXT import action;
- center panel: saved targets table;
- lower panels: recent changes and selected target history.

The saved target form keeps current fields:

- label;
- type: domain, IP, CIDR, ASN, Shodan query;
- value;
- limit;
- daily snapshot toggle;
- active TCP validation toggle.

TXT import in Monitor mode creates saved target drafts from the
recognized lines. The user still confirms save actions; import does not
immediately persist many assets without review.

### Route And Navigation

- `/attack-surface` renders the unified feature.
- `/attack-surface?mode=monitor` opens monitoring mode.
- `/exposure-watchlist` redirects to `/attack-surface?mode=monitor`.
- Header/sidebar navigation exposes one Attack Surface item only.
- If the monitoring mode is premium-gated, route protection must still apply
  before showing saved assets or calling watchlist APIs. One-off scan mode stays
  as accessible as it is today.

## Data Flow

### One-Off Scan

1. User enters or imports a target.
2. Frontend builds `AttackSurfaceInput`.
3. Frontend calls `fetchAttackSurface`.
4. Backend returns normalized findings.
5. UI renders results.
6. XLSX export uses the in-memory `AttackSurfaceResponse`.

### Monitoring

1. User switches to Monitor mode.
2. Frontend loads assets and recent changes with existing exposure watchlist API
   helpers.
3. User saves or edits a target.
4. User runs a snapshot.
5. Backend executes the existing Attack Surface module through watchlist logic.
6. UI refreshes the target table, recent changes, and selected target history.

## Components And Utilities

Frontend structure:

- keep `src/pages/AttackSurface.tsx` as the canonical page;
- remove or replace `src/pages/ExposureWatchlist.tsx` with a redirect component;
- add TXT parser utility at `src/utils/attackSurfaceImport.ts`;
- add XLSX exporter utility at `src/utils/attackSurfaceExport.ts`;
- extract monitor UI helpers into local components if `AttackSurface.tsx`
  becomes hard to review after the initial merge.

Backend route names can remain unchanged for this iteration:

- `POST /api/attack-surface`
- `/api/exposure-watchlist/*`

## Error Handling

- TXT read errors show a toast and leave current form values untouched.
- TXT import with no recognized targets shows a warning toast.
- Multiple imported targets are shown as selectable drafts.
- XLSX export errors show a destructive toast and do not clear results.
- Watchlist API errors keep using existing public error messages.
- Active TCP validation warning remains visible whenever enabled.

## Testing

Add focused coverage for:

- TXT parser recognition and ignored-line behavior.
- XLSX exporter success path through a mocked or real `exceljs` workbook.
- route redirect from `/exposure-watchlist` to `/attack-surface?mode=monitor`;
- existing Attack Surface and Exposure Watchlist backend tests remain passing.

Manual/browser verification covers:

- scan mode with manual target;
- scan mode TXT import;
- XLSX export button disabled/enabled states;
- monitor mode list, create/edit, run snapshot;
- `/exposure-watchlist` redirect;
- desktop and mobile layout for both modes.

## Decisions

- The feature is one product surface: Attack Surface.
- Monitoring remains implemented through existing Exposure Watchlist APIs for
  now.
- XLSX export belongs to one-off scan results first.
- TXT import supports both scan target fill and monitor target drafts.
