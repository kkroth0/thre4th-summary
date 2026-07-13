# Exposure Watchlist Design

Date: 2026-07-13
Branch: `main`
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Add an Exposure Watchlist feature that turns the current Attack Surface workflow
into continuous monitoring. A signed-in premium user should be able to register
external assets manually, run snapshots on demand, let the backend run daily
snapshots, and review in-app changes between the latest snapshot and the
previous one.

The v1 should answer one operational question clearly:

What changed in my exposed attack surface since the last snapshot?

## Approved Scope

- Asset registration is manual in v1.
- Daily automatic snapshots are included.
- Manual "run snapshot now" is included.
- Active TCP validation is configurable per asset.
- Alerts are in-app only.
- Shodan remains the primary source through the existing Attack Surface logic.
- Censys enrichment remains optional and fail-soft.

## Non-Goals

- Do not add automatic subdomain, CIDR, ASN, or company discovery in v1.
- Do not add email, Slack, Discord, webhook, or SIEM notifications in v1.
- Do not scan arbitrary ports. TCP validation stays limited to provider-observed
  public IPv4 and port pairs.
- Do not build a new microservice.
- Do not migrate persistence to a database in v1.
- Do not add an admin-wide tenant console.
- Do not expose API key material in frontend responses or logs.

## Current State

ThreatSumm4ry already has:

- `/attack-surface`, a public manual scan UI.
- `POST /api/attack-surface`, backed by `server/attackSurface.js`.
- Normalized Attack Surface findings with deterministic risk, optional Censys
  enrichment, and optional active TCP validation.
- Per-user JSON-backed stores for saved scans, users, posts, allowlists, and
  feed jobs.
- Premium route support through GitHub sessions and allow-list gating.
- BYOK support for `shodan` and `censys`, encrypted at rest.

Exposure Watchlist should reuse the Attack Surface scan module instead of
duplicating provider logic.

## User Workflow

1. User opens `/exposure-watchlist`.
2. Premium route checks that the user is signed in and allowed.
3. User creates an asset with:
   - label
   - type
   - value or advanced Shodan query
   - result limit
   - active TCP validation toggle
   - daily schedule toggle
4. User can run the first snapshot immediately.
5. Backend executes the scan through the Attack Surface module.
6. Backend stores the normalized snapshot.
7. Backend compares the new snapshot with the previous snapshot for that asset.
8. UI shows asset status, latest risk, and recent changes.
9. A lightweight backend scheduler runs due scheduled assets daily.
10. User reviews the in-app Changes feed and drills into an asset detail view.

## Asset Types

The v1 supports these manually entered target types:

- `domain`
- `ip`
- `cidr`
- `asn`
- `shodan_query`

Mapping to Attack Surface input:

- `domain`: guided mode with `targetType: "domain"`.
- `ip`: guided mode with `targetType: "ip"`.
- `cidr`: guided mode with `targetType: "cidr"`.
- `asn`: advanced Shodan query `asn:"<asn>"`.
- `shodan_query`: advanced Shodan query using the saved value.

ASN validation should accept `AS12345` and `12345`, normalize to `AS12345`, and
reject non-numeric ASN content.

## Backend Design

### Module

Add a focused module:

- `server/exposureWatchlist.js`

Responsibilities:

- Validate and normalize watchlist assets.
- Convert asset targets to Attack Surface scan input.
- Load and save JSON stores.
- Run snapshots for one asset.
- Compare snapshots.
- Select assets due for daily scheduling.
- Keep per-user caps and retention.

`server/index.js` should only wire routes and scheduler startup.

### Endpoints

All endpoints require premium access.

- `GET /api/exposure-watchlist/assets`
- `POST /api/exposure-watchlist/assets`
- `PATCH /api/exposure-watchlist/assets/:id`
- `DELETE /api/exposure-watchlist/assets/:id`
- `POST /api/exposure-watchlist/assets/:id/run`
- `GET /api/exposure-watchlist/assets/:id/snapshots`
- `GET /api/exposure-watchlist/changes`

The route layer must enforce owner isolation. A user can only read, edit, run,
or delete their own assets and snapshots.

### Asset Shape

```ts
interface ExposureAsset {
  id: string;
  ownerId: string;
  ownerLogin: string;
  label: string;
  type: "domain" | "ip" | "cidr" | "asn" | "shodan_query";
  value: string;
  limit: number;
  activeValidation: boolean;
  scheduleEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastRunAt: string | null;
  lastStatus: "never_run" | "running" | "success" | "error" | "config_error";
  lastError: string | null;
  lastSnapshotId: string | null;
  lastRisk: "critical" | "high" | "medium" | "low" | null;
  lastSummary: ExposureSnapshotSummary | null;
}
```

Limits:

- Maximum 25 assets per user.
- Maximum scan limit 100 per asset, using the same cap as Attack Surface.
- Label max 80 characters.
- Asset value max 512 characters.

### Snapshot Shape

```ts
interface ExposureSnapshot {
  id: string;
  assetId: string;
  ownerId: string;
  startedAt: string;
  completedAt: string | null;
  status: "success" | "error" | "config_error";
  error: string | null;
  input: AttackSurfaceInput;
  summary: ExposureSnapshotSummary;
  findings: AttackSurfaceFinding[];
  changes: ExposureChange[];
  warnings: string[];
}
```

Store only normalized findings from the existing Attack Surface response. Do not
store raw Shodan or Censys responses.

Retention:

- Keep the latest 14 snapshots per asset.
- Keep all changes embedded in retained snapshots.
- Deleting an asset deletes its snapshots.

### Change Shape

```ts
interface ExposureChange {
  id: string;
  assetId: string;
  snapshotId: string;
  detectedAt: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  type:
    | "service_added"
    | "service_removed"
    | "cve_added"
    | "cve_removed"
    | "risk_increased"
    | "risk_decreased"
    | "banner_changed"
    | "validation_changed";
  title: string;
  description: string;
  ip: string | null;
  port: number | null;
  transport: "tcp" | "udp" | null;
  previous: unknown;
  current: unknown;
}
```

The first successful snapshot for an asset should produce informational
baseline changes, not a flood of high-severity "new service" alerts.

## Diff Logic

Use stable service identity:

```txt
ip + ":" + transport + "/" + port
```

Compare the current successful snapshot against the previous successful snapshot
for the same asset.

Detect:

- `service_added`: identity exists now and did not exist before.
- `service_removed`: identity existed before and does not exist now.
- `cve_added`: service has a CVE now that it did not have before.
- `cve_removed`: service no longer has a previous CVE.
- `risk_increased`: risk order increased for a service identity.
- `risk_decreased`: risk order decreased for a service identity.
- `banner_changed`: product, version, service, or banner snippet changed.
- `validation_changed`: active validation status changed when validation was
  attempted in either snapshot.

Severity rules:

- Critical for newly observed CVEs on any service, or a new critical service.
- High for new high-risk services and risk increases to high.
- Medium for new medium-risk services and banner changes on high or critical
  services.
- Low for service removals and risk decreases.
- Info for first baselines and low-risk banner changes.

## Scheduling

Add a lightweight scheduler inside the Node backend process.

Behavior:

- On startup, wait a short warmup period before scheduling.
- Every 15 minutes, select scheduled assets due for a daily run.
- An asset is due when `scheduleEnabled` is true and `lastRunAt` is missing or
  older than 24 hours.
- Run due assets with low concurrency, recommended concurrency 1.
- Do not start a run for an asset already marked `running`.
- Manual runs update the same `lastRunAt` and snapshot history.
- Scheduler failures should mark the asset as `error` or `config_error`, store a
  sanitized message, and continue with the next asset.

Operational controls:

- Add `EXPOSURE_WATCHLIST_DISABLE_DAILY=true` as an emergency off switch.
- Disable the scheduler automatically under `NODE_ENV=test`.

The production deployment is a single VPS backend process, so the v1 does not
need distributed locks. If the backend becomes horizontally scaled later, the
scheduler should move to a worker or database-backed lock.

## API Key Resolution

Manual and scheduled runs should use the same key resolution order:

1. User BYOK key for Shodan or Censys, if configured and decryptable.
2. Server environment key, if configured.
3. Configuration error if Shodan is unavailable.

Censys remains optional. Missing or failing Censys should produce warnings, not
fail the snapshot.

No endpoint should return decrypted keys or reveal whether another user has
configured a key.

## Frontend Design

### Route

Add a premium route:

- `/exposure-watchlist`

Add it to the Analysis or Tools navigation near Attack Surface.

### Page Structure

Use the existing `PageLayout`, shadcn/ui controls, and compact operational
layout.

Primary sections:

- Header with title, daily monitoring badge, and last refresh indicator.
- Asset toolbar with add asset button and filter/search.
- Watchlist table:
  - label
  - type and value
  - latest risk
  - exposed service count
  - critical/high count
  - last run status
  - daily schedule state
  - active TCP state
  - run now action
  - detail action
- Changes feed:
  - grouped by detected date
  - severity badge
  - change type
  - asset label
  - affected service
  - short description
- Asset detail drawer or page:
  - latest summary
  - current exposed services
  - snapshot history
  - changes for the selected asset
  - edit asset controls

### Add/Edit Asset Form

Fields:

- label
- type selector
- value input or Shodan query textarea
- result limit
- active TCP validation switch
- daily monitoring switch

Copy should be direct and operational. The active TCP switch must keep the same
safety framing as Attack Surface: validation is only against provider-observed
public IP and port pairs.

## Error Handling

- Missing Shodan key: asset run becomes `config_error` with a clear in-app
  message.
- Shodan provider error: asset run becomes `error` with sanitized provider
  context.
- Optional Censys error: snapshot succeeds with warning.
- TCP validation failure for one service: finding records validation error;
  snapshot still succeeds.
- Scheduler run failure: asset status updates and scheduler continues.
- Store write failure: route returns 500 for manual actions; scheduler logs and
  marks the asset error if possible.

## Security and Safety

- Require premium auth for every watchlist endpoint.
- Keep owner isolation on every route and store operation.
- Reuse Attack Surface validation for public IPv4 and provider-observed TCP
  validation.
- Store only normalized findings, not raw provider responses.
- Sanitize errors returned to the UI.
- Do not log saved Shodan queries, decrypted API keys, or full banners.
- Keep result and retention caps to prevent unbounded JSON growth.

## Testing

Add focused tests for `server/exposureWatchlist.js`:

- asset validation by type
- ASN normalization
- conversion to Attack Surface input
- first baseline diff
- service added and removed diff
- CVE added diff
- risk increased and decreased diff
- banner changed diff
- due asset selection
- snapshot retention cap

Add route tests only for auth/owner behavior if the route wiring becomes
non-trivial.

Run quality gates before merge:

- `npm run lint`
- `npm run typecheck`
- `npm run build`
- `npm run test:server`
- `node --check server/index.js`
- `node --check server/attackSurface.js`
- `node --check server/exposureWatchlist.js`
- `python3 -m py_compile hunt-service/*.py`

## Acceptance Criteria

- A premium user can create, edit, and delete watchlist assets.
- A premium user can run an asset snapshot manually from the UI.
- Daily scheduling runs enabled assets that are due.
- Snapshots reuse the existing Attack Surface scan logic.
- The UI shows watchlist status, latest risk, and in-app changes.
- The diff detects new/removed services, CVE changes, risk changes, banner
  changes, and validation changes.
- Active TCP validation is controlled per asset and never scans arbitrary ports.
- A user cannot access another user's assets or snapshots.
- Missing Censys does not fail a run.
- Missing Shodan produces a clear configuration error.
- Production deployment remains the existing push-to-main CI/CD flow.
