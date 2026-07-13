# Attack Surface Feature Design

Date: 2026-07-12
Branch: `feature/attack-surface`
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Add a dedicated Attack Surface feature to ThreatSumm4ry that turns the existing
Shodan collector idea into a product workflow. Analysts should be able to run a
guided or advanced external exposure search, see exposed assets ranked by risk,
optionally enrich hosts with Censys, and optionally perform active TCP validation
from the ThreatSumm4ry backend when they explicitly enable it.

## Non-Goals

- Do not scan arbitrary ports. Active TCP validation is limited to ports returned
  by Shodan or Censys.
- Do not run active TCP validation by default.
- Do not build a new microservice for the MVP.
- Do not modify the dirty working copy at `/home/mandrade/Dev/THREAT SUMMARY/thre4th-summary`.
- Do not store scan history in the MVP unless existing scan persistence can be
  reused without expanding scope.

## User Workflow

1. User opens `/attack-surface`.
2. User chooses one of two input modes:
   - Guided mode: domain, IP, CIDR, or organization.
   - Advanced mode: raw Shodan query.
3. User sets a result limit.
4. User optionally enables "Validate ports now" after seeing an authorization
   notice.
5. Frontend calls `POST /api/attack-surface`.
6. Backend runs Shodan search or host lookup, normalizes exposed services, and
   enriches IPs with Censys when available.
7. If active validation is enabled, backend attempts TCP connect checks only
   against returned public IP and port pairs.
8. UI renders summary metrics, risk distribution, filters, and an asset table
   with expandable service details.

## Frontend Design

### Route

Add a lazily loaded page at:

- `/attack-surface`

Add it to the sidebar navigation under the existing `Analysis` group because
this is an operational investigation workflow, not a threat feed or report.

### Page Layout

Use the existing `PageLayout` shell and existing shadcn/ui components. The page
should feel like an operational SOC tool: dense, scannable, and focused on
repeat work.

Primary sections:

- Header with title, short subtitle, and beta/source badges.
- Search panel with segmented input mode:
  - Guided inputs for `domain`, `ip`, `cidr`, `org`.
  - Advanced Shodan query textarea/input.
  - Limit selector/input.
  - Toggle or checkbox for active TCP validation.
- Safety notice shown near the active validation control.
- Summary metric row:
  - Total assets.
  - Total exposed services.
  - Critical/high findings.
  - Actively confirmed open services, when validation is enabled.
- Filters:
  - Risk level.
  - Port.
  - Service/product.
  - Validation state.
- Results table:
  - Risk.
  - IP.
  - Port/transport.
  - Service/product/version.
  - CVEs.
  - Organization/ASN/location.
  - Source freshness.
  - Active TCP status.
  - Details action.
- Empty/loading/error states consistent with existing pages.

### Frontend API Types

Add typed helpers to `src/services/threatApi.ts`:

- `AttackSurfaceInput`
- `AttackSurfaceFinding`
- `AttackSurfaceSummary`
- `AttackSurfaceResponse`
- `fetchAttackSurface(input)`

The frontend should not calculate canonical risk. It can derive display-only
counts from the backend response, but the backend owns normalization and risk.

## Backend Design

### Endpoint

Add:

`POST /api/attack-surface`

Use the existing JSON parser, rate limiter, error sanitizer, API key patterns,
and outbound request timeout conventions.

Request shape:

```json
{
  "mode": "guided",
  "targetType": "cidr",
  "target": "203.0.113.0/24",
  "advancedQuery": "",
  "limit": 100,
  "activeValidation": false
}
```

For advanced mode:

```json
{
  "mode": "advanced",
  "advancedQuery": "org:\"Example\" port:3389",
  "limit": 100,
  "activeValidation": true
}
```

### Query Construction

Guided mode maps to Shodan syntax:

- `ip`: use Shodan host lookup for the single IP.
- `cidr`: `net:"<cidr>"`
- `domain`: `hostname:"<domain>"`
- `org`: `org:"<organization>"`

Advanced mode passes the raw Shodan query after validation and length limiting.

### Validation

Backend validation requirements:

- `mode` must be `guided` or `advanced`.
- `limit` must be clamped to a safe maximum. Suggested maximum: 100.
- Guided targets must be validated with existing IP/domain/CIDR helpers or
  equivalent stricter helpers.
- Organization and advanced query strings must be length-limited and reject
  control characters.
- Active TCP validation must only run on public IPv4 addresses.
- Active TCP validation must only attempt ports observed in provider results.

### Provider Behavior

Shodan is required for this feature. If `SHODAN_API_KEY` is missing, return a
clear 503-style configuration error.

Censys is optional. If `CENSYS_API_KEY` is missing or Censys fails for an IP,
the endpoint should still return Shodan results with a warning entry. Censys
failures must not fail the whole scan.

### Normalized Finding

Each exposed service should normalize into this shape:

```ts
interface AttackSurfaceFinding {
  id: string;
  ip: string;
  port: number;
  transport: "tcp" | "udp";
  risk: "critical" | "high" | "medium" | "low";
  riskScore: number;
  riskReasons: string[];
  service: string | null;
  product: string | null;
  version: string | null;
  organization: string | null;
  asn: string | null;
  hostnames: string[];
  country: string | null;
  city: string | null;
  source: {
    shodan: boolean;
    censys: boolean;
  };
  observedAt: string | null;
  cves: string[];
  tags: string[];
  bannerSnippet: string | null;
  validation: {
    attempted: boolean;
    status: "open" | "closed" | "timeout" | "udp_not_supported" | "error" | "not_requested";
    detail: string | null;
  };
}
```

Exact naming can adapt to local TypeScript style, but the API should keep a
stable, documented contract.

### Risk Logic

Start with deterministic rules inspired by the Shodan script, then improve the
reasoning:

- Critical:
  - Any CVE reported by Shodan or Censys.
  - Telnet `23/tcp`.
  - SMB `445/tcp`.
  - RDP `3389/tcp`.
- High:
  - FTP `21/tcp`.
  - SSH `22/tcp`.
  - MSSQL `1433/tcp`.
  - MySQL `3306/tcp`.
  - VNC `5900/tcp`.
  - Admin-like HTTP services when provider data indicates admin panel, login
    page, management, router, camera, printer, or dashboard.
- Medium:
  - SMTP `25/tcp`.
  - Alternative HTTP ports such as `8080/tcp`, `8000/tcp`, `8443/tcp`.
  - Exposed web service with sensitive product tags but no known CVE.
- Low:
  - Standard web ports `80/tcp` and `443/tcp` without CVEs or sensitive signals.
  - Other services with no high-risk rule match.

Risk reasons must be returned to the UI so analysts can audit why an item was
ranked.

### Active TCP Validation

Active validation mirrors the script's socket idea, with product safeguards:

- Disabled unless `activeValidation: true`.
- TCP only. UDP returns `udp_not_supported`.
- Timeout: 3 seconds or less.
- Low concurrency. Suggested maximum: 5 simultaneous sockets.
- Public IPv4 only.
- No retries in MVP.
- Return a per-service validation result; do not block the entire scan if one
  validation fails.

## Testing Strategy

Use test-first implementation for logic that can be isolated:

- Query builder tests.
- Risk scoring tests.
- Shodan/Censys normalization tests using fixtures.
- Active validation helper tests with mocked socket behavior or dependency
  injection.

For UI:

- Prefer focused component tests only if the repo already has a test setup.
- Otherwise verify with `npm run typecheck`, `npm run lint`, and `npm run build`.

For backend:

- At minimum run `node --check server/index.js`.
- Run the existing CI scripts if available:
  - `npm run typecheck`
  - `npm run lint`
  - `npm run build`
  - `npm run ci:server`

## Rollout Notes

- The feature should appear in navigation but remain clearly labeled as Attack
  Surface, not IOC lookup.
- Missing API key errors should guide the operator to configure Shodan/Censys.
- Active validation should show an authorization reminder in the UI.
- Censys enrichment should be visible as an optional source signal rather than a
  hard dependency.

## Open Decisions Resolved

- Use a dedicated page instead of embedding this in IOC lookup.
- Use hybrid guided plus advanced Shodan input.
- Use Shodan plus optional/fail-soft Censys enrichment.
- Include active TCP validation in the MVP, controlled by the UI and off by
  default.
- Implement in a new branch from the clean repository.
