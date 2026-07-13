# Hunt Service Removal Design

Date: 2026-07-13
Branch: `main`
Repository: `/home/mandrade/Dev/thre4th-summary`

## Goal

Remove the Hunt Pack feature and its Python microservice from the current
product. The removal closes the unauthenticated SSRF and resource-exhaustion
surface identified in the security review and leaves no live route, navigation
entry, deployment setting, or CI job that depends on the service.

Git history remains the recovery path if the product reintroduces Hunt Pack.

## Approved Decision

The product will remove the feature instead of hiding it behind a flag or
keeping a disabled compatibility endpoint.

The removal includes the dedicated Threat Hunting page because that page only
acts as a client for Hunt Pack. It has no independent workflow to preserve.

## Current State

The feature spans five areas:

- `hunt-service/` runs FastAPI, Scrapling, OpenRouter, and Pydantic.
- `POST /api/newsletter/hunt-pack` proxies premium requests from Node to the
  Python service and caches generated packs.
- `src/pages/ThreatHunting.tsx` provides the dedicated generation and export
  workflow.
- `src/pages/Newsletter.tsx` embeds Hunt Pack generation in advisory details.
- CI, environment examples, endpoint documentation, product navigation, and
  feature links advertise or configure the feature.

Removing only the Python directory would leave broken controls and a permanent
503 response. The codebase must remove the complete request path.

## Backend Removal

Remove these runtime elements from `server/index.js`:

- The `huntPack` memory cache.
- `POST /api/newsletter/hunt-pack`.
- Proxy logic for `HUNT_SERVICE_URL` and `HUNT_SERVICE_SECRET`.
- Comments that describe the removed integration.

Keep `assertSafePublicUrl` and `isPrivateAddress`. Newsletter enrichment also
uses them when it accepts a user-provided article URL.

Remove `HUNT_SERVICE_URL` and `HUNT_SERVICE_SECRET` from
`server/.env.example`. Do not remove `OPENROUTER_API_KEY`,
`OPENROUTER_MODEL`, or `OPENROUTER_DAILY_MODEL`; Daily Editions, advisory
enrichment, and feed jobs still use those variables.

Requests to the old Hunt Pack endpoint should reach the standard unknown API
handler and return HTTP 404.

## Frontend Removal

Delete `src/pages/ThreatHunting.tsx` and remove:

- Its lazy import and `/threat-hunting` route from `src/App.tsx`.
- Its navigation item and now-unused icon import from `src/components/Header.tsx`.
- The `threat-hunting` feature metadata from `src/components/PremiumRoute.tsx`
  when no remaining route uses it.
- Home and Features page links that point to `/threat-hunting`.

Remove the embedded Hunt Pack integration from `src/pages/Newsletter.tsx`:

- Hunt Pack response types.
- Per-advisory Hunt Pack state.
- The request handler.
- Generate, retry, loading, result, copy, and detection-query controls.
- Imports used only by that block.

Newsletter enrichment, deterministic IOC extraction, IOC copying, and CSV
export must remain unchanged.

The removal does not uninstall `pptxgenjs`; Patch Tuesday exports still use the
package.

## Product And Operations Cleanup

Remove active Hunt Pack references from:

- `package.json`, including `ci:hunt`.
- `.github/workflows/ci.yml`, including the Python compile job.
- `README.md`, `DEPLOYMENT.md`, and `ENDPOINTS.txt`.
- `.gitignore` entries used only by the removed service.
- `PRODUCT_IDEA.txt` statements that describe the service as an existing
  component.

Historical specifications and implementation plans under `docs/superpowers/`
remain unchanged. They record earlier decisions and are not deployment or user
documentation.

Generic references to threat hunting as a cybersecurity discipline may remain
in SEO and product copy when they do not promise the removed generator or link
to the removed route.

## User-Visible Behavior

- The header, home page, and Features page no longer link to
  `/threat-hunting`.
- Direct navigation to `/threat-hunting` reaches the application's existing
  not-found view.
- Newsletter advisory details no longer show Hunt Pack controls.
- Existing newsletter, IOC, report, Daily Editions, and Attack Surface flows
  retain their current behavior.
- Direct API requests to `/api/newsletter/hunt-pack` return HTTP 404.

## Verification

Add a backend regression test that posts to the removed Hunt Pack endpoint and
expects HTTP 404. The test proves that no compatibility handler or proxy remains.

Add a focused source-level regression test that checks the live frontend route,
navigation, Newsletter page, package scripts, and CI workflow for removed Hunt
Pack integration identifiers. Historical design documents are outside this
assertion.

Run these checks after implementation:

```bash
npm run test:unit
npm run test:brand
npm run test:server
npm run ci
node --check server/index.js
rg -n -i "hunt-service|hunt-pack|HUNT_SERVICE|/threat-hunting" \
  src server package.json README.md DEPLOYMENT.md ENDPOINTS.txt \
  PRODUCT_IDEA.txt .github .gitignore
```

The final `rg` command should return no live integration references. Allowed
historical references remain under `docs/superpowers/`.

## Non-Goals

- Do not redesign Threat Hunting as a new local workflow.
- Do not change unrelated OpenRouter features.
- Do not address the remaining security audit findings in this change.
- Do not modify or commit the user's existing working-tree changes.
- Do not purge Hunt Pack code from Git history.
