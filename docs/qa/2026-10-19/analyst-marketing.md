# Analyst-focused marketing — 2026-10-19

## Change
- Positioned ThreatSumm4ry around the analyst's workflow: connected investigations, source evidence, prioritization and reports.
- Main Portuguese headline: “Inteligência de ameaças feita para o analista.” English: “Threat intelligence built for the analyst.”
- Replaced landing-page repository/setup calls to action with news investigation, IOC lookup and intelligence overview links.
- Updated footer, sidebar, home SEO, social metadata, manifest, README introduction and product-direction positioning. Legal license files were not changed.

## Local verification
- TypeScript and affected-file lint passed. Frontend unit/brand bundle: 264 tests passed. Production build passed with the existing chunk-size warning.
- Browser preview confirmed the new headline, descriptive copy, internal CTA destinations and footer. No open-source product claim remained in the rendered landing page; no horizontal page overflow was observed at the tested desktop viewport.
- Existing social preview artwork was inspected and contains no open-source claim.
- Temporary preview tab closed and development server stopped.

## Production
- Functional release: `a6c985923fa1c4da5ffac6e6e56c4a3e67903013`.
- CI 39341984468 and Cloudflare Pages deployment 39342165327 passed.
- Public production page verified the exact Portuguese headline, updated title/description/social title, both investigation/IOC links and analyst-focused footer. No open-source claim or horizontal overflow was present.
- Production screenshot saved locally at `C:/Users/mandrade/AppData/Local/Temp/analyst-marketing-2026-10-19/landing-production.jpg`.
- VPS deployment 39342165408 passed, including restart and health checks.
- The separate dependency security scan retains existing findings; this change does not modify dependencies.
