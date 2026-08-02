# Hunting Library Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish and verify the in-progress HEARTH-backed Hunting library, private KQL hunts, and coverage views without expanding phase 3.

**Architecture:** Express fetches and caches the public HEARTH catalog, persists private hunts per authenticated owner, and reuses the existing ATT&CK index for relationships and coverage. The React page composes the existing UI primitives for catalog filtering, private CRUD, report-to-hunt creation, and three coverage axes.

**Tech Stack:** Node.js, Express, `node:test`, React 18, TypeScript, React Router, existing shadcn/Radix components, Tailwind CSS.

## Global Constraints

- KQL only in this phase; ES|QL and the Detection library remain future work.
- HEARTH is a read-only external catalog; copied hypotheses become private user-owned hunts.
- Private hunts and report relationships must never cross account boundaries.
- Add no dependency and no second service.
- Preserve the existing single-page report flow and current site design system.

---

### Task 1: Verify the hunting domain and API boundary

**Files:**
- Create: `server/hearth.js`
- Create: `server/hunts.js`
- Create: `server/test/hunts.test.js`
- Modify: `server/index.js`
- Modify: `server/test/smoke.test.js`

**Interfaces:**
- Produces: `parseHearthData(source)`, `normalizeHuntInput(input, identity)`, `upsertHunt(list, hunt, cap)`.
- Produces: authenticated `/api/hearth`, `/api/hunts`, `/api/hunts/coverage`, and `/api/feed/job/:id/related` endpoints.

- [x] Run `node --test server/test/hunts.test.js` and confirm parser, validation, identity, update, and cap checks pass.
- [x] Run `node --test server/test/smoke.test.js` and confirm authentication, CRUD, and all three coverage axes pass.
- [x] If a check fails, first add or narrow one regression assertion that reproduces the defect, watch it fail, then make the smallest server-side fix and rerun both commands.

### Task 2: Verify the React data flow and pure view helpers

**Files:**
- Create: `src/pages/Hunting.tsx`
- Create: `src/pages/huntingView.ts`
- Create: `src/pages/huntingView.test.ts`
- Create: `src/pages/dailyBulletinView.ts`
- Create: `src/pages/dailyBulletinView.test.ts`
- Modify: `src/services/threatApi.ts`
- Modify: `src/App.tsx`
- Modify: `src/components/Header.tsx`
- Modify: `src/components/PremiumRoute.tsx`
- Modify: `src/components/ReportPane.tsx`
- Modify: `src/pages/DailyBulletin.tsx`

**Interfaces:**
- Consumes: the authenticated hunting and relationship endpoints from Task 1.
- Produces: `/hunting`, report-to-hunt links, related-item navigation, filters, CRUD dialogs, and coverage tabs.

- [x] Run `npm run test:unit` and confirm filtering, list parsing, report links, and persisted-report opening checks pass.
- [x] Run `npm run typecheck` and `npm run build`; fix only concrete type or bundling failures.
- [x] For any behavior fix, add a focused failing pure-helper test first when the behavior can be isolated outside React.

### Task 3: Render and exercise the Hunting workflow

**Files:**
- Verify: `src/pages/Hunting.tsx`
- Reference: `other-sites-examples/`

**Interfaces:**
- Consumes: the existing local Vite and Express development scripts.
- Produces: visual and interaction evidence for the primary Hunting workflow.

- [x] Start the local app without changing dependencies.
- [x] Verify desktop and mobile rendering: header, filter rail, result table, detail dialog, private hunt form, and coverage tabs have no clipping or overflow.
- [x] Exercise `/hunting` → filter catalog → open hunt → copy as private hypothesis → save → inspect coverage.
- [x] Check URL/title, meaningful content, framework overlays, console warnings/errors, and the observed state change after the interaction.
- [x] Compare the latest screenshot with the supplied Detection Library reference using `view_image`; fix only visible mismatches within the approved information architecture.

### Task 4: Final verification and phase commit

**Files:**
- Review: all phase-3 files listed above.

- [x] Run `npm run lint`, `npm run typecheck`, `npm run test:unit`, `npm run test:server`, and `npm run build` from a clean command invocation.
- [x] Review `git diff --check`, the complete phase diff, and `git status --short`; exclude the user transcript and reference screenshots from staging.
- [x] Commit only the phase-3 plan, implementation, and tests with `git commit -m "feat: conectar hunting ao HEARTH e aos relatórios"`.
