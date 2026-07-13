# Brand Assets Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the approved `threatsumm4ry-ui-toolkit` identity to the React app, browser metadata, installable icons, and social previews.

**Architecture:** Keep the toolkit as the editable source and copy its release assets into `public`. Add one small React brand component for repeated compact marks, then replace hand-built `t4` blocks with that component. Treat `index.html` and the advisory metadata function as the two metadata entry points.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind CSS, Node test runner, Cloudflare Pages and GitHub Actions.

## Global Constraints

- Do not redesign toolkit assets or alter general layout, colors, navigation, or product copy.
- Use the official mark in compact UI placements.
- Serve the complete favicon, PWA icon, pinned-tab, manifest, and Open Graph package.
- Do not edit generated `dist` files by hand.
- Remove legacy public assets only after proving no source references remain.

---

### Task 1: Brand contract test and public assets

**Files:**
- Create: `src/brandAssets.test.ts`
- Create: `public/threatsumm4ry-mark.svg`
- Create: `public/threatsumm4ry-logo-horizontal-dark.svg`
- Create: `public/threatsumm4ry-logo-horizontal-light.svg`
- Create: `public/threatsumm4ry-og-image-1200x630.png`
- Create: favicon and installable-icon files listed in `threatsumm4ry-ui-toolkit/favicons`
- Modify: `package.json`

**Interfaces:**
- Consumes: release files from `threatsumm4ry-ui-toolkit/brand` and `threatsumm4ry-ui-toolkit/favicons`.
- Produces: stable root URLs such as `/threatsumm4ry-mark.svg`, `/favicon.svg`, and `/site.webmanifest`.

- [ ] **Step 1: Write the failing contract test**

Create a Node test that reads `public`, `index.html`, `src/components/Header.tsx`, `src/pages/Index.tsx`, and `functions/advisories/[slug].js`. Assert that every required asset exists, metadata points to the new files, UI code references `/threatsumm4ry-mark.svg`, advisory metadata points to `/threatsumm4ry-og-image-1200x630.png`, and source code no longer references `/favicon.png`, `/logo.png`, or `/logo-full.jpg`.

- [ ] **Step 2: Run the contract test and verify RED**

Run: `node --test src/brandAssets.test.ts`
Expected: FAIL because the new public assets and references do not exist.

- [ ] **Step 3: Copy approved release assets and expose the test script**

Copy the three brand release assets and every file from `threatsumm4ry-ui-toolkit/favicons` to `public`. Add `"test:brand": "node --test src/brandAssets.test.ts"` to `package.json`.

- [ ] **Step 4: Keep the test red for missing integration**

Run: `npm run test:brand`
Expected: FAIL on HTML and React references while asset-existence assertions pass.

### Task 2: Browser and social metadata

**Files:**
- Modify: `index.html`
- Modify: `functions/advisories/[slug].js`
- Delete after reference audit: `public/favicon.png`, `public/logo.png`, `public/logo-full.jpg`

**Interfaces:**
- Consumes: public URLs created in Task 1.
- Produces: complete browser metadata and social preview metadata.

- [ ] **Step 1: Replace metadata declarations**

Add SVG, 32 px, 16 px and ICO favicon links; Apple Touch Icon; Safari pinned tab; manifest; `theme-color`; Microsoft tile color; canonical Open Graph image and Twitter card metadata. Preserve the RSS declaration and existing analytics script.

- [ ] **Step 2: Update dynamic advisory metadata**

Replace `${url.origin}/favicon.png` with `${url.origin}/threatsumm4ry-og-image-1200x630.png`.

- [ ] **Step 3: Audit and remove legacy files**

Run: `rg -n '/(favicon\.png|logo\.png|logo-full\.jpg)' index.html src functions public --glob '!public/favicon.png' --glob '!public/logo.png' --glob '!public/logo-full.jpg'`
Expected: no output. Remove the three legacy files.

### Task 3: Reusable mark and UI integration

**Files:**
- Create: `src/components/BrandMark.tsx`
- Modify: `src/components/Header.tsx`
- Modify: `src/pages/Index.tsx`

**Interfaces:**
- Produces: `BrandMark({ className?: string, decorative?: boolean })` rendering the official SVG with stable dimensions and accessible alternative text.
- Consumes: `/threatsumm4ry-mark.svg` from Task 1.

- [ ] **Step 1: Create the focused brand primitive**

Implement a plain image component with `className`, `decorative`, `alt`, fixed intrinsic width/height, and `draggable={false}`. Use a decorative empty alt where adjacent text already names the product.

- [ ] **Step 2: Replace hand-built marks in shared navigation**

Use `BrandMark` in mobile header, mobile sheet title, expanded sidebar, and collapsed sidebar. Keep existing sizing and surrounding text.

- [ ] **Step 3: Replace the hand-built public-home mark**

Use `BrandMark` in the public page header without changing its text, spacing, or controls.

- [ ] **Step 4: Verify GREEN**

Run: `npm run test:brand`
Expected: PASS with all brand-contract assertions satisfied.

### Task 4: Automated and rendered verification

**Files:**
- Modify only if verification finds a defect in files from Tasks 1–3.

- [ ] **Step 1: Run static project checks**

Run: `npm run test:brand && npm run test:unit && npm run lint && npm run typecheck && npm run build`
Expected: all commands exit 0.

- [ ] **Step 2: Verify generated files**

Check that `dist/index.html`, `dist/site.webmanifest`, required favicon files, mark SVG and OG image exist and contain the expected URLs.

- [ ] **Step 3: Run rendered desktop and mobile QA**

Because the Browser plugin is unavailable in this session, run Vite locally and use installed Playwright tooling if available. Verify `/` at desktop and mobile widths, sidebar expanded and collapsed where reachable, theme switching, no console errors, no missing images, and one navigation interaction. Save temporary screenshots under `/tmp`.

- [ ] **Step 4: Inspect visual evidence**

Use `view_image` on the official mark and the latest desktop and mobile screenshots. Record mismatches and fix any clipping, scaling, contrast, or asset-loading problem.

### Task 5: Commit, push, deploy, and production probe

**Files:**
- Commit all intended brand, test, plan, and toolkit files; exclude unrelated user changes.

- [ ] **Step 1: Review and commit**

Run `git diff --check`, inspect `git status` and the staged diff, then commit with a scoped message.

- [ ] **Step 2: Push main**

Push the verified commit to `origin/main`. This is authorized by the user's explicit request to push and deploy.

- [ ] **Step 3: Monitor CI and deploy workflows**

Use GitHub CLI to follow CI, Cloudflare Pages, and VPS workflows for the pushed SHA until each reaches a terminal state. If a relevant workflow fails, inspect logs, fix the cause, re-run verification, commit, and push the correction.

- [ ] **Step 4: Probe production**

Request `https://threatsumm4ry.app/`, the new favicon/manifest/mark/OG URLs, and `https://threatsumm4ry.app/api/vendors/status`. Confirm HTTP 200 and inspect production HTML for the new metadata before reporting completion.
