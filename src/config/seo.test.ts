import assert from "node:assert/strict";
import test from "node:test";
import {
  PUBLIC_SEO_ROUTES,
  SITE_URL,
  getCanonicalUrl,
  getSeoMetadata,
  getSeoRoute,
} from "./seo";

const expectedRoutes = [
  "/",
  "/analyzer",
  "/cves",
  "/atores",
  "/threat-map",
  "/patch-tuesday",
  "/ot-patch-day",
  "/ai-patch-day",
  "/sap-patch",
  "/vendors",
  "/attack-surface",
  "/phishing-analyzer",
];

test("defines the canonical production site URL", () => {
  assert.equal(SITE_URL, "https://threatsumm4ry.app");
});

test("lists the approved public SEO routes only", () => {
  assert.deepEqual(PUBLIC_SEO_ROUTES.map((route) => route.path), expectedRoutes);
  assert.equal(PUBLIC_SEO_ROUTES.some((route) => route.path === "/login"), false);
  assert.equal(PUBLIC_SEO_ROUTES.some((route) => route.path === "/settings"), false);
  assert.equal(PUBLIC_SEO_ROUTES.some((route) => route.path === "/newsletter"), false);
});

test("builds stable absolute canonical URLs", () => {
  assert.equal(getCanonicalUrl("/"), "https://threatsumm4ry.app/");
  assert.equal(getCanonicalUrl("/cves"), "https://threatsumm4ry.app/cves");
  assert.equal(getCanonicalUrl("vendors"), "https://threatsumm4ry.app/vendors");
  assert.equal(getCanonicalUrl("/vendors/"), "https://threatsumm4ry.app/vendors");
});

test("returns localized metadata and falls back to English for unsupported app languages", () => {
  const pt = getSeoMetadata("/phishing-analyzer", "pt");
  const en = getSeoMetadata("/phishing-analyzer", "en");
  const fallback = getSeoMetadata("/phishing-analyzer", "fr");

  assert.match(pt.title, /ThreatSumm4ry/);
  assert.match(pt.description, /phishing/i);
  assert.match(en.description, /phishing/i);
  assert.equal(fallback.title, en.title);
  assert.equal(pt.canonicalUrl, "https://threatsumm4ry.app/phishing-analyzer");
});

test("falls back to homepage metadata for unknown routes", () => {
  const unknown = getSeoRoute("/not-a-real-page");
  assert.equal(unknown.path, "/");
});

test("keeps every public route fully described in both SEO languages", () => {
  const titles = new Set<string>();
  const descriptions = new Set<string>();

  for (const route of PUBLIC_SEO_ROUTES) {
    for (const lang of ["pt", "en"] as const) {
      const metadata = getSeoMetadata(route.path, lang);
      assert.ok(metadata.title.length >= 20, `${route.path} ${lang} title is too short`);
      assert.ok(metadata.description.length >= 80, `${route.path} ${lang} description is too short`);
      assert.ok(metadata.description.length <= 180, `${route.path} ${lang} description is too long`);
      assert.match(metadata.canonicalUrl, /^https:\/\/threatsumm4ry\.app\//);
      titles.add(metadata.title);
      descriptions.add(metadata.description);
    }
  }

  assert.equal(titles.size, PUBLIC_SEO_ROUTES.length * 2);
  assert.equal(descriptions.size, PUBLIC_SEO_ROUTES.length * 2);
});

test("provides metadata needed by the runtime SEO component", () => {
  const metadata = getSeoMetadata("/cves", "pt");

  assert.equal(metadata.htmlLang, "pt-BR");
  assert.equal(metadata.locale, "pt_BR");
  assert.equal(metadata.imageUrl, "https://threatsumm4ry.app/threatsumm4ry-og-image-1200x630.png");
  assert.match(metadata.title, /CVE/i);
  assert.match(metadata.description, /EPSS/);
});
