import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("legacy LATAM route redirects to the global threat map without loading a page chunk", async () => {
  const app = await read("src/App.tsx");

  assert.doesNotMatch(app, /LatamThreats/);
  assert.match(app, /<Route path="\/latam-threats" element=\{<Navigate to="\/threat-map" replace \/>\} \/>/);
});

test("public navigation, home cards, SEO, and sitemap no longer advertise LATAM Threats", async () => {
  const [header, home, seo, sitemap] = await Promise.all([
    read("src/components/Header.tsx"),
    read("src/pages/Index.tsx"),
    read("src/config/seo.ts"),
    read("public/sitemap.xml"),
  ]);

  for (const source of [header, home, seo, sitemap]) {
    assert.doesNotMatch(source, /\/latam-threats/);
    assert.doesNotMatch(source, /Latam Threats/i);
  }
});

test("removed LATAM page no longer leaves an unused frontend client", async () => {
  const threatApi = await read("src/services/threatApi.ts");

  await assert.rejects(() => access("src/pages/LatamThreats.tsx"));
  assert.doesNotMatch(threatApi, /interface LatamThreats/);
  assert.doesNotMatch(threatApi, /fetchLatamThreats/);
});
