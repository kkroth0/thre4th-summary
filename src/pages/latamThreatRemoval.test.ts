import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("legacy LATAM and threat-map routes are retired without loading page chunks", async () => {
  const app = await read("src/App.tsx");

  assert.doesNotMatch(app, /LatamThreats/);
  assert.doesNotMatch(app, /\/(?:latam-threats|threat-map)/);
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
