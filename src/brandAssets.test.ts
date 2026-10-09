import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const requiredAssets = [
  "public/threatsumm4ry-mark.svg",
  "public/threatsumm4ry-logo-horizontal-dark.svg",
  "public/threatsumm4ry-logo-horizontal-light.svg",
  "public/threatsumm4ry-og-image-1200x630.png",
  "public/favicon.svg",
  "public/favicon-16x16.png",
  "public/favicon-32x32.png",
  "public/favicon.ico",
  "public/apple-touch-icon.png",
  "public/android-chrome-192x192.png",
  "public/android-chrome-512x512.png",
  "public/maskable-icon-512x512.png",
  "public/safari-pinned-tab.svg",
  "public/site.webmanifest",
  "public/browserconfig.xml",
];

const read = (path: string) => readFile(path, "utf8");

test("publishes the complete approved brand asset set", async () => {
  await Promise.all(requiredAssets.map((path) => access(path)));
});

test("declares the new favicon, manifest, and social metadata", async () => {
  const html = await read("index.html");

  assert.match(html, /href="\/favicon\.svg"/);
  assert.match(html, /href="\/favicon-32x32\.png"/);
  assert.match(html, /href="\/favicon-16x16\.png"/);
  assert.match(html, /href="\/favicon\.ico"/);
  assert.match(html, /href="\/apple-touch-icon\.png"/);
  assert.match(html, /href="\/safari-pinned-tab\.svg"/);
  assert.match(html, /href="\/site\.webmanifest"/);
  assert.match(html, /property="og:image" content="https:\/\/threatsumm4ry\.app\/threatsumm4ry-og-image-1200x630\.png"/);
  assert.match(html, /name="twitter:card" content="summary_large_image"/);
  assert.doesNotMatch(html, /href="\/favicon\.png"/);
});

test("declares canonical production SEO metadata in the base HTML", async () => {
  const html = await read("index.html");

  assert.match(html, /<html lang="pt-BR">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/threatsumm4ry\.app\/" \/>/);
  assert.match(html, /property="og:url" content="https:\/\/threatsumm4ry\.app\/"/);
  assert.match(html, /property="og:image" content="https:\/\/threatsumm4ry\.app\/threatsumm4ry-og-image-1200x630\.png"/);
  assert.match(html, /name="twitter:image" content="https:\/\/threatsumm4ry\.app\/threatsumm4ry-og-image-1200x630\.png"/);
  assert.match(html, /name="language" content="pt-BR"/);
});

test("publishes robots sitemap discovery", async () => {
  const robots = await read("public/robots.txt");

  assert.match(robots, /User-agent: \*/);
  assert.match(robots, /Allow: \//);
  assert.match(robots, /Sitemap: https:\/\/threatsumm4ry\.app\/sitemap\.xml/);
});

test("publishes the approved static sitemap", async () => {
  const sitemap = await read("public/sitemap.xml");
  const expectedRoutes = [
    "/",
    "/analyzer",
    "/cves",
    "/atores",
    "/threat-map",
    "/patch-tuesday",
    "/vendors",
    "/attack-surface",
    "/phishing-analyzer",
  ];

  assert.match(sitemap, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  for (const route of expectedRoutes) {
    const url = route === "/" ? "https://threatsumm4ry.app/" : `https://threatsumm4ry.app${route}`;
    assert.match(sitemap, new RegExp(`<loc>${url.replace(/\//g, "\\/")}<\\/loc>`));
  }

  assert.doesNotMatch(sitemap, /\/login<\/loc>/);
  assert.doesNotMatch(sitemap, /\/settings<\/loc>/);
  assert.doesNotMatch(sitemap, /\/newsletter<\/loc>/);
  assert.doesNotMatch(sitemap, /\/dnsbl<\/loc>/);
});

test("uses the official mark in shared and public navigation", async () => {
  const [header, home, analyzer] = await Promise.all([
    read("src/components/Header.tsx"),
    read("src/pages/Home.tsx"),
    read("src/pages/Index.tsx"),
  ]);

  assert.match(header, /<BrandMark/);
  assert.match(home, /<Header/);
  assert.match(analyzer, /<Header/);
  assert.doesNotMatch(header, />\s*t4\s*</);
  assert.doesNotMatch(home, />\s*t4\s*</);
});

test("does not reference legacy public brand files", async () => {
  const paths = [
    "index.html",
    "src/components/Header.tsx",
    "src/pages/Index.tsx",
  ];
  const sources = await Promise.all(paths.map(read));

  for (const source of sources) {
    assert.doesNotMatch(source, /\/(?:favicon\.png|logo\.png|logo-full\.jpg)/);
  }
});
