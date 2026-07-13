import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("Seo component updates runtime document metadata from the SEO catalog", async () => {
  const source = await read("src/components/Seo.tsx");

  assert.match(source, /getSeoMetadata\(location\.pathname, language\)/);
  assert.match(source, /document\.documentElement\.lang = metadata\.htmlLang/);
  assert.match(source, /document\.title = metadata\.title/);
  assert.match(source, /meta\[name="description"\]/);
  assert.match(source, /meta\[property="og:url"\]/);
  assert.match(source, /meta\[name="twitter:image"\]/);
  assert.match(source, /link\[rel="canonical"\]/);
});

test("App mounts Seo inside the router so route changes can update metadata", async () => {
  const source = await read("src/App.tsx");

  assert.match(source, /import \{ Seo \} from "\.\/components\/Seo";/);
  assert.match(source, /<Seo \/>/);
});
