import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("removes the Hunt Pack frontend and dedicated route", async () => {
  const liveSources = await Promise.all([
    "src/App.tsx",
    "src/components/Header.tsx",
    "src/components/PremiumRoute.tsx",
    "src/pages/Index.tsx",
    "src/pages/Features.tsx",
    "src/pages/Newsletter.tsx",
  ].map(read));

  for (const source of liveSources) {
    assert.doesNotMatch(source, /\/threat-hunting|hunt-pack|HuntPack|huntPacks|getHuntPack/);
  }
  await assert.rejects(access("src/pages/ThreatHunting.tsx"), { code: "ENOENT" });
});

test("removes the Hunt service runtime and operational configuration", async () => {
  const activeFiles = await Promise.all([
    "server/index.js",
    "server/.env.example",
    "package.json",
    ".github/workflows/ci.yml",
    "README.md",
    "DEPLOYMENT.md",
    "ENDPOINTS.txt",
    "PRODUCT_IDEA.txt",
    ".gitignore",
  ].map(read));

  for (const source of activeFiles) {
    assert.doesNotMatch(source, /hunt-service|hunt-pack|HUNT_SERVICE|ci:hunt|\/threat-hunting/i);
  }
  await assert.rejects(access("hunt-service"), { code: "ENOENT" });
});
