import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("the ransomware victims page and its legacy alias are no longer advertised or routed", async () => {
  for (const path of ["src/App.tsx", "src/components/useNavCatalog.ts", "src/components/WorkspaceShell.tsx", "src/pages/Home.tsx", "src/config/seo.ts", "public/sitemap.xml"]) {
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(source, /\/(?:threat-map|latam-threats)/, path);
  }
  for (const path of ["src/pages/ThreatMap.tsx", "src/components/workbench/RansomwareVictimsTable.tsx"]) {
    await assert.rejects(access(path), { code: "ENOENT" });
  }
});

test("retired ransomware victims API clients and page types are removed", async () => {
  const source = await readFile("src/services/threatApi.ts", "utf8");
  assert.doesNotMatch(source, /fetchThreatMap|fetchThreatSectors|ThreatMapData|ThreatSectorsResponse/);
});
