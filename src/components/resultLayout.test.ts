import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("places network overview after summary and removes obsolete charts", () => {
  const source = readFileSync(new URL("src/pages/Index.tsx", `file://${process.cwd()}/`), "utf8");
  const summary = source.indexOf("<ThreatSummary");
  const overview = source.indexOf("<GeographicNetworkOverview");
  const timeline = source.indexOf("<IocTimeline");
  assert.ok(summary >= 0 && overview > summary && timeline > overview);
  assert.equal(source.includes("<ThreatCharts"), false);
});
