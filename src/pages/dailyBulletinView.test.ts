import test from "node:test";
import assert from "node:assert/strict";
import { buildHuntLink, canOpenReport } from "./dailyBulletinView.ts";

test("relatório persistido abre mesmo quando a listagem omite o JSON", () => {
  assert.equal(canOpenReport({ status: "done", json: null, hasReport: true }), true);
  assert.equal(canOpenReport({ status: "done", json: {} }), true);
  assert.equal(canOpenReport({ status: "pending", json: {}, hasReport: true }), false);
  assert.equal(canOpenReport({ status: "done", json: null }), false);
});

test("leva referências do relatório para a nova hunt", () => {
  const link = buildHuntLink({
    id: "job 1",
    title: "Campanha A",
    techniques: ["T1059.001", "T1078"],
    cves: ["CVE-2026-12345"],
  });
  const url = new URL(link, "https://example.com");
  assert.equal(url.pathname, "/hunting");
  assert.equal(url.searchParams.get("new"), "1");
  assert.equal(url.searchParams.get("sourceReportId"), "job 1");
  assert.equal(url.searchParams.get("techniques"), "T1059.001,T1078");
  assert.equal(url.searchParams.get("cves"), "CVE-2026-12345");
});
