import test from "node:test";
import assert from "node:assert/strict";
import { buildHuntLink, canOpenReport, DEFAULT_SUGGESTION_PREFS, filterSuggestions } from "./dailyBulletinView.ts";

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

test("preferências das sugestões cortam por severidade, KEV e palavra-chave", () => {
  const items = [
    { title: "Fortinet RCE", severity: "Critical", kev: true, cves: ["CVE-2026-1"] },
    { title: "Patch menor no Chrome", severity: "Medium", kev: false, cves: [] },
    { title: "Campanha contra bancos", severity: "High", kev: false, cves: [] },
  ];
  const prefs = { ...DEFAULT_SUGGESTION_PREFS };

  assert.equal(filterSuggestions(items, prefs).length, 3);
  assert.deepEqual(filterSuggestions(items, { ...prefs, kevOnly: true }).map((i) => i.title), ["Fortinet RCE"]);
  assert.deepEqual(
    filterSuggestions(items, { ...prefs, minSeverity: "High" }).map((i) => i.title),
    ["Fortinet RCE", "Campanha contra bancos"],
  );
  // Palavra-chave bate no título ou no CVE, sem diferenciar maiúscula.
  assert.deepEqual(filterSuggestions(items, { ...prefs, keywords: "fortinet, cve-2026-9" }).map((i) => i.title), ["Fortinet RCE"]);
  assert.equal(filterSuggestions(items, { ...prefs, keywords: "  " }).length, 3);
});
