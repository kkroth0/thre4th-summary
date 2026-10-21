import test from "node:test";
import assert from "node:assert/strict";
import { canOpenJob, canOpenReport, DEFAULT_SUGGESTION_PREFS, explainFailure, filterSuggestions, filterReportLibrary, reportTitle, parseReportSources } from "./dailyBulletinView.ts";

test("fontes múltiplas preservam ordem, removem duplicadas e validam todos os links", () => {
  assert.deepEqual(parseReportSources(" https://news.example/a\nhttps://vendor.example/b https://news.example/a "), {
    urls: ["https://news.example/a", "https://vendor.example/b"],
  });
  assert.equal(parseReportSources("https://news.example/a\ninválido").error, "invalid");
  assert.equal(parseReportSources("ftp://news.example/a").error, "invalid");
  assert.equal(parseReportSources("").error, "empty");
  assert.equal(parseReportSources(Array.from({ length: 6 }, (_, i) => `https://news.example/${i}`).join("\n")).error, "limit");
  assert.equal(parseReportSources(Array.from({ length: 5 }, (_, i) => `https://news.example/${i}`).join("\n")).error, undefined);
});

test("busca na biblioteca combina título, fonte e CVE sem perder sugestões após a 14ª", () => {
  const items = Array.from({ length: 40 }, (_, index) => ({ title: `Análise ${index + 1}`, url: `https://vendor.example/report-${index}`, cves: [`CVE-2026-${10000 + index}`] }));
  assert.equal(filterReportLibrary(items, "").length, 40);
  assert.deepEqual(filterReportLibrary(items, "ANALISE 40 vendor.example").map((item) => item.title), ["Análise 40"]);
  assert.deepEqual(filterReportLibrary(items, "CVE-2026-10039").map((item) => item.title), ["Análise 40"]);
  assert.equal(filterReportLibrary(items, "unknown.example").length, 0);
  assert.equal(items.length, 40);
});

test("relatório persistido abre mesmo quando a listagem omite o JSON", () => {
  assert.equal(canOpenReport({ status: "done", json: null, hasReport: true }), true);
  assert.equal(canOpenReport({ status: "done", json: {} }), true);
  assert.equal(canOpenReport({ status: "pending", json: {}, hasReport: true }), false);
  assert.equal(canOpenReport({ status: "done", json: null }), false);
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

// ─── DEN-01: a lista mostrava URL crua no lugar do título ───────────────────
// O job só ganha `title` quando o worker responde, então metade da lista ficava
// com "https://www.atf.gov/news/press-rele...". O nome da página já está na URL.
test("o título sai do slug quando o worker ainda não respondeu", () => {
  assert.equal(
    reportTitle({ title: "", url: "https://socradar.io/blog/shinyhunters-extortion-campaign/" }),
    "shinyhunters extortion campaign",
  );
  assert.equal(
    reportTitle({ title: "Nimbus Manticore expande arsenal", url: "https://x.example/a" }),
    "Nimbus Manticore expande arsenal",
    "título de verdade sempre vence",
  );
});

test("slug sem informação cai no domínio, em vez de virar lixo", () => {
  assert.equal(reportTitle({ title: "", url: "https://www.bleepingcomputer.com/news/12345/" }), "bleepingcomputer.com");
  assert.equal(reportTitle({ title: "", url: "https://thehackernews.com/" }), "thehackernews.com");
  // URL gravada no campo de título não serve como nome.
  assert.equal(reportTitle({ title: "https://x.example/y", url: "https://x.example/threat-brief-report" }), "threat brief report");
});

// ─── EST-01: o item que falhou abria o estado vazio ─────────────────────────
test("o item com erro abre, o pendente não", () => {
  assert.equal(canOpenJob({ status: "error" }), true);
  assert.equal(canOpenJob({ status: "pending" }), false);
  assert.equal(canOpenJob({ status: "done", json: {} }), true);
  assert.equal(canOpenJob({ status: "done" }), false, "done sem relatório continua sem abrir");
});

test("a falha é explicada em linguagem de analista, com saída", () => {
  const timeout = explainFailure("timeout após 240s (árvore de processos encerrada)", true);
  assert.match(timeout.resumo, /passou do tempo limite/);
  assert.match(timeout.causa, /paywall|JavaScript/i);
  assert.ok(timeout.acoes.includes("Colar o texto do artigo"));

  assert.match(explainFailure("job perdido (servidor reiniciou?)", true).resumo, /reiniciou/);
  assert.match(explainFailure("Request failed with status code 403", true).resumo, /recusou o acesso/);
  // Mensagem desconhecida não inventa diagnóstico.
  assert.match(explainFailure("erro estranho", true).resumo, /^A geração falhou$/);
});
