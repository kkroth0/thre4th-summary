import test from "node:test";
import assert from "node:assert/strict";
import { filterNewsletterAdvisories, formatNewsletterDate, NEWS_CATEGORY_ORDER, countByCategory, filterStoryCards, groupAdvisoriesIntoStories, severityEvidence, severityIsUnexplained } from "./newsletterView.ts";

test("formats today's full date in the selected language", () => {
  const date = new Date("2026-07-13T12:00:00-03:00");

  assert.equal(formatNewsletterDate(date, "pt"), "Hoje, 13 de julho de 2026");
  assert.equal(formatNewsletterDate(date, "en"), "Today, July 13, 2026");
});

test("keeps matching advisories from different months", () => {
  const advisories = [
    { title: "July item", description: "alpha", source: "CISA", pubDate: "2026-07-01", severity: "High" },
    { title: "June item", description: "alpha", source: "Vendor", pubDate: "2026-06-01", severity: "Medium" },
  ];

  const result = filterNewsletterAdvisories(advisories, {
    search: "alpha",
    severity: "all",
    kevOnly: false,
    sortByRelevance: false,
  });

  assert.deepEqual(result.map((item) => item.title), ["July item", "June item"]);
});

const advisory = (over: Record<string, unknown> = {}) => ({
  title: "T", description: "", link: "https://a.example/1", pubDate: "2026-08-10T00:00:00.000Z",
  source: "Feed", storyId: "s1", actors: [], newsCategories: [], primaryCategory: null, cves: [], ...over,
});

test("itens da mesma história viram um card só, com as fontes dentro", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ link: "https://a.example/1", source: "Reuters", pubDate: "2026-08-10T00:00:00.000Z" }),
    advisory({ link: "https://b.example/2", source: "BleepingComputer", pubDate: "2026-08-11T00:00:00.000Z" }),
  ]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].sources.length, 2);
  assert.equal(cards[0].lastSeen, "2026-08-11T00:00:00.000Z", "a história é datada pela fonte mais recente");
});

test("item sem storyId continua aparecendo, como card de uma fonte", () => {
  const cards = groupAdvisoriesIntoStories([advisory({ storyId: null, link: "https://c.example/3" })]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].sources.length, 1);
});

test("o card herda categorias e atores da união das fontes", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ link: "https://a.example/1", newsCategories: ["Ransomware"], actors: [{ id: "a1", name: "Cl0p" }] }),
    advisory({ link: "https://b.example/2", newsCategories: ["Vulnerabilities"], cves: ["CVE-1"] }),
  ]);
  assert.deepEqual(cards[0].categories, ["Ransomware", "Vulnerabilities"]);
  assert.deepEqual(cards[0].actors.map((a) => a.id), ["a1"]);
  assert.deepEqual(cards[0].cves, ["CVE-1"]);
});

test("cards são ordenados pela história mais recente", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "old", link: "https://a.example/1", pubDate: "2026-08-01T00:00:00.000Z" }),
    advisory({ storyId: "new", link: "https://b.example/2", pubDate: "2026-08-11T00:00:00.000Z" }),
  ]);
  assert.deepEqual(cards.map((c) => c.storyId), ["new", "old"]);
});

test("a contagem por categoria conta histórias, não fontes", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", newsCategories: ["Ransomware"] }),
    advisory({ storyId: "s1", link: "https://b.example/2", newsCategories: ["Ransomware"] }),
    advisory({ storyId: "s2", link: "https://c.example/3", newsCategories: ["Ransomware", "Microsoft"] }),
  ]);
  assert.equal(countByCategory(cards).Ransomware, 2);
  assert.equal(countByCategory(cards).Microsoft, 1);
});

test("filtro por categoria", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", newsCategories: ["Ransomware"] }),
    advisory({ storyId: "s2", link: "https://b.example/2", newsCategories: ["Microsoft"] }),
  ]);
  assert.deepEqual(filterStoryCards(cards, { category: "Ransomware" }).map((c) => c.storyId), ["s1"]);
  assert.equal(filterStoryCards(cards, { category: "" }).length, 2);
});

test("categorias são ordenadas pela precedência, não pela ordem de inserção", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", newsCategories: ["Microsoft"] }),
    advisory({ storyId: "s1", link: "https://b.example/2", newsCategories: ["Ransomware"] }),
  ]);
  assert.deepEqual(cards[0].categories, ["Ransomware", "Microsoft"], "categorias em ordem de precedência");
  assert.equal(cards[0].primaryCategory, "Ransomware", "categoria primária é a de maior precedência");
});

test("a ordem das categorias é a mesma do servidor", () => {
  assert.deepEqual(NEWS_CATEGORY_ORDER, [
    "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Microsoft",
    "Finance/Banking", "Health/Pharma",
  ]);
});

test("sem sortByRelevance, os cards continuam em ordem de data (comportamento padrão)", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "old-loud", link: "https://a.example/1", pubDate: "2026-08-01T00:00:00.000Z", score: 90 }),
    advisory({ storyId: "new-quiet", link: "https://b.example/2", pubDate: "2026-08-11T00:00:00.000Z", score: 10 }),
  ]);
  assert.deepEqual(cards.map((c) => c.storyId), ["new-quiet", "old-loud"]);
});

test("com sortByRelevance, a história de maior score vem primeiro mesmo sendo mais antiga", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "old-loud", link: "https://a.example/1", pubDate: "2026-08-01T00:00:00.000Z", score: 90 }),
    advisory({ storyId: "new-quiet", link: "https://b.example/2", pubDate: "2026-08-11T00:00:00.000Z", score: 10 }),
  ], { sortByRelevance: true });
  assert.deepEqual(cards.map((c) => c.storyId), ["old-loud", "new-quiet"], "maior score vence mesmo sendo a história mais antiga");
});

test("o score do card é o máximo entre as fontes, não o da primeira", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", score: 20 }),
    advisory({ storyId: "s1", link: "https://b.example/2", score: 75 }),
  ]);
  assert.equal(cards[0].score, 75);
});

test("fonte sem score conta como 0 no score do card", () => {
  const cards = groupAdvisoriesIntoStories([advisory({ storyId: "s1", link: "https://a.example/1" })]);
  assert.equal(cards[0].score, 0);
});

const orgItem = (over: Record<string, unknown> = {}) => ({
  link: "l1", source: "S", title: "T", pubDate: "2026-08-17T00:00:00.000Z",
  orgScore: 0, orgMatches: [], ...over,
});

test("a história herda o maior orgScore entre as fontes", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "s1", orgScore: 20, orgMatches: [{ kind: "sector", label: "Energy" }] }),
    orgItem({ link: "b", storyId: "s1", orgScore: 60, orgMatches: [{ kind: "asset", label: "FortiGate" }] }),
  ]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].orgScore, 60);
  assert.deepEqual(cards[0].orgMatches, [
    { kind: "sector", label: "Energy" },
    { kind: "asset", label: "FortiGate" },
  ]);
});

test("match repetido entre fontes aparece uma vez na história", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "s1", orgScore: 40, orgMatches: [{ kind: "asset", label: "FortiGate" }] }),
    orgItem({ link: "b", storyId: "s1", orgScore: 40, orgMatches: [{ kind: "asset", label: "FortiGate" }] }),
  ]);
  assert.deepEqual(cards[0].orgMatches, [{ kind: "asset", label: "FortiGate" }]);
});

test("orgOnly esconde o que está fora do contexto", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "a", orgScore: 40 }),
    orgItem({ link: "b", storyId: "b", orgScore: 0 }),
  ]);
  const filtered = filterStoryCards(cards, { category: "", orgOnly: true });
  assert.deepEqual(filtered.map((card) => card.storyId), ["a"]);
});

test("sem orgOnly, nada é escondido — o contexto ou filtra tudo ou nada", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "a", orgScore: 40 }),
    orgItem({ link: "b", storyId: "b", orgScore: 0 }),
  ]);
  assert.equal(filterStoryCards(cards, { category: "" }).length, 2);
});

// ─── EST-05: a severidade precisa mostrar de onde veio ──────────────────────
test("os sinais medidos viram rótulos, do mais forte para o mais fraco", () => {
  const chips = severityEvidence({ kev: true, epss: 0.42, cvss: 9.8 }, true);
  assert.deepEqual(chips.map((c) => c.label), ["Explorada (KEV)", "EPSS 42%", "CVSS 9.8"]);
});

test("EPSS baixo não vira etiqueta", () => {
  // O kernel do achado: EPSS de 4% marcado como BAIXO. O número não muda a
  // decisão e só competiria com as outras sete etiquetas do card.
  assert.deepEqual(severityEvidence({ epss: 0.04 }, true), []);
  assert.deepEqual(severityEvidence({ epss: 0.05 }, true).map((c) => c.label), ["EPSS 5%"]);
});

test("card sem nenhum sinal medido é reconhecido como tal", () => {
  // "Long Term Support Channel Update for ChromeOS" marcado como CRÍTICO.
  assert.equal(severityIsUnexplained({}), true);
  assert.equal(severityIsUnexplained({ cvss: 0 }), true, "CVSS zero não é sinal");
  assert.equal(severityIsUnexplained({ kev: true }), false);
  assert.equal(severityIsUnexplained({ cvss: 7.5 }), false);
});
