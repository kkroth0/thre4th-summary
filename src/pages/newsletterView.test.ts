import test from "node:test";
import assert from "node:assert/strict";
import { filterNewsletterAdvisories, formatNewsletterDate, NEWS_CATEGORY_ORDER, countByCategory, filterStoryCards, groupAdvisoriesIntoStories } from "./newsletterView.ts";

test("formats today's full date in the selected language", () => {
  const date = new Date("2026-07-13T12:00:00-03:00");

  assert.equal(formatNewsletterDate(date, "pt"), "Hoje, 13 de julho de 2026");
  assert.equal(formatNewsletterDate(date, "en"), "Today, July 13, 2026");
});

test("keeps matching advisories from different months", () => {
  const advisories = [
    { title: "July item", description: "alpha", source: "CISA", pubDate: "2026-07-01", layer: 1, severity: "High" },
    { title: "June item", description: "alpha", source: "Vendor", pubDate: "2026-06-01", layer: 2, severity: "Medium" },
  ];

  const result = filterNewsletterAdvisories(advisories, {
    search: "alpha",
    layer: "all",
    severity: "all",
    kevOnly: false,
    sortByRelevance: false,
  });

  assert.deepEqual(result.map((item) => item.title), ["July item", "June item"]);
});

const advisory = (over: Record<string, unknown> = {}) => ({
  title: "T", description: "", link: "https://a.example/1", pubDate: "2026-08-10T00:00:00.000Z",
  source: "Feed", storyId: "s1", actors: [], categories: [], primaryCategory: null, cves: [], ...over,
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
    advisory({ link: "https://a.example/1", categories: ["Ransomware"], actors: [{ id: "a1", name: "Cl0p" }] }),
    advisory({ link: "https://b.example/2", categories: ["Vulnerabilities"], cves: ["CVE-1"] }),
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
    advisory({ storyId: "s1", link: "https://a.example/1", categories: ["Ransomware"] }),
    advisory({ storyId: "s1", link: "https://b.example/2", categories: ["Ransomware"] }),
    advisory({ storyId: "s2", link: "https://c.example/3", categories: ["Ransomware", "Microsoft"] }),
  ]);
  assert.equal(countByCategory(cards).Ransomware, 2);
  assert.equal(countByCategory(cards).Microsoft, 1);
});

test("filtro por categoria e por ator", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", categories: ["Ransomware"], actors: [{ id: "a1", name: "Cl0p" }] }),
    advisory({ storyId: "s2", link: "https://b.example/2", categories: ["Microsoft"] }),
  ]);
  assert.deepEqual(filterStoryCards(cards, { category: "Ransomware", actor: "" }).map((c) => c.storyId), ["s1"]);
  assert.deepEqual(filterStoryCards(cards, { category: "", actor: "a1" }).map((c) => c.storyId), ["s1"]);
  assert.equal(filterStoryCards(cards, { category: "", actor: "" }).length, 2);
});

test("categorias são ordenadas pela precedência, não pela ordem de inserção", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", categories: ["Microsoft"] }),
    advisory({ storyId: "s1", link: "https://b.example/2", categories: ["Ransomware"] }),
  ]);
  assert.deepEqual(cards[0].categories, ["Ransomware", "Microsoft"], "categorias em ordem de precedência");
  assert.equal(cards[0].primaryCategory, "Ransomware", "categoria primária é a de maior precedência");
});

test("a ordem das categorias é a mesma do servidor", () => {
  assert.deepEqual(NEWS_CATEGORY_ORDER, [
    "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Microsoft",
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
