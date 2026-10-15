import test from "node:test";
import assert from "node:assert/strict";
import { filterNewsletterAdvisories, formatNewsletterDate, NEWS_CATEGORY_ORDER, countByCategory, filterStoryCards, groupAdvisoriesIntoStories, severityEvidence, severityIsUnexplained, activeFilterChips, advisoryVendor } from "./newsletterView.ts";

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

test('CVE search finds evidence extracted from the body, including CVEs outside the compact preview',()=>{
  const cves=Array.from({length:22},(_,i)=>`CVE-2026-${69414+i}`);
  const advisories=[{title:'Monthly security update',description:'Vendor fixes',source:'Research',pubDate:'2026-10-14',cves},
    {title:'Unrelated security news',description:'Another topic',source:'Research',pubDate:'2026-10-14'}];
  const result=filterNewsletterAdvisories(advisories,{search:'cve-2026-69435',severity:'all',kevOnly:false,sortByRelevance:false});
  assert.deepEqual(result.map(item=>item.title),['Monthly security update']);
  assert.deepEqual(result[0].cves,cves);
});

test("source filtra por fonte exata; 'all' não filtra nada", () => {
  const advisories = [
    { title: "A", description: "", source: "BleepingComputer", pubDate: "2026-07-01", severity: "High" },
    { title: "B", description: "", source: "The Hacker News", pubDate: "2026-07-01", severity: "High" },
  ];
  const base = { search: "", severity: "all", kevOnly: false, sortByRelevance: false };

  assert.deepEqual(
    filterNewsletterAdvisories(advisories, { ...base, source: "BleepingComputer" }).map((i) => i.title),
    ["A"],
  );
  assert.deepEqual(
    filterNewsletterAdvisories(advisories, { ...base, source: "all" }).map((i) => i.title),
    ["A", "B"],
  );
  assert.deepEqual(
    filterNewsletterAdvisories(advisories, base).map((i) => i.title),
    ["A", "B"],
    "source omitido não filtra",
  );
});

test("timeRange corta pelo relógio informado, não pelo do sistema", () => {
  const now = new Date("2026-08-10T12:00:00.000Z");
  const advisories = [
    { title: "1h atrás", description: "", source: "Feed", pubDate: "2026-08-10T11:00:00.000Z" },
    { title: "2 dias atrás", description: "", source: "Feed", pubDate: "2026-08-08T12:00:00.000Z" },
    { title: "40 dias atrás", description: "", source: "Feed", pubDate: "2026-07-01T12:00:00.000Z" },
  ];
  const base = { search: "", severity: "all", kevOnly: false, sortByRelevance: false, now };

  assert.deepEqual(
    filterNewsletterAdvisories(advisories, { ...base, timeRange: "24h" }).map((i) => i.title),
    ["1h atrás"],
  );
  assert.deepEqual(
    filterNewsletterAdvisories(advisories, { ...base, timeRange: "7d" }).map((i) => i.title),
    ["1h atrás", "2 dias atrás"],
  );
  assert.deepEqual(
    filterNewsletterAdvisories(advisories, { ...base, timeRange: "all" }).map((i) => i.title),
    ["1h atrás", "2 dias atrás", "40 dias atrás"],
  );
});

test("timeRange nunca descarta item com data ilegível", () => {
  const now = new Date("2026-08-10T12:00:00.000Z");
  const advisories = [{ title: "sem data", description: "", source: "Feed", pubDate: "" }];

  const result = filterNewsletterAdvisories(advisories, {
    search: "", severity: "all", kevOnly: false, sortByRelevance: false, timeRange: "24h", now,
  });

  assert.equal(result.length, 1);
});

const advisory = (over: Record<string, unknown> = {}) => ({
  title: "T", description: "", link: "https://a.example/1", pubDate: "2026-08-10T00:00:00.000Z",
  source: "Feed", storyId: "s1", actors: [], malware: [], campaigns: [], newsCategories: [], primaryCategory: null, cves: [], ...over,
});

test('legacy null entities cannot crash news grouping and valid evidence survives on all sources',()=>{
  const cards=groupAdvisoriesIntoStories([
    advisory({actors:[null,{id:'actor',name:'Actor'}],malware:[null,{id:'malware',name:'Malware'}],campaigns:[null]}),
    advisory({link:'https://b.example/2',actors:[null,{id:'actor2',name:'Actor 2'}],malware:[{id:'malware',name:'Malware'},null],campaigns:[{id:'campaign',name:'Campaign'},null]}),
  ]);
  assert.deepEqual(cards[0].actors.map(row=>row.id),['actor','actor2']);
  assert.deepEqual(cards[0].malware.map(row=>row.id),['malware']);
  assert.deepEqual(cards[0].campaigns.map(row=>row.id),['campaign']);
  assert.ok(cards[0].sources.every(row=>row.actors.every(Boolean)&&row.malware.every(Boolean)&&row.campaigns.every(Boolean)));
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

test("o card herda malware da união das fontes, sem duplicar por id", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ link: "https://a.example/1", malware: [{ id: "m1", name: "LummaC2" }] }),
    advisory({ link: "https://b.example/2", malware: [{ id: "m1", name: "LummaC2" }, { id: "m2", name: "AsyncRAT" }] }),
  ]);
  assert.deepEqual(cards[0].malware.map((m) => m.id).sort(), ["m1", "m2"]);
});

test("o card herda campanhas da união das fontes, sem duplicar por id", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ link: "https://a.example/1", campaigns: [{ id: "c1", name: "Operation Dream Job" }] }),
    advisory({ link: "https://b.example/2", campaigns: [{ id: "c1", name: "Operation Dream Job" }] }),
  ]);
  assert.deepEqual(cards[0].campaigns.map((c) => c.id), ["c1"]);
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
    "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Phishing", "Microsoft",
    "Artificial Intelligence", "Finance/Banking", "Health/Pharma",
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

// ─── DEN-02: o que está filtrando precisa estar à vista ─────────────────────
test("cada filtro ativo vira um chip, e nenhum inativo aparece", () => {
  const chips = activeFilterChips(
    { severity: "Critical", kevOnly: true, orgOnly: false, sortByRelevance: true, search: "  fortinet  " },
    true,
  );
  assert.deepEqual(chips.map((c) => c.label), [
    "Severidade: Critical", "Só KEV", "Por relevância", '"fortinet"',
  ]);
  assert.deepEqual(chips.map((c) => c.key), ["severity", "kevOnly", "sortByRelevance", "search"]);
});

test("feed sem filtro não mostra chip nenhum", () => {
  assert.deepEqual(
    activeFilterChips({ severity: "all", kevOnly: false, orgOnly: false, sortByRelevance: false, search: "   " }, true),
    [],
  );
});

test("período vira chip removível quando diferente de 'all', em pt e en", () => {
  const state = { severity: "all", kevOnly: false, orgOnly: false, sortByRelevance: false, search: "", timeRange: "24h" as const };
  assert.deepEqual(activeFilterChips(state, true), [{ key: "timeRange", label: "Últimas 24h" }]);
  assert.deepEqual(activeFilterChips(state, false), [{ key: "timeRange", label: "Last 24h" }]);
  assert.deepEqual(activeFilterChips({ ...state, timeRange: "all" }, true), []);
});

test("fonte vira chip removível quando diferente de 'all', e não aparece quando ausente/'all'", () => {
  const base = { severity: "all", kevOnly: false, orgOnly: false, sortByRelevance: false, search: "" };
  assert.deepEqual(
    activeFilterChips({ ...base, source: "BleepingComputer" }, true),
    [{ key: "source", label: "Fonte: BleepingComputer" }],
  );
  assert.deepEqual(
    activeFilterChips({ ...base, source: "BleepingComputer" }, false),
    [{ key: "source", label: "Source: BleepingComputer" }],
  );
  assert.deepEqual(activeFilterChips({ ...base, source: "all" }, true), []);
  assert.deepEqual(activeFilterChips(base, true), []);
});

// ─── EST-05: avisos de distribuição repetidos no mesmo dia ──────────────────

test("identidade do evento prevalece sobre fornecedor e data", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ title: "USN-8666-3: Linux kernel (GCP FIPS) vulnerabilities", link: "https://u.example/1", storyId: "s1", cves: ["CVE-2020-24588"], pubDate: "2026-08-28T09:00:00.000Z" }),
    advisory({ title: "USN-8661-3: Linux kernel vulnerabilities", link: "https://u.example/2", storyId: "s2", cves: ["CVE-2025-27558"], pubDate: "2026-08-28T11:00:00.000Z" }),
  ], { pt: true });

  assert.equal(cards.length, 2, "eventos distintos não podem ser colapsados pelo frontend");
  assert.ok(cards.every((card) => card.storyId === "s1" || card.storyId === "s2"));
  assert.equal(cards.flatMap((card) => card.cves).length, 2);
  assert.ok(cards.every((card) => card.sources.length === 1));
});

test("aviso de fornecedor sozinho mantém o próprio título", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ title: "USN-8688-1: PAM vulnerability", link: "https://u.example/3", pubDate: "2026-08-28T09:00:00.000Z" }),
  ], { pt: true });

  assert.equal(cards[0].title, "USN-8688-1: PAM vulnerability");
});

test("sem ID do servidor, avisos do mesmo fornecedor em dias diferentes continuam separados", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: null, title: "USN-8666-3: Linux kernel vulnerabilities", link: "https://u.example/1", pubDate: "2026-08-28T09:00:00.000Z" }),
    advisory({ storyId: null, title: "USN-8600-1: OpenSSL vulnerability", link: "https://u.example/2", pubDate: "2026-08-27T09:00:00.000Z" }),
  ], { pt: true });

  assert.equal(cards.length, 2);
});

test("aviso e notícia de outro veículo sobre o mesmo evento ficam no mesmo card", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ title: "USN-8666-3: Linux kernel vulnerabilities", link: "https://u.example/1", storyId: "event", source: "Ubuntu" }),
    advisory({ title: "Kernel exploitation affects Ubuntu", link: "https://n.example/1", storyId: "event", source: "News" }),
  ]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].storyId, "event");
  assert.equal(cards[0].sources.length, 2);
});

test("uma publicação repetida não duplica a contagem de fontes do card", () => {
  assert.equal(groupAdvisoriesIntoStories([advisory(), advisory()])[0].sources.length, 1);
});

test("notícia comum não é confundida com aviso de fornecedor", () => {
  assert.equal(advisoryVendor("Ransomware crew hits hospital"), null);
  assert.equal(advisoryVendor("DSA-5812-1 chromium security update"), "Debian");
});
