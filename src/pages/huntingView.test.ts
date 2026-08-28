import test from "node:test";
import assert from "node:assert/strict";
import { filterHunts, groupByDay, monthGrid, parseList, buildQueryCards, groupQueryCards } from "./huntingView.ts";

const hunts = [
  {
    id: "B001", origin: "hearth" as const, category: "Flames", title: "PowerShell incomum",
    tactics: ["Execution"], techniques: ["T1059.001"], tags: ["powershell"],
  },
  {
    id: "mine", title: "Logon de alto risco", hypothesis: "Conta comprometida",
    tactics: ["Credential Access"], techniques: ["T1078"], cves: [],
    technologies: ["Microsoft Sentinel"], dataSources: ["SigninLogs"], query: "SigninLogs | where RiskLevel == 'high'",
    status: "ready" as const,
  },
];

test("busca em hipótese, técnica e fonte de dados e combina os filtros", () => {
  assert.deepEqual(filterHunts(hunts, { query: "powershell" }).map((h) => h.id), ["B001"]);
  assert.deepEqual(filterHunts(hunts, { query: "T1078" }).map((h) => h.id), ["mine"]);
  assert.deepEqual(filterHunts(hunts, { query: "signinlogs" }).map((h) => h.id), ["mine"]);
  assert.deepEqual(filterHunts(hunts, { origin: "private", tactic: "Credential Access", technology: "Microsoft Sentinel" }).map((h) => h.id), ["mine"]);
  assert.deepEqual(filterHunts(hunts, { origin: "hearth", tactic: "Credential Access" }), []);
});

test("normaliza listas digitadas sem duplicatas", () => {
  assert.deepEqual(parseList("T1078, t1059.001\nT1078", true), ["T1078", "T1059.001"]);
  assert.deepEqual(parseList("SigninLogs, DeviceEvents\nSigninLogs"), ["SigninLogs", "DeviceEvents"]);
});

test("monthGrid cobre o mês inteiro e marca o que é de fora", () => {
  // Agosto de 2026 começa num sábado — o caso que mais quebra grade de mês.
  const weeks = monthGrid("2026-08");

  assert.ok(weeks.every((week) => week.length === 7), "toda semana tem sete dias");
  assert.equal(weeks[0][0].date, "2026-07-26", "a grade começa no domingo anterior");
  assert.equal(weeks[0][6].date, "2026-08-01");
  assert.equal(weeks[0][6].inMonth, true);
  assert.equal(weeks[0][0].inMonth, false, "dia do mês anterior fica marcado como de fora");

  const dias = weeks.flat().filter((cell) => cell.inMonth).map((cell) => cell.day);
  assert.equal(dias.length, 31, "agosto tem 31 dias e todos aparecem uma vez");
  assert.equal(dias[0], 1);
  assert.equal(dias[30], 31);
});

test("monthGrid não deixa semana inteiramente fora do mês", () => {
  for (const month of ["2026-02", "2026-08", "2027-01", "2024-02"]) {
    const weeks = monthGrid(month);
    assert.ok(
      weeks.every((week) => week.some((cell) => cell.inMonth)),
      `${month} tem semana sem nenhum dia do mês`,
    );
  }
  assert.deepEqual(monthGrid("mês-inválido"), []);
});

test("groupByDay ignora data quebrada em vez de criar chave lixo", () => {
  const runs = [
    { id: "a", startedAt: "2026-08-03T10:00:00.000Z" },
    { id: "b", startedAt: "2026-08-03T22:00:00.000Z" },
    { id: "c", startedAt: "2026-08-11T09:00:00.000Z" },
    { id: "d", startedAt: "" },
    { id: "e", startedAt: undefined },
  ];

  const byDay = groupByDay(runs, (run) => run.startedAt);
  assert.deepEqual(Object.keys(byDay).sort(), ["2026-08-03", "2026-08-11"]);
  assert.deepEqual(byDay["2026-08-03"].map((run) => run.id), ["a", "b"]);
});

// ─── FLX-04: 237 cartões chamados h001…h237 ────────────────────────────────
// O nome bom já existia no catálogo pt-BR; a aba Queries só não fazia a junção.
const kqls = [
  { path: "sentinel/kql/daily/data-source-health.kql", folder: "daily", name: "data-source-health" },
  { path: "sentinel/kql/hearth/h001.kql", folder: "hearth", name: "h001" },
  { path: "sentinel/kql/hearth/h999.kql", folder: "hearth", name: "h999" },
];
const catalogo = [
  {
    queryPath: "sentinel/kql/hearth/h001.kql",
    hypothesis: "Baseline de processos que acessam o lsass.exe",
    cadence: "diária", technologies: ["Defender"], dataSources: ["DeviceEvents"],
  },
  {
    queryPath: "sentinel/kql/daily/data-source-health.kql",
    title: "Saúde da fonte de dados", cadence: "diária", technologies: [], dataSources: [],
  },
];

test("a hipótese vira o título e o identificador desce para o apoio", () => {
  const [saude, h001, h999] = buildQueryCards(kqls, catalogo);

  assert.equal(h001.title, "Baseline de processos que acessam o lsass.exe");
  assert.equal(h001.subtitle, "h001 · hearth", "o id continua visível, como apoio");
  assert.deepEqual(h001.tags, ["Defender", "DeviceEvents"]);
  assert.equal(saude.title, "Saúde da fonte de dados", "cai no title quando não há hipótese");

  // Sem descrição, o identificador continua sendo o título — não inventamos nome.
  assert.equal(h999.title, "h999");
  assert.equal(h999.subtitle, "hearth");
  assert.equal(h999.described, false);
  assert.deepEqual(h999.tags, []);
});

test("agrupa por cadência, com a diária antes da semanal e a sem cadência por último", () => {
  const cards = buildQueryCards(
    [...kqls, { path: "p/m.kql", folder: "monthly", name: "m1" }],
    [...catalogo, { queryPath: "p/m.kql", hypothesis: "Revisão mensal", cadence: "mensal" }],
  );
  const grupos = groupQueryCards(cards);

  assert.deepEqual(grupos.map((g) => g.cadence), ["diária", "mensal", ""]);
  assert.equal(grupos[0].cards.length, 2);
  assert.equal(grupos[2].cards[0].path, "sentinel/kql/hearth/h999.kql");
});
