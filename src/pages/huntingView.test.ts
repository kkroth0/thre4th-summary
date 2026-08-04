import test from "node:test";
import assert from "node:assert/strict";
import { filterHunts, groupByDay, monthGrid, parseList } from "./huntingView.ts";

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
