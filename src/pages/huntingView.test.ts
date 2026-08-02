import test from "node:test";
import assert from "node:assert/strict";
import { filterHunts, parseList } from "./huntingView.ts";

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
