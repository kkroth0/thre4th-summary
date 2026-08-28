import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("threat map prioritizes recent ransomware victims before map context", async () => {
  const source = await read("src/pages/ThreatMap.tsx");

  const victimTable = source.indexOf("VictimTable");
  const mapContext = source.indexOf("ContextMapPanel");

  assert.ok(victimTable > -1, "VictimTable component should exist");
  assert.ok(mapContext > -1, "ContextMapPanel component should exist");
  assert.ok(victimTable < mapContext, "victim table should be defined before map context");
  assert.match(source, /Ransomware Map/);
  assert.match(source, /Vítimas recentes/);
  assert.match(source, /Situação agora/);
  assert.match(source, /Fonte/);
  assert.match(source, /Evidência/);
});

test("threat map exposes local triage controls for victims", async () => {
  const source = await read("src/pages/ThreatMap.tsx");

  assert.match(source, /victimSearch/);
  assert.match(source, /groupFilter/);
  assert.match(source, /countryFilter/);
  assert.match(source, /sectorFilter/);
  assert.match(source, /filteredVictims/);
  assert.match(source, /placeholder=\{pt \? "Buscar vítima, grupo, país ou setor"/);
});
