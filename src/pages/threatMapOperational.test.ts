import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("threat map leads with victims and carries no world map", async () => {
  const source = await read("src/pages/ThreatMap.tsx");

  assert.ok(source.indexOf("VictimTable") > -1, "VictimTable component should exist");
  // O mapa-múndi saiu: era desenho sem uso de triagem, e a página já responde
  // "quem, onde, quando" na tabela e no painel de situação.
  assert.doesNotMatch(source, /ThreatWorldMap|ContextMapPanel/);
  assert.match(source, /Ransomware Victims/);
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
