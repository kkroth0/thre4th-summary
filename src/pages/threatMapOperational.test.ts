import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("threat map leads with victims and carries no world map", async () => {
  const source = await read("src/pages/ThreatMap.tsx");

  const table = await read("src/components/workbench/RansomwareVictimsTable.tsx");
  assert.match(source, /<RansomwareVictimsTable/);
  // O mapa-múndi saiu: era desenho sem uso de triagem, e a página já responde
  // "quem, onde, quando" na tabela e no detalhe do registro.
  assert.doesNotMatch(source, /ThreatWorldMap|ContextMapPanel/);
  assert.match(source, /Ransomware Victims/);
  assert.match(table, /Vítimas reivindicadas/);
  assert.match(table, /Fonte/);
  assert.match(table, /Evidências/);
});

test("threat map exposes local triage controls for victims", async () => {
  const table = await read("src/components/workbench/RansomwareVictimsTable.tsx");

  assert.match(table, /Buscar vítima/);
  for (const label of ["Grupo", "País", "Setor"]) assert.ok(table.includes(label));
  assert.match(table, /Limpar filtros/);
  assert.match(table, /<DataPager/);
  assert.match(table, /<RecordDrawer/);
});
