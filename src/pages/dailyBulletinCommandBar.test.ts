import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("report composer preserves source, subtype and template controls", async () => {
  const source = await read("src/pages/DailyBulletin.tsx");
  const start = source.indexOf('data-testid="report-generator-command-bar"');
  assert.ok(start > -1, "command bar should have a stable test id");

  const statusStart = source.indexOf('data-testid="report-generator-status-row"', start);
  assert.ok(statusStart > start, "status row should sit outside the command bar");
  const commandBar = source.slice(start, statusStart);

  assert.match(commandBar, /aria-label=\{pt \? "Links das fontes, um por linha" : "Source links, one per line"\}/);
  assert.match(commandBar, /data-testid="report-generator-template-trigger"/);
  // Subtipo (malware/phishing/ransomware/cve_unica/cve_varias, ou automático)
  // substitui o antigo seletor de tipo -- um subtipo concreto já implica o
  // tipo, então não precisa escolher os dois.
  assert.match(commandBar, /data-testid="report-generator-subtype-trigger"/);
  assert.doesNotMatch(commandBar, /data-testid="report-generator-type-trigger"/);
  assert.match(source, /generate\(pasteUrl\.trim\(\), "auto", ""\)/);
  assert.doesNotMatch(commandBar, /<SelectValue\s*\/>/);
  assert.doesNotMatch(commandBar, /flex-col gap-2 rounded-xl bg-muted\/40 p-2/);
});
