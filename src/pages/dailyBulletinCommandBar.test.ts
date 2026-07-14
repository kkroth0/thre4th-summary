import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(path, "utf8");

test("report generator uses a single-line desktop command bar", async () => {
  const source = await read("src/pages/DailyBulletin.tsx");
  const start = source.indexOf('data-testid="report-generator-command-bar"');
  assert.ok(start > -1, "command bar should have a stable test id");

  const statusStart = source.indexOf('data-testid="report-generator-status-row"', start);
  assert.ok(statusStart > start, "status row should sit outside the command bar");
  const commandBar = source.slice(start, statusStart);

  assert.match(commandBar, /sm:flex-row/);
  assert.match(commandBar, /sm:items-center/);
  assert.match(commandBar, /data-testid="report-generator-type-trigger"/);
  assert.match(commandBar, /pasteType === "vuln"/);
  assert.doesNotMatch(commandBar, /<SelectValue\s*\/>/);
  assert.doesNotMatch(commandBar, /flex-col gap-2 rounded-xl bg-muted\/40 p-2/);
});
