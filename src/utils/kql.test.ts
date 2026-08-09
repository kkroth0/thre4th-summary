import test from "node:test";
import assert from "node:assert/strict";
import { formatKql } from "./kql.ts";

test("quebra a consulta em linha única num pipe por linha", () => {
  const out = formatKql("SigninLogs | where ResultType == 0 | summarize c=count() by IPAddress | where c > 10");
  assert.equal(out, [
    "SigninLogs",
    "| where ResultType == 0",
    "| summarize c=count() by IPAddress",
    "| where c > 10",
  ].join("\n"));
});

test("não quebra pipe dentro de string, parêntese ou comentário", () => {
  const out = formatKql(`DeviceEvents | where Cmd has "a|b" and Id in (parse_json('x|y')) // nota | falsa`);
  assert.equal(out, [
    "DeviceEvents",
    `| where Cmd has "a|b" and Id in (parse_json('x|y')) // nota | falsa`,
  ].join("\n"));
});

test("fecha statement no ponto e vírgula e preserva espaço dentro de string", () => {
  const out = formatKql(`let janela = ago(1d);   SigninLogs | where Msg == "dois  espacos"`);
  assert.equal(out, [
    "let janela = ago(1d);",
    "SigninLogs",
    `| where Msg == "dois  espacos"`,
  ].join("\n"));
});

test("é idempotente: consulta já formatada não muda", () => {
  const once = formatKql("SigninLogs | where ResultType == 0 | take 10");
  assert.equal(formatKql(once), once);
});

test("string vazia sai vazia", () => {
  assert.equal(formatKql(""), "");
  assert.equal(formatKql("   \n  "), "");
});
