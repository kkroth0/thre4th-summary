import test from "node:test";
import assert from "node:assert/strict";
import { boletimFilename } from "./boletimExport.ts";
import type { BoletimJob, BoletimReport } from "@/services/threatApi";

const job = (json: BoletimReport | null): BoletimJob => ({
  id: "j1", url: "https://exemplo.test/aviso", type: "vuln", title: "Aviso",
  status: "done", json, error: null, createdAt: "", updatedAt: "",
});

// Os casos espelham tests/test_i18n.py do motor: os dois lados têm que gerar o
// mesmo nome pro mesmo título.
test("nome do arquivo é o padrão da casa, com fallback pro job", () => {
  assert.equal(boletimFilename(job({ titulo: "Ransomware X abusa de Y" })),
    "SRR - Surface Risk Report - Ransomware X abusa de Y");
  assert.equal(boletimFilename(job(null)), "SRR - Surface Risk Report - Aviso");
});

test("tira o que o Windows recusa em nome de arquivo, mantém acento", () => {
  const out = boletimFilename(job({ titulo: 'Falha crítica: RCE em Foo/Bar "v2"?' }));
  assert.ok(!/[<>:"/\\|?*]/.test(out), out);
  assert.ok(out.startsWith("SRR - Surface Risk Report - "));
  assert.match(out, /crítica/);
});

test("título vazio deixa só o prefixo, sem hífen solto no fim", () => {
  assert.equal(boletimFilename({ ...job(null), title: "", url: "" }), "SRR - Surface Risk Report");
});
