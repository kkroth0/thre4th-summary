import test from "node:test";
import assert from "node:assert/strict";
import { boletimFilename, boletimSections } from "./boletimExport.ts";
import type { BoletimJob, BoletimReport } from "@/services/threatApi";

const job = (json: BoletimReport | null): BoletimJob => ({
  id: "j1", url: "https://exemplo.test/aviso", type: "vuln", title: "Aviso",
  status: "done", json, error: null, createdAt: "", updatedAt: "",
});

test("descarta seções vazias e os placeholders do motor", () => {
  const sections = boletimSections({
    sumario_executivo: "Resumo real.",
    estado_exploracao: "Não informado",
    descricao: "   ",
    impactos: [],
  });
  assert.deepEqual(sections.map((s) => s.title), ["Sumário executivo"]);
});

test("tecnologias afetadas viram tabela com KEV e severidade na coluna CVSS", () => {
  const [tabela] = boletimSections({
    tecnologias_afetadas: [
      { fabricante: "Acme", software: "Portal", versao: "1.0", versao_corrigida: "N/A", cve: "CVE-2026-1", cvss: "9.8", severidade: "Critical", kev: true },
    ],
  });
  assert.equal(tabela.title, "Tecnologias afetadas");
  assert.deepEqual(tabela.blocks, [{
    kind: "table",
    head: ["Produto", "Versão", "Corrigida", "CVE", "CVSS"],
    rows: [["Acme Portal", "1.0", "—", "CVE-2026-1", "9.8 · Critical · KEV"]],
  }]);
});

test("recomendações agrupadas viram título em texto seguido dos itens", () => {
  const [rec] = boletimSections({ recomendacoes: [{ titulo: "Contenção", itens: ["Bloquear IP", ""] }] });
  assert.deepEqual(rec.blocks, [
    { kind: "text", text: "Contenção" },
    { kind: "bullets", items: ["Bloquear IP"] },
  ]);
});

test("superfície de ataque aceita objeto e tabela antiga", () => {
  const [objeto] = boletimSections({ superficie_de_ataque: { vetor_inicial: "Phishing", superficie: "N/A" } });
  assert.deepEqual(objeto.blocks, [{ kind: "bullets", items: ["Vetor inicial: Phishing"] }]);

  const [antiga] = boletimSections({ superficie_de_ataque: [{ categoria: "Rede", tecnologia: "VPN", utilizacao: "Acesso" }] });
  assert.deepEqual(antiga.blocks, [{ kind: "bullets", items: ["VPN: Rede — Acesso"] }]);
});

test("nome do arquivo sai de um título limpo, com fallback pro job", () => {
  assert.equal(boletimFilename(job({ titulo: "Falha crítica no Portal Acme!" })), "boletim-vuln-falha-critica-no-portal-acme");
  assert.equal(boletimFilename(job(null)), "boletim-vuln-aviso");
});
