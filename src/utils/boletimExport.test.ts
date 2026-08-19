import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { boletimFilename, boletimSections, buildBoletimPresentation, colWidths } from "./boletimExport.ts";
import { DECK_FONTS } from "./deckTemplate";
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

// ---- PPTX ------------------------------------------------------------------

test("colunas da tabela repartem a largura pelo tamanho do conteúdo", () => {
  const w = colWidths(["Categoria", "Tipo", "Valor"], [["Rede", "sha256", "a".repeat(64)]], 8.95);
  assert.equal(Math.round(w.reduce((a, b) => a + b, 0) * 1000) / 1000, 8.95);
  assert.ok(w[2] > w[1], "a coluna do hash é a mais larga");
  assert.ok(Math.min(...w) >= 0.6, "coluna curta continua legível");
});

const fullReport: BoletimReport = {
  titulo: "Falha crítica no Portal Acme\u0007",  // controle vindo da fonte: o XML não aceita
  cve_id: "CVE-2026-1",
  sumario_executivo: "Resumo real do boletim.",
  impactos: ["Execução remota", "Vazamento de dados"],
  iocs: [{ categoria: "Rede", tipo: "sha256", valor: "b".repeat(64) }],
  source_published: "2026-08-11T07:00:00",
};

// O painel escuro é a área de desenho de todo slide de conteúdo; só o rodapé e a
// placa reservada podem ficar abaixo dele. Elemento fora disso é o relato de
// "deck abriu quebrado".
const PANEL = { x: 0.264, y: 0.234, w: 9.472, h: 5.151 };

const buildDeck = async () => {
  const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
  const JSZip = runtimeRequire("jszip") as typeof import("jszip");
  const PptxGenJS = runtimeRequire("pptxgenjs") as typeof import("pptxgenjs").default;
  const pptx = buildBoletimPresentation(job(fullReport), PptxGenJS);
  const zip = await JSZip.loadAsync((await pptx.write({ outputType: "nodebuffer" })) as ArrayBuffer);
  const read = async (pattern: RegExp) => {
    const files = Object.values(zip.files).filter((f) => !f.dir && pattern.test(f.name));
    return (await Promise.all(files.map((f) => f.async("string")))).join("\n");
  };
  return { pptx, zip, xml: await read(/\.xml$/), slidesXml: await read(/^ppt\/slides\/.+\.xml$/) };
};

test("o boletim sai no padrão do time, sem capa e sem logo embutida", async () => {
  const { pptx, zip, xml, slidesXml } = await buildDeck();

  // Primeiro slide já é conteúdo: nenhuma capa na frente.
  assert.match(xml, /Sumário executivo/);
  assert.match(xml, /Cyber Threat Intelligence &amp; Cyber Threat Hunting/, "rodapé do template");
  assert.match(xml, /Falha crítica no Portal Acme/, "título do boletim na linha sob a régua");
  // eslint-disable-next-line no-control-regex
  assert.doesNotMatch(slidesXml, /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/, "controle no XML faz o PowerPoint pedir reparo");
  assert.doesNotMatch(xml, /Consolidado - /, "a capa do template não entra");
  // A única imagem do pacote é a arte de fundo do template; nenhuma figura é
  // colada por cima, então não há logo embutida em slide nenhum.
  const media = Object.values(zip.files).filter((f) => !f.dir && /^ppt\/media\//.test(f.name)).map((f) => f.name);
  assert.ok(media.length > 0 && media.every((f) => /\.jpe?g$/.test(f)), `mídia fora do template: ${media}`);
  // Quem apresenta põe a própria marca: o deck não nomeia consultoria nenhuma.
  for (const id of [/\bEY\b/i, /Ernst\s*&\s*Young/i]) assert.doesNotMatch(xml, id, String(id));
  // Só as fontes do template, senão o PowerPoint substitui e a caixa anda.
  for (const face of slidesXml.matchAll(/typeface="([^"]+)"/g)) {
    assert.ok(DECK_FONTS.includes(face[1]), `fonte fora do padrão: ${face[1]}`);
  }

  type Positioned = { options?: { x?: number; y?: number; w?: number; h?: number } };
  const slides = (pptx as unknown as { slides: { _slideObjects: (Positioned & { _type?: string })[] }[] }).slides;
  for (const slide of slides) assert.ok(!slide._slideObjects.some((o) => o._type === "image"), "nenhuma figura colada no slide");
  assert.ok(slides.length >= 3, "uma seção por slide");
  for (const [i, slide] of slides.entries()) {
    for (const o of slide._slideObjects.map((obj) => obj.options)) {
      if (o?.x == null || o?.y == null || o.w == null || o.h == null) continue;
      assert.ok(o.x + o.w <= 10.001, `slide ${i + 1}: x=${o.x} passa da margem direita`);
      assert.ok(o.y + o.h <= 5.626, `slide ${i + 1}: y=${o.y} passa do rodapé`);
      if (o.y >= 4.99) continue; // faixa de rodapé e placa reservada
      assert.ok(o.x >= PANEL.x - 0.001 && o.x + o.w <= PANEL.x + PANEL.w + 0.001, `slide ${i + 1}: x=${o.x} sai do painel`);
      assert.ok(o.y + o.h <= PANEL.y + PANEL.h + 0.001, `slide ${i + 1}: y=${o.y} sai do painel`);
    }
  }
});

test("a url da fonte abre as referências, sem duplicar a que o motor já coletou", () => {
  const [refs] = boletimSections({
    source_url: "https://exemplo.test/aviso",
    referencias_coletadas: [{ url: "https://exemplo.test/aviso" }, { url: "https://nvd.nist.gov/x" }],
  });
  assert.deepEqual(refs.blocks, [{ kind: "bullets", items: ["https://exemplo.test/aviso", "https://nvd.nist.gov/x"] }]);
});
