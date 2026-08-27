import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import type { EnrichmentReport } from "./enrichment";
import { buildEnrichmentWorkbook, enrichmentExcelFilename } from "./enrichmentExport";

const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");

const report: EnrichmentReport = {
    generatedAt: "2026-08-27T09:00:00.000Z",
    indicators: [
        {
            indicator: "185.220.101.5", type: "IP", verdict: "Malicioso",
            actors: "Wizard Spider", campaign: "Emotet epoch4 infra", families: "Emotet",
            attackIds: "T1566", confidence: "Alta",
            basis: "OTX nomeia Wizard Spider em 2 pulses · catálogo: Emotet é usada por Wizard Spider",
            vtDetections: "42/94", abuseScore: "100%", otxPulses: 2, tags: "banker",
            country: "RU", asn: "AS49505", firstSeen: "2026-08-01", lastSeen: "2026-08-25",
            sources: "VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox", unanswered: "",
            mentions: "Mandiant: Going with the Flow(s) (UNC6293, APT29)",
        },
        {
            indicator: "1.1.1.1", type: "IP", verdict: "Limpo", actors: "", campaign: "",
            families: "", attackIds: "", confidence: "Sem atribuição",
            basis: "nenhuma base nomeou grupo ou família", vtDetections: "0/94",
            abuseScore: "0%", otxPulses: 0, tags: "", country: "AU", asn: "AS13335",
            firstSeen: "", lastSeen: "", sources: "VirusTotal", unanswered: "ThreatFox", mentions: "",
        },
    ],
    evidence: [
        {
            indicator: "185.220.101.5", source: "AlienVault OTX", kind: "Pulse",
            title: "Emotet epoch4 infra", detail: "Grupo: Wizard Spider · TLP: WHITE",
            date: "2026-08-02T00:00:00", link: "https://otx.alienvault.com/pulse/5f1e",
        },
        {
            indicator: "185.220.101.5", source: "AbuseIPDB", kind: "Denúncia",
            title: "Força bruta, SSH", detail: "SSH brute force", date: "2026-08-20T10:00:00+00:00",
            link: "",
        },
    ],
    byActor: [{ name: "Wizard Spider", count: 1 }],
    byFamily: [{ name: "Emotet", count: 1 }],
    byVerdict: [{ name: "Malicioso", count: 1 }, { name: "Limpo", count: 1 }],
    byCountry: [{ name: "AU", count: 1 }, { name: "RU", count: 1 }],
};

test("a planilha sai nas três abas do padrão EY", () => {
    const wb = buildEnrichmentWorkbook(report, ExcelJS);
    assert.deepEqual(wb.worksheets.map((ws) => ws.name), ["Indicadores", "Evidências", "Sumário"]);

    const indicadores = wb.getWorksheet("Indicadores")!;
    const header = indicadores.getRow(1);
    assert.equal(header.getCell(1).value, "Indicador");
    assert.equal(header.getCell(4).value, "Grupo / Ator");
    assert.equal(header.getCell(7).value, "Confiança da Atribuição");
    assert.equal(header.getCell(8).value, "Base da Atribuição", "a atribuição sempre vem com o porquê ao lado");

    // Faixa preta, Calibri 14 amarelo em negrito, com borda, congelada e filtrável.
    const style = header.getCell(1);
    assert.deepEqual(style.font, { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFE600" } });
    assert.equal((style.fill as { fgColor: { argb: string } }).fgColor.argb, "FF000000");
    assert.ok(style.border?.bottom);
    assert.deepEqual(indicadores.views, [{ state: "frozen", ySplit: 1 }]);
    assert.ok(indicadores.autoFilter);
    assert.equal(indicadores.properties.tabColor?.argb, "FFFFE600", "abas amarelas");

    // Sem cor nas linhas de dados — quem recebe filtra por coluna.
    assert.equal(indicadores.getRow(2).getCell(3).fill, undefined);
    assert.equal(indicadores.getRow(2).getCell(3).font, undefined);

    assert.equal(indicadores.getRow(2).getCell(4).value, "Wizard Spider");
    assert.equal(indicadores.getRow(3).getCell(7).value, "Sem atribuição");
    // Zero pulse é ausência de dado, não a contagem zero.
    assert.equal(indicadores.getRow(3).getCell(12).value, "");

    assert.equal(indicadores.getRow(1).getCell(19).value, "Bases sem Resposta");
    assert.equal(indicadores.getRow(3).getCell(19).value, "ThreatFox", "base caída fica à vista na planilha");
    assert.equal(indicadores.getRow(1).getCell(20).value, "Mencionado Em");
    assert.match(String(indicadores.getRow(2).getCell(20).value), /Mandiant.*UNC6293/);

    assert.equal(enrichmentExcelFilename(report), "Enriquecimento-de-Indicadores-2026-08-27.xlsx");
});

test("cada evidência aponta para a fonte, com link no estilo do Excel", () => {
    const evidencias = buildEnrichmentWorkbook(report, ExcelJS).getWorksheet("Evidências")!;
    assert.equal(evidencias.getRow(1).getCell(3).value, "Tipo de Evidência");
    assert.deepEqual(evidencias.getRow(2).getCell(7).value, {
        text: "Abrir",
        hyperlink: "https://otx.alienvault.com/pulse/5f1e",
    });
    assert.deepEqual(evidencias.getRow(2).getCell(7).font, {
        name: "Calibri", color: { argb: "FF0563C1" }, underline: true,
    });
    // Evidência sem link não pode virar hyperlink vazio: o Excel reclama.
    assert.equal(evidencias.getRow(3).getCell(7).value, "");
});

test("o sumário conta por grupo, família, veredito e país", () => {
    const sumario = buildEnrichmentWorkbook(report, ExcelJS).getWorksheet("Sumário")!;
    assert.equal(sumario.getCell("A1").value, "Enriquecimento de Indicadores");
    assert.match(String(sumario.getCell("A2").value), /^2 indicadores · 2 evidências/);
    const column = (n: number) => sumario.getColumn(n).values.map((v) => (v == null ? "" : String(v)));
    const labels = column(1);
    assert.ok(labels.includes("Grupo / Ator"));
    assert.ok(labels.includes("Família de Malware"));
    assert.ok(labels.includes("Veredito"));
    assert.ok(labels.includes("País"));
    assert.ok(labels.includes("Wizard Spider"));
});

test("seção sem dado diz que está vazia em vez de sumir", () => {
    const empty = buildEnrichmentWorkbook(
        { ...report, byActor: [], byFamily: [] },
        ExcelJS,
    ).getWorksheet("Sumário")!;
    assert.equal(empty.getRow(5).getCell(1).value, "Nenhum");
});

// Comentário de denúncia é texto que um terceiro escreveu. Um controle C0 no
// meio dele faz o Excel da Microsoft declarar o arquivo corrompido e oferecer
// reparo — que é exatamente o que não pode acontecer na mão do cliente.
test("texto de terceiro não corrompe o arquivo nem vira fórmula", async () => {
    const hostile: EnrichmentReport = {
        ...report,
        evidence: [{
            ...report.evidence[1],
            // Bell (U+0007) no meio do texto: ilegal em XML 1.0, nem escapado.
            title: "For\u0007ça bruta",
            detail: "=cmd|'/c calc'!A1",
        }],
    };
    const wb = buildEnrichmentWorkbook(hostile, ExcelJS);
    const row = wb.getWorksheet("Evidências")!.getRow(2);
    assert.equal(row.getCell(4).value, "Força bruta", "controle C0 removido");
    assert.equal(row.getCell(5).value, "=cmd|'/c calc'!A1");
    assert.equal(row.getCell(5).type, ExcelJS.ValueType.String, "célula de texto, nunca fórmula");

    const xml = await wb.xlsx.writeBuffer();
    assert.ok((xml as ArrayBuffer).byteLength > 0);
});

test("a planilha não identifica a consultoria em nenhum metadado", async () => {
    const JSZip = runtimeRequire("jszip") as typeof import("jszip");
    const bytes = await buildEnrichmentWorkbook(report, ExcelJS).xlsx.writeBuffer();
    const zip = await JSZip.loadAsync(bytes as ArrayBuffer);
    const files = Object.values(zip.files).filter((f) => !f.dir && /\.xml$/.test(f.name));
    const xml = (await Promise.all(files.map((f) => f.async("string")))).join("\n");

    assert.match(xml, /Wizard Spider/);
    for (const identifier of [/\bEY\b/i, /Ernst\s*&\s*Young/i, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});
