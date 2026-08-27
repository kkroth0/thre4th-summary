import assert from "node:assert/strict";
import test from "node:test";
import type { ThreatIntelligenceResult, VendorData } from "@/types/threat-intelligence";
import { buildEnrichment, softwareKey, type SoftwareIndex } from "./enrichment";

const actor = (id: string, name: string) => ({ id, name });

// Recorte fiel ao catálogo real: Emotet e SUNBURST com um grupo cada, QakBot
// com três, Cobalt Strike com trinta — os regimes que a atribuição separa.
const index: SoftwareIndex = {
    [softwareKey("Emotet")]: [actor("G0102", "Wizard Spider")],
    [softwareKey("QakBot")]: [actor("G1046", "Storm-1811"), actor("G0127", "TA551"), actor("G0143", "TA577")],
    [softwareKey("Cobalt Strike")]: Array.from({ length: 30 }, (_, i) => actor(`G${i}`, `Grupo ${i}`)),
    [softwareKey("SUNBURST")]: [actor("G0016", "APT29")],
};

const vendor = (name: string, data: Record<string, unknown>): VendorData => ({ name, data });

const pulse = (over: Record<string, unknown> = {}) => ({
    id: "5f1e", name: "Emotet epoch4 infra", adversary: "", malwareFamilies: [],
    attackIds: [], tags: [], tlp: "white", created: "2026-08-01T00:00:00", modified: "2026-08-02T00:00:00",
    ...over,
});

const result = (over: Partial<ThreatIntelligenceResult> = {}): ThreatIntelligenceResult => ({
    query: "185.220.101.5",
    overallScore: 80,
    threatLevel: "malicious",
    totalVendors: 4,
    detections: 3,
    vendorData: [],
    ...over,
});

const only = (over: Partial<ThreatIntelligenceResult>) => buildEnrichment([result(over)], index).indicators[0];

test("adversary do OTX atribui o grupo e cita o pulse como base", () => {
    const row = only({
        vendorData: [vendor("AlienVault OTX", {
            "Pulse Details": [pulse({ adversary: "Wizard Spider", attackIds: ["T1566"] })],
        })],
    });
    assert.equal(row.actors, "Wizard Spider");
    assert.equal(row.confidence, "Média");
    assert.match(row.basis, /OTX nomeia Wizard Spider em 1 pulse/);
    assert.equal(row.campaign, "Emotet epoch4 infra");
    assert.equal(row.attackIds, "T1566");
});

test("família específica chega ao grupo pelo catálogo, com confiança baixa", () => {
    const row = only({ vendorData: [vendor("ThreatFox", { Status: "Malicious", "All Malware": ["Emotet"] })] });
    assert.equal(row.actors, "Wizard Spider");
    assert.equal(row.confidence, "Baixa");
    assert.match(row.basis, /catálogo: Emotet é usada por Wizard Spider/);
});

// A regra que impede a planilha de virar ficção: sem ela, todo IP com Cobalt
// Strike sairia atribuído a trinta grupos de uma vez.
test("ferramenta compartilhada não atribui grupo nenhum", () => {
    const row = only({ vendorData: [vendor("ThreatFox", { Status: "Malicious", "All Malware": ["Cobalt Strike"] })] });
    assert.equal(row.actors, "");
    assert.equal(row.confidence, "Sem atribuição");
    assert.match(row.basis, /ferramenta compartilhada.*Cobalt Strike \(30 grupos\)/);
    assert.equal(row.families, "Cobalt Strike", "a família continua no relatório como contexto");
});

test("as duas fontes apontando o mesmo grupo sobem para alta", () => {
    const row = only({
        vendorData: [
            vendor("AlienVault OTX", { "Pulse Details": [pulse({ adversary: "Wizard Spider" })] }),
            vendor("ThreatFox", { Status: "Malicious", "All Malware": ["Emotet"] }),
        ],
    });
    assert.equal(row.actors, "Wizard Spider");
    assert.equal(row.confidence, "Alta");
});

test("dois pulses com o mesmo adversary também sobem para alta", () => {
    const row = only({
        vendorData: [vendor("AlienVault OTX", {
            "Pulse Details": [pulse({ adversary: "APT29" }), pulse({ id: "6a2b", adversary: "APT29" })],
        })],
    });
    assert.equal(row.confidence, "Alta");
});

test("sem nenhum sinal a base diz que ninguém nomeou nada", () => {
    const row = only({ threatLevel: "safe", vendorData: [vendor("VirusTotal", { "Detection Rate": "0/94" })] });
    assert.equal(row.confidence, "Sem atribuição");
    assert.equal(row.basis, "nenhuma base nomeou grupo ou família");
    assert.equal(row.verdict, "Limpo");
});

// Pulse de feed automático não tem adversary nem técnica; entrar como campanha
// encheria a coluna de lixo tipo "Daily IP blocklist".
test("pulse sem grupo e sem técnica não vira campanha", () => {
    const row = only({
        vendorData: [vendor("AlienVault OTX", { "Pulse Details": [pulse({ name: "Daily IP blocklist" })] })],
    });
    assert.equal(row.campaign, "");
    assert.equal(row.otxPulses, 1);
});

test("a classificação da VirusTotal também alimenta a família", () => {
    const row = only({
        vendorData: [vendor("VirusTotal", {
            "Detection Rate": "42/94", "Threat Classification": "SUNBURST", Country: "CN", ASN: "4134",
        })],
    });
    assert.equal(row.actors, "APT29");
    assert.equal(row.country, "CN");
    assert.equal(row.asn, "4134");
    assert.equal(row.vtDetections, "42/94");
});

// "Unknown" é preenchimento das APIs; numa planilha entregue ao cliente a
// célula vazia é mais honesta do que a palavra.
test("preenchimento das APIs não vai para a planilha", () => {
    const row = only({ vendorData: [vendor("VirusTotal", { Country: "Unknown", ASN: "Unknown" })] });
    assert.equal(row.country, "");
    assert.equal(row.asn, "");
});

// A abuse.ch devolve 401 sem Auth-Key: sem essa distinção, o ThreatFox caído
// sai da planilha igual ao ThreatFox que respondeu "não conheço esse IOC", e
// "Sem atribuição" passa a ler como veredito.
test("base que não respondeu aparece, em vez de virar silêncio", () => {
    const row = only({
        vendorData: [
            { name: "ThreatFox", data: {}, error: "ThreatFox API error: 401 Unauthorized" },
            vendor("VirusTotal", { "Detection Rate": "0/94" }),
        ],
    });
    assert.equal(row.unanswered, "ThreatFox");
    assert.equal(row.sources, "VirusTotal", "base caída não conta como consultada");
    assert.match(row.basis, /sem resposta: ThreatFox$/);
});

test("as evidências ficam rastreáveis até o provedor", () => {
    const report = buildEnrichment([result({
        vendorData: [
            vendor("AlienVault OTX", { "Pulse Details": [pulse({ adversary: "Wizard Spider", tags: ["banker"] })] }),
            vendor("AbuseIPDB", {
                "Abuse Confidence Score": "100%",
                Reports: [{ date: "2026-08-20T10:00:00+00:00", comment: "SSH brute force", categoryNames: ["Força bruta", "SSH"], reporterCountry: "DE" }],
            }),
        ],
    })], index);

    const otx = report.evidence.find((e) => e.source === "AlienVault OTX")!;
    assert.equal(otx.kind, "Pulse");
    assert.equal(otx.link, "https://otx.alienvault.com/pulse/5f1e");
    assert.match(otx.detail, /Grupo: Wizard Spider · Tags: banker · TLP: WHITE/);

    const abuse = report.evidence.find((e) => e.source === "AbuseIPDB")!;
    assert.equal(abuse.title, "Força bruta, SSH");
    assert.match(abuse.detail, /SSH brute force · Denunciante em DE/);
    assert.equal(abuse.link, "https://www.abuseipdb.com/check/185.220.101.5");
});

test("o sumário conta grupo, família, veredito e país", () => {
    const report = buildEnrichment([
        result({ vendorData: [vendor("ThreatFox", { Status: "Malicious", "All Malware": ["Emotet"] })] }),
        result({ query: "evil.example.com", vendorData: [vendor("ThreatFox", { Status: "Malicious", "All Malware": ["Emotet"] })] }),
        result({ query: "1.1.1.1", threatLevel: "safe", vendorData: [] }),
    ], index);

    assert.deepEqual(report.byActor, [{ name: "Wizard Spider", count: 2 }]);
    assert.deepEqual(report.byFamily, [{ name: "Emotet", count: 2 }]);
    assert.deepEqual(report.byVerdict, [{ name: "Malicioso", count: 2 }, { name: "Limpo", count: 1 }]);
    assert.equal(report.indicators[1].type, "Domínio");
});
