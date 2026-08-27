import assert from "node:assert/strict";
import test from "node:test";
import type { ThreatIntelligenceResult, VendorData } from "@/types/threat-intelligence";
import { buildEnrichment, softwareKey, type ActorNameIndex, type SoftwareIndex } from "./enrichment";

const actor = (id: string, name: string) => ({ id, name });

// Recorte fiel ao catálogo real: Emotet e SUNBURST com um grupo cada, QakBot
// com três, Cobalt Strike com trinta — os regimes que a atribuição separa.
const index: SoftwareIndex = {
    [softwareKey("Emotet")]: [actor("G0102", "Wizard Spider")],
    [softwareKey("QakBot")]: [actor("G1046", "Storm-1811"), actor("G0127", "TA551"), actor("G0143", "TA577")],
    [softwareKey("Cobalt Strike")]: Array.from({ length: 30 }, (_, i) => actor(`G${i}`, `Grupo ${i}`)),
    [softwareKey("SUNBURST")]: [actor("G0016", "APT29")],
};

// Nome e alias do catálogo. UNC2452 é alias da APT29 — é o que colapsa a
// duplicata que a OTX manda como se fossem dois grupos.
const names: ActorNameIndex = {
    [softwareKey("APT29")]: "APT29",
    [softwareKey("UNC2452")]: "APT29",
    [softwareKey("Wizard Spider")]: "Wizard Spider",
    [softwareKey("UNC6293")]: "UNC6293",
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

// O catálogo só cobre ferramental que o MITRE amarra a grupo nomeado. Crimeware
// de mercado cai fora, e a linha precisa separar "não achei o grupo dessa
// família" de "ninguém nomeou nada" — senão o leitor culpa a base errada.
test("família fora do catálogo diz isso, em vez de fingir que ninguém nomeou nada", () => {
    const row = only({ vendorData: [vendor("ThreatFox", { Status: "Malicious", "All Malware": ["ClearFake"] })] });
    assert.equal(row.actors, "");
    assert.equal(row.families, "ClearFake");
    assert.equal(row.basis, "família ClearFake não consta no catálogo de atores");
});

// O ponto da feature: correlacionar o indicador com um APT, inclusive pelo que
// a notícia disse. A menção atribui, mas só em Baixa e sempre citando o artigo:
// a story casa ator no texto inteiro, então grupo mencionado de passagem entra
// junto. O que tornou isso seguro foi o filtro de benignos — antes dele,
// `slack.com` citado num artigo sobre APT29 viraria "slack.com é da APT29".
test("menção em notícia atribui em Baixa, citando o artigo", () => {
    const mention = {
        storyId: "st1", title: "Going with the Flow(s)", source: "Mandiant",
        link: "https://cloud.google.com/blog/flow", pubDate: "2026-08-20T00:00:00Z",
        actors: ["UNC6293", "APT29"], categories: ["Espionagem"],
    };
    const report = buildEnrichment(
        [result({ query: "107.189.18.7", vendorData: [] })],
        index, new Date("2026-08-27T00:00:00Z"),
        { "107.189.18.7": [mention] },
    );
    const row = report.indicators[0];

    assert.match(row.mentions, /Mandiant: Going with the Flow\(s\) \(UNC6293, APT29\)/);
    assert.equal(row.actors, "UNC6293, APT29");
    assert.equal(row.confidence, "Baixa", "ler num artigo não é ver o indicador ser usado");
    assert.match(row.basis, /Mandiant cita UNC6293, APT29 em "Going with the Flow\(s\)"/);

    const ev = report.evidence.find((e) => e.kind === "Menção em notícia")!;
    assert.equal(ev.source, "Mandiant");
    assert.equal(ev.link, "https://cloud.google.com/blog/flow");
    assert.match(ev.detail, /Ator citado na matéria: UNC6293, APT29/);
});

// A notícia não pode rebaixar o que a base já sabia: adversary do OTX em dois
// pulses continua Alta mesmo que uma matéria fraca cite outro grupo junto.
test("menção não rebaixa a atribuição que veio da base", () => {
    const report = buildEnrichment(
        [result({
            query: "185.220.101.5",
            vendorData: [vendor("AlienVault OTX", {
                "Pulse Details": [pulse({ adversary: "APT29" }), pulse({ id: "b2", adversary: "APT29" })],
            })],
        })],
        index, new Date("2026-08-27T00:00:00Z"),
        { "185.220.101.5": [{ storyId: "s", title: "Roundup", source: "Blog", link: "https://x.example",
                              pubDate: "2026-08-01T00:00:00Z", actors: ["Lazarus Group"], categories: [] }] },
    );
    const row = report.indicators[0];

    assert.equal(row.confidence, "Alta");
    assert.match(row.actors, /^APT29, Lazarus Group$/, "os dois aparecem, a ordem põe a base na frente");
});

test("indicador sem menção não inventa coluna", () => {
    const row = buildEnrichment([result({ vendorData: [] })], index).indicators[0];
    assert.equal(row.mentions, "");
});

// O `adversary` do pulse é texto livre. Medido em dois indicadores reais: de 26
// rótulos, 21 eram nome de malware, rótulo de campanha ou título de artigo. Sem
// o filtro, a coluna Grupo da planilha saía com 21 nomes.
test("rótulo da OTX que não é ator não vira grupo", () => {
    const report = buildEnrichment(
        [result({
            vendorData: [vendor("AlienVault OTX", {
                "Pulse Details": [
                    pulse({ adversary: "APT29" }),
                    pulse({ id: "b", adversary: "M365 AiTM PhaaS" }),
                    pulse({ id: "c", adversary: "FTP Banners" }),
                ],
            })],
        })],
        index, new Date("2026-08-27T00:00:00Z"), {}, names,
    );
    const row = report.indicators[0];

    assert.equal(row.actors, "APT29");
    assert.equal(row.otxLabels, "M365 AiTM PhaaS, FTP Banners",
        "campanha e malware da OTX ficam à vista, em coluna própria");
    assert.match(row.basis, /2 rótulo\(s\) da OTX sem atribuição/);
});

// Pulse em lote ("EbeeAug2026 Pt1") despeja o mês num pulse só e enfia no
// adversary a lista de tudo que ele cobre. Seis coisas sem relação: o indicador
// estar lá dentro não o liga a nenhuma. Nem o ator de verdade da lista atribui.
test("pulse em lote não atribui, nem o ator que está na lista", () => {
    const report = buildEnrichment(
        [result({
            vendorData: [vendor("AlienVault OTX", {
                "Pulse Details": [pulse({ adversary: "Mirage Kitten, APT29, MedusaHVNC" })],
            })],
        })],
        index, new Date("2026-08-27T00:00:00Z"), {}, names,
    );
    const row = report.indicators[0];

    assert.equal(row.actors, "", "APT29 veio de pulse em lote, não atribui");
    assert.equal(row.otxLabels, "Mirage Kitten, APT29, MedusaHVNC", "a lista inteira vira contexto");
    assert.match(row.basis, /1 de pulse em lote/);
});

// Dezesseis rótulos na base da atribuição ninguém lê — mas nenhum se perde:
// eles vão inteiros para a coluna Campanha/Malware.
test("lista longa de rótulo da OTX fica inteira na coluna, e a base só conta", () => {
    const soltos = ["L1", "L2", "L3", "L4", "L5", "L6"].join(", ");
    const report = buildEnrichment(
        [result({ vendorData: [vendor("AlienVault OTX", { "Pulse Details": [pulse({ adversary: soltos })] })] })],
        index, new Date("2026-08-27T00:00:00Z"), {}, names,
    );
    assert.equal(report.indicators[0].otxLabels, "L1, L2, L3, L4, L5, L6");
    assert.match(report.indicators[0].basis, /6 rótulo\(s\) da OTX sem atribuição, 1 de pulse em lote/);
});

// A OTX escreve "Qilin Ransomware"; o catálogo, que puxa do ransomware.live,
// tem "Qilin". O nome inteiro é tentado primeiro, então "Lazarus Group" — que é
// o nome canônico dele mesmo — não é mutilado pelo corte.
test("qualificador colado no nome não impede achar o ator", () => {
    const comSufixo: ActorNameIndex = { ...names, [softwareKey("Qilin")]: "Qilin", [softwareKey("Lazarus Group")]: "Lazarus Group" };
    const report = buildEnrichment(
        [result({
            vendorData: [vendor("AlienVault OTX", {
                "Pulse Details": [
                    pulse({ adversary: "Qilin Ransomware" }),
                    pulse({ id: "b", adversary: "Lazarus Group" }),
                ],
            })],
        })],
        index, new Date("2026-08-27T00:00:00Z"), {}, comSufixo,
    );
    assert.equal(report.indicators[0].actors, "Qilin, Lazarus Group");
    assert.equal(report.indicators[0].otxLabels, "");
});

test("alias colapsa: UNC2452 e APT29 não saem como dois grupos", () => {
    const report = buildEnrichment(
        [result({
            vendorData: [vendor("AlienVault OTX", {
                "Pulse Details": [pulse({ adversary: "APT29" }), pulse({ id: "b", adversary: "UNC2452" })],
            })],
        })],
        index, new Date("2026-08-27T00:00:00Z"), {}, names,
    );
    assert.equal(report.indicators[0].actors, "APT29");
});

// Catálogo fora do ar não pode zerar a coluna: rótulo cru é pior que nome
// canônico, e muito melhor que célula vazia.
test("sem catálogo de nomes, o rótulo passa cru", () => {
    const row = only({
        vendorData: [vendor("AlienVault OTX", { "Pulse Details": [pulse({ adversary: "M365 AiTM PhaaS" })] })],
    });
    assert.equal(row.actors, "M365 AiTM PhaaS");
});

// Tag de pulse mistura técnica, nome de ator, nome de malware e lixo estrutural
// do publicador. O que diz COMO o ataque acontece é a granularidade que o ATT&CK
// não tem: ele registra "Phishing", a tag registra "device code phishing".
test("tag que descreve técnica sai separada, e o lixo estrutural sai fora", () => {
    const row = only({
        vendorData: [vendor("AlienVault OTX", {
            "Pulse Details": [pulse({
                adversary: "APT29",
                tags: [
                    "device code phishing", "captive portal compromise", "authentication abuse",
                    "cozy bear", "chocoshell", "microsoft 365",
                    "filehashsha256", "pajaxsuccessfml", "methodindex", "monthly",
                ],
            })],
        })],
    });

    assert.equal(row.techniques, "device code phishing, captive portal compromise, authentication abuse");
    assert.equal(row.tags, "cozy bear, chocoshell, microsoft 365", "ator e malware ficam em Tags");
    for (const lixo of ["filehashsha256", "pajaxsuccessfml", "methodindex", "monthly"]) {
        assert.doesNotMatch(`${row.tags} ${row.techniques}`, new RegExp(lixo), lixo);
    }
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
