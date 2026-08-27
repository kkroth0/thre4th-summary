// Enriquecimento de indicadores: pega o que as bases já responderam e tenta
// dizer a que grupo ou campanha aquele IP/domínio/URL/hash pertence.
//
// Regra que sustenta o resto: **família de malware não é grupo**. O ThreatFox e
// o VirusTotal quase sempre respondem com a família, e famílias populares —
// Cobalt Strike, PlugX, njRAT — são usadas por dezenas de grupos. Atribuir por
// elas transformaria qualquer IP com Cobalt Strike em trinta atores. Por isso a
// família só atribui quando poucos grupos a usam; acima disso ela vira
// "ferramenta compartilhada" e entra no relatório como contexto, não como
// atribuição.
//
// Módulo puro: recebe resultados e o índice, devolve linhas. Sem fetch, sem DOM.
import type { ThreatIntelligenceResult, VendorData } from "@/types/threat-intelligence";
import type { NewsMention, OtxPulseDetail } from "@/services/threatApi";
import { detectAnalyzerQueryType } from "@/utils/iocExtract";

// Mesma normalização do server/actorSoftware.js, que constrói as chaves do
// índice — as duas pontas têm que concordar ou nada casa.
export const softwareKey = (name: string): string =>
    String(name || "")
        .toLowerCase()
        .normalize("NFD")
        .replace(/\p{Mn}/gu, "")
        .replace(/[^a-z0-9]/g, "");

export type SoftwareIndex = Record<string, { id: string; name: string }[]>;
/** nome ou alias normalizado → nome canônico. Vem do mesmo endpoint. */
export type ActorNameIndex = Record<string, string>;

// A partir de quantos grupos uma família deixa de atribuir e passa a ser
// ferramenta compartilhada. Três ainda cabe numa linha de planilha como
// "candidatos"; quatro já é ruído.
export const SHARED_TOOL_ACTORS = 4;

export type AttributionConfidence = "Alta" | "Média" | "Baixa" | "Sem atribuição";

export interface EnrichedIndicator {
    indicator: string;
    type: string;
    verdict: string;
    actors: string;
    campaign: string;
    families: string;
    attackIds: string;
    confidence: AttributionConfidence;
    basis: string;
    vtDetections: string;
    abuseScore: string;
    otxPulses: number;
    tags: string;
    country: string;
    asn: string;
    firstSeen: string;
    lastSeen: string;
    sources: string;
    unanswered: string;
    mentions: string;
    otxLabels: string;
}

export interface EnrichmentEvidence {
    indicator: string;
    source: string;
    kind: string;
    title: string;
    detail: string;
    date: string;
    link: string;
}

export interface NamedCount {
    name: string;
    count: number;
}

export interface EnrichmentReport {
    generatedAt: string;
    indicators: EnrichedIndicator[];
    evidence: EnrichmentEvidence[];
    byActor: NamedCount[];
    byFamily: NamedCount[];
    byVerdict: NamedCount[];
    byCountry: NamedCount[];
}

const TYPE_LABEL: Record<string, string> = {
    ip: "IP",
    domain: "Domínio",
    url: "URL",
    hash: "Hash",
    unknown: "Indefinido",
};

const VERDICT_LABEL: Record<string, string> = {
    malicious: "Malicioso",
    suspicious: "Suspeito",
    safe: "Limpo",
    unknown: "Inconclusivo",
};

// Qualificador que a OTX cola no nome e o catálogo não tem: "Qilin Ransomware"
// contra a "Qilin" do ransomware.live.
const QUALIFIER_SUFFIX = /\s+(ransomware|group|gang|team|crew|botnet|malware)$/i;

const unique = (values: string[]): string[] =>
    Array.from(new Set(values.map((v) => String(v || "").trim()).filter(Boolean)));

const vendorOf = (result: ThreatIntelligenceResult, name: string): Record<string, any> | null => {
    const found = result.vendorData?.find((v: VendorData) => v.name === name && !v.error);
    return found?.data && Object.keys(found.data).length ? found.data : null;
};

const asList = (value: unknown): string[] =>
    Array.isArray(value) ? value.map((v) => String(v || "").trim()).filter(Boolean) : [];

// "Unknown"/"None"/"N/A" são preenchimento das bases, não valor — numa planilha
// entregue ao cliente a célula vazia diz a verdade melhor.
const EMPTY_MARKERS = new Set(["unknown", "none", "n/a", "never", "no data", "no data available", ""]);
const clean = (value: unknown): string => {
    const text = String(value ?? "").trim();
    return EMPTY_MARKERS.has(text.toLowerCase()) ? "" : text;
};

const pulseDetails = (otx: Record<string, any> | null): OtxPulseDetail[] =>
    Array.isArray(otx?.["Pulse Details"]) ? (otx!["Pulse Details"] as OtxPulseDetail[]) : [];

// Pulse de feed automático não tem adversary nem técnica — vira ruído se entrar
// como campanha. Só o pulse escrito por analista carrega um dos dois.
const isCampaignPulse = (pulse: OtxPulseDetail): boolean =>
    Boolean(pulse.adversary) || (pulse.attackIds || []).length > 0;

interface Signals {
    adversaries: string[];
    adversaryPulses: number;
    families: string[];
    campaigns: string[];
    attackIds: string[];
    tags: string[];
}

const collectSignals = (result: ThreatIntelligenceResult): Signals => {
    const otx = vendorOf(result, "AlienVault OTX");
    const threatfox = vendorOf(result, "ThreatFox");
    const virustotal = vendorOf(result, "VirusTotal");
    // Num hash é a MalwareBazaar que nomeia a família; numa URL, a URLhaus.
    // Sem elas o indicador que não é IP chegava ao catálogo sem nada para casar.
    const bazaar = vendorOf(result, "MalwareBazaar");
    const urlhaus = vendorOf(result, "URLhaus");
    const pulses = pulseDetails(otx);
    const withAdversary = pulses.filter((p) => clean(p.adversary));

    return {
        adversaries: unique(withAdversary.map((p) => p.adversary)),
        adversaryPulses: withAdversary.length,
        families: unique([
            ...asList(threatfox?.["All Malware"]),
            ...pulses.flatMap((p) => p.malwareFamilies || []),
            clean(virustotal?.["Threat Classification"]),
            ...asList(virustotal?.["Threat Names"]),
            clean(bazaar?.["Signature"]),
            clean(urlhaus?.["Signature"]),
        ]),
        campaigns: unique(pulses.filter(isCampaignPulse).map((p) => p.name)),
        attackIds: unique(pulses.flatMap((p) => p.attackIds || [])),
        tags: unique([
            ...asList(threatfox?.["All Tags"]),
            ...asList(virustotal?.["All Tags"]),
            ...pulses.flatMap((p) => p.tags || []),
            ...String(bazaar?.["Tags"] || "").split(",").map((t) => t.trim()),
            ...asList(urlhaus?.["Tags"]),
        ]),
    };
};

export interface Attribution {
    actors: string[];
    confidence: AttributionConfidence;
    basis: string;
    /** o que a OTX chamou de adversary e o catálogo não conhece como grupo:
     *  nome de campanha e de malware, que valem por si. */
    otxLabels: string[];
}

export const attribute = (
    signals: Signals,
    index: SoftwareIndex,
    mentions: NewsMention[] = [],
    names: ActorNameIndex = {},
): Attribution => {
    // O `adversary` do pulse é texto livre, e analista escreve o que quiser:
    // medido, de 26 rótulos vindos de dois indicadores reais só 5 eram ator — o
    // resto era nome de malware, rótulo de campanha e até título de artigo. Sem
    // este filtro a coluna Grupo saía com 21 nomes. Quando o catálogo está vazio
    // (endpoint fora), passa tudo: é melhor um rótulo cru do que coluna vazia.
    //
    // O campo também chega com vários rótulos numa string só — "Mirage Kitten,
    // Fox Tempest, Qilin Ransomware, MedusaHVNC" veio assim de um pulse real —,
    // então separar por vírgula vem antes de procurar: sem isso o Fox Tempest,
    // que ESTÁ no catálogo, era descartado junto com os vizinhos.
    const rotulos = unique(signals.adversaries.flatMap((a) => a.split(/[,;]/)));
    // "Qilin Ransomware" é a Qilin do catálogo, e "Lazarus Group" é o nome
    // canônico dela mesma — por isso o nome inteiro é tentado primeiro e o
    // corte do qualificador só entra como segunda chance.
    const canon = (label: string) => {
        if (!Object.keys(names).length) return label.trim();
        const semQualificador = label.replace(QUALIFIER_SUFFIX, "").trim();
        return names[softwareKey(label)] || names[softwareKey(semQualificador)] || "";
    };
    const direct = unique(rotulos.map(canon).filter(Boolean));
    // O que sobra não é lixo: é nome de campanha ("M365 AiTM PhaaS") e de
    // malware ("WordlistLoader"), que o MISP e o MITRE não catalogam como ator
    // mas que valem por si. Ganha coluna própria em vez de virar descarte.
    const otxLabels = rotulos.filter((label) => !canon(label)).map((label) => label.trim()).filter(Boolean);
    const viaFamily = new Map<string, string[]>();
    const sharedTools: string[] = [];
    // O catálogo cobre o ferramental que o MITRE amarra a grupo nomeado. Crimeware
    // de mercado — ClearFake, Mozi, RedLine, Lumma — não está lá, e a linha tem
    // que dizer isso: "não achei o grupo" é diferente de "ninguém nomeou nada".
    const unmapped: string[] = [];

    for (const family of signals.families) {
        const actors = index[softwareKey(family)] || [];
        if (!actors.length) {
            unmapped.push(family);
            continue;
        }
        if (actors.length >= SHARED_TOOL_ACTORS) {
            sharedTools.push(`${family} (${actors.length} grupos)`);
            continue;
        }
        for (const actor of actors) {
            viaFamily.set(actor.name, unique([...(viaFamily.get(actor.name) || []), family]));
        }
    }

    const catalogActors = [...viaFamily.keys()];
    // O que a matéria atribuiu. É sinal fraco de propósito: a story casa ator no
    // texto inteiro do artigo, então um grupo citado de passagem entra junto —
    // por isso entra como Baixa e sempre com o título do artigo ao lado, para o
    // analista poder discordar sem abrir a fonte.
    const fromNews = unique(mentions.flatMap((m) => m.actors || []).map(canon).filter(Boolean));
    const agreeing = [...catalogActors, ...fromNews].filter((name) =>
        direct.some((adversary) => softwareKey(adversary) === softwareKey(name)));
    const actors = unique([...direct, ...catalogActors, ...fromNews]);

    const basis: string[] = [];
    if (direct.length) {
        const plural = signals.adversaryPulses === 1 ? "pulse" : "pulses";
        basis.push(`OTX nomeia ${direct.join(", ")} em ${signals.adversaryPulses} ${plural}`);
    }
    for (const [actor, families] of viaFamily) {
        basis.push(`catálogo: ${families.join(", ")} é usada por ${actor}`);
    }
    if (sharedTools.length) {
        basis.push(`ferramenta compartilhada, não atribui sozinha: ${sharedTools.join("; ")}`);
    }
    for (const mention of mentions) {
        if (!mention.actors?.length) continue;
        basis.push(`${mention.source} cita ${mention.actors.join(", ")} em "${mention.title}"`);
    }
    if (otxLabels.length) {
        // A base cita a contagem; os nomes inteiros ficam na coluna própria,
        // porque dezesseis rótulos aqui dentro ninguém lê.
        basis.push(`${otxLabels.length} rótulo(s) da OTX sem ator no catálogo, na coluna Campanha/Malware`);
    }
    if (!actors.length && unmapped.length) {
        basis.push(`família ${unmapped.join(", ")} não consta no catálogo de atores`);
    }
    if (!actors.length && !basis.length) {
        basis.push("nenhuma base nomeou grupo ou família");
    }

    let confidence: AttributionConfidence = "Sem atribuição";
    if (actors.length) {
        if (agreeing.length || (direct.length && signals.adversaryPulses >= 2)) confidence = "Alta";
        else if (direct.length) confidence = "Média";
        // Catálogo e notícia ficam os dois em Baixa: um deduziu pela família, o
        // outro leu num artigo. Nenhum dos dois viu o indicador ser usado.
        else confidence = "Baixa";
    }

    return { actors, confidence, basis: basis.join(" · "), otxLabels };
};

const evidenceFor = (result: ThreatIntelligenceResult): EnrichmentEvidence[] => {
    const rows: EnrichmentEvidence[] = [];
    const indicator = result.query;

    for (const pulse of pulseDetails(vendorOf(result, "AlienVault OTX"))) {
        const detail = [
            pulse.adversary && `Grupo: ${pulse.adversary}`,
            pulse.malwareFamilies?.length && `Famílias: ${pulse.malwareFamilies.join(", ")}`,
            pulse.attackIds?.length && `ATT&CK: ${pulse.attackIds.join(", ")}`,
            pulse.tags?.length && `Tags: ${pulse.tags.join(", ")}`,
            pulse.tlp && `TLP: ${pulse.tlp.toUpperCase()}`,
        ].filter(Boolean).join(" · ");
        rows.push({
            indicator,
            source: "AlienVault OTX",
            kind: "Pulse",
            title: pulse.name,
            detail,
            date: clean(pulse.modified) || clean(pulse.created),
            link: pulse.id ? `https://otx.alienvault.com/pulse/${pulse.id}` : "",
        });
    }

    const threatfox = vendorOf(result, "ThreatFox");
    if (threatfox && clean(threatfox["Status"]) === "Malicious") {
        rows.push({
            indicator,
            source: "ThreatFox",
            kind: "IOC catalogado",
            title: asList(threatfox["All Malware"]).join(", ") || clean(threatfox["Malware"]),
            detail: [
                clean(threatfox["Threat Type"]) && `Tipo: ${clean(threatfox["Threat Type"])}`,
                clean(threatfox["Confidence"]) && `Confiança: ${clean(threatfox["Confidence"])}`,
                asList(threatfox["All Tags"]).length && `Tags: ${asList(threatfox["All Tags"]).join(", ")}`,
            ].filter(Boolean).join(" · "),
            date: clean(threatfox["First Seen"]),
            link: clean(threatfox["Reference"])
                || `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(indicator)}`,
        });
    }

    const virustotal = vendorOf(result, "VirusTotal");
    if (virustotal) {
        const classification = clean(virustotal["Threat Classification"]);
        if (classification || clean(virustotal["Top Detections"])) {
            rows.push({
                indicator,
                source: "VirusTotal",
                kind: "Classificação",
                title: classification || clean(virustotal["Detection Rate"]),
                detail: [
                    clean(virustotal["Detection Rate"]) && `Detecções: ${clean(virustotal["Detection Rate"])}`,
                    clean(virustotal["Top Detections"]) && `Engines: ${clean(virustotal["Top Detections"])}`,
                ].filter(Boolean).join(" · "),
                date: clean(virustotal["Last Analysis"]),
                link: `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`,
            });
        }
        for (const context of ((virustotal["Crowdsourced Context"] as any[]) || [])) {
            rows.push({
                indicator,
                source: "VirusTotal",
                kind: "Contexto colaborativo",
                title: clean(context?.title),
                detail: [clean(context?.source), clean(context?.detail)].filter(Boolean).join(" · "),
                date: "",
                link: clean(context?.link),
            });
        }
    }

    const abuse = vendorOf(result, "AbuseIPDB");
    for (const report of ((abuse?.["Reports"] as any[]) || [])) {
        rows.push({
            indicator,
            source: "AbuseIPDB",
            kind: "Denúncia",
            title: (report?.categoryNames || []).join(", ") || "Sem categoria",
            detail: [
                clean(report?.comment),
                clean(report?.reporterCountry) && `Denunciante em ${clean(report.reporterCountry)}`,
            ].filter(Boolean).join(" · "),
            date: clean(report?.date),
            link: `https://www.abuseipdb.com/check/${encodeURIComponent(indicator)}`,
        });
    }

    return rows;
};

const enrichOne = (
    result: ThreatIntelligenceResult,
    index: SoftwareIndex,
    mentions: NewsMention[],
    names: ActorNameIndex,
): EnrichedIndicator => {
    const signals = collectSignals(result);
    const { actors, confidence, basis, otxLabels } = attribute(signals, index, mentions, names);
    // Base que respondeu erro (401 da abuse.ch, cota estourada, timeout) não é
    // base que respondeu "nada". Sem essa coluna, "Sem atribuição" numa planilha
    // de cliente lê como veredito quando na verdade a fonte não foi consultada.
    const unanswered = (result.vendorData || []).filter((v) => v.error).map((v) => v.name);
    const virustotal = vendorOf(result, "VirusTotal");
    const abuse = vendorOf(result, "AbuseIPDB");
    const otx = vendorOf(result, "AlienVault OTX");
    const threatfox = vendorOf(result, "ThreatFox");
    const pulses = pulseDetails(otx);

    return {
        indicator: result.query,
        type: TYPE_LABEL[detectAnalyzerQueryType(result.query)] || TYPE_LABEL.unknown,
        verdict: VERDICT_LABEL[result.threatLevel] || VERDICT_LABEL.unknown,
        actors: actors.join(", "),
        campaign: signals.campaigns.join(" · "),
        families: signals.families.join(", "),
        attackIds: signals.attackIds.join(", "),
        confidence,
        basis: unanswered.length ? `${basis} · sem resposta: ${unanswered.join(", ")}` : basis,
        vtDetections: clean(virustotal?.["Detection Rate"]),
        abuseScore: clean(abuse?.["Abuse Confidence Score"]),
        otxPulses: pulses.length,
        tags: signals.tags.join(", "),
        country: clean(virustotal?.["Country"]) || clean(abuse?.["Country"]) || clean(otx?.["Country"]),
        asn: clean(virustotal?.["ASN"]) || clean(abuse?.["ASN"]) || clean(otx?.["ASN"]),
        firstSeen: clean(threatfox?.["First Seen"])
            || clean(pulses.map((p) => p.created).filter(Boolean).sort()[0]),
        lastSeen: clean(threatfox?.["Last Seen"]) || clean(abuse?.["Last Report"]),
        sources: (result.vendorData || [])
            .filter((v) => !v.error && v.data && Object.keys(v.data).length)
            .map((v) => v.name)
            .join(", "),
        unanswered: unanswered.join(", "),
        // Só o que a matéria diz, nunca a atribuição: o Unit 42 defanga até
        // serviço legítimo quando descreve o abuso dele, então `slack.com`
        // aparece citado num artigo sobre APT29. A menção é a evidência; quem
        // conclui é o analista.
        otxLabels: otxLabels.join(", "),
        mentions: mentions
            .map((m) => `${m.source}: ${m.title}${m.actors.length ? ` (${m.actors.join(", ")})` : ""}`)
            .join(" · "),
    };
};

const tally = (values: string[]): NamedCount[] => {
    const counts = new Map<string, number>();
    for (const value of values.filter(Boolean)) counts.set(value, (counts.get(value) || 0) + 1);
    return [...counts.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
};

export const buildEnrichment = (
    results: ThreatIntelligenceResult[],
    index: SoftwareIndex,
    now: Date = new Date(),
    mentionsByIoc: Record<string, NewsMention[]> = {},
    names: ActorNameIndex = {},
): EnrichmentReport => {
    const mentionsOf = (query: string) => mentionsByIoc[query] || [];
    const indicators = results.map((result) => enrichOne(result, index, mentionsOf(result.query), names));
    return {
        generatedAt: now.toISOString(),
        indicators,
        evidence: results.flatMap((result) => [
            ...evidenceFor(result),
            ...mentionsOf(result.query).map((m) => ({
                indicator: result.query,
                source: m.source,
                kind: "Menção em notícia",
                title: m.title,
                detail: [
                    m.actors.length && `Ator citado na matéria: ${m.actors.join(", ")}`,
                    m.categories.length && m.categories.join(", "),
                ].filter(Boolean).join(" · "),
                date: clean(m.pubDate),
                link: m.link,
            })),
        ]),
        byActor: tally(indicators.flatMap((i) => i.actors.split(", ").filter(Boolean))),
        byFamily: tally(indicators.flatMap((i) => i.families.split(", ").filter(Boolean))),
        byVerdict: tally(indicators.map((i) => i.verdict)),
        byCountry: tally(indicators.map((i) => i.country)),
    };
};
