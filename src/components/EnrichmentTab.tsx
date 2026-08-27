import { useEffect, useMemo, useState } from "react";
import { Download, Loader2, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useLanguage } from "@/contexts/LanguageContext";
import type { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { ENRICHMENT_VENDORS, fetchNewsMentions, fetchSoftwareIndex, fetchThreatData, type ActorIndexes, type NewsMention } from "@/services/threatApi";
import { extractIocsFromText, isSupportedAnalyzerQuery } from "@/utils/iocExtract";
import { buildEnrichment } from "@/utils/enrichment";
import { exportEnrichmentExcel } from "@/utils/enrichmentExport";
import { toast } from "sonner";

// Aba de Enriquecimento: parte dos indicadores já analisados na tela (custo zero
// de API) e aceita uma lista colada, que consulta só as quatro bases que
// nomeiam família, campanha ou grupo. A saída é a planilha.

const CONFIDENCE_TONE: Record<string, string> = {
    Alta: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    Média: "border-amber-500/40 bg-amber-500/10 text-amber-400",
    Baixa: "border-sky-500/40 bg-sky-500/10 text-sky-400",
    "Sem atribuição": "border-border bg-muted/30 text-muted-foreground",
};

export const EnrichmentTab = ({ results }: { results: ThreatIntelligenceResult[] }) => {
    const { language } = useLanguage();
    const pt = language === "pt";
    const [index, setIndex] = useState<ActorIndexes | null>(null);
    const [pasted, setPasted] = useState("");
    const [extra, setExtra] = useState<ThreatIntelligenceResult[]>([]);
    const [running, setRunning] = useState(false);
    const [mentions, setMentions] = useState<Record<string, NewsMention[]>>({});

    useEffect(() => {
        // Catálogo indisponível não derruba a aba: a atribuição por adversary do
        // OTX continua, só a que vem da família desliga — e o aviso diz isso.
        fetchSoftwareIndex().then(setIndex).catch(() => setIndex({ software: {}, names: {} }));
    }, []);

    const all = useMemo(() => {
        const seen = new Set<string>();
        return [...extra, ...results].filter((r) => !seen.has(r.query) && seen.add(r.query));
    }, [extra, results]);

    // Menção é acréscimo: se o acervo não responder (usuário sem premium, feed
    // frio), o enriquecimento sai igual, só sem a coluna.
    useEffect(() => {
        const faltando = all.map((r) => r.query).filter((q) => !(q in mentions));
        if (!faltando.length) return;
        let vivo = true;
        Promise.all(faltando.map(async (q) => [q, await fetchNewsMentions(q).catch(() => [])] as const))
            .then((pares) => { if (vivo) setMentions((atual) => ({ ...atual, ...Object.fromEntries(pares) })); });
        return () => { vivo = false; };
    }, [all, mentions]);

    const report = useMemo(
        () => buildEnrichment(all, index?.software || {}, new Date(), mentions, index?.names || {}),
        [all, index, mentions],
    );

    const runPasted = async () => {
        const targets = extractIocsFromText(pasted).filter(isSupportedAnalyzerQuery);
        if (!targets.length) {
            toast.error(pt ? "Nenhum indicador reconhecido no texto." : "No indicator found in the text.");
            return;
        }
        setRunning(true);
        try {
            const fetched = await Promise.all(targets.map((t) => fetchThreatData(t, ENRICHMENT_VENDORS)));
            setExtra((current) => [...fetched, ...current.filter((r) => !targets.includes(r.query))]);
            toast.success(pt ? `${targets.length} indicadores enriquecidos.` : `${targets.length} indicators enriched.`);
        } catch (error) {
            toast.error(pt ? "Falha ao consultar as bases." : "Failed to query the sources.");
        } finally {
            setRunning(false);
        }
    };

    const attributed = report.indicators.filter((i) => i.actors).length;
    const mencionados = report.indicators.filter((i) => i.mentions).length;

    return (
        <div className="space-y-6">
            <div className="soc-panel rounded-lg p-5">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                        <h3 className="flex items-center gap-2 text-sm font-black uppercase tracking-wide">
                            <Sparkles className="h-4 w-4 text-primary" />
                            {pt ? "Enriquecimento de Indicadores" : "Indicator Enrichment"}
                        </h3>
                        <p className="mt-1 text-xs text-muted-foreground">
                            {pt
                                ? `${report.indicators.length} indicadores · ${attributed} com grupo atribuído · ${mencionados} citados em notícia · ${report.evidence.length} evidências`
                                : `${report.indicators.length} indicators · ${attributed} attributed · ${mencionados} in the news · ${report.evidence.length} pieces of evidence`}
                        </p>
                    </div>
                    <Button
                        size="sm"
                        className="gap-2 rounded-full"
                        disabled={!report.indicators.length}
                        onClick={() => exportEnrichmentExcel(report)}
                    >
                        <Download className="h-4 w-4" />
                        {pt ? "Exportar Excel" : "Export Excel"}
                    </Button>
                </div>

                {index && !Object.keys(index.software).length && (
                    <p className="mt-3 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
                        {pt
                            ? "Catálogo de atores indisponível — a atribuição por família de malware está desligada nesta sessão."
                            : "Actor catalog unavailable — malware-family attribution is off for this session."}
                    </p>
                )}

                <div className="mt-4 space-y-2">
                    <Textarea
                        value={pasted}
                        onChange={(e) => setPasted(e.target.value)}
                        placeholder={pt
                            ? "Cole IPs, domínios, URLs ou hashes para enriquecer (consulta VirusTotal, OTX, ThreatFox e AbuseIPDB)"
                            : "Paste IPs, domains, URLs or hashes to enrich (queries VirusTotal, OTX, ThreatFox and AbuseIPDB)"}
                        className="min-h-[88px] font-mono text-xs"
                    />
                    <Button size="sm" variant="outline" className="gap-2 rounded-full" onClick={runPasted} disabled={running}>
                        {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                        {running ? (pt ? "Consultando..." : "Querying...") : (pt ? "Enriquecer lista" : "Enrich list")}
                    </Button>
                </div>
            </div>

            <div className="soc-panel overflow-x-auto rounded-lg">
                <table className="w-full text-left text-xs">
                    <thead className="bg-muted/40 text-[11px] uppercase tracking-wide text-muted-foreground">
                        <tr>
                            <th className="px-3 py-2 font-black">{pt ? "Indicador" : "Indicator"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Veredito" : "Verdict"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Grupo / Ator" : "Group / Actor"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Campanha" : "Campaign"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Família" : "Family"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Confiança" : "Confidence"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Base da atribuição" : "Basis"}</th>
                            <th className="px-3 py-2 font-black">{pt ? "Mencionado em" : "Mentioned in"}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {report.indicators.map((row) => (
                            <tr key={row.indicator} className="border-t border-border/60 align-top">
                                <td className="px-3 py-2 font-mono">{row.indicator}</td>
                                <td className="px-3 py-2">{row.verdict}</td>
                                <td className="px-3 py-2 font-semibold">{row.actors || "—"}</td>
                                <td className="px-3 py-2 text-muted-foreground">{row.campaign || "—"}</td>
                                <td className="px-3 py-2 text-muted-foreground">{row.families || "—"}</td>
                                <td className="px-3 py-2">
                                    <span className={`rounded-full border px-2 py-0.5 text-[11px] ${CONFIDENCE_TONE[row.confidence]}`}>
                                        {row.confidence}
                                    </span>
                                </td>
                                <td className="px-3 py-2 text-muted-foreground">{row.basis}</td>
                                <td className="px-3 py-2 text-muted-foreground">{row.mentions || "—"}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};
