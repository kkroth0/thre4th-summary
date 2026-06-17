import React, { useState, useEffect, useMemo } from "react";
import {
  Crosshair, Search, Loader2, Copy, ExternalLink, Download, RefreshCw,
  AlertTriangle, ChevronRight, Target, ShieldAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { toast } from "sonner";

// Mirrors the advisory shape returned by GET /api/newsletter (only the fields
// this page needs to list and pick a report to hunt over).
interface Advisory {
  title: string;
  titlePt?: string;
  link: string;
  pubDate: string;
  source: string;
  severity?: string;
  cves?: string[];
}

// Guided Threat Hunting pack produced by the Python hunt-service (Groq +
// Pydantic), proxied through /api/newsletter/hunt-pack. IOCs arrive defanged.
interface HuntIoc {
  type: "ip" | "domain" | "url" | "hash";
  value: string;
}
interface HuntDetectionQuery {
  kql: string;
  sigma?: string;
}
interface HuntPackData {
  available: boolean;
  scraped_chars?: number;
  lang?: string;
  threat_actor: string;
  ttp_mitre: string[];
  ioc_list: HuntIoc[];
  hunting_hypothesis: string;
  detection_query: HuntDetectionQuery;
  executive_brief: string;
  soc_summary: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-500 border-red-500/20",
  High: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  Medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  Low: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

const T = {
  en: {
    title: "Threat Hunting",
    subtitle:
      "Turn a live security advisory into a validated Threat Hunting Pack — threat actor, MITRE ATT&CK TTPs, defanged IOCs, a hunting hypothesis, and ready-to-run Sentinel KQL + Sigma. Powered by the scrape → Groq → Pydantic hunt microservice.",
    pickTitle: "1. Pick an advisory",
    pickHint: "Hunting runs only over reports in the live advisory feed.",
    searchPlaceholder: "Search advisories…",
    loadingFeed: "Loading advisory feed…",
    feedError: "Could not load the advisory feed.",
    noResults: "No advisories match your search.",
    generate: "Generate Hunt Pack",
    regenerate: "Regenerate",
    generating:
      "Scraping the article and building the Hunt Pack (the service may be cold-starting, ~1 min)…",
    packTitle: "Threat Hunting Pack",
    pickPrompt: "Select an advisory on the left to generate its Hunt Pack.",
    threatActor: "Threat actor",
    mitre: "MITRE ATT&CK",
    iocs: "Indicators (IOCs)",
    hypothesis: "Hunting hypothesis",
    kql: "KQL query (Sentinel)",
    sigma: "Sigma rule",
    execBrief: "Executive brief",
    socSummary: "SOC summary",
    copy: "Copy",
    copyAll: "Copy pack",
    exportJson: "JSON",
    retry: "Retry",
    disclaimer:
      "AI-generated from the article — defanged indicators; validate before acting.",
    copiedIocs: "IOCs copied (defanged)",
    copiedKql: "KQL copied",
    copiedSigma: "Sigma copied",
    copiedPack: "Hunt Pack copied",
    source: "Source",
  },
  pt: {
    title: "Threat Hunting",
    subtitle:
      "Transforme um advisory de segurança ao vivo em um Pacote de Threat Hunting validado — ator de ameaça, TTPs do MITRE ATT&CK, IOCs defanged, hipótese de caça e KQL do Sentinel + Sigma prontos para uso. Movido pelo microserviço scrape → Groq → Pydantic.",
    pickTitle: "1. Escolha um advisory",
    pickHint: "A caça roda apenas sobre relatórios do feed de advisories ao vivo.",
    searchPlaceholder: "Buscar advisories…",
    loadingFeed: "Carregando o feed de advisories…",
    feedError: "Não foi possível carregar o feed de advisories.",
    noResults: "Nenhum advisory corresponde à sua busca.",
    generate: "Gerar Hunt Pack",
    regenerate: "Gerar novamente",
    generating:
      "Coletando o artigo e montando o Hunt Pack (o serviço pode estar aquecendo, ~1 min)…",
    packTitle: "Pacote de Threat Hunting",
    pickPrompt: "Selecione um advisory à esquerda para gerar o Hunt Pack.",
    threatActor: "Ator de ameaça",
    mitre: "MITRE ATT&CK",
    iocs: "Indicadores (IOCs)",
    hypothesis: "Hipótese de caça",
    kql: "Consulta KQL (Sentinel)",
    sigma: "Regra Sigma",
    execBrief: "Brief executivo",
    socSummary: "Resumo SOC",
    copy: "Copiar",
    copyAll: "Copiar pacote",
    exportJson: "JSON",
    retry: "Tentar de novo",
    disclaimer:
      "Gerado por IA a partir do artigo — indicadores defanged; valide antes de agir.",
    copiedIocs: "IOCs copiados (defanged)",
    copiedKql: "KQL copiada",
    copiedSigma: "Sigma copiada",
    copiedPack: "Hunt Pack copiado",
    source: "Fonte",
  },
};

// Flatten a Hunt Pack into a shareable plain-text block.
const buildPackText = (pack: HuntPackData, title: string, t: typeof T["en"]): string => {
  const out: string[] = [];
  out.push(`# ${t.packTitle} — ${title}`);
  out.push("");
  out.push(`${t.threatActor}: ${pack.threat_actor}`);
  if (pack.ttp_mitre?.length) out.push(`${t.mitre}: ${pack.ttp_mitre.join(", ")}`);
  if (pack.ioc_list?.length) {
    out.push("", `[ ${t.iocs} ]`);
    pack.ioc_list.forEach((i) => out.push(`${i.type}\t${i.value}`));
  }
  if (pack.hunting_hypothesis) out.push("", `[ ${t.hypothesis} ]`, pack.hunting_hypothesis);
  if (pack.detection_query?.kql) out.push("", `[ ${t.kql} ]`, pack.detection_query.kql);
  if (pack.detection_query?.sigma) out.push("", `[ ${t.sigma} ]`, pack.detection_query.sigma);
  if (pack.executive_brief) out.push("", `[ ${t.execBrief} ]`, pack.executive_brief);
  if (pack.soc_summary) out.push("", `[ ${t.socSummary} ]`, pack.soc_summary);
  out.push("", t.disclaimer);
  return out.join("\n");
};

const SectionLabel = ({ children }: { children: React.ReactNode }) => (
  <div className="text-[11px] font-bold text-muted-foreground/80 tracking-wide mb-1.5">
    [ {children} ]
  </div>
);

const CopyButton = ({ onClick, label }: { onClick: () => void; label: string }) => (
  <button
    onClick={onClick}
    className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
  >
    <Copy className="h-3 w-3" />
    {label}
  </button>
);

export default function ThreatHunting() {
  const { isCollapsed } = useSidebar();
  const { language } = useLanguage();
  const t = T[(language as "en" | "pt")] || T.en;

  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [loadingFeed, setLoadingFeed] = useState(true);
  const [feedError, setFeedError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Advisory | null>(null);
  const [pack, setPack] = useState<{ loading: boolean; error?: string; data?: HuntPackData } | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/newsletter");
        if (!res.ok) throw new Error(String(res.status));
        const body = await res.json();
        const items: Advisory[] = Array.isArray(body) ? body : body?.items ?? [];
        if (!cancelled) setAdvisories(items);
      } catch {
        if (!cancelled) setFeedError(t.feedError);
      } finally {
        if (!cancelled) setLoadingFeed(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return advisories;
    return advisories.filter((a) =>
      `${a.title} ${a.titlePt ?? ""} ${a.source} ${(a.cves ?? []).join(" ")}`
        .toLowerCase()
        .includes(q)
    );
  }, [advisories, query]);

  const titleOf = (a: Advisory) => (language === "pt" ? a.titlePt || a.title : a.title);

  const generate = async (item: Advisory) => {
    setPack({ loading: true });
    try {
      const res = await fetch("/api/newsletter/hunt-pack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: item.link, lang: language }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body?.error || String(res.status));
      setPack({ loading: false, data: body as HuntPackData });
    } catch (e) {
      setPack({ loading: false, error: e instanceof Error ? e.message : "Failed to generate Hunt Pack" });
    }
  };

  const select = (item: Advisory) => {
    setSelected(item);
    setPack(null);
    void generate(item);
  };

  const copy = (text: string, msg: string) => {
    navigator.clipboard.writeText(text);
    toast.success(msg);
  };

  const downloadJson = (data: HuntPackData, item: Advisory) => {
    const blob = new Blob([JSON.stringify({ advisory: { title: item.title, link: item.link }, ...data }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hunt-pack-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />

      <div className="flex-1 max-w-7xl w-full mx-auto px-4 md:px-8 py-8 md:py-12 space-y-8">
        {/* Hero */}
        <div className="space-y-3">
          <div className="flex items-center gap-2.5">
            <div className="h-10 w-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
              <Crosshair className="h-5 w-5" />
            </div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-foreground">{t.title}</h1>
          </div>
          <p className="text-sm text-muted-foreground leading-relaxed max-w-3xl">{t.subtitle}</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: advisory picker */}
          <div className="lg:col-span-5 space-y-3">
            <div>
              <h2 className="text-sm font-bold text-foreground tracking-wide">{t.pickTitle}</h2>
              <p className="text-[11px] text-muted-foreground/70 mt-0.5">{t.pickHint}</p>
            </div>

            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t.searchPlaceholder}
                className="w-full h-9 pl-9 pr-3 rounded-xl bg-muted/30 border border-border/50 text-[13px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-primary/40"
              />
            </div>

            <div className="space-y-1.5 max-h-[60vh] overflow-y-auto pr-1">
              {loadingFeed ? (
                <div className="flex items-center gap-2 text-xs text-muted-foreground py-3">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  {t.loadingFeed}
                </div>
              ) : feedError ? (
                <div className="flex items-center gap-2 text-xs text-red-500 py-3">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  {feedError}
                </div>
              ) : filtered.length === 0 ? (
                <div className="text-xs text-muted-foreground/70 py-3">{t.noResults}</div>
              ) : (
                filtered.map((a) => {
                  const isActive = selected?.link === a.link;
                  return (
                    <button
                      key={a.link}
                      onClick={() => select(a)}
                      className={`w-full text-left rounded-xl border p-3 transition-all ${
                        isActive
                          ? "border-primary/40 bg-primary/[0.06]"
                          : "border-border/40 bg-white/[0.01] hover:bg-muted/20 hover:border-border/70"
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        <ChevronRight className={`h-3.5 w-3.5 mt-0.5 shrink-0 ${isActive ? "text-primary" : "text-muted-foreground/50"}`} />
                        <div className="min-w-0 space-y-1">
                          <div className="text-[13px] font-semibold text-foreground leading-snug line-clamp-2">{titleOf(a)}</div>
                          <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-muted-foreground/70">
                            <span>{a.source}</span>
                            {a.severity && (
                              <span className={`px-1.5 py-0.5 rounded border font-bold ${SEVERITY_STYLES[a.severity] || SEVERITY_STYLES.Low}`}>
                                {a.severity}
                              </span>
                            )}
                            {(a.cves ?? []).slice(0, 2).map((c) => (
                              <span key={c} className="font-mono text-primary/80">{c}</span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Right: hunt pack panel */}
          <div className="lg:col-span-7">
            {!selected ? (
              <div className="h-full min-h-[300px] rounded-2xl border border-dashed border-border/50 flex flex-col items-center justify-center text-center gap-3 p-8">
                <Target className="h-8 w-8 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground/70 max-w-xs">{t.pickPrompt}</p>
              </div>
            ) : (
              <div className="rounded-2xl border border-primary/20 bg-primary/[0.03] p-4 md:p-5 space-y-4">
                {/* Pack header */}
                <div className="flex items-start justify-between gap-3 border-b border-border/40 pb-3">
                  <div className="flex items-center gap-1.5 text-[12px] font-bold text-primary tracking-wide">
                    <Crosshair className="h-4 w-4" />
                    {t.packTitle.toUpperCase()}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <a
                      href={selected.link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {t.source}
                    </a>
                    {pack?.data && (
                      <>
                        <CopyButton onClick={() => copy(buildPackText(pack.data!, titleOf(selected), t), t.copiedPack)} label={t.copyAll} />
                        <button
                          onClick={() => downloadJson(pack.data!, selected)}
                          className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                        >
                          <Download className="h-3 w-3" />
                          {t.exportJson}
                        </button>
                        <button
                          onClick={() => void generate(selected)}
                          className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                          title={t.regenerate}
                        >
                          <RefreshCw className="h-3 w-3" />
                        </button>
                      </>
                    )}
                  </div>
                </div>

                {/* Selected advisory title */}
                <div className="text-[13px] font-semibold text-foreground/90 leading-snug">{titleOf(selected)}</div>

                {pack?.loading ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground py-4">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t.generating}
                  </div>
                ) : pack?.error ? (
                  <div className="flex items-center justify-between gap-2 text-xs py-2">
                    <span className="flex items-center gap-1.5 text-red-500">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      {pack.error}
                    </span>
                    <button
                      onClick={() => void generate(selected)}
                      className="text-[10px] px-1.5 py-0.5 rounded border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/50"
                    >
                      {t.retry}
                    </button>
                  </div>
                ) : pack?.data ? (
                  <div className="space-y-4">
                    <div className="text-[13px]">
                      <span className="font-bold">{t.threatActor}:</span> {pack.data.threat_actor}
                    </div>

                    {pack.data.ttp_mitre?.length ? (
                      <div>
                        <SectionLabel>{t.mitre}</SectionLabel>
                        <div className="flex flex-wrap gap-1.5">
                          {pack.data.ttp_mitre.map((tech) => (
                            <a
                              key={tech}
                              href={`https://attack.mitre.org/techniques/${tech.replace(".", "/")}/`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-[11px] px-1.5 py-0.5 rounded border border-primary/20 text-primary hover:bg-primary/10"
                            >
                              {tech}
                            </a>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {pack.data.ioc_list?.length ? (
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <SectionLabel>{t.iocs}</SectionLabel>
                          <CopyButton
                            onClick={() => copy(pack.data!.ioc_list.map((i) => `${i.type}\t${i.value}`).join("\n"), t.copiedIocs)}
                            label={t.copy}
                          />
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {pack.data.ioc_list.map((i) => (
                            <span
                              key={`${i.type}:${i.value}`}
                              title={i.type}
                              className="font-mono text-[11px] px-1.5 py-0.5 rounded border border-amber-500/25 bg-amber-500/5 text-amber-600 dark:text-amber-400 break-all"
                            >
                              {i.value}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {pack.data.hunting_hypothesis ? (
                      <div>
                        <SectionLabel>{t.hypothesis}</SectionLabel>
                        <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{pack.data.hunting_hypothesis}</p>
                      </div>
                    ) : null}

                    {pack.data.detection_query?.kql ? (
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <SectionLabel>{t.kql}</SectionLabel>
                          <CopyButton onClick={() => copy(pack.data!.detection_query.kql, t.copiedKql)} label={t.copy} />
                        </div>
                        <pre className="text-[11px] font-mono bg-muted/40 border border-border/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{pack.data.detection_query.kql}</pre>
                      </div>
                    ) : null}

                    {pack.data.detection_query?.sigma ? (
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <SectionLabel>{t.sigma}</SectionLabel>
                          <CopyButton onClick={() => copy(pack.data!.detection_query.sigma || "", t.copiedSigma)} label={t.copy} />
                        </div>
                        <pre className="text-[11px] font-mono bg-muted/40 border border-border/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{pack.data.detection_query.sigma}</pre>
                      </div>
                    ) : null}

                    {pack.data.executive_brief ? (
                      <div>
                        <SectionLabel>{t.execBrief}</SectionLabel>
                        <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{pack.data.executive_brief}</p>
                      </div>
                    ) : null}

                    {pack.data.soc_summary ? (
                      <div>
                        <SectionLabel>{t.socSummary}</SectionLabel>
                        <p className="text-sm leading-relaxed text-foreground/90 whitespace-pre-line">{pack.data.soc_summary}</p>
                      </div>
                    ) : null}

                    <p className="text-[10px] text-muted-foreground/60 italic pt-1 border-t border-border/30">{t.disclaimer}</p>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}
