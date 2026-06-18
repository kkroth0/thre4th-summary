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
// One ordered stage of the KQL-driven Microsoft Sentinel hunting process.
interface HuntStep {
  step: string;
  data_source: string;
  kql: string;
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
  hunting_process?: HuntStep[];
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
      "Turn a live advisory — or any report URL you paste — into a validated Threat Hunting Pack: threat actor, MITRE ATT&CK TTPs, defanged IOCs, a hunting hypothesis, a step-by-step Microsoft Sentinel KQL hunting process, and ready-to-run KQL + Sigma. Export it as a branded PPTX. Powered by the scrape → Groq → Pydantic hunt microservice.",
    pickTitle: "1. Pick an advisory",
    pickHint: "Hunting runs over the live advisory feed, or any report URL you paste.",
    searchPlaceholder: "Search advisories…",
    orPasteTitle: "…or paste any report URL",
    orPasteHint: "Analyze any public threat report — not just the feed.",
    urlPlaceholder: "https://example.com/threat-report",
    urlInvalid: "Enter a valid http(s) URL.",
    hunt: "Hunt",
    pastedSource: "Pasted URL",
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
    process: "Hunting process (Sentinel KQL)",
    dataSource: "Data source",
    stepLabel: "Step",
    execBrief: "Executive brief",
    socSummary: "SOC summary",
    copy: "Copy",
    copyAll: "Copy pack",
    exportJson: "JSON",
    exportPptx: "PPTX",
    building: "Building report…",
    reportTitle: "Threat Hunting Report",
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
      "Transforme um advisory ao vivo — ou qualquer URL de relatório que você colar — em um Pacote de Threat Hunting validado: ator de ameaça, TTPs do MITRE ATT&CK, IOCs defanged, hipótese de caça, um processo de caça passo a passo em KQL do Microsoft Sentinel e KQL + Sigma prontos para uso. Exporte como um PPTX com marca. Movido pelo microserviço scrape → Groq → Pydantic.",
    pickTitle: "1. Escolha um advisory",
    pickHint: "A caça roda sobre o feed de advisories ao vivo, ou qualquer URL de relatório que você colar.",
    searchPlaceholder: "Buscar advisories…",
    orPasteTitle: "…ou cole qualquer URL de relatório",
    orPasteHint: "Analise qualquer relatório de ameaça público — não só o feed.",
    urlPlaceholder: "https://exemplo.com/relatorio-de-ameaca",
    urlInvalid: "Informe uma URL http(s) válida.",
    hunt: "Caçar",
    pastedSource: "URL colada",
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
    process: "Processo de caça (KQL Sentinel)",
    dataSource: "Fonte de dados",
    stepLabel: "Etapa",
    execBrief: "Brief executivo",
    socSummary: "Resumo SOC",
    copy: "Copiar",
    copyAll: "Copiar pacote",
    exportJson: "JSON",
    exportPptx: "PPTX",
    building: "Gerando relatório…",
    reportTitle: "Relatório de Threat Hunting",
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
  if (pack.hunting_process?.length) {
    out.push("", `[ ${t.process} ]`);
    pack.hunting_process.forEach((s, i) => {
      out.push(`${t.stepLabel} ${i + 1}: ${s.step}  (${t.dataSource}: ${s.data_source})`, s.kql, "");
    });
  }
  if (pack.detection_query?.kql) out.push("", `[ ${t.kql} ]`, pack.detection_query.kql);
  if (pack.detection_query?.sigma) out.push("", `[ ${t.sigma} ]`, pack.detection_query.sigma);
  if (pack.executive_brief) out.push("", `[ ${t.execBrief} ]`, pack.executive_brief);
  if (pack.soc_summary) out.push("", `[ ${t.socSummary} ]`, pack.soc_summary);
  out.push("", t.disclaimer);
  return out.join("\n");
};

// Branded PPTX colours (hex without '#', as pptxgenjs expects). BRAND matches
// the site's --primary (hsl 220 90% 56%).
const PPTX = {
  BRAND: "2A6DF4",
  INK: "0F172A",
  MUTED: "64748B",
  LIGHT: "F1F5F9",
  AMBER: "B45309",
  CODE_BG: "0F172A",
  CODE_FG: "E2E8F0",
  WHITE: "FFFFFF",
};

// Build and download a branded Threat Hunting deck from a Hunt Pack. pptxgenjs is
// heavy, so it's imported dynamically on first export (keeps it out of the main
// bundle). Layout is 16:9 widescreen (13.33 × 7.5in).
const exportPptx = async (
  pack: HuntPackData,
  title: string,
  sourceLink: string,
  t: typeof T["en"],
) => {
  const PptxGenJS = (await import("pptxgenjs")).default;
  const pptx = new PptxGenJS();
  pptx.layout = "LAYOUT_WIDE";
  pptx.author = "ThreatSumm4ry";
  pptx.title = `${t.reportTitle} — ${title}`;

  const W = 13.33;
  const H = 7.5;
  const M = 0.6;
  const CW = W - 2 * M;
  const dateStr = new Date().toISOString().slice(0, 10);

  // Standard content slide with top accent band, kicker, title and footer.
  const baseSlide = (kicker: string, heading: string) => {
    const s = pptx.addSlide();
    s.background = { color: PPTX.WHITE };
    s.addShape(pptx.ShapeType.rect, { x: 0, y: 0, w: W, h: 0.16, fill: { color: PPTX.BRAND } });
    s.addText(kicker.toUpperCase(), {
      x: M, y: 0.42, w: CW, h: 0.3, fontSize: 11, bold: true, color: PPTX.BRAND, charSpacing: 2, fontFace: "Arial",
    });
    s.addText(heading, {
      x: M, y: 0.72, w: CW, h: 0.7, fontSize: 24, bold: true, color: PPTX.INK, fontFace: "Arial",
    });
    s.addText(t.disclaimer, {
      x: M, y: H - 0.42, w: CW - 2.5, h: 0.3, fontSize: 8, italic: true, color: PPTX.MUTED, fontFace: "Arial",
    });
    s.addText(`threat-summ4ry · ${dateStr}`, {
      x: W - M - 2.5, y: H - 0.42, w: 2.5, h: 0.3, fontSize: 8, color: PPTX.MUTED, align: "right", fontFace: "Arial",
    });
    return s;
  };

  // Dark monospace code box (KQL / Sigma / YAML).
  const codeBox = (s: ReturnType<typeof baseSlide>, code: string, x: number, y: number, w: number, h: number) => {
    s.addShape(pptx.ShapeType.roundRect, {
      x, y, w, h, rectRadius: 0.06, fill: { color: PPTX.CODE_BG }, line: { color: "1E293B", width: 1 },
    });
    s.addText(code, {
      x: x + 0.18, y: y + 0.12, w: w - 0.36, h: h - 0.24,
      fontSize: 9, color: PPTX.CODE_FG, fontFace: "Consolas", valign: "top", align: "left",
    });
  };

  // ---- 1. Cover -------------------------------------------------------------
  const cover = pptx.addSlide();
  cover.background = { color: PPTX.INK };
  cover.addShape(pptx.ShapeType.rect, { x: 0, y: 0, w: W, h: 0.22, fill: { color: PPTX.BRAND } });
  cover.addText(t.reportTitle.toUpperCase(), {
    x: M, y: 1.6, w: CW, h: 0.5, fontSize: 14, bold: true, color: PPTX.BRAND, charSpacing: 3, fontFace: "Arial",
  });
  cover.addText(title, {
    x: M, y: 2.1, w: CW, h: 1.8, fontSize: 32, bold: true, color: PPTX.WHITE, fontFace: "Arial", valign: "top",
  });
  cover.addText(
    [
      { text: `${t.threatActor}: `, options: { color: PPTX.MUTED } },
      { text: pack.threat_actor || "Unknown", options: { color: PPTX.WHITE, bold: true } },
    ],
    { x: M, y: 4.3, w: CW, h: 0.4, fontSize: 16, fontFace: "Arial" },
  );
  if (pack.ttp_mitre?.length) {
    cover.addText(`${t.mitre}: ${pack.ttp_mitre.join("  ·  ")}`, {
      x: M, y: 4.8, w: CW, h: 0.4, fontSize: 12, color: "94A3B8", fontFace: "Consolas",
    });
  }
  cover.addText(sourceLink, {
    x: M, y: H - 0.7, w: CW, h: 0.3, fontSize: 9, color: PPTX.BRAND, fontFace: "Arial", hyperlink: { url: sourceLink },
  });

  // ---- 2. Executive brief ---------------------------------------------------
  if (pack.executive_brief) {
    const s = baseSlide(t.packTitle, t.execBrief);
    s.addText(pack.executive_brief, {
      x: M, y: 1.7, w: CW, h: 3.0, fontSize: 18, color: PPTX.INK, fontFace: "Arial", valign: "top", lineSpacingMultiple: 1.2,
    });
  }

  // ---- 3. Threat actor & MITRE ATT&CK --------------------------------------
  {
    const s = baseSlide(t.packTitle, `${t.threatActor} · ${t.mitre}`);
    s.addText(pack.threat_actor || "Unknown", {
      x: M, y: 1.7, w: CW, h: 0.5, fontSize: 20, bold: true, color: PPTX.BRAND, fontFace: "Arial",
    });
    if (pack.ttp_mitre?.length) {
      s.addText(
        pack.ttp_mitre.map((tech) => ({
          text: tech,
          options: { bullet: { code: "2022" }, color: PPTX.INK, fontFace: "Consolas", fontSize: 14, breakLine: true },
        })),
        { x: M, y: 2.4, w: CW, h: 4.0, valign: "top" },
      );
    }
  }

  // ---- 4. IOCs --------------------------------------------------------------
  if (pack.ioc_list?.length) {
    const s = baseSlide(t.packTitle, t.iocs);
    s.addTable(
      [
        [
          { text: "Type", options: { bold: true, color: PPTX.WHITE, fill: { color: PPTX.BRAND }, fontFace: "Arial" } },
          { text: "Indicator (defanged)", options: { bold: true, color: PPTX.WHITE, fill: { color: PPTX.BRAND }, fontFace: "Arial" } },
        ],
        ...pack.ioc_list.map((i, idx) => [
          { text: i.type, options: { color: PPTX.AMBER, bold: true, fontFace: "Arial", fill: { color: idx % 2 ? PPTX.LIGHT : PPTX.WHITE } } },
          { text: i.value, options: { color: PPTX.INK, fontFace: "Consolas", fill: { color: idx % 2 ? PPTX.LIGHT : PPTX.WHITE } } },
        ]),
      ],
      { x: M, y: 1.7, w: CW, colW: [2.0, CW - 2.0], fontSize: 11, border: { type: "solid", color: "E2E8F0", pt: 1 }, valign: "middle", rowH: 0.32 },
    );
  }

  // ---- 5. Hunting hypothesis & SOC summary ---------------------------------
  {
    const s = baseSlide(t.packTitle, t.hypothesis);
    s.addText(pack.hunting_hypothesis || "—", {
      x: M, y: 1.7, w: CW, h: 2.2, fontSize: 16, color: PPTX.INK, fontFace: "Arial", valign: "top", lineSpacingMultiple: 1.2,
    });
    if (pack.soc_summary) {
      s.addText(t.socSummary.toUpperCase(), {
        x: M, y: 4.1, w: CW, h: 0.3, fontSize: 11, bold: true, color: PPTX.BRAND, charSpacing: 1, fontFace: "Arial",
      });
      s.addText(pack.soc_summary, {
        x: M, y: 4.45, w: CW, h: 2.0, fontSize: 14, color: PPTX.MUTED, fontFace: "Arial", valign: "top", lineSpacingMultiple: 1.15,
      });
    }
  }

  // ---- 6. Hunting process — one slide per KQL stage -------------------------
  (pack.hunting_process || []).forEach((step, i) => {
    const s = baseSlide(`${t.process} · ${t.stepLabel} ${i + 1}/${pack.hunting_process!.length}`, step.step);
    s.addText(
      [
        { text: `${t.dataSource}: `, options: { color: PPTX.MUTED, bold: true } },
        { text: step.data_source || "—", options: { color: PPTX.INK, fontFace: "Consolas" } },
      ],
      { x: M, y: 1.65, w: CW, h: 0.4, fontSize: 13, fontFace: "Arial" },
    );
    codeBox(s, step.kql, M, 2.2, CW, 4.4);
  });

  // ---- 7. Detection summary: KQL + Sigma ------------------------------------
  if (pack.detection_query?.kql) {
    const s = baseSlide(t.packTitle, t.kql);
    codeBox(s, pack.detection_query.kql, M, 1.7, CW, pack.detection_query.sigma ? 2.3 : 4.9);
    if (pack.detection_query.sigma) {
      s.addText(t.sigma.toUpperCase(), {
        x: M, y: 4.15, w: CW, h: 0.3, fontSize: 11, bold: true, color: PPTX.BRAND, charSpacing: 1, fontFace: "Arial",
      });
      codeBox(s, pack.detection_query.sigma, M, 4.5, CW, 2.1);
    }
  }

  const safeName = title.replace(/[^a-z0-9]+/gi, "-").slice(0, 48).replace(/^-|-$/g, "") || "report";
  await pptx.writeFile({ fileName: `hunt-report-${safeName}-${dateStr}.pptx` });
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
  const [urlInput, setUrlInput] = useState("");
  const [pptxBuilding, setPptxBuilding] = useState(false);

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

  // Hunt over an arbitrary pasted URL: synthesise a minimal Advisory so the rest
  // of the panel (title, source link, generate, regenerate) works unchanged. The
  // server validates the URL (SSRF guard) before scraping.
  const huntUrl = () => {
    const raw = urlInput.trim();
    let parsed: URL;
    try {
      parsed = new URL(raw);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("proto");
    } catch {
      toast.error(t.urlInvalid);
      return;
    }
    const item: Advisory = { title: parsed.hostname + parsed.pathname, link: raw, pubDate: "", source: t.pastedSource };
    select(item);
  };

  const copy = (text: string, msg: string) => {
    navigator.clipboard.writeText(text);
    toast.success(msg);
  };

  const exportReport = async (data: HuntPackData, item: Advisory) => {
    setPptxBuilding(true);
    try {
      await exportPptx(data, titleOf(item), item.link, t);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "PPTX export failed");
    } finally {
      setPptxBuilding(false);
    }
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

            {/* Paste any report URL */}
            <div className="pt-3 mt-1 border-t border-border/40 space-y-2">
              <div>
                <h2 className="text-sm font-bold text-foreground tracking-wide">{t.orPasteTitle}</h2>
                <p className="text-[11px] text-muted-foreground/70 mt-0.5">{t.orPasteHint}</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <ExternalLink className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && huntUrl()}
                    placeholder={t.urlPlaceholder}
                    className="w-full h-9 pl-9 pr-3 rounded-xl bg-muted/30 border border-border/50 text-[13px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-primary/40"
                  />
                </div>
                <Button onClick={huntUrl} disabled={!urlInput.trim()} className="h-9 px-4 gap-1.5 shrink-0">
                  <Crosshair className="h-3.5 w-3.5" />
                  {t.hunt}
                </Button>
              </div>
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
                          onClick={() => void exportReport(pack.data!, selected)}
                          disabled={pptxBuilding}
                          className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-primary/40 bg-primary/10 text-primary hover:bg-primary/20 disabled:opacity-50"
                          title={t.exportPptx}
                        >
                          {pptxBuilding ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
                          {pptxBuilding ? t.building : t.exportPptx}
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

                    {pack.data.hunting_process?.length ? (
                      <div>
                        <SectionLabel>{t.process}</SectionLabel>
                        <ol className="space-y-2.5">
                          {pack.data.hunting_process.map((s, i) => (
                            <li key={i} className="rounded-lg border border-border/40 bg-muted/20 p-2.5">
                              <div className="flex items-start gap-2 mb-1.5">
                                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[10px] font-bold text-primary">
                                  {i + 1}
                                </span>
                                <div className="min-w-0">
                                  <div className="text-[13px] font-semibold text-foreground leading-snug">{s.step}</div>
                                  {s.data_source ? (
                                    <div className="text-[10px] text-muted-foreground/80 mt-0.5">
                                      {t.dataSource}: <span className="font-mono text-primary/80">{s.data_source}</span>
                                    </div>
                                  ) : null}
                                </div>
                                <CopyButton onClick={() => copy(s.kql, t.copiedKql)} label={t.copy} />
                              </div>
                              <pre className="text-[11px] font-mono bg-muted/40 border border-border/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{s.kql}</pre>
                            </li>
                          ))}
                        </ol>
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
