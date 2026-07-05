import { useEffect, useMemo, useState } from "react";
import {
    FileText,
    Presentation,
    Sheet,
    ShieldAlert,
    Bug,
    Megaphone,
    TrendingUp,
    Loader2,
    Download,
    AlertCircle,
    CalendarDays,
    Search,
    ListFilter,
    ChevronLeft,
    ChevronRight,
    X,
    ExternalLink,
} from "lucide-react";
import { PageLayout } from "@/components/PageLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
import {
    fetchPatchTuesdayMonths,
    fetchPatchTuesdaySummary,
    type PatchTuesdayMonth,
    type PatchTuesdaySummary,
} from "@/services/msrcApi";
import {
    exportPatchTuesdayPDF,
    exportPatchTuesdayPPTX,
    exportPatchTuesdayExcel,
} from "@/utils/patchTuesdayExport";

const SEV_STYLES: Record<string, string> = {
    Critical: "bg-red-500/10 text-red-500 border-red-500/20",
    Important: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    Moderate: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
    Low: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
    Unknown: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

type ExportKind = "pdf" | "pptx" | "xlsx";

const PatchTuesday = () => {
    const { language } = useLanguage();
    const { toast } = useToast();
    const isPt = language === "pt";

    const [months, setMonths] = useState<PatchTuesdayMonth[]>([]);
    const [selectedId, setSelectedId] = useState<string>("");
    const [summary, setSummary] = useState<PatchTuesdaySummary | null>(null);
    const [loadingMonths, setLoadingMonths] = useState(true);
    const [loadingSummary, setLoadingSummary] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [exporting, setExporting] = useState<ExportKind | null>(null);

    // CVE explorer filters
    const [fSeverity, setFSeverity] = useState("ALL");
    const [fImpact, setFImpact] = useState("ALL");
    const [fStatus, setFStatus] = useState("ALL"); // ALL | priority | exploited | disclosed | moreLikely
    const [fCvss, setFCvss] = useState("0"); // minimum base score threshold
    const [search, setSearch] = useState("");
    const [page, setPage] = useState(1);
    const PAGE_SIZE = 25;

    // Load available Patch Tuesday months once
    useEffect(() => {
        (async () => {
            try {
                const list = await fetchPatchTuesdayMonths();
                setMonths(list);
                if (list.length) setSelectedId(list[0].id);
            } catch (e) {
                setError(e instanceof Error ? e.message : "Failed to load months");
            } finally {
                setLoadingMonths(false);
            }
        })();
    }, []);

    // Load summary whenever the selected month changes
    useEffect(() => {
        if (!selectedId) return;
        let cancelled = false;
        (async () => {
            setLoadingSummary(true);
            setError(null);
            try {
                const data = await fetchPatchTuesdaySummary(selectedId);
                if (!cancelled) setSummary(data);
            } catch (e) {
                if (!cancelled) {
                    setSummary(null);
                    setError(e instanceof Error ? e.message : "Failed to load summary");
                }
            } finally {
                if (!cancelled) setLoadingSummary(false);
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [selectedId]);

    const maxFamily = useMemo(
        () => (summary ? Math.max(1, ...summary.byFamily.map((f) => f.count)) : 1),
        [summary]
    );
    const maxImpact = useMemo(
        () => (summary ? Math.max(1, ...summary.byImpact.map((i) => i.count)) : 1),
        [summary]
    );

    // Reset to first page whenever filters or the loaded month change
    useEffect(() => {
        setPage(1);
    }, [fSeverity, fImpact, fStatus, fCvss, search, selectedId]);

    // Apply all active filters to the full vulnerability catalog
    const filtered = useMemo(() => {
        if (!summary) return [];
        const q = search.trim().toLowerCase();
        const minCvss = parseFloat(fCvss);
        return summary.vulnerabilities.filter((v) => {
            if (fSeverity !== "ALL" && v.severity !== fSeverity) return false;
            if (fImpact !== "ALL" && v.impact !== fImpact) return false;
            if (minCvss > 0 && (v.cvss ?? 0) < minCvss) return false;
            const moreLikely = /more likely/i.test(v.exploitability);
            if (fStatus === "exploited" && !v.exploited) return false;
            if (fStatus === "disclosed" && !v.publiclyDisclosed) return false;
            if (fStatus === "moreLikely" && !moreLikely) return false;
            if (fStatus === "priority" && !(v.exploited || v.publiclyDisclosed || moreLikely)) return false;
            if (q && !(v.cve.toLowerCase().includes(q) || v.title.toLowerCase().includes(q))) return false;
            return true;
        });
    }, [summary, fSeverity, fImpact, fStatus, fCvss, search]);

    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    const pageClamped = Math.min(page, totalPages);
    const pageRows = filtered.slice((pageClamped - 1) * PAGE_SIZE, pageClamped * PAGE_SIZE);
    const filtersActive = fSeverity !== "ALL" || fImpact !== "ALL" || fStatus !== "ALL" || fCvss !== "0" || search.trim() !== "";

    const clearFilters = () => {
        setFSeverity("ALL");
        setFImpact("ALL");
        setFStatus("ALL");
        setFCvss("0");
        setSearch("");
    };

    const runExport = async (kind: ExportKind) => {
        if (!summary) return;
        setExporting(kind);
        try {
            if (kind === "pdf") await exportPatchTuesdayPDF(summary);
            else if (kind === "pptx") await exportPatchTuesdayPPTX(summary);
            else await exportPatchTuesdayExcel(summary);
            toast({
                title: isPt ? "Documento gerado" : "Document generated",
                description: isPt
                    ? `O arquivo ${kind.toUpperCase()} foi baixado.`
                    : `Your ${kind.toUpperCase()} file has been downloaded.`,
            });
        } catch (e) {
            toast({
                variant: "destructive",
                title: isPt ? "Falha ao gerar" : "Generation failed",
                description: e instanceof Error ? e.message : "Unexpected error",
            });
        } finally {
            setExporting(null);
        }
    };

    const t = summary?.totals;

    const kpis = t
        ? [
              { label: isPt ? "Total de CVEs" : "Total CVEs", value: t.total, icon: Bug, color: "text-primary" },
              { label: "Critical", value: t.critical, icon: ShieldAlert, color: "text-red-500" },
              { label: "Important", value: t.important, icon: AlertCircle, color: "text-orange-500" },
              { label: isPt ? "Explorados" : "Exploited", value: t.exploited, icon: TrendingUp, color: "text-red-600" },
              { label: isPt ? "Divulgados" : "Disclosed", value: t.disclosed, icon: Megaphone, color: "text-violet-500" },
          ]
        : [];

    const exportButtons: { kind: ExportKind; label: string; icon: typeof FileText; cls: string }[] = [
        { kind: "pdf", label: "PDF", icon: FileText, cls: "bg-red-500/10 text-red-500 hover:bg-red-500/20 border-red-500/20" },
        { kind: "pptx", label: "PowerPoint", icon: Presentation, cls: "bg-orange-500/10 text-orange-500 hover:bg-orange-500/20 border-orange-500/20" },
        { kind: "xlsx", label: "Excel", icon: Sheet, cls: "bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 border-emerald-500/20" },
    ];

    return (
        <PageLayout bare>
            <div className="flex-1 p-4 md:p-8">
                <div className="max-w-6xl mx-auto space-y-6">
                    {/* Title + month selector */}
                    <div className="flex flex-col lg:flex-row justify-between items-start lg:items-end gap-4 bg-card/20 p-6 rounded-3xl border border-primary/10 backdrop-blur-md">
                        <div className="space-y-1.5">
                            <div className="flex items-center gap-2">
                                <h1 className="text-2xl font-bold flex items-center gap-2.5">
                                    <span className="grid place-items-center h-9 w-9 rounded-xl bg-primary/10 text-primary">
                                        <CalendarDays className="h-5 w-5" />
                                    </span>
                                    {isPt ? "Resumo do Patch Tuesday" : "Patch Tuesday Summary"}
                                </h1>
                                <Badge variant="secondary" className="bg-primary/10 text-primary border-primary/20">
                                    MSRC
                                </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground max-w-xl">
                                {isPt
                                    ? "Gere relatórios consolidados e profissionais (PDF, PPTX e Excel) das atualizações de segurança da Microsoft, direto da API oficial do MSRC."
                                    : "Generate consolidated, professional reports (PDF, PPTX & Excel) of Microsoft's security updates, straight from the official MSRC API."}
                            </p>
                        </div>

                        <div className="flex items-center gap-2 w-full lg:w-auto">
                            <Select value={selectedId} onValueChange={setSelectedId} disabled={loadingMonths || !months.length}>
                                <SelectTrigger className="w-full lg:w-[260px] h-10 rounded-xl bg-background border-primary/15">
                                    <SelectValue placeholder={loadingMonths ? (isPt ? "Carregando meses..." : "Loading months...") : isPt ? "Selecione o mês" : "Select month"} />
                                </SelectTrigger>
                                <SelectContent className="max-h-[320px]">
                                    {months.map((m) => (
                                        <SelectItem key={m.id} value={m.id}>
                                            {m.title}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                    </div>

                    {/* Export bar */}
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-card/45 border border-primary/10 p-4 rounded-2xl">
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Download className="h-4 w-4 text-primary" />
                            <span className="font-semibold text-foreground">
                                {isPt ? "Exportar relatório consolidado" : "Export consolidated report"}
                            </span>
                            {summary && (
                                <span className="hidden md:inline text-muted-foreground/70">
                                    · {summary.title}
                                </span>
                            )}
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {exportButtons.map(({ kind, label, icon: Icon, cls }) => (
                                <Button
                                    key={kind}
                                    variant="outline"
                                    onClick={() => runExport(kind)}
                                    disabled={!summary || loadingSummary || exporting !== null}
                                    className={cn("h-9 rounded-xl text-xs font-semibold border gap-2", cls)}
                                >
                                    {exporting === kind ? (
                                        <Loader2 className="h-4 w-4 animate-spin" />
                                    ) : (
                                        <Icon className="h-4 w-4" />
                                    )}
                                    {label}
                                </Button>
                            ))}
                        </div>
                    </div>

                    {/* Error state */}
                    {error && !loadingSummary && (
                        <div className="flex items-center gap-3 p-4 rounded-2xl border border-red-500/20 bg-red-500/5 text-sm text-red-500">
                            <AlertCircle className="h-5 w-5 shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Loading state */}
                    {loadingSummary && (
                        <div className="flex flex-col items-center justify-center py-24 gap-3 text-muted-foreground">
                            <Loader2 className="h-8 w-8 animate-spin text-primary" />
                            <span className="text-xs font-semibold tracking-wide">
                                {isPt ? "Carregando dados do MSRC..." : "Fetching data from MSRC..."}
                            </span>
                        </div>
                    )}

                    {/* Content */}
                    {summary && !loadingSummary && (
                        <>
                            {/* Release meta */}
                            <div className="text-xs text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 px-1">
                                <span>
                                    {isPt ? "Lançado em" : "Released"}:{" "}
                                    <span className="text-foreground font-medium">
                                        {summary.initialReleaseDate
                                            ? new Date(summary.initialReleaseDate).toLocaleDateString(isPt ? "pt-BR" : "en-US", {
                                                  year: "numeric",
                                                  month: "long",
                                                  day: "numeric",
                                              })
                                            : "N/A"}
                                    </span>
                                </span>
                                <span>
                                    {isPt ? "Fonte" : "Source"}:{" "}
                                    <span className="text-foreground font-medium">MSRC CVRF v3.0</span>
                                </span>
                            </div>

                            {/* KPI cards */}
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                {kpis.map((k) => {
                                    const Icon = k.icon;
                                    return (
                                        <div
                                            key={k.label}
                                            className="p-4 rounded-2xl border border-primary/10 bg-card/30 flex flex-col gap-1.5"
                                        >
                                            <div className="flex items-center justify-between">
                                                <span className="text-[10px] font-bold text-muted-foreground/60 uppercase tracking-wider">
                                                    {k.label}
                                                </span>
                                                <Icon className={cn("h-4 w-4", k.color)} />
                                            </div>
                                            <span className={cn("text-3xl font-bold tabular-nums", k.color)}>{k.value}</span>
                                        </div>
                                    );
                                })}
                            </div>

                            {/* Distribution panels */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                <DistroPanel
                                    title={isPt ? "Por Impacto" : "By Impact"}
                                    rows={summary.byImpact}
                                    max={maxImpact}
                                    barClass="bg-primary"
                                />
                                <DistroPanel
                                    title={isPt ? "Famílias de Produtos Afetadas" : "Affected Product Families"}
                                    rows={summary.byFamily}
                                    max={maxFamily}
                                    barClass="bg-indigo-500"
                                />
                            </div>

                            {/* CVE Explorer */}
                            <div className="rounded-2xl border border-primary/10 bg-card/30 overflow-hidden">
                                <div className="px-5 py-3.5 border-b border-primary/10 flex flex-wrap items-center gap-2">
                                    <ShieldAlert className="h-4 w-4 text-primary" />
                                    <h2 className="text-sm font-bold">{isPt ? "Explorador de CVEs" : "CVE Explorer"}</h2>
                                    <span className="text-[11px] text-muted-foreground">
                                        {isPt
                                            ? `${filtered.length} de ${summary.vulnerabilities.length} CVEs`
                                            : `${filtered.length} of ${summary.vulnerabilities.length} CVEs`}
                                    </span>
                                </div>

                                {/* Filter bar */}
                                <div className="px-4 py-3 border-b border-primary/10 bg-card/20 flex flex-wrap items-center gap-2">
                                    <div className="relative flex-1 min-w-[180px]">
                                        <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground/60" />
                                        <Input
                                            type="text"
                                            placeholder={isPt ? "Buscar CVE ou título..." : "Search CVE or title..."}
                                            value={search}
                                            onChange={(e) => setSearch(e.target.value)}
                                            className="pl-9 h-9 text-xs rounded-xl bg-background border-primary/15"
                                        />
                                    </div>

                                    <Select value={fSeverity} onValueChange={setFSeverity}>
                                        <SelectTrigger className="w-[140px] h-9 text-xs rounded-xl bg-background border-primary/15">
                                            <SelectValue placeholder={isPt ? "Severidade" : "Severity"} />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="ALL">{isPt ? "Toda severidade" : "All severities"}</SelectItem>
                                            <SelectItem value="Critical">Critical</SelectItem>
                                            <SelectItem value="Important">Important</SelectItem>
                                            <SelectItem value="Moderate">Moderate</SelectItem>
                                            <SelectItem value="Low">Low</SelectItem>
                                            <SelectItem value="Unknown">{isPt ? "Sem classificação" : "Unrated / Edge"}</SelectItem>
                                        </SelectContent>
                                    </Select>

                                    <Select value={fCvss} onValueChange={setFCvss}>
                                        <SelectTrigger className="w-[130px] h-9 text-xs rounded-xl bg-background border-primary/15">
                                            <SelectValue placeholder="CVSS" />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="0">{isPt ? "Qualquer CVSS" : "Any CVSS"}</SelectItem>
                                            <SelectItem value="9">CVSS ≥ 9.0</SelectItem>
                                            <SelectItem value="7">CVSS ≥ 7.0</SelectItem>
                                            <SelectItem value="4">CVSS ≥ 4.0</SelectItem>
                                        </SelectContent>
                                    </Select>

                                    <Select value={fImpact} onValueChange={setFImpact}>
                                        <SelectTrigger className="w-[170px] h-9 text-xs rounded-xl bg-background border-primary/15">
                                            <SelectValue placeholder={isPt ? "Impacto" : "Impact"} />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="ALL">{isPt ? "Todo impacto" : "All impacts"}</SelectItem>
                                            {summary.byImpact.map((i) => (
                                                <SelectItem key={i.name} value={i.name}>
                                                    {i.name} ({i.count})
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>

                                    <Select value={fStatus} onValueChange={setFStatus}>
                                        <SelectTrigger className="w-[160px] h-9 text-xs rounded-xl bg-background border-primary/15">
                                            <SelectValue placeholder="Status" />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="ALL">{isPt ? "Todo status" : "All statuses"}</SelectItem>
                                            <SelectItem value="priority">{isPt ? "Prioritários" : "Priority"}</SelectItem>
                                            <SelectItem value="exploited">{isPt ? "Explorados" : "Exploited"}</SelectItem>
                                            <SelectItem value="disclosed">{isPt ? "Divulgados" : "Publicly Disclosed"}</SelectItem>
                                            <SelectItem value="moreLikely">{isPt ? "Exploração provável" : "Exploitation More Likely"}</SelectItem>
                                        </SelectContent>
                                    </Select>

                                    {filtersActive && (
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={clearFilters}
                                            className="h-9 rounded-xl text-xs gap-1.5 text-muted-foreground hover:text-foreground"
                                        >
                                            <X className="h-3.5 w-3.5" />
                                            {isPt ? "Limpar" : "Clear"}
                                        </Button>
                                    )}
                                </div>

                                {/* Table */}
                                <div className="overflow-x-auto">
                                    <table className="w-full text-xs">
                                        <thead>
                                            <tr className="text-left text-muted-foreground/70 border-b border-primary/5">
                                                <th className="px-4 py-2.5 font-semibold">CVE</th>
                                                <th className="px-4 py-2.5 font-semibold">{isPt ? "Severidade" : "Severity"}</th>
                                                <th className="px-4 py-2.5 font-semibold">CVSS</th>
                                                <th className="px-4 py-2.5 font-semibold hidden md:table-cell">{isPt ? "Impacto" : "Impact"}</th>
                                                <th className="px-4 py-2.5 font-semibold hidden xl:table-cell">{isPt ? "Família" : "Family"}</th>
                                                <th className="px-4 py-2.5 font-semibold hidden lg:table-cell">Status</th>
                                                <th className="px-4 py-2.5 font-semibold">{isPt ? "Título" : "Title"}</th>
                                                <th className="px-4 py-2.5 font-semibold">Links</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {pageRows.map((v) => (
                                                <tr key={v.cve} className="border-b border-primary/5 last:border-0 hover:bg-muted/20">
                                                    <td className="px-4 py-2.5 font-mono font-semibold whitespace-nowrap">
                                                        <a
                                                            href={`https://msrc.microsoft.com/update-guide/vulnerability/${v.cve}`}
                                                            target="_blank"
                                                            rel="noreferrer"
                                                            className="text-primary hover:underline"
                                                        >
                                                            {v.cve}
                                                        </a>
                                                    </td>
                                                    <td className="px-4 py-2.5">
                                                        <Badge variant="outline" className={cn("text-[10px] font-semibold", SEV_STYLES[v.severity] || SEV_STYLES.Unknown)}>
                                                            {v.severity}
                                                        </Badge>
                                                    </td>
                                                    <td className="px-4 py-2.5 font-semibold tabular-nums">{v.cvss ?? "—"}</td>
                                                    <td className="px-4 py-2.5 hidden md:table-cell text-muted-foreground">{v.impact}</td>
                                                    <td className="px-4 py-2.5 hidden xl:table-cell text-muted-foreground">{v.family}</td>
                                                    <td className="px-4 py-2.5 hidden lg:table-cell">
                                                        <div className="flex gap-1">
                                                            {v.exploited && (
                                                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-500/15 text-red-500">EXPLOITED</span>
                                                            )}
                                                            {v.publiclyDisclosed && (
                                                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-500">DISCLOSED</span>
                                                            )}
                                                            {!v.exploited && !v.publiclyDisclosed && /more likely/i.test(v.exploitability) && (
                                                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-500">LIKELY</span>
                                                            )}
                                                            {!v.exploited && !v.publiclyDisclosed && !/more likely/i.test(v.exploitability) && (
                                                                <span className="text-muted-foreground/50">—</span>
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-2.5 text-muted-foreground max-w-[340px] truncate" title={v.title}>
                                                        {v.title}
                                                    </td>
                                                    <td className="px-4 py-2.5">
                                                        <div className="flex items-center gap-1.5">
                                                            <a
                                                                href={`https://msrc.microsoft.com/update-guide/vulnerability/${v.cve}`}
                                                                target="_blank"
                                                                rel="noreferrer"
                                                                title={isPt ? "Microsoft Security Update Guide" : "Microsoft Security Update Guide"}
                                                                className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border border-primary/20 text-primary hover:bg-primary/10 transition-colors whitespace-nowrap"
                                                            >
                                                                MSRC <ExternalLink className="h-2.5 w-2.5" />
                                                            </a>
                                                            <a
                                                                href={`https://nvd.nist.gov/vuln/detail/${v.cve}`}
                                                                target="_blank"
                                                                rel="noreferrer"
                                                                title={isPt ? "Registro oficial da CVE (NVD/NIST)" : "Official CVE record (NVD/NIST)"}
                                                                className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors whitespace-nowrap"
                                                            >
                                                                NVD <ExternalLink className="h-2.5 w-2.5" />
                                                            </a>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))}
                                            {pageRows.length === 0 && (
                                                <tr>
                                                    <td colSpan={8} className="px-4 py-10 text-center text-muted-foreground">
                                                        <ListFilter className="h-5 w-5 mx-auto mb-2 opacity-50" />
                                                        {isPt ? "Nenhum CVE corresponde aos filtros." : "No CVEs match the current filters."}
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>

                                {/* Pagination */}
                                <div className="px-5 py-2.5 border-t border-primary/10 flex items-center justify-between gap-3 text-[11px] text-muted-foreground">
                                    <span>
                                        {filtered.length > 0
                                            ? isPt
                                                ? `Mostrando ${(pageClamped - 1) * PAGE_SIZE + 1}–${Math.min(pageClamped * PAGE_SIZE, filtered.length)} de ${filtered.length}`
                                                : `Showing ${(pageClamped - 1) * PAGE_SIZE + 1}–${Math.min(pageClamped * PAGE_SIZE, filtered.length)} of ${filtered.length}`
                                            : isPt
                                                ? "Nenhum resultado"
                                                : "No results"}
                                    </span>
                                    <div className="flex items-center gap-2">
                                        <Button
                                            variant="outline"
                                            size="icon"
                                            disabled={pageClamped <= 1}
                                            onClick={() => setPage((p) => Math.max(1, p - 1))}
                                            className="h-7 w-7 rounded-lg border-primary/15"
                                        >
                                            <ChevronLeft className="h-4 w-4" />
                                        </Button>
                                        <span className="font-semibold text-foreground tabular-nums">
                                            {pageClamped} / {totalPages}
                                        </span>
                                        <Button
                                            variant="outline"
                                            size="icon"
                                            disabled={pageClamped >= totalPages}
                                            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                                            className="h-7 w-7 rounded-lg border-primary/15"
                                        >
                                            <ChevronRight className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                            </div>
                        </>
                    )}

                    {/* Empty (months failed) */}
                    {!loadingMonths && !months.length && !loadingSummary && (
                        <div className="flex flex-col items-center justify-center py-24 gap-3 text-muted-foreground">
                            <AlertCircle className="h-8 w-8" />
                            <span className="text-xs font-semibold">
                                {isPt ? "Nenhum mês disponível no momento." : "No months available right now."}
                            </span>
                        </div>
                    )}
                </div>
            </div>
        </PageLayout>
    );
};

interface DistroPanelProps {
    title: string;
    rows: { name: string; count: number }[];
    max: number;
    barClass: string;
}

const DistroPanel = ({ title, rows, max, barClass }: DistroPanelProps) => (
    <div className="rounded-2xl border border-primary/10 bg-card/30 p-5">
        <h2 className="text-sm font-bold mb-4">{title}</h2>
        <div className="space-y-2.5">
            {rows.map((r) => (
                <div key={r.name} className="space-y-1">
                    <div className="flex justify-between items-center text-xs">
                        <span className="text-muted-foreground truncate pr-2">{r.name}</span>
                        <span className="font-semibold tabular-nums">{r.count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-muted/40 overflow-hidden">
                        <div
                            className={cn("h-full rounded-full transition-all", barClass)}
                            style={{ width: `${Math.max(2, (r.count / max) * 100)}%` }}
                        />
                    </div>
                </div>
            ))}
        </div>
    </div>
);

export default PatchTuesday;
