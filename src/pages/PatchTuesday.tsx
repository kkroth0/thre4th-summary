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
} from "lucide-react";
import { Header } from "@/components/Header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
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
    const { isCollapsed } = useSidebar();
    const { toast } = useToast();
    const isPt = language === "pt";

    const [months, setMonths] = useState<PatchTuesdayMonth[]>([]);
    const [selectedId, setSelectedId] = useState<string>("");
    const [summary, setSummary] = useState<PatchTuesdaySummary | null>(null);
    const [loadingMonths, setLoadingMonths] = useState(true);
    const [loadingSummary, setLoadingSummary] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [exporting, setExporting] = useState<ExportKind | null>(null);

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

    const runExport = async (kind: ExportKind) => {
        if (!summary) return;
        setExporting(kind);
        try {
            if (kind === "pdf") exportPatchTuesdayPDF(summary);
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
        <div
            className={cn(
                "min-h-screen bg-background flex flex-col transition-all duration-300",
                isCollapsed ? "lg:pl-20" : "lg:pl-64"
            )}
        >
            <Header showBackButton />
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

                            {/* Priority CVEs */}
                            <div className="rounded-2xl border border-primary/10 bg-card/30 overflow-hidden">
                                <div className="px-5 py-3.5 border-b border-primary/10 flex items-center gap-2">
                                    <ShieldAlert className="h-4 w-4 text-primary" />
                                    <h2 className="text-sm font-bold">{isPt ? "CVEs Prioritários" : "Priority CVEs"}</h2>
                                    <span className="text-[11px] text-muted-foreground">
                                        {isPt ? "explorados, divulgados e maior CVSS" : "exploited, disclosed & highest CVSS"}
                                    </span>
                                </div>
                                <div className="overflow-x-auto">
                                    <table className="w-full text-xs">
                                        <thead>
                                            <tr className="text-left text-muted-foreground/70 border-b border-primary/5">
                                                <th className="px-4 py-2.5 font-semibold">CVE</th>
                                                <th className="px-4 py-2.5 font-semibold">{isPt ? "Severidade" : "Severity"}</th>
                                                <th className="px-4 py-2.5 font-semibold">CVSS</th>
                                                <th className="px-4 py-2.5 font-semibold hidden md:table-cell">{isPt ? "Impacto" : "Impact"}</th>
                                                <th className="px-4 py-2.5 font-semibold hidden lg:table-cell">Status</th>
                                                <th className="px-4 py-2.5 font-semibold">{isPt ? "Título" : "Title"}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {summary.topCves.map((v) => (
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
                                                    <td className="px-4 py-2.5 hidden lg:table-cell">
                                                        <div className="flex gap-1">
                                                            {v.exploited && (
                                                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-500/15 text-red-500">EXPLOITED</span>
                                                            )}
                                                            {v.publiclyDisclosed && (
                                                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-500">DISCLOSED</span>
                                                            )}
                                                            {!v.exploited && !v.publiclyDisclosed && (
                                                                <span className="text-muted-foreground/50">—</span>
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-2.5 text-muted-foreground max-w-[340px] truncate" title={v.title}>
                                                        {v.title}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                                <div className="px-5 py-2.5 border-t border-primary/10 text-[11px] text-muted-foreground">
                                    {isPt
                                        ? `Catálogo completo com ${summary.vulnerabilities.length} CVEs disponível nos arquivos exportados.`
                                        : `Full catalog of ${summary.vulnerabilities.length} CVEs available in the exported files.`}
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
        </div>
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
