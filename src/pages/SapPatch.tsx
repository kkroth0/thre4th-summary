import { MetricCard, type MetricTone } from "@/components/MetricCard";

const metricTone = (tone?: string): MetricTone =>
  !tone ? "neutral"
    : /red|destructive/.test(tone) ? "critical"
    : /amber|yellow|orange/.test(tone) ? "warning"
    : /emerald|green/.test(tone) ? "positive"
    : "neutral";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Download, ExternalLink, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { PageLayout } from "@/components/PageLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
    Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
    DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
import { fetchSapPatch, type SapNote, type SapPatchSummary } from "@/services/sapApi";

const PRIORITY_RANK: Record<string, number> = { "Hot News": 4, Critical: 4, High: 3, Medium: 2, Low: 1 };

const priorityClass = (p: string) => {
    const r = PRIORITY_RANK[p] || 0;
    if (r >= 4) return "bg-red-500/15 text-red-500 border-red-500/25";
    if (r === 3) return "bg-orange-500/15 text-orange-500 border-orange-500/25";
    if (r === 2) return "bg-yellow-500/15 text-yellow-600 border-yellow-500/25";
    return "bg-slate-500/15 text-slate-400 border-slate-500/25";
};

const cvssClass = (score: number | null) => {
    if (score == null) return "text-muted-foreground";
    if (score >= 9) return "text-red-500 font-bold";
    if (score >= 7) return "text-orange-500 font-semibold";
    if (score >= 4) return "text-yellow-600";
    return "text-muted-foreground";
};

type ExportKind = "pdf" | "pptx" | "excel";
const PAGE_SIZE = 25;

export const canExportSapPatch = (data: SapPatchSummary | null): boolean =>
    Boolean(data?.notes.length);

export default function SapPatch() {
    const { language } = useLanguage();
    const pt = language === "pt";
    const { toast } = useToast();

    const [data, setData] = useState<SapPatchSummary | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [exporting, setExporting] = useState<ExportKind | null>(null);

    const [fPriority, setFPriority] = useState("ALL");
    const [fCvss, setFCvss] = useState("0");
    const [search, setSearch] = useState("");
    const [page, setPage] = useState(1);

    const load = () => {
        setLoading(true);
        setError(null);
        fetchSapPatch()
            .then(setData)
            .catch((e) => setError(e.message || "Erro ao carregar"))
            .finally(() => setLoading(false));
    };
    useEffect(load, []);

    const filtered = useMemo(() => {
        if (!data) return [] as SapNote[];
        const q = search.trim().toLowerCase();
        const minCvss = Number(fCvss);
        return data.notes.filter((n) => {
            if (fPriority !== "ALL" && n.priority !== fPriority) return false;
            if (minCvss > 0 && (n.cvss ?? 0) < minCvss) return false;
            if (q && !`${n.note} ${n.title} ${n.cves.join(" ")}`.toLowerCase().includes(q)) return false;
            return true;
        });
    }, [data, fPriority, fCvss, search]);

    useEffect(() => setPage(1), [fPriority, fCvss, search]);

    const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    const pageRows = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

    const runExport = async (kind: ExportKind) => {
        if (!data || !canExportSapPatch(data)) {
            toast({
                title: "Não há notas SAP para exportar neste ciclo.",
                variant: "destructive",
            });
            return;
        }
        setExporting(kind);
        try {
            const exports = await import("@/utils/sapPatchExport");
            const fn = { pdf: exports.exportSapPatchPDF, pptx: exports.exportSapPatchPPTX, excel: exports.exportSapPatchExcel }[kind];
            await fn(data);
        } catch (e) {
            toast({ title: pt ? "Falha no export" : "Export failed", description: (e as Error).message, variant: "destructive" });
        } finally {
            setExporting(null);
        }
    };

    const priorities = useMemo(
        () => Object.keys(data?.summary.byPriority || {}).sort((a, b) => (PRIORITY_RANK[b] || 0) - (PRIORITY_RANK[a] || 0)),
        [data],
    );

    const kpis = data ? [
        { label: pt ? "Notas" : "Notes", value: data.summary.total },
        { label: pt ? "Críticas (Hot News)" : "Hot News", value: data.summary.hotNews, accent: "text-red-500" },
        { label: pt ? "Altas" : "High", value: data.summary.high, accent: "text-orange-500" },
        { label: pt ? "CVSS máx." : "Max CVSS", value: data.summary.maxCvss.toFixed(1), accent: cvssClass(data.summary.maxCvss) },
        { label: "CVEs", value: data.summary.cveCount },
    ] : [];

    return (
        <PageLayout width="max-w-6xl">
            {/* Header */}
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-end gap-4 bg-muted/40 p-6 rounded-xl border border-border/50">
                <div>
                    <h1 className="page-title">{pt ? "Correções SAP" : "SAP Fixes"}</h1>
                    <div className="page-lede flex flex-wrap items-center gap-2">
                        <span>{pt
                            ? "Notas de segurança do patch day mensal da SAP, com severidade e produto afetado."
                            : "Security notes from SAP's monthly patch day, with severity and affected product."}</span>
                        {data?.releaseDate && (
                            <Badge variant="outline">
                                {new Date(data.releaseDate).toLocaleDateString(pt ? "pt-BR" : "en-US", { day: "2-digit", month: "long", year: "numeric", timeZone: "UTC" })}
                            </Badge>
                        )}
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={load} disabled={loading} className="rounded-xl">
                        <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
                        {pt ? "Atualizar" : "Refresh"}
                    </Button>
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button size="sm" disabled={!canExportSapPatch(data) || !!exporting} className="rounded-xl">
                                <Download className="h-4 w-4" />
                                {exporting ? "Exportando…" : "Exportar"}
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => runExport("pdf")}>PDF</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => runExport("pptx")}>PowerPoint</DropdownMenuItem>
                            <DropdownMenuItem onClick={() => runExport("excel")}>Excel</DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
            </div>

            {error && (
                <div className="mt-4 flex items-center gap-3 p-4 rounded-xl border border-red-500/20 bg-red-500/5 text-sm text-red-500">
                    <AlertTriangle className="h-4 w-4 shrink-0" /> {error}
                </div>
            )}

            {/* KPIs */}
            {data && (
                <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                    {kpis.map((k) => (
                        <MetricCard key={k.label} label={k.label} value={k.value} tone={metricTone(k.accent)} />
                    ))}
                </div>
            )}

            {/* Filters */}
            {data && (
                <div className="mt-4 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 bg-muted/40 border border-border/50 p-4 rounded-xl">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input value={search} onChange={(e) => setSearch(e.target.value)}
                            placeholder={pt ? "Buscar nota, título ou CVE…" : "Search note, title or CVE…"}
                            className="pl-9 h-9 text-sm rounded-xl bg-background border-border/50" />
                    </div>
                    <Select value={fPriority} onValueChange={setFPriority}>
                        <SelectTrigger className="w-full sm:w-[170px] h-9 rounded-xl bg-background border-border/50"><SelectValue /></SelectTrigger>
                        <SelectContent>
                            <SelectItem value="ALL">{pt ? "Toda prioridade" : "Any priority"}</SelectItem>
                            {priorities.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                        </SelectContent>
                    </Select>
                    <Select value={fCvss} onValueChange={setFCvss}>
                        <SelectTrigger className="w-full sm:w-[150px] h-9 rounded-xl bg-background border-border/50"><SelectValue /></SelectTrigger>
                        <SelectContent>
                            <SelectItem value="0">{pt ? "Qualquer CVSS" : "Any CVSS"}</SelectItem>
                            <SelectItem value="9">CVSS ≥ 9.0</SelectItem>
                            <SelectItem value="7">CVSS ≥ 7.0</SelectItem>
                            <SelectItem value="4">CVSS ≥ 4.0</SelectItem>
                        </SelectContent>
                    </Select>
                </div>
            )}

            {/* Table */}
            {data && (
                <div className="mt-4 rounded-xl border border-border/50 bg-muted/40 overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="bg-muted/60 text-xs uppercase tracking-wide text-muted-foreground">
                                <tr>
                                    <th className="text-left font-medium px-4 py-2.5">Note#</th>
                                    <th className="text-left font-medium px-4 py-2.5">{pt ? "Título" : "Title"}</th>
                                    <th className="text-left font-medium px-4 py-2.5">CVE</th>
                                    <th className="text-left font-medium px-4 py-2.5">{pt ? "Prioridade" : "Priority"}</th>
                                    <th className="text-right font-medium px-4 py-2.5">CVSS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {pageRows.map((n) => (
                                    <tr key={n.note} className="border-t border-border/40 hover:bg-muted/40">
                                        <td className="px-4 py-2.5 align-top whitespace-nowrap">
                                            <a href={n.noteUrl} target="_blank" rel="noopener noreferrer" className="font-mono text-primary hover:underline inline-flex items-center gap-1">
                                                {n.note} <ExternalLink className="h-3 w-3" />
                                            </a>
                                        </td>
                                        <td className="px-4 py-2.5 align-top max-w-[520px]">
                                            {n.title}
                                                {n.isUpdate && <Badge variant="outline" className="ml-2 text-[10px] border-border/60">{pt ? "atualizada" : "updated"}</Badge>}
                                        </td>
                                        <td className="px-4 py-2.5 align-top">
                                            <div className="flex flex-wrap gap-1">
                                                    {n.cves.map((c) => <span key={c} className="font-mono text-xs text-muted-foreground">{c}</span>)}
                                            </div>
                                        </td>
                                        <td className="px-4 py-2.5 align-top">
                                            <Badge variant="outline" className={cn("rounded-md text-[10px] font-bold", priorityClass(n.priority))}>{n.priority}</Badge>
                                        </td>
                                        <td className={cn("px-4 py-2.5 align-top text-right tabular-nums", cvssClass(n.cvss))}>
                                            {n.cvss ?? "—"}
                                        </td>
                                    </tr>
                                ))}
                                {!pageRows.length && (
                                    <tr><td colSpan={5} className="px-4 py-10 text-center text-sm text-muted-foreground">
                                        {loading ? (pt ? "Carregando…" : "Loading…") : (pt ? "Nenhuma nota." : "No notes.")}
                                    </td></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                    {pageCount > 1 && (
                        <div className="flex items-center justify-between px-4 py-3 border-t border-border/40 text-xs text-muted-foreground">
                            <span>{filtered.length} {pt ? "notas" : "notes"}</span>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm" className="h-8 rounded-lg" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>‹</Button>
                                <span>{page}/{pageCount}</span>
                                <Button variant="outline" size="sm" className="h-8 rounded-lg" disabled={page >= pageCount} onClick={() => setPage((p) => p + 1)}>›</Button>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </PageLayout>
    );
}
