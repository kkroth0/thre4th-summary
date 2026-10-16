import { MetricCard, type MetricTone } from "@/components/MetricCard";

const metricTone = (tone?: string): MetricTone =>
  !tone ? "neutral"
    : /red|destructive/.test(tone) ? "critical"
    : /amber|yellow|orange/.test(tone) ? "warning"
    : /emerald|green/.test(tone) ? "positive"
    : "neutral";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Download, ExternalLink, Search } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { PatchDayToolbar, PatchDayTabs } from "@/components/PatchDayToolbar";
import { otCurrentMonth } from "@/services/otPatchApi";
import { PageLayout } from "@/components/PageLayout";
import { EmptyState } from "@/components/EmptyState";
import { LoadingRows } from "@/components/LoadingState";
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

type ExportKind = "pdf" | "pptx" | "excel" | "json";
const PAGE_SIZE = 25;

export const canExportSapPatch = (data: SapPatchSummary | null): boolean =>
    Boolean(data?.notes.length);

export default function SapPatch() {
    const { language } = useLanguage();
    const pt = language === "pt";
    const { toast } = useToast();

    const [params, setParams] = useSearchParams();
    const month = /^20\d{2}-(0[1-9]|1[0-2])$/.test(params.get('month') || '') ? params.get('month')! : otCurrentMonth();
    const [revision, setRevision] = useState(0), [tab, setTab] = useState('advisories');
    const [data, setData] = useState<SapPatchSummary | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [exporting, setExporting] = useState<ExportKind | null>(null);

    const [fPriority, setFPriority] = useState("ALL");
    const [fCvss, setFCvss] = useState("0");
    const [search, setSearch] = useState("");
    const [page, setPage] = useState(1);

    useEffect(() => {
        const controller = new AbortController(); setLoading(true); setError(null); setData(null);
        fetchSapPatch(month, controller.signal).then(next => { if (!controller.signal.aborted) setData(next); })
            .catch(e => { if (!controller.signal.aborted) setError(e.message || 'Erro ao carregar'); })
            .finally(() => { if (!controller.signal.aborted) setLoading(false); });
        return () => controller.abort();
    }, [month, revision]);

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

    useEffect(() => setPage(1), [fPriority, fCvss, search, month]);

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
            if (kind === "json") {
                const { exportSapPatchCtiflowJSON } = await import("@/utils/sapPatchCtiflow");
                exportSapPatchCtiflowJSON(data);
            } else {
                const exports = await import("@/utils/sapPatchExport");
                const fn = { pdf: exports.exportSapPatchPDF, pptx: exports.exportSapPatchPPTX, excel: exports.exportSapPatchExcel }[kind];
                await fn(data);
            }
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
        <PageLayout width="max-w-7xl">
            <div className="page-head"><div><h1 className="page-title">SAP Patch Day</h1><p className="page-lede">{pt ? 'Notas de segurança SAP organizadas por mês, com CVEs, prioridade e referências oficiais.' : 'Monthly SAP security notes with CVEs, priority and official references.'}</p></div></div>
            <PatchDayToolbar month={month} onMonthChange={value => setParams({ month: value })} onRefresh={() => setRevision(v => v + 1)} loading={loading} pt={pt} min="2018-01" actions={<>
                <Button disabled={!canExportSapPatch(data) || !!exporting} onClick={() => void runExport('excel')}><Download className="h-4 w-4" />{exporting === 'excel' ? (pt ? 'Preparando…' : 'Preparing…') : (pt ? 'Relatório Excel' : 'Excel report')}</Button>
                <DropdownMenu><DropdownMenuTrigger asChild><Button variant="outline" disabled={!canExportSapPatch(data) || !!exporting}>{pt ? 'Mais formatos' : 'More formats'}</Button></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuItem onClick={() => void runExport('pdf')}>PDF</DropdownMenuItem><DropdownMenuItem onClick={() => void runExport('pptx')}>PowerPoint</DropdownMenuItem><DropdownMenuItem onClick={() => void runExport('json')}>JSON (CTIFLOW)</DropdownMenuItem></DropdownMenuContent></DropdownMenu>
            </>} />
            {error && (
                <div className="mt-4 flex items-center gap-3 p-4 rounded-lg border border-red-500/20 bg-red-500/5 text-sm text-red-500">
                    <AlertTriangle className="h-4 w-4 shrink-0" /> {error}
                </div>
            )}

            {/* KPIs */}
            {data && (
                <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
                    {kpis.map((k) => (
                        <MetricCard size="sm" key={k.label} label={k.label} value={k.value} tone={metricTone(k.accent)} />
                    ))}
                </div>
            )}

            <PatchDayTabs value={tab} onChange={setTab} label="SAP Patch Day" tabs={[{ id: 'advisories', label: pt ? 'Avisos e correções' : 'Advisories and fixes' }, { id: 'coverage', label: pt ? 'Catálogo e cobertura' : 'Catalog and coverage' }]} />
            {data?.stale && <p role="status" className="mb-4 rounded-lg border border-amber-500/30 p-3 text-sm">{pt ? 'A fonte não respondeu nesta atualização. Exibindo o último resultado salvo para este mês.' : 'The source did not respond. Showing the last saved result for this month.'}</p>}
            {tab === 'coverage' && <section className="grid gap-3 md:grid-cols-2"><div className="rounded-lg border bg-card p-4"><a className="font-semibold text-primary" href={data?.url || 'https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html'} target="_blank" rel="noreferrer">SAP Security Notes</a><p className="mt-2 text-sm text-muted-foreground">{pt ? 'Publicação oficial do mês: notas SAP e avisos GitHub referenciados pela SAP, com CVEs e versões descritas pelo fabricante.' : 'Official monthly publication: SAP notes and linked GitHub advisories, with CVEs and vendor version details.'}</p><p className="mt-2 text-xs text-muted-foreground">{pt ? 'Publicação' : 'Published'}: {data?.releaseDate || '—'}</p></div></section>}
            {/* Filters */}
            {data && tab === 'advisories' && (
                <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-[minmax(240px,1fr)_200px_200px]">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input value={search} onChange={(e) => setSearch(e.target.value)}
                            placeholder={pt ? "Buscar nota, título ou CVE…" : "Search note, title or CVE…"}
                            className="pl-9" />
                    </div>
                    <Select value={fPriority} onValueChange={setFPriority}>
                        <SelectTrigger aria-label={pt ? "Prioridade SAP" : "SAP priority"} className="w-full"><SelectValue /></SelectTrigger>
                        <SelectContent>
                            <SelectItem value="ALL">{pt ? "Toda prioridade" : "Any priority"}</SelectItem>
                            {priorities.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                        </SelectContent>
                    </Select>
                    <Select value={fCvss} onValueChange={setFCvss}>
                        <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
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
            {data && tab === 'advisories' && (
                <div className="overflow-hidden rounded-lg border">
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead className="bg-muted/40 text-xs text-muted-foreground">
                                <tr>
                                    <th className="text-left font-medium p-4">Note#</th>
                                    <th className="text-left font-medium p-4">{pt ? "Título" : "Title"}</th>
                                    <th className="text-left font-medium p-4">CVE</th>
                                    <th className="text-left font-medium p-4">{pt ? "Prioridade" : "Priority"}</th>
                                    <th className="text-right font-medium p-4">CVSS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {pageRows.map((n) => (
                                    <tr key={n.note} className="border-t border-border/40 hover:bg-muted/40">
                                        <td className="p-4 align-top whitespace-nowrap">
                                            <a href={n.noteUrl} target="_blank" rel="noopener noreferrer" className="font-mono text-primary hover:underline inline-flex items-center gap-1">
                                                {n.note} <ExternalLink className="h-3 w-3" />
                                            </a>
                                        </td>
                                        <td className="p-4 align-top max-w-[520px]">
                                            <span className="line-clamp-2">{n.title}</span>
                                            <details className="mt-3 text-xs"><summary className="cursor-pointer font-medium text-primary">{pt ? 'Produtos, CVEs e orientações' : 'Products, CVEs and guidance'}</summary><div className="mt-3 space-y-3 rounded-md border bg-background p-4"><p>{n.title}</p><div className="flex flex-wrap gap-2">{n.cves.map(c => <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer" className="font-mono text-primary">{c}</a>)}</div><a href={n.noteUrl} target="_blank" rel="noreferrer" className="text-primary underline">{pt ? 'Consultar orientação oficial' : 'Official guidance'}</a></div></details>
                                                {n.isUpdate && <Badge variant="outline" className="ml-2 text-[10px] border-border/60">{pt ? "atualizada" : "updated"}</Badge>}
                                        </td>
                                        <td className="p-4 align-top">
                                            <div className="flex flex-wrap gap-1">
                                                    {n.cves.length > 3 && <span className="text-xs">+{n.cves.length - 3}</span>}
                                                    {n.cves.slice(0, 3).map((c) => <span key={c} className="font-mono text-xs text-muted-foreground">{c}</span>)}
                                            </div>
                                        </td>
                                        <td className="p-4 align-top">
                                            <Badge variant="outline" className={cn("rounded-md text-[10px] font-bold", priorityClass(n.priority))}>{n.priority}</Badge>
                                        </td>
                                        <td className={cn("p-4 align-top text-right tabular-nums", cvssClass(n.cvss))}>
                                            {n.cvss ?? "—"}
                                        </td>
                                    </tr>
                                ))}
                                {!pageRows.length && (
                                    <tr><td colSpan={5}>
                                        {loading ? (
                                            <LoadingRows rows={5} className="px-4" />
                                        ) : (
                                            <EmptyState
                                                bare
                                                title={pt ? "Nenhuma nota neste ciclo" : "No notes in this cycle"}
                                                description={pt
                                                    ? "Escolha outro mês no seletor acima, ou limpe o filtro de severidade."
                                                    : "Pick another month above, or clear the severity filter."}
                                            />
                                        )}
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
