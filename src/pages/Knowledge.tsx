import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ExternalLink, FileSearch, Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { LoadingRows } from "@/components/LoadingState";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { deleteKnowledge, fetchKnowledge, type KnowledgeItem } from "@/services/threatApi";

const LOCALE: Record<string, string> = { pt: "pt-BR", en: "en-US", es: "es-ES", fr: "fr-FR" };

const shortDate = (value: string, language: string) =>
    value ? new Date(/^\d{4}-\d\d-\d\d$/.test(value) ? value + 'T12:00:00Z' : value).toLocaleDateString(LOCALE[language] || "pt-BR", { timeZone: 'America/Fortaleza', day: "2-digit", month: "short" }) : "—";

const Knowledge = () => {
    const { language } = useLanguage();
    const pt = language === "pt";
    const [items, setItems] = useState<KnowledgeItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [query, setQuery] = useState("");
    const [source, setSource] = useState("all");

    useEffect(() => {
        fetchKnowledge()
            .then(setItems)
            .catch((e) => toast.error(e.message))
            .finally(() => setLoading(false));
    }, []);

    const sources = useMemo(
        () => [...new Set(items.map((i) => i.source).filter(Boolean))].sort(),
        [items],
    );

    // Busca casa título, fonte e também os IDs indexados, pra achar "tudo que eu
    // guardei sobre T1566" sem precisar de filtro dedicado.
    const shown = useMemo(() => {
        const q = query.trim().toLowerCase();
        return items.filter((item) => {
            if (source !== "all" && item.source !== source) return false;
            if (!q) return true;
            return [item.title, item.source, item.host, ...item.techniques, ...item.cves]
                .join(" ")
                .toLowerCase()
                .includes(q);
        });
    }, [items, query, source]);

    const remove = async (item: KnowledgeItem) => {
        try {
            setItems(await deleteKnowledge(item.id));
        } catch (e) {
            toast.error((e as Error).message);
        }
    };

    return (
        <PageLayout width="max-w-6xl">
            <PageHeader
                title={pt ? "Publicações salvas" : "Saved publications"}
                subtitle={pt
                    ? "Notícias e referências que você salvou para retomar a investigação."
                    : "News and references you saved to continue your investigation."}
            />

            <div className="mb-4 flex flex-wrap items-center gap-2">
                <Input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder={pt ? "Buscar por título, fonte, técnica ou CVE…" : "Search title, source, technique or CVE…"}
                    className="max-w-md"
                />
                <select
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    className="h-10 rounded-md border border-input bg-background px-3 text-sm"
                >
                    <option value="all">{pt ? "Todas as fontes" : "All sources"}</option>
                    {sources.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <span className="ml-auto text-sm text-muted-foreground">
                    {shown.length === items.length
                        ? `${items.length} ${pt ? (items.length === 1 ? "publicação" : "publicações") : (items.length === 1 ? "publication" : "publications")}`
                        : `${shown.length} / ${items.length}`}
                </span>
            </div>

            {loading ? (
                <LoadingRows rows={6} />
            ) : items.length === 0 ? (
                <EmptyState
                    title={pt ? "Nenhuma publicação salva" : "No saved publications"}
                    action={<Button asChild size="sm" variant="outline"><Link to="/newsletter">{pt ? "Abrir notícias e IOCs" : "Open News & IOCs"}</Link></Button>}
                    description={pt
                        ? "Salve notícias em Notícias e IOCs para consultá-las aqui."
                        : "Save publications from News & IOCs to find them here."}
                />
            ) : (
                <div className="overflow-x-auto rounded-lg border border-border">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>{pt ? "Publicação" : "Publication"}</TableHead>
                                <TableHead>{pt ? "Técnicas" : "Techniques"}</TableHead>
                                <TableHead>CVEs</TableHead>
                                <TableHead>{pt ? "Salvo" : "Saved"}</TableHead>
                                <TableHead className="text-right">{pt ? "Ações" : "Actions"}</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {shown.map((item) => (
                                <TableRow key={item.id}>
                                    <TableCell className="max-w-xl">
                                        <a
                                            href={item.url}
                                            target="_blank"
                                            rel="noreferrer"
                                            className="inline-flex items-start gap-1.5 font-medium leading-snug hover:text-primary"
                                        >
                                            <span className="line-clamp-2">{item.title}</span>
                                            <ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                                        </a>
                                        <p className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                                            <span>
                                                {[item.source || item.host, shortDate(item.publishedAt, language)]
                                                    .filter((v) => v && v !== "—")
                                                    .join(" · ")}
                                            </span>
                                            {/* A cobertura seguida continua crescendo depois do clique.
                                                Só destaca quando entrou veículo novo — um contador parado
                                                em "4 fontes" toda semana vira ruído e some da vista. */}
                                            {item.sourceCount ? (
                                                <Badge
                                                    variant="outline"
                                                    className={item.newSources
                                                        ? "border-primary/40 bg-primary/10 text-[10px] font-bold text-primary"
                                                        : "text-[10px] font-bold text-muted-foreground border-border"}
                                                >
                                                    {item.newSources
                                                        ? (pt ? `+${item.newSources} nova(s) de ${item.sourceCount}` : `+${item.newSources} new of ${item.sourceCount}`)
                                                        : (pt
                                                            ? `${item.sourceCount} ${item.sourceCount === 1 ? "fonte" : "fontes"}`
                                                            : `${item.sourceCount} ${item.sourceCount === 1 ? "source" : "sources"}`)}
                                                </Badge>
                                            ) : null}
                                        </p>
                                    </TableCell>
                                    <TableCell>
                                        <div className="flex flex-wrap gap-1">
                                            {item.techniques.length
                                                ? item.techniques.map((t) => (
                                                    <Badge key={t} variant="outline" className="font-mono text-[11px]">{t}</Badge>
                                                ))
                                                : <span className="text-xs text-muted-foreground">—</span>}
                                        </div>
                                    </TableCell>
                                    <TableCell>
                                        <div className="flex flex-wrap gap-1">
                                            {item.cves.length
                                                ? item.cves.map((c) => (
                                                    <Badge key={c} variant="secondary" className="font-mono text-[11px]">{c}</Badge>
                                                ))
                                                : <span className="text-xs text-muted-foreground">—</span>}
                                        </div>
                                    </TableCell>
                                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                                        {shortDate(item.savedAt, language)}
                                    </TableCell>
                                    <TableCell className="text-right">
                                        <div className="flex justify-end gap-1">
                                            <Button asChild variant="ghost" size="icon" title={pt ? "Gerar Boletim" : "Generate Bulletin"}>
                                                <Link to={`/relatorios?url=${encodeURIComponent(item.url)}`}>
                                                    <FileSearch className="h-4 w-4" />
                                                </Link>
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                onClick={() => remove(item)}
                                                title={pt ? "Remover" : "Remove"}
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            )}
        </PageLayout>
    );
};

export default Knowledge;
