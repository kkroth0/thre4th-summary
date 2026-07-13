import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, Crosshair, Megaphone, Plus, Loader2, CalendarDays, User, FileText, Rss, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { PostEditor } from "@/components/PostEditor";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchDailyBrief, fetchPosts, type DailyBrief, type PostCard } from "@/services/threatApi";

const LOCALE: Record<string, string> = { pt: "pt-BR", en: "en-US", es: "es-ES", fr: "fr-FR" };
const fmtDate = (iso: string | null, lang: string) =>
    iso ? new Date(iso).toLocaleDateString(LOCALE[lang] || "en-US", { day: "2-digit", month: "short", year: "numeric" }) : "";
const fmtDateTime = (iso: string | null | undefined, lang: string) =>
    iso ? new Date(iso).toLocaleString(LOCALE[lang] || "en-US", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "";

const groupTone: Record<string, string> = {
    kev: "border-red-500/30 bg-red-500/5",
    critical: "border-orange-500/30 bg-orange-500/5",
    ransomware: "border-purple-500/30 bg-purple-500/5",
    other: "border-border bg-card",
};

const Advisories = () => {
    const { language, tr } = useLanguage();

    const [posts, setPosts] = useState<PostCard[]>([]);
    const [brief, setBrief] = useState<DailyBrief | null>(null);
    const [isAdmin, setIsAdmin] = useState(false);
    const [loading, setLoading] = useState(true);
    const [briefError, setBriefError] = useState(false);

    const load = async () => {
        setLoading(true);
        setBriefError(false);
        try {
            let dailyFailed = false;
            const [daily, r] = await Promise.all([
                fetchDailyBrief().catch((e) => {
                    console.warn(e);
                    dailyFailed = true;
                    return null;
                }),
                fetchPosts(),
            ]);
            setBrief(daily);
            setBriefError(dailyFailed);
            setPosts(r.posts);
            setIsAdmin(r.isAdmin);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : tr({ pt: "Falha ao carregar publicações", en: "Failed to load posts", es: "Error al cargar las publicaciones", fr: "Échec du chargement des publications" }));
        } finally {
            setLoading(false);
        }
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    useEffect(() => { load(); }, []);

    return (
        <PageLayout width="max-w-6xl" showBackButton={false}>
                <div className="mb-6 flex items-start justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-2">
                            <Megaphone className="h-7 w-7 text-primary" /> {tr({ pt: "Summ4ry das ultimas 36h", en: "Last 36h Summ4ry", es: "Summ4ry de las ultimas 36h", fr: "Summ4ry des dernieres 36 h" })}
                        </h1>
                        <p className="text-muted-foreground mt-1">
                            {tr({
                                pt: "Um apanhado de advisories, exploração ativa, ransomware, CVEs e notícias relevantes no recorte recente.",
                                en: "A roundup of advisories, active exploitation, ransomware, CVEs and relevant security news in the recent window.",
                                es: "Resumen de advisories, explotación activa, ransomware, CVEs y noticias relevantes recientes.",
                                fr: "Synthese des advisories, exploitation active, ransomware, CVE et actualites de securite recentes.",
                            })}
                        </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                        <Button asChild variant="ghost" size="icon" className="text-muted-foreground" title="RSS">
                            <a href="/api/advisories/feed.xml" target="_blank" rel="noreferrer"><Rss className="h-4 w-4" /></a>
                        </Button>
                        {isAdmin && (
                            <PostEditor
                                trigger={<Button className="gap-2"><Plus className="h-4 w-4" /> {tr({ pt: "Nova publicação", en: "New post", es: "Nueva publicación", fr: "Nouvelle publication" })}</Button>}
                                onSaved={() => load()}
                            />
                        )}
                    </div>
                </div>

                {loading ? (
                    <div className="flex items-center gap-2 text-muted-foreground py-16 justify-center">
                        <Loader2 className="h-5 w-5 animate-spin" /> {tr({ pt: "Carregando…", en: "Loading…", es: "Cargando…", fr: "Chargement…" })}
                    </div>
                ) : (
                    <div className="space-y-8">
                        {briefError && !brief && (
                            <Card className="border-dashed">
                                <CardContent className="p-6 text-sm text-muted-foreground">
                                    {tr({
                                        pt: "O summ4ry automatizado esta temporariamente indisponivel. As analises publicadas continuam abaixo.",
                                        en: "The automated summ4ry is temporarily unavailable. Published analysis remains available below.",
                                        es: "El summ4ry automatizado no esta disponible temporalmente. Los analisis publicados siguen abajo.",
                                        fr: "Le summ4ry automatise est temporairement indisponible. Les analyses publiees restent disponibles ci-dessous.",
                                    })}
                                </CardContent>
                            </Card>
                        )}

                        {brief && (
                            <section className="overflow-hidden rounded-lg border border-border bg-card">
                                <div className="border-b border-border bg-secondary/30 p-6">
                                    <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                                        <div>
                                            <Badge className="mb-3 gap-1">
                                                {brief.verdict === "hot" ? <AlertTriangle className="h-3.5 w-3.5" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
                                                {brief.verdict === "hot" ? tr({ pt: "dia quente", en: "hot day", es: "día caliente", fr: "jour chaud" })
                                                    : brief.verdict === "watch" ? tr({ pt: "atenção", en: "watch", es: "atención", fr: "surveillance" })
                                                    : tr({ pt: "calmo", en: "calm", es: "tranquilo", fr: "calme" })}
                                            </Badge>
                                            <h2 className="max-w-3xl text-3xl font-black tracking-tight">{brief.title}</h2>
                                            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm font-medium text-muted-foreground">
                                                <span>{tr({ pt: "Janela", en: "Window", es: "Ventana", fr: "Fenetre" })}: {brief.windowHours || 36}h</span>
                                                <span>{fmtDateTime(brief.generatedAt, language)}</span>
                                                <span>{tr({ pt: "RSS advisories, CISA KEV, FIRST EPSS e ransomware.live", en: "RSS advisories, CISA KEV, FIRST EPSS and ransomware.live", es: "RSS advisories, CISA KEV, FIRST EPSS y ransomware.live", fr: "RSS advisories, CISA KEV, FIRST EPSS et ransomware.live" })}</span>
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
                                            {[
                                                [tr({ pt: "Advisories", en: "Advisories", es: "Advisories", fr: "Advisories" }), brief.summary.totalAdvisories],
                                                [tr({ pt: "Críticas", en: "Critical", es: "Críticas", fr: "Critiques" }), brief.summary.critical],
                                                ["KEV", brief.summary.kev],
                                                ["CVEs", brief.summary.cves],
                                                ["Ransomware", brief.summary.ransomwareVictims],
                                                ["Latam", brief.summary.latamVictims],
                                            ].map(([label, value]) => (
                                                <div key={String(label)} className="rounded-md border border-border bg-background px-3 py-2 text-right">
                                                    <div className="font-mono text-xl font-black text-foreground">{String(value)}</div>
                                                    <div className="text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{String(label)}</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                    <div className="mt-5 rounded-lg border border-border bg-background p-4">
                                        <div className="mb-3 text-xs font-bold uppercase tracking-wide text-muted-foreground">
                                            {tr({ pt: "Resumo executivo", en: "Executive summary", es: "Resumen ejecutivo", fr: "Resume executif" })}
                                        </div>
                                        <ul className="space-y-2">
                                            {(brief.executiveSummary || []).map((line) => (
                                                <li key={line} className="flex gap-2 text-sm leading-relaxed text-foreground">
                                                    <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                                                    <span>{line}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                </div>

                                <div className="grid gap-6 p-6 lg:grid-cols-[1.15fr_0.85fr]">
                                    <div>
                                        <div className="mb-4 flex items-center gap-2">
                                            <ShieldAlert className="h-5 w-5 text-primary" />
                                            <h3 className="text-xl font-black tracking-tight">{tr({ pt: "Destaques críticos", en: "Critical highlights", es: "Destacados críticos", fr: "Points critiques" })}</h3>
                                        </div>
                                        <div className="space-y-3">
                                            {brief.highlights.slice(0, 6).map((item, idx) => (
                                                <a key={`${item.id}-${idx}`} href={item.link} target="_blank" rel="noreferrer" className="block rounded-lg border border-border bg-background p-4 transition-colors hover:border-primary/40">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <Badge variant={item.kev ? "destructive" : "secondary"}>{item.kev ? "CISA KEV" : item.severity}</Badge>
                                                        <span className="font-mono text-xs font-bold text-muted-foreground">{item.score ?? 0}/100</span>
                                                        <span className="text-xs text-muted-foreground">{item.source}</span>
                                                    </div>
                                                    <h4 className="mt-2 line-clamp-2 font-semibold text-foreground">{language === "pt" ? item.titlePt || item.title : item.title}</h4>
                                                    {!!item.cves.length && <p className="mt-2 font-mono text-xs text-muted-foreground">{item.cves.slice(0, 4).join(" · ")}</p>}
                                                </a>
                                            ))}
                                        </div>
                                    </div>

                                    <div>
                                        <div className="mb-4 flex items-center gap-2">
                                            <Crosshair className="h-5 w-5 text-primary" />
                                            <h3 className="text-xl font-black tracking-tight">{tr({ pt: "Ransomware nas ultimas 36h", en: "Ransomware in the last 36h", es: "Ransomware en las ultimas 36h", fr: "Ransomware sur les dernieres 36 h" })}</h3>
                                        </div>
                                        <div className="rounded-lg border border-border bg-background">
                                            <div className="divide-y divide-border">
                                                {brief.ransomware.victims.slice(0, 8).map((v) => (
                                                    <div key={`${v.name}-${v.discovered}`} className="p-4">
                                                        <div className="flex items-center justify-between gap-3">
                                                            <span className="min-w-0 truncate font-semibold text-foreground">{v.name}</span>
                                                            <Badge variant="outline">{v.group}</Badge>
                                                        </div>
                                                        <div className="mt-1 text-xs text-muted-foreground">{v.countryName} · {v.sector}</div>
                                                    </div>
                                                ))}
                                                {!brief.ransomware.victims.length && (
                                                    <div className="p-6 text-center text-sm text-muted-foreground">{tr({ pt: "Sem vitimas recentes no recorte.", en: "No recent victims in this window.", es: "Sin víctimas recientes.", fr: "Aucune victime récente." })}</div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </section>
                        )}

                        {brief && (
                            <section>
                                <div className="mb-4 flex items-center justify-between gap-4 border-b border-border pb-4">
                                    <div>
                                        <h2 className="text-2xl font-black tracking-tight">
                                            {tr({ pt: "Feed organizado", en: "Organized feed", es: "Feed organizado", fr: "Flux organise" })}
                                        </h2>
                                        <p className="mt-1 text-sm text-muted-foreground">
                                            {tr({
                                                pt: "Itens das ultimas 36h agrupados por prioridade operacional.",
                                                en: "Last 36h items grouped by operational priority.",
                                                es: "Items de las ultimas 36h agrupados por prioridad.",
                                                fr: "Elements des dernieres 36 h groupes par priorite.",
                                            })}
                                        </p>
                                    </div>
                                </div>
                                <div className="space-y-4">
                                    {(brief.feedGroups || []).map((group) => (
                                        <div key={group.key} className={`rounded-lg border p-4 ${groupTone[group.key] || groupTone.other}`}>
                                            <div className="mb-3 flex items-start justify-between gap-3">
                                                <div>
                                                    <h3 className="font-bold">{group.title}</h3>
                                                    <p className="text-sm text-muted-foreground">{group.description}</p>
                                                </div>
                                                <Badge variant="secondary">{group.items.length}</Badge>
                                            </div>
                                            {group.items.length ? (
                                                <div className="divide-y divide-border/70">
                                                    {group.items.map((item) => (
                                                        <div key={item.id} className="py-3 first:pt-0 last:pb-0">
                                                            <div className="flex flex-wrap items-center gap-2">
                                                                {item.kind === "ransomware" && <Badge variant="outline">ransomware</Badge>}
                                                                {item.kev && <Badge variant="destructive">KEV</Badge>}
                                                                {item.severity && <Badge variant="secondary">{item.severity}</Badge>}
                                                                {typeof item.score === "number" && <span className="font-mono text-xs text-muted-foreground">{item.score}/100</span>}
                                                                <span className="text-xs text-muted-foreground">{item.source}</span>
                                                                {item.pubDate && <span className="text-xs text-muted-foreground">{fmtDateTime(item.pubDate, language)}</span>}
                                                            </div>
                                                            {item.link ? (
                                                                <a href={item.link} target="_blank" rel="noreferrer" className="mt-1 block font-semibold text-foreground hover:text-primary">
                                                                    {language === "pt" ? item.titlePt || item.title : item.title}
                                                                </a>
                                                            ) : (
                                                                <div className="mt-1 font-semibold text-foreground">{item.title}</div>
                                                            )}
                                                            {item.kind === "ransomware" ? (
                                                                <p className="mt-1 text-xs text-muted-foreground">{[item.group, item.countryName, item.sector].filter(Boolean).join(" · ")}</p>
                                                            ) : item.cves.length ? (
                                                                <p className="mt-1 font-mono text-xs text-muted-foreground">{item.cves.slice(0, 6).join(" · ")}</p>
                                                            ) : null}
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <p className="py-4 text-sm text-muted-foreground">
                                                    {tr({ pt: "Nenhum item neste grupo.", en: "No items in this group.", es: "Sin items en este grupo.", fr: "Aucun element dans ce groupe." })}
                                                </p>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </section>
                        )}

                        <section>
                            <div className="mb-4 flex items-center justify-between gap-4 border-b border-border pb-4">
                                <div>
                                    <h2 className="text-2xl font-black tracking-tight">{tr({ pt: "Analises publicadas", en: "Published analysis", es: "Analisis publicados", fr: "Analyses publiees" })}</h2>
                                    <p className="mt-1 text-sm text-muted-foreground">{tr({ pt: "Conteudo editorial salvo a partir de curadoria manual.", en: "Editorial content saved from manual curation.", es: "Contenido editorial guardado desde curadoria manual.", fr: "Contenu editorial enregistre depuis une curation manuelle." })}</p>
                                </div>
                            </div>

                            {!posts.length ? (
                                <Card className="border-dashed">
                                    <CardContent className="p-10 flex flex-col items-center text-center gap-3 text-muted-foreground">
                                        <FileText className="h-8 w-8" />
                                        <div>
                                            <div className="font-medium text-foreground">{tr({ pt: "Nenhuma publicação ainda", en: "No posts yet", es: "Aún no hay publicaciones", fr: "Aucune publication pour l'instant" })}</div>
                                            <p className="text-sm mt-1">
                                                {isAdmin
                                                    ? tr({ pt: "Clique em “Nova publicação” para escrever a primeira.", en: "Click “New post” to write the first one.", es: "Haz clic en “Nueva publicación” para escribir la primera.", fr: "Cliquez sur « Nouvelle publication » pour écrire la première." })
                                                    : tr({ pt: "Volte em breve.", en: "Check back soon.", es: "Vuelve pronto.", fr: "Revenez bientôt." })}
                                            </p>
                                        </div>
                                    </CardContent>
                                </Card>
                            ) : (
                                <div className="grid gap-4 md:grid-cols-2">
                                    {posts.map((p) => (
                                        <Link key={p.id} to={`/advisories/${p.slug}`} className="block group">
                                            <Card className="h-full transition-colors group-hover:border-border/50">
                                                <CardContent className="p-5">
                                                    <div className="flex items-center gap-2 flex-wrap mb-1.5">
                                                        {isAdmin && !p.published && (
                                                            <Badge variant="outline" className="text-[10px] border-amber-500/40 text-amber-600 dark:text-amber-400">
                                                                {tr({ pt: "rascunho", en: "draft", es: "borrador", fr: "brouillon" })}
                                                            </Badge>
                                                        )}
                                                        {p.tags.slice(0, 4).map((t) => (
                                                            <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                                                        ))}
                                                    </div>
                                                    <h3 className="text-lg font-semibold group-hover:text-primary transition-colors">{p.title}</h3>
                                                    {p.summary && <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{p.summary}</p>}
                                                    <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                                                        <span className="inline-flex items-center gap-1"><CalendarDays className="h-3.5 w-3.5" /> {fmtDate(p.publishedAt || p.createdAt, language)}</span>
                                                        <span className="inline-flex items-center gap-1"><User className="h-3.5 w-3.5" /> {p.author}</span>
                                                    </div>
                                                </CardContent>
                                            </Card>
                                        </Link>
                                    ))}
                                </div>
                            )}
                        </section>
                    </div>
                )}
        </PageLayout>
    );
};

export default Advisories;
