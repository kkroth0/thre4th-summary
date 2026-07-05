import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Megaphone, Plus, Loader2, CalendarDays, User, FileText, Rss } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { PostEditor } from "@/components/PostEditor";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchPosts, type PostCard } from "@/services/threatApi";

const LOCALE: Record<string, string> = { pt: "pt-BR", en: "en-US", es: "es-ES", fr: "fr-FR" };
const fmtDate = (iso: string | null, lang: string) =>
    iso ? new Date(iso).toLocaleDateString(LOCALE[lang] || "en-US", { day: "2-digit", month: "short", year: "numeric" }) : "";

const Advisories = () => {
    const { language, tr } = useLanguage();

    const [posts, setPosts] = useState<PostCard[]>([]);
    const [isAdmin, setIsAdmin] = useState(false);
    const [loading, setLoading] = useState(true);

    const load = async () => {
        setLoading(true);
        try {
            const r = await fetchPosts();
            setPosts(r.posts);
            setIsAdmin(r.isAdmin);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : tr({ pt: "Falha ao carregar publicações", en: "Failed to load posts", es: "Error al cargar las publicaciones", fr: "Échec du chargement des publications" }));
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

    return (
        <PageLayout width="max-w-3xl" showBackButton={false}>
                <div className="mb-6 flex items-start justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-2">
                            <Megaphone className="h-7 w-7 text-primary" /> Advisories
                        </h1>
                        <p className="text-muted-foreground mt-1">
                            {tr({
                                pt: "Análises e alertas sobre campanhas, ameaças e tendências.",
                                en: "Analysis and alerts on campaigns, threats and trends.",
                                es: "Análisis y alertas sobre campañas, amenazas y tendencias.",
                                fr: "Analyses et alertes sur les campagnes, menaces et tendances.",
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
                ) : !posts.length ? (
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
                    <div className="space-y-4">
                        {posts.map((p) => (
                            <Link key={p.id} to={`/advisories/${p.slug}`} className="block group">
                                <Card className="transition-colors group-hover:border-border/50">
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
                                        <h2 className="text-lg font-semibold group-hover:text-primary transition-colors">{p.title}</h2>
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
        </PageLayout>
    );
};

export default Advisories;
