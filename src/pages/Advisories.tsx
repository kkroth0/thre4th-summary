import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Megaphone, Plus, Loader2, CalendarDays, User, FileText, Rss } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { PostEditor } from "@/components/PostEditor";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { fetchPosts, type PostCard } from "@/services/threatApi";

const fmtDate = (iso: string | null, pt: boolean) =>
    iso ? new Date(iso).toLocaleDateString(pt ? "pt-BR" : "en-US", { day: "2-digit", month: "short", year: "numeric" }) : "";

const Advisories = () => {
    const { language } = useLanguage();
    const { isCollapsed } = useSidebar();
    const pt = language === "pt";

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
            toast.error(e instanceof Error ? e.message : (pt ? "Falha ao carregar publicações" : "Failed to load posts"));
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

    return (
        <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
            <Header />
            <main className="flex-1 container mx-auto px-4 py-8 max-w-3xl w-full">
                <div className="mb-6 flex items-start justify-between gap-4">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-2">
                            <Megaphone className="h-7 w-7 text-primary" /> Advisories
                        </h1>
                        <p className="text-muted-foreground mt-1">
                            {pt
                                ? "Análises e alertas sobre campanhas, ameaças e tendências."
                                : "Analysis and alerts on campaigns, threats and trends."}
                        </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                        <Button asChild variant="ghost" size="icon" className="text-muted-foreground" title="RSS">
                            <a href="/api/advisories/feed.xml" target="_blank" rel="noreferrer"><Rss className="h-4 w-4" /></a>
                        </Button>
                        {isAdmin && (
                            <PostEditor
                                trigger={<Button className="gap-2"><Plus className="h-4 w-4" /> {pt ? "Nova publicação" : "New post"}</Button>}
                                onSaved={() => load()}
                            />
                        )}
                    </div>
                </div>

                {loading ? (
                    <div className="flex items-center gap-2 text-muted-foreground py-16 justify-center">
                        <Loader2 className="h-5 w-5 animate-spin" /> {pt ? "Carregando…" : "Loading…"}
                    </div>
                ) : !posts.length ? (
                    <Card className="border-dashed">
                        <CardContent className="p-10 flex flex-col items-center text-center gap-3 text-muted-foreground">
                            <FileText className="h-8 w-8" />
                            <div>
                                <div className="font-medium text-foreground">{pt ? "Nenhuma publicação ainda" : "No posts yet"}</div>
                                <p className="text-sm mt-1">
                                    {isAdmin
                                        ? (pt ? "Clique em “Nova publicação” para escrever a primeira." : "Click “New post” to write the first one.")
                                        : (pt ? "Volte em breve." : "Check back soon.")}
                                </p>
                            </div>
                        </CardContent>
                    </Card>
                ) : (
                    <div className="space-y-4">
                        {posts.map((p) => (
                            <Link key={p.id} to={`/advisories/${p.slug}`} className="block group">
                                <Card className="transition-colors group-hover:border-primary/30">
                                    <CardContent className="p-5">
                                        <div className="flex items-center gap-2 flex-wrap mb-1.5">
                                            {isAdmin && !p.published && (
                                                <Badge variant="outline" className="text-[10px] border-amber-500/40 text-amber-600 dark:text-amber-400">
                                                    {pt ? "rascunho" : "draft"}
                                                </Badge>
                                            )}
                                            {p.tags.slice(0, 4).map((t) => (
                                                <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                                            ))}
                                        </div>
                                        <h2 className="text-lg font-semibold group-hover:text-primary transition-colors">{p.title}</h2>
                                        {p.summary && <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{p.summary}</p>}
                                        <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                                            <span className="inline-flex items-center gap-1"><CalendarDays className="h-3.5 w-3.5" /> {fmtDate(p.publishedAt || p.createdAt, pt)}</span>
                                            <span className="inline-flex items-center gap-1"><User className="h-3.5 w-3.5" /> {p.author}</span>
                                        </div>
                                    </CardContent>
                                </Card>
                            </Link>
                        ))}
                    </div>
                )}
            </main>
            <Footer />
        </div>
    );
};

export default Advisories;
