import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Loader2, CalendarDays, User, Pencil, Megaphone } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { Markdown } from "@/components/Markdown";
import { PostEditor } from "@/components/PostEditor";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchPost, type Post } from "@/services/threatApi";

const LOCALE: Record<string, string> = { pt: "pt-BR", en: "en-US", es: "es-ES", fr: "fr-FR" };
const fmtDate = (iso: string | null, lang: string) =>
    iso ? new Date(iso).toLocaleDateString(LOCALE[lang] || "en-US", { day: "2-digit", month: "long", year: "numeric" }) : "";

const AdvisoryPost = () => {
    const { slug } = useParams<{ slug: string }>();
    const navigate = useNavigate();
    const { language, tr } = useLanguage();

    const [post, setPost] = useState<Post | null>(null);
    const [isAdmin, setIsAdmin] = useState(false);
    const [loading, setLoading] = useState(true);
    const [notFound, setNotFound] = useState(false);

    const load = async (s: string) => {
        setLoading(true);
        try {
            const r = await fetchPost(s);
            setPost(r.post);
            setIsAdmin(r.isAdmin);
            setNotFound(false);
        } catch {
            setNotFound(true);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { if (slug) load(slug); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [slug]);

    const shell = (children: React.ReactNode) => (
        <PageLayout width="max-w-3xl">{children}</PageLayout>
    );

    if (loading) {
        return shell(
            <div className="flex items-center gap-2 text-muted-foreground py-16 justify-center">
                <Loader2 className="h-5 w-5 animate-spin" /> {tr({ pt: "Carregando…", en: "Loading…", es: "Cargando…", fr: "Chargement…" })}
            </div>
        );
    }

    if (notFound || !post) {
        return shell(
            <Card className="border-dashed">
                <CardContent className="p-10 flex flex-col items-center text-center gap-3 text-muted-foreground">
                    <Megaphone className="h-8 w-8" />
                    <div className="font-medium text-foreground">{tr({ pt: "Publicação não encontrada", en: "Post not found", es: "Publicación no encontrada", fr: "Publication introuvable" })}</div>
                    <Button asChild variant="outline" size="sm"><Link to="/advisories"><ArrowLeft className="h-4 w-4 mr-1.5" /> {tr({ pt: "Voltar", en: "Back", es: "Volver", fr: "Retour" })}</Link></Button>
                </CardContent>
            </Card>
        );
    }

    return shell(
        <>
            <div className="flex items-center justify-between gap-3 mb-6">
                <Button asChild variant="ghost" size="sm" className="gap-1.5 -ml-2 text-muted-foreground">
                    <Link to="/advisories"><ArrowLeft className="h-4 w-4" /> Advisories</Link>
                </Button>
                {isAdmin && (
                    <PostEditor
                        post={post}
                        trigger={<Button variant="outline" size="sm" className="gap-1.5"><Pencil className="h-4 w-4" /> {tr({ pt: "Editar", en: "Edit", es: "Editar", fr: "Modifier" })}</Button>}
                        onSaved={(p) => { if (p.slug !== post.slug) navigate(`/advisories/${p.slug}`, { replace: true }); else load(post.slug); }}
                        onDeleted={() => navigate("/advisories", { replace: true })}
                    />
                )}
            </div>

            <article>
                <div className="flex items-center gap-2 flex-wrap mb-3">
                    {isAdmin && !post.published && (
                        <Badge variant="outline" className="text-[10px] border-amber-500/40 text-amber-600 dark:text-amber-400">
                            {tr({ pt: "rascunho", en: "draft", es: "borrador", fr: "brouillon" })}
                        </Badge>
                    )}
                    {post.tags.map((t) => <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>)}
                </div>
                <h1 className="text-3xl font-bold leading-tight">{post.title}</h1>
                {post.summary && <p className="text-lg text-muted-foreground mt-2">{post.summary}</p>}
                <div className="flex items-center gap-4 mt-4 pb-6 border-b text-sm text-muted-foreground">
                    <span className="inline-flex items-center gap-1.5"><CalendarDays className="h-4 w-4" /> {fmtDate(post.publishedAt || post.createdAt, language)}</span>
                    <span className="inline-flex items-center gap-1.5"><User className="h-4 w-4" /> {post.author}</span>
                </div>

                <div className="mt-6">
                    <Markdown>{post.body}</Markdown>
                </div>
            </article>
        </>
    );
};

export default AdvisoryPost;
