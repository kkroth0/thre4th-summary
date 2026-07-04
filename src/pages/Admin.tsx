import { useEffect, useState } from "react";
import { Navigate, Link } from "react-router-dom";
import { ShieldCheck, Loader2, CheckCircle2, XCircle, Plug, Megaphone, Plus, Pencil, Rss } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import AllowlistManager from "@/components/AllowlistManager";
import FeedSourcesManager from "@/components/FeedSourcesManager";
import { PostEditor } from "@/components/PostEditor";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { useAuth } from "@/contexts/AuthContext";
import { fetchIntegrationStatus, fetchPosts, type IntegrationStatus, type PostCard } from "@/services/threatApi";
import { toast } from "sonner";

const Admin = () => {
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
  const { auth, loading } = useAuth();
  const pt = language === "pt";

  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([]);
  const [keyless, setKeyless] = useState<string[]>([]);
  const [posts, setPosts] = useState<PostCard[]>([]);

  const loadPosts = async () => {
    try { setPosts((await fetchPosts()).posts); } catch { /* ignore */ }
  };

  useEffect(() => {
    if (!auth.isAdmin) return;
    fetchIntegrationStatus()
      .then((r) => { setIntegrations(r.integrations); setKeyless(r.keyless); })
      .catch((e) => toast.error(e instanceof Error ? e.message : "Falha ao carregar integrações"));
    loadPosts();
  }, [auth.isAdmin]);

  const shell = (children: React.ReactNode) => (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-3xl w-full">{children}</main>
      <Footer />
    </div>
  );

  if (loading) {
    return shell(
      <Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}
      </CardContent></Card>
    );
  }
  if (!auth.authenticated) return <Navigate to="/login" replace />;
  if (!auth.isAdmin) return <Navigate to="/" replace />;

  const missing = integrations.filter((i) => !i.configured && i.required).length;

  return shell(
    <>
      <div className="mb-6">
        <h1 className="text-3xl font-bold flex items-center gap-2"><ShieldCheck className="h-7 w-7 text-primary" /> Admin</h1>
        <p className="text-muted-foreground mt-1">{pt ? "Painel do administrador do ThreatSumm4ry." : "ThreatSumm4ry administrator panel."}</p>
      </div>

      {/* Allow-list (componente reaproveitado) */}
      <AllowlistManager />

      {/* Publicações */}
      <Card className="mb-5">
        <CardContent className="p-5 space-y-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <span className="h-11 w-11 rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center shrink-0">
                <Megaphone className="h-5 w-5 text-primary" />
              </span>
              <div>
                <div className="font-medium">{pt ? "Publicações (Advisories)" : "Posts (Advisories)"}</div>
                <div className="text-sm text-muted-foreground">
                  {posts.length} {pt ? "no total" : "total"} · {posts.filter((p) => !p.published).length} {pt ? "rascunho(s)" : "draft(s)"}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Button asChild variant="ghost" size="icon" className="text-muted-foreground" title="RSS">
                <a href="/api/advisories/feed.xml" target="_blank" rel="noreferrer"><Rss className="h-4 w-4" /></a>
              </Button>
              <PostEditor
                trigger={<Button size="sm" className="gap-1.5"><Plus className="h-4 w-4" /> {pt ? "Nova" : "New"}</Button>}
                onSaved={() => loadPosts()}
              />
            </div>
          </div>
          {posts.length > 0 && (
            <div className="space-y-1.5">
              {posts.map((p) => (
                <div key={p.id} className="flex items-center gap-3 rounded-md border px-3 py-2">
                  <Link to={`/advisories/${p.slug}`} className="min-w-0 flex-1 text-sm font-medium truncate hover:text-primary">{p.title}</Link>
                  {!p.published && <Badge variant="outline" className="text-[10px] border-amber-500/40 text-amber-600 dark:text-amber-400 shrink-0">{pt ? "rascunho" : "draft"}</Badge>}
                  <PostEditor
                    post={p}
                    trigger={<Button variant="ghost" size="icon" className="h-8 w-8 shrink-0"><Pencil className="h-4 w-4" /></Button>}
                    onSaved={() => loadPosts()}
                    onDeleted={() => loadPosts()}
                  />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Integrações (status das chaves) */}
      <Card className="mb-5">
        <CardContent className="p-5 space-y-4">
          <div className="flex items-start gap-3">
            <span className="h-11 w-11 rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center shrink-0">
              <Plug className="h-5 w-5 text-primary" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="font-medium flex items-center gap-2">
                {pt ? "Integrações (IOC search)" : "Integrations (IOC search)"}
                {missing > 0 && <Badge variant="outline" className="text-[10px] border-destructive/40 text-destructive">{missing} {pt ? "sem chave" : "missing"}</Badge>}
              </div>
              <div className="text-sm text-muted-foreground">
                {pt ? "Chaves configuradas na .env da VPS. Faltando = provedor fica inativo." : "Keys set in the VPS .env. Missing = provider inactive."}
              </div>
            </div>
            <FeedSourcesManager />
          </div>

          <div className="space-y-1.5">
            {integrations.map((i) => (
              <div key={i.name} className="flex items-center gap-3 rounded-md border px-3 py-2">
                {i.configured
                  ? <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
                  : <XCircle className={`h-4 w-4 shrink-0 ${i.required ? "text-destructive" : "text-muted-foreground"}`} />}
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium truncate">{i.name}</div>
                  <div className="text-xs text-muted-foreground truncate">
                    <code>{i.env}</code>{i.note ? ` · ${i.note}` : ""}
                  </div>
                </div>
                {i.configured
                  ? <Badge variant="secondary" className="text-[10px] shrink-0">{pt ? "ativo" : "active"}</Badge>
                  : <Badge variant="outline" className={`text-[10px] shrink-0 ${i.required ? "border-destructive/40 text-destructive" : ""}`}>{i.required ? (pt ? "faltando" : "missing") : (pt ? "opcional" : "optional")}</Badge>}
              </div>
            ))}
            {keyless.length > 0 && (
              <div className="pt-2 text-xs text-muted-foreground">
                {pt ? "Sem chave (sempre ativos): " : "No key needed (always on): "}{keyless.join(" · ")}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </>
  );
};

export default Admin;
