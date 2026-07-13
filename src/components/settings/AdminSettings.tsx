import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Megaphone, Pencil, Plug, Plus, Rss, ShieldCheck, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import AllowlistManager from "@/components/AllowlistManager";
import FeedSourcesManager from "@/components/FeedSourcesManager";
import { PostEditor } from "@/components/PostEditor";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchIntegrationStatus, fetchPosts, type IntegrationStatus, type PostCard } from "@/services/threatApi";

export function AdminSettings() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([]);
  const [keyless, setKeyless] = useState<string[]>([]);
  const [posts, setPosts] = useState<PostCard[]>([]);

  const loadPosts = useCallback(async () => {
    try {
      setPosts((await fetchPosts()).posts);
    } catch {
      // The publications card remains usable for creating a post.
    }
  }, []);

  useEffect(() => {
    fetchIntegrationStatus()
      .then((result) => {
        setIntegrations(result.integrations);
        setKeyless(result.keyless);
      })
      .catch((error) => toast.error(error instanceof Error ? error.message : "Falha ao carregar integrações"));
    loadPosts();
  }, [loadPosts]);

  const missing = integrations.filter((integration) => !integration.configured && integration.required).length;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="flex items-center gap-2 text-xl font-semibold"><ShieldCheck className="text-primary" /> Admin</h2>
        <p className="mt-1 text-sm text-muted-foreground">{pt ? "Acesso, publicações e integrações da plataforma." : "Platform access, publications, and integrations."}</p>
      </div>

      <AllowlistManager />

      <Card>
        <CardContent className="flex flex-col gap-4 p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              <span className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20">
                <Megaphone className="text-primary" />
              </span>
              <div>
                <div className="font-medium">{pt ? "Publicações (Advisories)" : "Posts (Advisories)"}</div>
                <div className="text-sm text-muted-foreground">
                  {posts.length} {pt ? "no total" : "total"} · {posts.filter((post) => !post.published).length} {pt ? "rascunho(s)" : "draft(s)"}
                </div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Button asChild variant="ghost" size="icon" className="text-muted-foreground" title="RSS">
                <a href="/api/advisories/feed.xml" target="_blank" rel="noreferrer"><Rss /><span className="sr-only">RSS</span></a>
              </Button>
              <PostEditor
                trigger={<Button size="sm"><Plus data-icon="inline-start" /> {pt ? "Nova" : "New"}</Button>}
                onSaved={loadPosts}
              />
            </div>
          </div>
          {posts.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {posts.map((post) => (
                <div key={post.id} className="flex items-center gap-3 rounded-md border px-3 py-2">
                  <Link to={`/advisories/${post.slug}`} className="min-w-0 flex-1 truncate text-sm font-medium hover:text-primary">{post.title}</Link>
                  {!post.published ? <Badge variant="outline" className="shrink-0 text-[10px]">{pt ? "rascunho" : "draft"}</Badge> : null}
                  <PostEditor
                    post={post}
                    trigger={<Button variant="ghost" size="icon" className="size-8 shrink-0"><Pencil /><span className="sr-only">{pt ? "Editar" : "Edit"}</span></Button>}
                    onSaved={loadPosts}
                    onDeleted={loadPosts}
                  />
                </div>
              ))}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col gap-4 p-5">
          <div className="flex items-start gap-3">
            <span className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20">
              <Plug className="text-primary" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 font-medium">
                {pt ? "Integrações (IOC search)" : "Integrations (IOC search)"}
                {missing > 0 ? <Badge variant="outline" className="text-[10px]">{missing} {pt ? "sem chave" : "missing"}</Badge> : null}
              </div>
              <div className="text-sm text-muted-foreground">
                {pt ? "Chaves configuradas na .env da VPS. Sem chave, o provedor fica inativo." : "Keys set in the VPS .env. Without a key, the provider is inactive."}
              </div>
            </div>
            <FeedSourcesManager />
          </div>

          <div className="flex flex-col gap-1.5">
            {integrations.map((integration) => (
              <div key={integration.name} className="flex items-center gap-3 rounded-md border px-3 py-2">
                {integration.configured ? <CheckCircle2 className="shrink-0 text-emerald-500" /> : <XCircle className="shrink-0 text-muted-foreground" />}
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{integration.name}</div>
                  <div className="truncate text-xs text-muted-foreground"><code>{integration.env}</code>{integration.note ? ` · ${integration.note}` : ""}</div>
                </div>
                <Badge variant={integration.configured ? "secondary" : "outline"} className="shrink-0 text-[10px]">
                  {integration.configured ? (pt ? "ativo" : "active") : integration.required ? (pt ? "faltando" : "missing") : (pt ? "opcional" : "optional")}
                </Badge>
              </div>
            ))}
            {keyless.length > 0 ? (
              <div className="pt-2 text-xs text-muted-foreground">{pt ? "Sem chave (sempre ativos): " : "No key needed (always on): "}{keyless.join(" · ")}</div>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
