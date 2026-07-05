import { useEffect, useState } from "react";
import { Navigate, Link } from "react-router-dom";
import {
  Github, KeyRound, LogOut, CheckCircle2, Loader2, ArrowRight, FileText,
  ExternalLink, Settings as SettingsIcon, ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { fetchApiKeys } from "@/services/threatApi";
import { toast } from "sonner";

const Profile = () => {
  const { language } = useLanguage();
  const { auth, loading, signOut } = useAuth();
  const pt = language === "pt";

  const [keyCount, setKeyCount] = useState<number | null>(null);

  // Feedback do retorno do OAuth (?auth=ok) — o callback de sucesso cai aqui.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("auth");
    if (p === "ok") toast.success(pt ? "Login efetuado" : "Signed in");
    else if (p === "negado") toast.error(pt ? "Conta não autorizada" : "Account not allow-listed");
    else if (p === "erro") toast.error(pt ? "Falha no login" : "Sign-in failed");
    if (p) window.history.replaceState({}, "", window.location.pathname);
  }, [pt]);

  useEffect(() => {
    if (auth.authenticated) fetchApiKeys().then((k) => setKeyCount(Object.values(k).filter(Boolean).length));
  }, [auth.authenticated]);

  const shell = (children: React.ReactNode) => (
    <PageLayout width="max-w-2xl">{children}</PageLayout>
  );

  if (loading) {
    return shell(
      <Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}
      </CardContent></Card>
    );
  }
  if (!auth.authenticated) return <Navigate to="/login" replace />;

  const avatarUrl = `https://github.com/${auth.login}.png?size=160`;

  return shell(
    <>
      <div className="mb-6">
        <h1 className="text-3xl font-bold">{pt ? "Perfil" : "Profile"}</h1>
        <p className="text-muted-foreground mt-1">{pt ? "Sua conta e sessão." : "Your account and session."}</p>
      </div>

      {/* Identidade */}
      <Card className="mb-5">
        <CardContent className="p-5 flex items-center gap-4">
          <Avatar className="h-16 w-16 ring-1 ring-primary/20">
            <AvatarImage src={avatarUrl} alt={auth.login} />
            <AvatarFallback className="text-lg font-semibold bg-primary/10 text-primary">
              {auth.login?.[0]?.toUpperCase() ?? "?"}
            </AvatarFallback>
          </Avatar>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-lg font-semibold truncate">{auth.login}</span>
              <Badge variant="secondary" className="gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> {pt ? "Autorizado" : "Allow-listed"}</Badge>
            </div>
            <a
              href={`https://github.com/${auth.login}`} target="_blank" rel="noreferrer"
              className="text-sm text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
            >
              <Github className="h-3.5 w-3.5" /> github.com/{auth.login} <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          <Button variant="outline" size="sm" onClick={signOut} className="shrink-0">
            <LogOut className="h-4 w-4 mr-1.5" /> {pt ? "Sair" : "Sign out"}
          </Button>
        </CardContent>
      </Card>

      {/* Admin (só admin): allow-list, publicações, integrações num só lugar */}
      {auth.isAdmin && (
        <Link to="/admin" className="block mb-5 group">
          <Card className="transition-colors group-hover:border-primary/30">
            <CardContent className="p-5 flex items-center gap-4">
              <span className="h-11 w-11 rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center shrink-0">
                <ShieldCheck className="h-5 w-5 text-primary" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="font-medium">{pt ? "Painel de administração" : "Admin panel"}</div>
                <div className="text-sm text-muted-foreground">
                  {pt ? "Allow-list, publicações e status das integrações." : "Allow-list, posts and integration status."}
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0" />
            </CardContent>
          </Card>
        </Link>
      )}

      {/* Chaves de API -> Settings */}
      <Link to="/settings" className="block mb-5 group">
        <Card className="transition-colors group-hover:border-primary/30">
          <CardContent className="p-5 flex items-center gap-4">
            <span className="h-11 w-11 rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center shrink-0">
              <KeyRound className="h-5 w-5 text-primary" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="font-medium flex items-center gap-2">
                {pt ? "Chaves de API (BYOK)" : "API keys (BYOK)"}
                {auth.hasKey && <Badge variant="secondary" className="gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> Groq</Badge>}
              </div>
              <div className="text-sm text-muted-foreground">
                {keyCount === null
                  ? (pt ? "Gerencie suas chaves de API." : "Manage your API keys.")
                  : keyCount > 0
                    ? (pt ? `${keyCount} chave(s) configurada(s).` : `${keyCount} key(s) configured.`)
                    : (pt ? "Nenhuma chave ainda — adicione a sua chave Groq para gerar." : "No keys yet — add your Groq key to generate.")}
              </div>
            </div>
            <SettingsIcon className="h-4 w-4 text-muted-foreground shrink-0" />
          </CardContent>
        </Card>
      </Link>

      {/* Atalho pro gerador */}
      <Card className="bg-muted/20 border-dashed">
        <CardContent className="p-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <FileText className="h-5 w-5 text-primary shrink-0" />
            <div className="min-w-0">
              <div className="font-medium">Threat Brief</div>
              <div className="text-sm text-muted-foreground truncate">
                {auth.hasKey
                  ? (pt ? "Tudo pronto — cole uma URL e gere seu boletim." : "All set — paste a URL and generate your bulletin.")
                  : (pt ? "Adicione sua chave Groq nas configurações para começar." : "Add your Groq key in settings to get started.")}
              </div>
            </div>
          </div>
          <Button asChild variant={auth.hasKey ? "default" : "outline"} className="shrink-0">
            <Link to="/threat-brief">{pt ? "Abrir" : "Open"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
          </Button>
        </CardContent>
      </Card>
    </>
  );
};

export default Profile;
