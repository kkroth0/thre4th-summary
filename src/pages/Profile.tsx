import { useEffect, useState } from "react";
import { Navigate, Link } from "react-router-dom";
import {
  Github, KeyRound, LogOut, CheckCircle2, Loader2, ShieldCheck, Trash2,
  ArrowRight, FileText, ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader,
  AlertDialogFooter, AlertDialogTitle, AlertDialogDescription, AlertDialogAction,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { useAuth } from "@/contexts/AuthContext";
import { saveGroqKey, deleteGroqKey } from "@/services/threatApi";
import { toast } from "sonner";

const Profile = () => {
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
  const { auth, loading, refresh, signOut } = useAuth();
  const pt = language === "pt";

  const [keyInput, setKeyInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [changing, setChanging] = useState(false);

  // Feedback do retorno do OAuth (?auth=ok) — o callback de sucesso cai aqui.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("auth");
    if (p === "ok") toast.success(pt ? "Login efetuado" : "Signed in");
    else if (p === "negado") toast.error(pt ? "Conta não autorizada" : "Account not allow-listed");
    else if (p === "erro") toast.error(pt ? "Falha no login" : "Sign-in failed");
    if (p) window.history.replaceState({}, "", window.location.pathname);
  }, [pt]);

  const shell = (children: React.ReactNode) => (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-2xl w-full">{children}</main>
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

  const submitKey = async () => {
    const k = keyInput.trim();
    if (!k) return;
    setSaving(true);
    try {
      await saveGroqKey(k);
      setKeyInput("");
      setChanging(false);
      toast.success(pt ? "Chave Groq salva" : "Groq key saved");
      await refresh();
    } catch (e) {
      toast.error((e as Error).message || (pt ? "Falha ao salvar a chave" : "Failed to save key"));
    } finally {
      setSaving(false);
    }
  };

  const removeKey = async () => {
    await deleteGroqKey();
    setChanging(false);
    toast.success(pt ? "Chave removida" : "Key removed");
    await refresh();
  };

  const avatarUrl = `https://github.com/${auth.login}.png?size=160`;

  return shell(
    <>
      <div className="mb-6">
        <h1 className="text-3xl font-bold">{pt ? "Perfil" : "Profile"}</h1>
        <p className="text-muted-foreground mt-1">
          {pt ? "Sua conta, chave Groq e sessão." : "Your account, Groq key and session."}
        </p>
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

      {/* Chave Groq (BYOK) */}
      <Card className="mb-5">
        <CardHeader className="pb-2">
          <CardTitle className="text-lg flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" /> {pt ? "Chave Groq" : "Groq key"}
            {auth.hasKey && !changing && (
              <Badge variant="secondary" className="ml-1 gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> {pt ? "Ativa" : "Active"}</Badge>
            )}
          </CardTitle>
          <CardDescription>
            {pt
              ? "Usada só para gerar seus boletins. É cifrada no servidor e nunca exibida de volta. "
              : "Used only to generate your bulletins. It's encrypted server-side and never shown back. "}
            <a href="https://console.groq.com/keys" target="_blank" rel="noreferrer" className="text-primary underline underline-offset-2">
              console.groq.com/keys
            </a>
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-1">
          {auth.hasKey && !changing ? (
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex items-center gap-2 font-mono text-sm text-muted-foreground flex-1">
                <ShieldCheck className="h-4 w-4 text-emerald-500 shrink-0" />
                gsk_••••••••••••••••••••••••
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={() => setChanging(true)}>
                  <KeyRound className="h-3.5 w-3.5 mr-1.5" /> {pt ? "Trocar" : "Change"}
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive">
                      <Trash2 className="h-3.5 w-3.5 mr-1.5" /> {pt ? "Remover" : "Remove"}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{pt ? "Remover a chave Groq?" : "Remove your Groq key?"}</AlertDialogTitle>
                      <AlertDialogDescription>
                        {pt
                          ? "Sem a chave você não consegue gerar boletins até adicionar outra."
                          : "Without a key you won't be able to generate bulletins until you add another."}
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{pt ? "Cancelar" : "Cancel"}</AlertDialogCancel>
                      <AlertDialogAction onClick={removeKey}>{pt ? "Remover" : "Remove"}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            </div>
          ) : (
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                type="password" placeholder="gsk_…" value={keyInput}
                onChange={(e) => setKeyInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") submitKey(); }}
                className="flex-1"
              />
              <Button onClick={submitKey} disabled={saving || !keyInput.trim()}>
                {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <KeyRound className="h-4 w-4 mr-2" />}
                {pt ? "Salvar chave" : "Save key"}
              </Button>
              {auth.hasKey && (
                <Button variant="ghost" onClick={() => { setChanging(false); setKeyInput(""); }}>
                  {pt ? "Cancelar" : "Cancel"}
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Atalho pro gerador */}
      <Card className="bg-muted/20 border-dashed">
        <CardContent className="p-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <FileText className="h-5 w-5 text-primary shrink-0" />
            <div className="min-w-0">
              <div className="font-medium">{pt ? "Threat Brief" : "Threat Brief"}</div>
              <div className="text-sm text-muted-foreground truncate">
                {auth.hasKey
                  ? (pt ? "Tudo pronto — cole uma URL e gere seu boletim." : "All set — paste a URL and generate your bulletin.")
                  : (pt ? "Adicione sua chave Groq acima para começar." : "Add your Groq key above to get started.")}
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
