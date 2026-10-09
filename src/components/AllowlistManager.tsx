import { useEffect, useState } from "react";
import { ShieldCheck, Plus, Trash2, Loader2, Lock, Github } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useLanguage } from "@/contexts/LanguageContext";
import { LoadingRows } from "@/components/LoadingState";
import {
    fetchAllowlist,
    addAllowlistEntry,
    removeAllowlistEntry,
    type AllowlistEntry,
} from "@/services/threatApi";

// Painel de admin: quem tem acesso premium. Entradas "env" vêm da
// GITHUB_ALLOWED_LOGINS do servidor e são somente-leitura aqui; as "dynamic"
// são adicionadas/removidas em runtime e persistidas em disco no servidor.
export default function AllowlistManager() {
    const { language } = useLanguage();
    const pt = language === "pt";

    const [entries, setEntries] = useState<AllowlistEntry[]>([]);
    const [org, setOrg] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [busyLogin, setBusyLogin] = useState<string | null>(null);
    const [newLogin, setNewLogin] = useState("");
    const [adding, setAdding] = useState(false);

    const load = async () => {
        setLoading(true);
        try {
            const r = await fetchAllowlist();
            setEntries(r.allowlist);
            setOrg(r.org);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : (pt ? "Falha ao carregar allow-list" : "Failed to load allow-list"));
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

    const onAdd = async () => {
        const login = newLogin.trim().replace(/^@/, "");
        if (!login) { toast.error(pt ? "Informe o login do GitHub" : "Enter a GitHub login"); return; }
        setAdding(true);
        try {
            setEntries(await addAllowlistEntry(login));
            setNewLogin("");
            toast.success(pt ? `Adicionado: ${login}` : `Added: ${login}`);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : (pt ? "Falha ao adicionar" : "Failed to add"));
        } finally {
            setAdding(false);
        }
    };

    const onRemove = async (login: string) => {
        setBusyLogin(login);
        try {
            setEntries(await removeAllowlistEntry(login));
            toast.success(pt ? `Removido: ${login}` : `Removed: ${login}`);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : (pt ? "Falha ao remover" : "Failed to remove"));
        } finally {
            setBusyLogin(null);
        }
    };

    return (
        <Card className="overflow-hidden rounded-sm shadow-none">
            <CardContent className="space-y-3 p-4">
                <div className="flex items-start gap-3">
                    <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 text-sm font-semibold">
                            {pt ? "Acesso premium" : "Premium access"}
                            <Badge variant="secondary" className="text-[10px]">{entries.length}</Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">
                            {pt
                                ? "Gerencie as contas autorizadas a usar os recursos premium."
                                : "Manage accounts authorized to use premium features."}
                            {org && (
                                <> {pt ? "Membros de" : "Members of"} <span className="font-medium">@{org}</span> {pt ? "também têm premium." : "also get premium."}</>
                            )}
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <Input
                        placeholder={pt ? "login do GitHub (ex.: fulano)" : "GitHub login (e.g. someone)"}
                        aria-label={pt ? "Login do GitHub" : "GitHub login"}
                        value={newLogin}
                        onChange={(e) => setNewLogin(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") onAdd(); }}
                    />
                    <Button size="sm" className="gap-2 shrink-0" onClick={onAdd} disabled={adding}>
                        {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                        {pt ? "Adicionar" : "Add"}
                    </Button>
                </div>

                <div className="divide-y divide-border rounded-sm border border-border">
                    {loading ? (
                        <LoadingRows rows={3} />
                    ) : !entries.length ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground py-4 justify-center">
                            <Lock className="h-4 w-4" /> {pt ? "Ninguém com premium dinâmico." : "Dynamic premium list is empty."}
                        </div>
                    ) : (
                        entries.map((e) => (
                            <div key={e.login} className="flex items-center gap-2 px-3 py-2.5">
                                <a
                                    href={`https://github.com/${e.login}`} target="_blank" rel="noreferrer"
                                    className="min-w-0 flex-1 flex items-center gap-2 text-sm hover:text-foreground text-muted-foreground"
                                >
                                    <Github className="h-3.5 w-3.5 shrink-0" />
                                    <span className="font-medium text-foreground truncate">{e.login}</span>
                                </a>
                                {e.admin && <Badge variant="secondary" className="text-[10px] shrink-0">admin</Badge>}
                                {e.source === "env" && (
                                    <Badge variant="outline" className="shrink-0 text-[10px]" title={pt ? "Definido pelo servidor" : "Set by server"}>{pt ? "Servidor" : "Server"}</Badge>
                                )}
                                {busyLogin === e.login ? (
                                    <Loader2 className="h-4 w-4 animate-spin text-muted-foreground shrink-0" />
                                ) : e.removable ? (
                                    <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => onRemove(e.login)} aria-label={pt ? `Remover acesso de ${e.login}` : `Remove access for ${e.login}`}>
                                        <Trash2 className="h-4 w-4 text-destructive" />
                                    </Button>
                                ) : (
                                    <Lock className="h-4 w-4 text-muted-foreground shrink-0" />
                                )}
                            </div>
                        ))
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
