import { useEffect, useMemo, useState } from "react";
import { Rss, Plus, Trash2, CheckCircle2, XCircle, Loader2, Lock, Search } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import {
    fetchFeeds,
    addFeed,
    toggleFeed,
    deleteFeed,
    type FeedSource,
} from "@/services/threatApi";

// Rótulos das "camadas" de confiança do catálogo (espelham o server/ctiIntel.js).
const LAYER_LABELS: Record<number, string> = {
    1: "PSIRT / advisories de fornecedor",
    2: "Notícias & reporting de TI",
    3: "Labs de threat research",
    4: "LATAM / Brasil",
};

// Painel de Fontes: mostra os feeds RSS que o coletor monitora e — pra admin —
// permite ligar/desligar, adicionar e remover feeds. Fica no Advisory Feed.
export default function FeedSourcesManager() {
    const [open, setOpen] = useState(false);
    const [feeds, setFeeds] = useState<FeedSource[]>([]);
    const [isAdmin, setIsAdmin] = useState(false);
    const [loading, setLoading] = useState(false);
    const [search, setSearch] = useState("");
    const [busyUrl, setBusyUrl] = useState<string | null>(null);

    // form de novo feed
    const [newUrl, setNewUrl] = useState("");
    const [newName, setNewName] = useState("");
    const [newLayer, setNewLayer] = useState("2");
    const [adding, setAdding] = useState(false);

    const load = async () => {
        setLoading(true);
        try {
            const r = await fetchFeeds();
            setFeeds(r.feeds);
            setIsAdmin(r.isAdmin);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : "Falha ao carregar fontes");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (open) load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open]);

    useEffect(() => {
        if (!open) return;
        const timer = setInterval(() => void load(), 15000);
        return () => clearInterval(timer);
    }, [open]);

    const grouped = useMemo(() => {
        const byLayer = new Map<number, FeedSource[]>();
        for (const f of feeds) {
            if (search && !`${f.source} ${f.url}`.toLowerCase().includes(search.trim().toLowerCase())) continue;
            const arr = byLayer.get(f.layer) || [];
            arr.push(f);
            byLayer.set(f.layer, arr);
        }
        return [...byLayer.entries()].sort((a, b) => a[0] - b[0]);
    }, [feeds, search]);

    const enabledCount = feeds.filter((f) => f.enabled).length;
    const healthyCount = feeds.filter(f => f.enabled && f.health?.ok).length;

    const onToggle = async (f: FeedSource, enabled: boolean) => {
        setBusyUrl(f.url);
        try {
            setFeeds(await toggleFeed(f.url, enabled));
        } catch (e) {
            toast.error(e instanceof Error ? e.message : "Falha ao alterar fonte");
        } finally {
            setBusyUrl(null);
        }
    };

    const onDelete = async (f: FeedSource) => {
        setBusyUrl(f.url);
        try {
            setFeeds(await deleteFeed(f.url));
            toast.success(`Fonte removida: ${f.source}`);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : "Falha ao remover fonte");
        } finally {
            setBusyUrl(null);
        }
    };

    const onAdd = async () => {
        if (!newUrl.trim() || !newName.trim()) {
            toast.error("Informe URL e nome da fonte");
            return;
        }
        setAdding(true);
        try {
            setFeeds(await addFeed({
                url: newUrl.trim(),
                source: newName.trim(),
                layer: parseInt(newLayer, 10) || 2,
                weight_boost: 10,
            }));
            setNewUrl("");
            setNewName("");
            setNewLayer("2");
            toast.success("Fonte adicionada");
        } catch (e) {
            toast.error(e instanceof Error ? e.message : "Falha ao adicionar fonte");
        } finally {
            setAdding(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                    <Rss className="h-4 w-4" />
                    Fontes
                </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <Rss className="h-5 w-5" />
                        Fontes de notícias
                    </DialogTitle>
                    <DialogDescription>
                        {loading
                            ? "Carregando…"
                            : `${enabledCount} de ${feeds.length} habilitadas · ${healthyCount} responderam${isAdmin ? "" : " · somente leitura"}.`}
                    </DialogDescription>
                </DialogHeader>

                {isAdmin && (
                    <div className="rounded-lg border p-3 space-y-2">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            <div className="space-y-1">
                                <Label htmlFor="feed-name" className="text-xs">Nome da fonte</Label>
                                <Input id="feed-name" placeholder="Ex.: Acme Security Blog"
                                    value={newName} onChange={(e) => setNewName(e.target.value)} />
                            </div>
                            <div className="space-y-1">
                                <Label htmlFor="feed-layer" className="text-xs">Camada</Label>
                                <Select value={newLayer} onValueChange={setNewLayer}>
                                    <SelectTrigger id="feed-layer"><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                        {[1, 2, 3, 4].map((l) => (
                                            <SelectItem key={l} value={String(l)}>{l} · {LAYER_LABELS[l]}</SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>
                        <div className="space-y-1">
                            <Label htmlFor="feed-url" className="text-xs">URL do feed (RSS/Atom)</Label>
                            <Input id="feed-url" placeholder="https://exemplo.com/feed/"
                                value={newUrl} onChange={(e) => setNewUrl(e.target.value)}
                                onKeyDown={(e) => { if (e.key === "Enter") onAdd(); }} />
                        </div>
                        <Button size="sm" className="gap-2" onClick={onAdd} disabled={adding}>
                            {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                            Adicionar fonte
                        </Button>
                    </div>
                )}

                <div className="relative"><Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" /><Input aria-label="Buscar fonte de notícias" placeholder="Buscar por fonte ou domínio…" className="pl-9" value={search} onChange={event => setSearch(event.target.value)} /></div>
                <ScrollArea className="max-h-[50vh] pr-3">
                    <div className="space-y-4">
                        {grouped.map(([layer, list]) => (
                            <div key={layer} className="space-y-1.5">
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                    Camada {layer} · {LAYER_LABELS[layer] || "Outros"}
                                </div>
                                {list.map((f) => (
                                    <div key={f.url}
                                        className="flex items-center gap-3 rounded-md border px-3 py-2">
                                        <div className="min-w-0 flex-1">
                                            <div className="flex items-center gap-2">
                                                <span className="font-medium text-sm truncate">{f.source}</span>
                                                {!f.builtin && <Badge variant="secondary" className="text-[10px]">custom</Badge>}
                                                {f.kind === "auto" && <Badge variant="outline" className="text-[10px]">RSS / HTML</Badge>}
                                                {f.kind === "github" && <Badge variant="outline" className="text-[10px]">GitHub · IOCs</Badge>}
                                                <FeedStatus feed={f} />
                                            </div>
                                            <div className="text-xs text-muted-foreground truncate" title={f.health?.endpoint || f.url}>{f.health?.endpoint || f.url}</div>
                                        </div>
                                        {busyUrl === f.url ? (
                                            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                                        ) : isAdmin ? (
                                            <div className="flex items-center gap-2 shrink-0">
                                                <Switch checked={f.enabled}
                                                    onCheckedChange={(v) => onToggle(f, v)} />
                                                {!f.builtin && (
                                                    <Button variant="ghost" size="icon" className="h-8 w-8"
                                                        onClick={() => onDelete(f)}>
                                                        <Trash2 className="h-4 w-4 text-destructive" />
                                                    </Button>
                                                )}
                                            </div>
                                        ) : (
                                            <Badge variant={f.enabled ? "default" : "outline"} className="text-[10px] shrink-0">
                                                {f.enabled ? "habilitada" : "desativada"}
                                            </Badge>
                                        )}
                                    </div>
                                ))}
                            </div>
                        ))}
                        {!loading && !feeds.length && (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground py-6 justify-center">
                                <Lock className="h-4 w-4" /> Nenhuma fonte disponível.
                            </div>
                        )}
                    </div>
                </ScrollArea>
            </DialogContent>
        </Dialog>
    );
}

// Selo de saúde: verde = respondeu (com nº de itens), vermelho = erro no último
// ciclo, cinza = ainda não coletado.
function FeedStatus({ feed }: { feed: FeedSource }) {
    if (!feed.health) {
        return <span className="text-[10px] text-muted-foreground">aguardando coleta</span>;
    }
    if (feed.health.status === "collecting") return <span className="flex items-center gap-1 text-[10px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> coletando</span>;
    if (feed.health.ok) {
        return (
            <span className="flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-3 w-3" /> {feed.health.method === "github" ? "GitHub · " : feed.health.method === "html" ? "HTML · " : "RSS · "}{feed.health.count}{feed.health.status === "unchanged" ? " · sem alterações" : ""}
            </span>
        );
    }
    return (
        <span className="flex items-center gap-1 text-[10px] text-destructive" title={feed.health.error || ""}>
            <XCircle className="h-3 w-3" /> {feed.health.status === "stale" ? `erro · ${feed.health.count} em cache` : "erro"}
        </span>
    );
}
