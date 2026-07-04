import { useEffect, useState } from "react";
import { History, Trash2, Loader2, Search, AlertTriangle, ShieldCheck, HelpCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
    Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogTrigger,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchScans, deleteScan, type SavedScan } from "@/services/threatApi";

const levelBadge = (level: string) => {
    switch (level) {
        case "malicious": return { icon: AlertTriangle, cls: "text-destructive border-destructive/40" };
        case "suspicious": return { icon: HelpCircle, cls: "text-amber-600 dark:text-amber-400 border-amber-500/40" };
        case "safe": return { icon: ShieldCheck, cls: "text-emerald-600 dark:text-emerald-400 border-emerald-500/40" };
        default: return { icon: HelpCircle, cls: "text-muted-foreground border-muted" };
    }
};

// Histórico de scans salvos do usuário (persistido no servidor). Clicar numa
// linha re-executa a busca via onPick; a lixeira remove.
export function ScanHistory({ onPick }: { onPick: (query: string) => void }) {
    const { language, tr } = useLanguage();
    const pt = language === "pt";
    const [open, setOpen] = useState(false);
    const [scans, setScans] = useState<SavedScan[]>([]);
    const [loading, setLoading] = useState(false);
    const [busyId, setBusyId] = useState<string | null>(null);

    useEffect(() => {
        if (!open) return;
        setLoading(true);
        fetchScans()
            .then(setScans)
            .catch((e) => toast.error(e instanceof Error ? e.message : tr({ pt: "Falha ao carregar histórico", en: "Failed to load history", es: "Error al cargar el historial", fr: "Échec du chargement de l'historique" })))
            .finally(() => setLoading(false));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open]);

    const onDelete = async (id: string) => {
        setBusyId(id);
        try { setScans(await deleteScan(id)); }
        catch (e) { toast.error(e instanceof Error ? e.message : tr({ pt: "Falha ao remover", en: "Failed to delete", es: "Error al eliminar", fr: "Échec de la suppression" })); }
        finally { setBusyId(null); }
    };

    const pick = (q: string) => { setOpen(false); onPick(q); };

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="h-9 px-4 rounded-full border-primary/20 hover:bg-primary/10 shadow-sm flex items-center gap-2">
                    <History className="h-4 w-4" />
                    <span>{tr({ pt: "Histórico", en: "History", es: "Historial", fr: "Historique" })}</span>
                </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2"><History className="h-5 w-5" /> {tr({ pt: "Scans salvos", en: "Saved scans", es: "Escaneos guardados", fr: "Scans enregistrés" })}</DialogTitle>
                    <DialogDescription>{tr({ pt: "Seus scans salvos, sincronizados na sua conta. Clique para refazer.", en: "Your saved scans, synced to your account. Click to re-run.", es: "Tus escaneos guardados, sincronizados en tu cuenta. Haz clic para repetir.", fr: "Vos scans enregistrés, synchronisés sur votre compte. Cliquez pour relancer." })}</DialogDescription>
                </DialogHeader>
                <ScrollArea className="max-h-[55vh] pr-3">
                    {loading ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground py-8 justify-center">
                            <Loader2 className="h-4 w-4 animate-spin" /> {tr({ pt: "Carregando…", en: "Loading…", es: "Cargando…", fr: "Chargement…" })}
                        </div>
                    ) : !scans.length ? (
                        <div className="text-sm text-muted-foreground py-8 text-center">{tr({ pt: "Nenhum scan salvo ainda.", en: "No saved scans yet.", es: "Aún no hay escaneos guardados.", fr: "Aucun scan enregistré pour l'instant." })}</div>
                    ) : (
                        <div className="space-y-1.5">
                            {scans.map((s) => {
                                const b = levelBadge(s.threatLevel);
                                const Icon = b.icon;
                                return (
                                    <div key={s.id} className="flex items-center gap-3 rounded-md border px-3 py-2">
                                        <button className="min-w-0 flex-1 flex items-center gap-2 text-left" onClick={() => pick(s.query)}>
                                            <Search className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                                            <span className="font-mono text-sm truncate">{s.query}</span>
                                        </button>
                                        <Badge variant="outline" className={`text-[10px] gap-1 shrink-0 ${b.cls}`}>
                                            <Icon className="h-3 w-3" /> {s.detections}/{s.totalVendors}
                                        </Badge>
                                        {busyId === s.id ? (
                                            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground shrink-0" />
                                        ) : (
                                            <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => onDelete(s.id)}>
                                                <Trash2 className="h-4 w-4 text-destructive" />
                                            </Button>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </ScrollArea>
            </DialogContent>
        </Dialog>
    );
}
