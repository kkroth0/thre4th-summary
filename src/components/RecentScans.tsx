import { useEffect, useState } from "react";
import { History, Loader2 } from "lucide-react";
import { fetchScans, type SavedScan } from "@/services/threatApi";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";

// DEN-04: a tela de entrada da busca usava um terço da altura e deixava o resto
// em branco, e o histórico de consultas só existia dentro de um modal que
// aparece depois do primeiro resultado — ou seja, nunca na hora em que ajudaria.
//
// Esta lista é a versão inline: as últimas consultas com o veredito que deram,
// clicáveis para refazer. Não é o modal: aqui não dá para apagar, porque a ação
// destrutiva não deve ficar no caminho de quem só quer repetir uma busca.

const VERDICT: Record<string, { pt: string; en: string; tone: string }> = {
  malicious: { pt: "Malicioso", en: "Malicious", tone: "text-red-700 dark:text-red-400" },
  suspicious: { pt: "Suspeito", en: "Suspicious", tone: "text-amber-700 dark:text-amber-400" },
  safe: { pt: "Limpo", en: "Clean", tone: "text-emerald-700 dark:text-emerald-400" },
  unknown: { pt: "Inconclusivo", en: "Inconclusive", tone: "text-muted-foreground" },
};

const relDay = (iso: string, pt: boolean): string => {
  const dias = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (Number.isNaN(dias)) return "";
  if (dias <= 0) return pt ? "hoje" : "today";
  if (dias === 1) return pt ? "ontem" : "yesterday";
  return pt ? `há ${dias} dias` : `${dias}d ago`;
};

export const RecentScans = ({ onPick, limit = 6 }: { onPick: (query: string) => void; limit?: number }) => {
  const { auth } = useAuth();
  const { language } = useLanguage();
  const pt = language === "pt";
  const [scans, setScans] = useState<SavedScan[] | null>(null);

  useEffect(() => {
    if (!auth.authenticated) return;
    // Histórico é acessório: falhar aqui não pode atrapalhar a busca.
    fetchScans().then((lista) => setScans(lista.slice(0, limit))).catch(() => setScans([]));
  }, [auth.authenticated, limit]);

  if (!auth.authenticated) return null;
  if (scans === null) {
    return (
      <div className="flex items-center gap-2 px-1 py-3 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> {pt ? "Carregando consultas recentes…" : "Loading recent searches…"}
      </div>
    );
  }
  if (!scans.length) return null;

  return (
    <section className="mt-6">
      <h2 className="mb-2 flex items-center gap-1.5 px-1 text-[11px] font-black uppercase tracking-wide text-muted-foreground">
        <History className="h-3.5 w-3.5" /> {pt ? "Suas últimas consultas" : "Your recent searches"}
      </h2>
      <ul className="divide-y divide-border/60 overflow-hidden rounded-lg border border-border">
        {scans.map((scan) => {
          const verdito = VERDICT[scan.threatLevel] || VERDICT.unknown;
          return (
            <li key={scan.id}>
              <button
                type="button"
                onClick={() => onPick(scan.query)}
                className="flex w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-muted/40"
              >
                <span className="min-w-0 flex-1 truncate font-mono text-xs">{scan.query}</span>
                <span className={`shrink-0 text-xs font-semibold ${verdito.tone}`}>{pt ? verdito.pt : verdito.en}</span>
                <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                  {scan.detections}/{scan.totalVendors}
                </span>
                <span className="hidden shrink-0 text-xs text-muted-foreground sm:inline">{relDay(scan.at, pt)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
};
