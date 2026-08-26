import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchVendorQuotas, type VendorQuota } from "@/services/threatApi";

// Faixa de créditos abaixo da barra de busca. Existe porque o lote deixou de ter
// cap: o teto agora é a cota das bases, então ele precisa estar à vista antes de
// disparar 50 IOCs. As bases sem cota consultável viram uma linha só no fim —
// quinze chips "sem cota" seriam ruído.

const pct = (q: VendorQuota) =>
  q.limit && q.remaining !== null && q.remaining !== undefined ? q.remaining / q.limit : null;

const toneFor = (q: VendorQuota) => {
  const p = pct(q);
  if (p === null) return "border-border text-muted-foreground";
  if (p <= 0.05) return "border-red-500/40 bg-red-500/10 text-red-400";
  if (p <= 0.2) return "border-amber-500/40 bg-amber-500/10 text-amber-400";
  return "border-primary/25 bg-primary/5 text-foreground";
};

export const VendorQuotas = ({ refreshKey = 0 }: { refreshKey?: number }) => {
  const { auth } = useAuth();
  const { language } = useLanguage();
  const pt = language === "pt";
  const [quotas, setQuotas] = useState<VendorQuota[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setQuotas((await fetchVendorQuotas()).quotas);
    } catch {
      setQuotas([]); // cota é acessório: falhar aqui não pode atrapalhar a busca
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (auth.authenticated) load();
  }, [auth.authenticated, refreshKey, load]);

  if (!auth.authenticated || !quotas.length) return null;

  const withQuota = quotas.filter((q) => q.state !== "none");
  const noQuota = quotas.filter((q) => q.state === "none");

  const label = (q: VendorQuota) => {
    if (q.state === "unconfigured") return pt ? "sem chave" : "no key";
    if (q.state === "error") return pt ? "indisponível" : "unavailable";
    if (q.state === "pending") return pt ? "após a 1ª busca" : "after 1st search";
    if (q.remaining === null || q.remaining === undefined) {
      return `${pt ? "teto" : "cap"} ${q.limit?.toLocaleString()}`;
    }
    const per = q.period === "month" ? (pt ? "/mês" : "/mo") : (pt ? "/dia" : "/day");
    return q.limit ? `${q.remaining.toLocaleString()}/${q.limit.toLocaleString()}${per}` : `${q.remaining.toLocaleString()}${per}`;
  };

  return (
    <div className="mt-3 flex flex-wrap items-center gap-1.5 px-1">
      <span className="text-xs text-muted-foreground">{pt ? "créditos:" : "credits:"}</span>

      {withQuota.map((q) => (
        <span
          key={q.name}
          title={q.error || (q.resetAt ? `${pt ? "renova" : "resets"} ${new Date(q.resetAt).toLocaleString()}` : undefined)}
          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[10px] tracking-wide ${toneFor(q)}`}
        >
          <span className="font-semibold">{q.name}</span>
          <span className="opacity-70">{label(q)}</span>
        </span>
      ))}

      {noQuota.length > 0 && (
        <span
          className="text-[10px] text-muted-foreground/70"
          title={noQuota.map((q) => q.name).join(", ")}
        >
          +{noQuota.length} {pt ? "fontes sem cota" : "sources without quota"}
        </span>
      )}

      <button
        type="button"
        onClick={load}
        disabled={loading}
        title={pt ? "Atualizar créditos" : "Refresh credits"}
        className="ml-0.5 text-muted-foreground transition-colors hover:text-foreground disabled:opacity-40"
      >
        <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
      </button>
    </div>
  );
};
