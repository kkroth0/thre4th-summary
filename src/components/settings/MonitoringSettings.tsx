import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, Rss, Target } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import FeedSourcesManager from "@/components/FeedSourcesManager";
import { OrgProfileEditor } from "@/components/settings/OrgProfileEditor";
import { NewsVendorMonitoring } from "@/components/settings/NewsVendorMonitoring";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchExposureAssets } from "@/services/threatApi";

// Tudo que responde "o que este app está observando" mora aqui: o contexto que
// filtra, as fontes que coletam, e os ativos que são varridos. Os resultados
// continuam nas telas donas de cada assunto — este é o painel de configuração.
export function MonitoringSettings() {
  const { language } = useLanguage();
  const pt = language === "pt";
  // Estado único evita confundir "carregando" com "erro": só vira número
  // quando a promise resolve, então os dois nunca caem no mesmo ramo do render.
  const [assetState, setAssetState] = useState<"loading" | "error" | number>("loading");
  const [lastRun, setLastRun] = useState<string | null>(null);

  useEffect(() => {
    fetchExposureAssets()
      .then((assets) => {
        setAssetState(assets.length);
        const runs = assets.map((asset) => asset.lastRunAt).filter(Boolean).sort();
        setLastRun(runs.length ? String(runs[runs.length - 1]) : null);
      })
      // Falha na watchlist não pode derrubar a aba inteira: mostramos estado
      // indisponível e seguimos com o resto do painel funcionando.
      .catch(() => setAssetState("error"));
  }, []);

  return (
    <div className="flex flex-col gap-4">

      <NewsVendorMonitoring />

      <OrgProfileEditor />

      <Card className="rounded-sm shadow-none">
        <CardHeader className="p-4 pb-3">
          <CardTitle className="flex items-center gap-2 text-sm"><Rss className="h-4 w-4 text-muted-foreground" /> {pt ? "Fontes de notícias" : "News sources"}</CardTitle>
          <CardDescription>
            {pt ? "RSS/Atom e páginas de publicações da coleta. Edição restrita a administradores." : "RSS/Atom feeds and publication pages. Editing is restricted to administrators."}
          </CardDescription>
        </CardHeader>
        <CardContent className="px-4 pb-4"><FeedSourcesManager /></CardContent>
      </Card>

      <Card className="rounded-sm shadow-none">
        <CardHeader className="p-4 pb-3">
          <CardTitle className="flex items-center gap-2 text-sm"><Target className="h-4 w-4 text-muted-foreground" /> {pt ? "Ativos monitorados" : "Monitored assets"}</CardTitle>
          <CardDescription>
            {assetState === "loading"
              ? (pt ? "Carregando watchlist…" : "Loading watchlist…")
              : assetState === "error"
                ? (pt ? "Watchlist indisponível." : "Watchlist unavailable.")
                : assetState === 0
                  // EST-04: "0 ativo(s) na watchlist." não convidava a nada.
                  // Estado vazio precisa dizer o que entra ali e para que serve.
                  ? (pt
                    ? "Nenhum domínio ou IP na watchlist de exposição."
                    : "No domains or IPs in the exposure watchlist.")
                  : pt
                    ? `${assetState} ativo(s) na watchlist${lastRun ? ` · última varredura em ${new Date(lastRun).toLocaleString("pt-BR")}` : ""}.`
                    : `${assetState} asset(s) on the watchlist${lastRun ? ` · last scan ${new Date(lastRun).toLocaleString("en-US")}` : ""}.`}
          </CardDescription>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          {/* Resumo e link, não um segundo CRUD: a tela de resultados continua dona do assunto. */}
          <Button asChild size="sm" variant="outline">
            <Link to="/attack-surface?mode=monitor">
              {pt ? "Gerenciar ativos" : "Manage assets"}<ArrowUpRight className="h-4 w-4" />
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
