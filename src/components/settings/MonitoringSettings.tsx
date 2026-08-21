import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Radar, Rss, Target } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import FeedSourcesManager from "@/components/FeedSourcesManager";
import { OrgProfileEditor } from "@/components/settings/OrgProfileEditor";
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
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="flex items-center gap-2 text-xl font-semibold"><Radar className="text-primary" /> {pt ? "Monitoramento" : "Monitoring"}</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {pt ? "O contexto que filtra, as fontes que coletam e os ativos que são varridos." : "The context that filters, the sources that collect, and the assets that get scanned."}
        </p>
      </div>

      <OrgProfileEditor />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Rss className="text-primary" /> {pt ? "Fontes de coleta" : "Collection sources"}</CardTitle>
          <CardDescription>
            {pt ? "Os feeds que alimentam as Notícias. Qualquer conta vê o catálogo; só admin edita." : "The feeds behind the news. Any account sees the catalog; only admins edit it."}
          </CardDescription>
        </CardHeader>
        <CardContent><FeedSourcesManager /></CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Target className="text-primary" /> {pt ? "Ativos monitorados" : "Monitored assets"}</CardTitle>
          <CardDescription>
            {assetState === "loading"
              ? (pt ? "Carregando watchlist…" : "Loading watchlist…")
              : assetState === "error"
                ? (pt ? "Watchlist indisponível." : "Watchlist unavailable.")
                : pt
                  ? `${assetState} ativo(s) na watchlist${lastRun ? ` · última varredura em ${new Date(lastRun).toLocaleString("pt-BR")}` : ""}.`
                  : `${assetState} asset(s) on the watchlist${lastRun ? ` · last scan ${new Date(lastRun).toLocaleString("en-US")}` : ""}.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Resumo e link, não um segundo CRUD: a tela de resultados continua dona do assunto. */}
          <Button asChild variant="outline"><Link to="/attack-surface?mode=monitor">{pt ? "Abrir a watchlist" : "Open the watchlist"}</Link></Button>
        </CardContent>
      </Card>
    </div>
  );
}
