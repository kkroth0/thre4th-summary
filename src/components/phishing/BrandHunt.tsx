// Caça a domínios: o que a vigilância do urlscan achou para as marcas do perfil
// da organização. Componente separado porque o PhishingAnalyzer já passa de mil
// linhas e as abas de lá pertencem ao e-mail analisado, não à página.
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState";
import { AlertTriangle, Check, Clock, ExternalLink, Loader2, RefreshCw, Search, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useLanguage } from "@/contexts/LanguageContext";
import { useOrgProfile } from "@/hooks/useOrgProfile";
import { toast } from "sonner";
import { defang } from "@/utils/defang";
import {
  fetchPhishHits, runPhishWatch, setPhishHitStatus,
  type PhishHit, type PhishHitStatus, type PhishRun,
} from "@/services/threatApi";

// Os motivos chegam do servidor como código justamente para a tradução morar
// aqui, onde já existe o idioma da tela.
const REASONS: Record<string, { pt: string; en: string }> = {
  "fresh-domain": { pt: "domínio de até 2 dias", en: "domain up to 2 days old" },
  "young-domain": { pt: "domínio de até 7 dias", en: "domain up to 7 days old" },
  "recent-domain": { pt: "domínio recente", en: "recent domain" },
  "brand-glued": { pt: "marca colada em outra palavra", en: "brand glued to another word" },
  certstream: { pt: "pescado no Certificate Transparency", en: "caught in Certificate Transparency" },
  "live-page": { pt: "página no ar", en: "page is live" },
  // Resolução DNS contínua (recheckHitsDns) — independente do urlscan reescanear.
  "dns-went-live": { pt: "domínio começou a resolver (A/AAAA)", en: "domain started resolving (A/AAAA)" },
  "dns-mx-appeared": { pt: "MX configurado — pronto para e-mail", en: "MX configured — ready for email" },
  "dns-infra-changed": { pt: "trocou de IP ou nameserver", en: "IP or nameserver changed" },
};

const scoreTone = (score: number): string =>
  (score >= 80 ? "text-red-500 border-red-500/30 bg-red-500/10"
    : score >= 50 ? "text-amber-500 border-amber-500/30 bg-amber-500/10"
      : "text-muted-foreground border-border/60");

const sinceLabel = (iso: string | undefined, pt: boolean): string => {
  if (!iso) return pt ? "nunca" : "never";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (!Number.isFinite(minutes)) return "—";
  if (minutes < 1) return pt ? "agora" : "just now";
  if (minutes < 60) return pt ? `há ${minutes} min` : `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return pt ? `há ${hours} h` : `${hours} h ago`;
};

export function BrandHunt() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const { profiles, activeId, setActiveId, loading: loadingProfiles } = useOrgProfile();

  const [status, setStatus] = useState<PhishHitStatus>("new");
  const [hits, setHits] = useState<PhishHit[]>([]);
  const [run, setRun] = useState<PhishRun | null>(null);
  const [configured, setConfigured] = useState(true);
  const [loading, setLoading] = useState(false);
  const [hunting, setHunting] = useState(false);

  const profile = profiles.find((item) => item.id === activeId) || null;
  const brands = profile?.brands ?? [];

  const load = useCallback(async (profileId: string, next: PhishHitStatus) => {
    setLoading(true);
    try {
      const data = await fetchPhishHits(profileId, next);
      setHits(data.hits);
      setRun(data.run);
      setConfigured(data.configured);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : (pt ? "Falha ao carregar" : "Failed to load"));
    } finally {
      setLoading(false);
    }
  }, [pt]);

  useEffect(() => {
    if (!activeId) { setHits([]); setRun(null); return; }
    load(activeId, status);
  }, [activeId, status, load]);

  const hunt = async () => {
    if (!activeId) return;
    setHunting(true);
    try {
      const data = await runPhishWatch(activeId);
      setRun(data.run);
      if (status === "new") setHits(data.hits); else await load(activeId, status);
      toast.success(data.found
        ? (pt ? `${data.found} domínio(s) novo(s)` : `${data.found} new domain(s)`)
        : (pt ? "Nenhum domínio novo" : "No new domains"));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : (pt ? "Falha na busca" : "Search failed"));
    } finally {
      setHunting(false);
    }
  };

  // A triagem tira o item da lista atual na hora: quem dispensou não quer vê-lo
  // de novo, e quem confirmou já está olhando para o próximo.
  const triage = async (hit: PhishHit, next: PhishHitStatus) => {
    setHits((current) => current.filter((item) => item.id !== hit.id));
    try {
      await setPhishHitStatus(hit.id, next);
    } catch (error) {
      setHits((current) => [hit, ...current]);
      toast.error(error instanceof Error ? error.message : (pt ? "Falha na triagem" : "Triage failed"));
    }
  };

  const filters: { key: PhishHitStatus; label: string }[] = [
    { key: "new", label: pt ? "Novos" : "New" },
    { key: "confirmed", label: pt ? "Confirmados" : "Confirmed" },
    { key: "dismissed", label: pt ? "Dispensados" : "Dismissed" },
  ];

  if (loadingProfiles) {
    return <div className="flex items-center gap-2 p-8 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> …</div>;
  }

  if (!profiles.length) {
    return (
      <Card className="border-dashed">
        <CardContent className="space-y-3 p-8 text-center">
          <ShieldAlert className="mx-auto h-10 w-10 text-muted-foreground/50" />
          <p className="text-sm text-muted-foreground">
            {pt
              ? "A caça usa as marcas do perfil da organização, e você ainda não tem perfil."
              : "The hunt uses the brands from your organization profile, and you don't have one yet."}
          </p>
          <Button asChild variant="outline" size="sm"><Link to="/settings">{pt ? "Criar perfil" : "Create profile"}</Link></Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 rounded-lg border bg-card p-3 xl:flex-row xl:items-center">
        <select
          value={activeId}
          onChange={(event) => setActiveId(event.target.value)}
          className="rounded-md border bg-background px-2 py-1.5 text-xs"
          aria-label={pt ? "Perfil da organização" : "Organization profile"}
        >
          <option value="">{pt ? "Escolha um perfil" : "Pick a profile"}</option>
          {profiles.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>

        <div className="flex flex-wrap items-center gap-1.5">
          {brands.map((brand) => <Badge key={brand} variant="secondary" className="text-[11px]">{brand}</Badge>)}
        </div>

        <div className="flex items-center gap-2 xl:ml-auto">
          <span className="flex items-center gap-1.5 whitespace-nowrap text-xs text-muted-foreground">
            <Clock className="h-3.5 w-3.5" />
            {pt ? "última rodada " : "last run "}{sinceLabel(run?.lastRunAt, pt)}
          </span>
          <Button size="sm" className="h-8 gap-1.5 text-xs" disabled={!activeId || !brands.length || hunting || !configured} onClick={hunt}>
            {hunting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
            {pt ? "Buscar agora" : "Hunt now"}
          </Button>
        </div>
      </div>

      {!configured && (
        <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-600">
          {pt
            ? "A chave do urlscan não está configurada no servidor (URLSCAN_API_KEY); a vigilância está parada."
            : "The urlscan key is not configured on the server (URLSCAN_API_KEY); the watch is idle."}
        </p>
      )}

      {run?.lastStatus === "error" && run.lastError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
          {pt ? "Última rodada falhou: " : "Last run failed: "}{run.lastError}
        </p>
      )}

      {activeId && !brands.length && (
        <Card className="border-dashed">
          <CardContent className="space-y-3 p-8 text-center">
            <p className="text-sm text-muted-foreground">
              {pt
                ? "Este perfil não tem marcas cadastradas, então não há o que vigiar."
                : "This profile has no brands registered, so there is nothing to watch."}
            </p>
            <Button asChild variant="outline" size="sm">
              <Link to="/settings">{pt ? "Cadastrar marcas no perfil" : "Add brands to the profile"}</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="flex flex-wrap gap-2">
        {filters.map((filter) => (
          <button
            key={filter.key}
            type="button"
            onClick={() => setStatus(filter.key)}
            aria-pressed={status === filter.key}
            className={`rounded-full border px-3 py-1 text-xs transition ${status === filter.key ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
          >
            {filter.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((n) => <div key={n} className="h-24 animate-pulse rounded-lg border bg-card" />)}
        </div>
      ) : !hits.length ? (
        <EmptyState
          title={status === "new"
            ? (pt ? "Nenhum domínio novo nas últimas rodadas" : "No new domains in the latest runs")
            : (pt ? "Nada nesta aba ainda" : "Nothing in this tab yet")}
          description={status === "new"
            ? (pt ? "O que é boa notícia: ninguém registrou parecido com a sua marca no período." : "Which is good news: nobody registered anything close to your brand in the period.")
            : (pt ? "Rode uma caçada para popular esta lista." : "Run a hunt to populate this list.")}
        />
      ) : (
        <div className="space-y-3">
          {hits.map((hit) => (
            <Card key={hit.id} className="overflow-hidden">
              <CardContent className="flex flex-col gap-3 p-3 sm:flex-row">
                {hit.screenshot && (
                  <a href={hit.scanUrl} target="_blank" rel="noopener noreferrer" className="shrink-0">
                    <img
                      src={hit.screenshot}
                      alt=""
                      loading="lazy"
                      referrerPolicy="no-referrer"
                      className="h-24 w-40 rounded border object-cover object-top"
                    />
                  </a>
                )}

                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Defangado: domínio de phishing não vira link clicável por acidente. */}
                    <span className="break-all font-mono text-sm font-semibold">{defang(hit.domain)}</span>
                    <Badge variant="outline" className={`text-[10px] tabular-nums ${scoreTone(hit.score)}`}>{hit.score}</Badge>
                    {hit.apexAgeDays !== null && (
                      <Badge variant="outline" className="text-[10px]">
                        {hit.apexAgeDays === 0
                          ? (pt ? "registrado hoje" : "registered today")
                          : (pt ? `${hit.apexAgeDays} dia(s)` : `${hit.apexAgeDays} day(s)`)}
                      </Badge>
                    )}
                    {hit.term && <Badge variant="secondary" className="text-[10px]">{hit.term}</Badge>}
                  </div>

                  {hit.title && <p className="truncate text-xs text-muted-foreground">{hit.title}</p>}

                  <div className="flex flex-wrap gap-1.5">
                    {hit.reasons.map((reason) => (
                      <span key={reason} className="rounded-full border px-2 py-0.5 text-[10px] text-muted-foreground">
                        {REASONS[reason] ? (pt ? REASONS[reason].pt : REASONS[reason].en) : reason}
                      </span>
                    ))}
                  </div>

                  <p className="text-[11px] text-muted-foreground">
                    {sinceLabel(hit.lastSeen, pt)}
                    {hit.country ? ` · ${hit.country}` : ""}
                    {hit.asn ? ` · ${hit.asn}` : ""}
                  </p>
                </div>

                <div className="flex shrink-0 flex-row gap-1.5 sm:flex-col">
                  <Button asChild variant="outline" size="sm" className="h-8 gap-1.5 text-xs">
                    <a href={hit.scanUrl} target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="h-3.5 w-3.5" /> urlscan
                    </a>
                  </Button>
                  {hit.status !== "confirmed" && (
                    <Button variant="outline" size="sm" className="h-8 gap-1.5 border-red-500/30 text-xs text-red-500 hover:bg-red-500/5" onClick={() => triage(hit, "confirmed")}>
                      <AlertTriangle className="h-3.5 w-3.5" /> {pt ? "É phishing" : "Phishing"}
                    </Button>
                  )}
                  {hit.status !== "dismissed" ? (
                    <Button variant="ghost" size="sm" className="h-8 gap-1.5 text-xs text-muted-foreground" onClick={() => triage(hit, "dismissed")}>
                      <X className="h-3.5 w-3.5" /> {pt ? "Dispensar" : "Dismiss"}
                    </Button>
                  ) : (
                    <Button variant="ghost" size="sm" className="h-8 gap-1.5 text-xs text-muted-foreground" onClick={() => triage(hit, "new")}>
                      <RefreshCw className="h-3.5 w-3.5" /> {pt ? "Devolver" : "Restore"}
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {status === "confirmed" && hits.length > 0 && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Check className="h-3.5 w-3.5" />
          {pt ? "Confirmados não expiram." : "Confirmed hits never expire."}
        </p>
      )}
    </div>
  );
}
