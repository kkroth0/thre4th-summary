import React, { useEffect, useMemo, useState } from "react";
import { ChevronDown, Crosshair, ExternalLink, FileText, Loader2 } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { BrandMark } from "@/components/BrandMark";
import { BoletimView } from "@/components/BoletimView";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { downloadBoletimDeck, fetchJobRelated, type BoletimJob, type BoletimReport, type PrivateHunt } from "@/services/threatApi";
import { buildHuntLink } from "@/pages/dailyBulletinView";
import { exportBoletimJSON } from "@/utils/boletimExport";

// Host da URL pra exibição compacta ("fortiguard.com" em vez do link inteiro).
export const hostOf = (url?: string): string => {
  try { return url ? new URL(url).host : ""; } catch { return ""; }
};

const fmtDate = (iso: string | undefined, pt: boolean) => {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(+d) ? "" : d.toLocaleDateString(pt ? "pt-BR" : "en-US");
};

// Modelo e custo de LLM da geração, discretos na toolbar. Os valores são de
// centésimos de centavo, então 4 casas; abaixo disso mostra "<$0.0001".
// Boletins gerados antes deste campo (ou em --dry-run) não mostram nada.
const usageTag = (c: BoletimReport["consumo"], pt: boolean): React.ReactNode => {
  const usd = c?.custo_usd;
  const models = c?.modelos || [];
  if (!models.length && !(typeof usd === "number" && usd > 0)) return null;
  // O id vem "provedor/modelo"; o provedor é ruído na toolbar e fica no title.
  // Mais de um modelo = a cadeia caiu pro fallback no meio do boletim — mostra
  // todos, senão o custo parece vir de um modelo que não foi o único usado.
  const label = models.map((m) => m.split("/").pop()).join(" + ");
  const detail = [
    models.join(", "),
    c?.chamadas ? `${c.chamadas} ${pt ? "chamadas" : "calls"}` : "",
    c?.tokens_in ? `${c.tokens_in.toLocaleString()} tokens in` : "",
    c?.tokens_out ? `${c.tokens_out.toLocaleString()} out` : "",
  ].filter(Boolean).join(" · ");
  return (
    <span className="font-mono text-xs text-muted-foreground" title={detail}>
      {label}
      {typeof usd === "number" && usd > 0 && (
        <span className="ml-1.5 text-foreground/70">
          {usd < 0.0001 ? "<$0.0001" : `$${usd.toFixed(4)}`}
        </span>
      )}
    </span>
  );
};

function ReportRelations({ job, pt }: { job: BoletimJob; pt: boolean }) {
  const [related, setRelated] = useState<{ hunts: PrivateHunt[]; reports: BoletimJob[] } | null>(null);
  useEffect(() => {
    let live = true;
    fetchJobRelated(job.id).then((value) => { if (live) setRelated(value); }).catch(() => {});
    return () => { live = false; };
  }, [job.id]);

  const huntLink = useMemo(() => {
    const report = job.json;
    const techniques = job.techniques?.length
      ? job.techniques
      : (report?.mitre_ttps || []).map((item) => item.id || "").filter(Boolean);
    const cves = job.cves?.length
      ? job.cves
      : [report?.cve_id, ...(report?.tecnologias_afetadas || []).map((item) => item.cve)].filter(Boolean) as string[];
    return buildHuntLink({ id: job.id, title: report?.titulo || job.title, techniques, cves });
  }, [job]);

  return (
    <section className="mt-8 border-t pt-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div><h3 className="text-sm font-semibold">{pt ? "Desdobramentos" : "Follow-ups"}</h3><p className="text-xs text-muted-foreground">{pt ? "Hunts e relatórios ligados por técnica ou CVE." : "Hunts and reports linked by technique or CVE."}</p></div>
        <Button asChild size="sm"><Link to={huntLink}><Crosshair className="mr-2 h-4 w-4" /> {pt ? "Criar hunt" : "Create hunt"}</Link></Button>
      </div>
      {!!(related?.hunts.length || related?.reports.length) && (
        <div className="mt-4 grid gap-2 sm:grid-cols-2">
          {related?.hunts.slice(0, 4).map((hunt) => (
            <Link key={hunt.id} to={`/hunting?query=${encodeURIComponent(hunt.title)}`} className="rounded-md border p-3 text-sm hover:border-primary/40 hover:bg-muted/40">
              <Crosshair className="mb-2 h-4 w-4 text-primary" /><span className="line-clamp-2 font-medium">{hunt.title}</span>
            </Link>
          ))}
          {related?.reports.slice(0, 4).map((report) => (
            <Link key={report.id} to={`/relatorios?job=${encodeURIComponent(report.id)}`} className="rounded-md border p-3 text-sm hover:border-primary/40 hover:bg-muted/40">
              <FileText className="mb-2 h-4 w-4 text-primary" /><span className="line-clamp-2 font-medium">{report.title || report.url}</span>
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}

// Um botão só: o formato é escolha de quem exporta, não três botões na toolbar.
// PPTX e PDF já vêm prontos da VPS (o PDF é o próprio deck convertido) e aqui é
// só o download; o JSON é local. A espera do download é o que o "gerando" cobre.
function ExportMenu({ job, pt }: { job: BoletimJob; pt: boolean }) {
  const { auth } = useAuth();
  const [busy, setBusy] = useState(false);
  const run = async (format: "json" | "pdf" | "pptx") => {
    setBusy(true);
    try {
      if (format === "json") exportBoletimJSON(job);
      else await downloadBoletimDeck(job, format);
    } catch (error) {
      toast.error((error as Error).message || (pt ? "Falha ao exportar" : "Export failed"));
    } finally {
      setBusy(false);
    }
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5" disabled={busy}>
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
          {pt ? "Exportar" : "Export"}
          <ChevronDown className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onSelect={() => void run("json")}>JSON</DropdownMenuItem>
        {/* Deck e PDF só existem se o worker os anexou. Boletim antigo não tem, e
            oferecer o item levaria a um 404 — ou pior, num navegador com a aba
            velha em memória, a um arquivo montado pelo código antigo, com o nome
            certo e o conteúdo errado. */}
        <DropdownMenuItem disabled={!job.deck?.pdf} onSelect={() => void run("pdf")}>
          PDF{job.deck?.pdf ? "" : pt ? " — indisponível" : " — unavailable"}
        </DropdownMenuItem>
        {/* O PPTX é a fonte editável no template SRR: só admin. O servidor
            também recusa — esconder aqui é só não oferecer o que dá 403. */}
        {auth.isAdmin && (
          <DropdownMenuItem disabled={!job.deck?.pptx} onSelect={() => void run("pptx")}>
            PowerPoint (PPTX){job.deck?.pptx ? "" : pt ? " — indisponível" : " — unavailable"}
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// Painel de leitura da workstation: toolbar com meta/ações + BoletimView.
// `job === null` (ou sem JSON) mostra o estado vazio.
export function ReportPane({ job }: { job: BoletimJob | null }) {
  const { language } = useLanguage();
  const pt = language === "pt";

  if (!job || !job.json) {
    return (
      <div className="flex min-h-[420px] flex-col items-center justify-center gap-4 rounded-lg border border-dashed border-border/60 p-8 text-center">
        <BrandMark className="h-11 w-11 opacity-80" />
        <div>
          <div className="text-sm font-medium">{pt ? "Nenhum relatório aberto" : "No report open"}</div>
          <p className="mt-1 max-w-[36ch] text-xs text-muted-foreground">
            {pt
              ? "Selecione um relatório pronto na lista ou cole uma URL para gerar um novo."
              : "Select a finished report from the list or paste a URL to generate a new one."}
          </p>
        </div>
      </div>
    );
  }

  const r = job.json;
  const usage = usageTag(r.consumo, pt);
  return (
    <div className="rounded-lg border bg-card/40 p-5 lg:p-6">
      {/* toolbar: meta à esquerda, ações à direita */}
      <div className="flex flex-wrap items-center gap-2">
        {r.tlp && (
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
            TLP:{r.tlp}
          </Badge>
        )}
        <Badge variant="secondary" className="font-mono text-[10px] uppercase">{job.type}</Badge>
        {r.generated_at && (
          <span className="text-xs text-muted-foreground" title={pt ? "Geração do boletim" : "Report generated"}>
            {fmtDate(r.generated_at, pt)}
          </span>
        )}
        {/* Publicação da FONTE. Rotulada porque sem isso vira sósia da data acima —
            e um advisory de dois anos passaria por novidade. */}
        {r.source_published && fmtDate(r.source_published, pt) && (
          <span className="text-xs text-muted-foreground" title={pt ? "Publicação da fonte" : "Source published"}>
            {pt ? "fonte" : "source"} {fmtDate(r.source_published, pt)}
          </span>
        )}
        {r.source_url && (
          <a
            href={r.source_url} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
          >
            {hostOf(r.source_url)} <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        )}
        <div className="ml-auto flex items-center gap-2">
          {usage}
          <ExportMenu job={job} pt={pt} />
        </div>
      </div>

      <h2 className="mt-4 text-lg font-semibold leading-snug">
        {r.titulo || job.title || job.url}
      </h2>

      <BoletimView report={r} />
      <ReportRelations job={job} pt={pt} />
    </div>
  );
}

export default ReportPane;
