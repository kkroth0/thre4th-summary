import React, { useEffect, useState } from "react";
import { ChevronDown, ExternalLink, FileText, Loader2 } from "lucide-react";
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
import { downloadBoletimDeck, fetchJobRelated, type BoletimJob, type BoletimReport } from "@/services/threatApi";
import { exportBoletimJSON, exportBoletimIocsExcel, canExportBoletimIocs } from "@/utils/boletimExport";

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
  const [related, setRelated] = useState<{ reports: BoletimJob[] } | null>(null);
  useEffect(() => {
    let live = true;
    fetchJobRelated(job.id).then((value) => { if (live) setRelated(value); }).catch(() => {});
    return () => { live = false; };
  }, [job.id]);

  if (!related?.reports.length) return null;

  return (
    <section className="mt-8 border-t pt-5">
      <div><h3 className="text-sm font-semibold">{pt ? "Desdobramentos" : "Follow-ups"}</h3><p className="text-xs text-muted-foreground">{pt ? "Relatórios ligados por técnica ou CVE." : "Reports linked by technique or CVE."}</p></div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        {related.reports.slice(0, 4).map((report) => (
          <Link key={report.id} to={`/relatorios?job=${encodeURIComponent(report.id)}`} className="rounded-md border p-3 text-sm hover:border-primary/40 hover:bg-muted/40">
            <FileText className="mb-2 h-4 w-4 text-primary" /><span className="line-clamp-2 font-medium">{report.title || report.url}</span>
          </Link>
        ))}
      </div>
    </section>
  );
}

// Um botão só: o formato é escolha de quem exporta, não três botões na toolbar.
// PPTX e PDF já vêm prontos da VPS (o PDF é o próprio deck convertido) e aqui é
// só o download; o JSON é local. A espera do download é o que o "gerando" cobre.
function ExportMenu({ job, pt }: { job: BoletimJob; pt: boolean }) {
  const { auth } = useAuth();
  const [busy, setBusy] = useState(false);
  const run = async (format: "json" | "pdf" | "pptx" | "iocs") => {
    setBusy(true);
    try {
      if (format === "json") exportBoletimJSON(job);
      else if (format === "iocs") await exportBoletimIocsExcel(job);
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
        {/* Só o que o deck não mostra por inteiro: o template de campanha lista no
            máximo 6 IOCs, e o de vulnerabilidade não tem slide de IOCs nenhum. */}
        <DropdownMenuItem disabled={!canExportBoletimIocs(job)} onSelect={() => void run("iocs")}>
          IOCs (Excel){canExportBoletimIocs(job) ? "" : pt ? " — indisponível" : " — unavailable"}
        </DropdownMenuItem>
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
export function ReportPane({ job, onCreate }: { job: BoletimJob | null; onCreate?: () => void }) {
  const { language } = useLanguage();
  const pt = language === "pt";

  if (!job || !job.json) {
    return (
      <div className="flex min-h-[480px] flex-col items-center justify-center gap-4 rounded-md border bg-card p-8 text-center">
        <BrandMark className="h-11 w-11 opacity-80" />
        <div>
          <div className="text-base font-semibold">{pt ? "Sua área de análise" : "Your analysis workspace"}</div>
          <p className="mt-1 max-w-[36ch] text-xs text-muted-foreground">
            {pt
              ? "Abra um relatório na biblioteca ou use uma fonte para criar uma nova análise."
              : "Open a report from the library or use a source to create new analysis."}
          </p>
        </div>
        {onCreate && <Button variant="outline" size="sm" onClick={onCreate}><FileText className="mr-2 h-4 w-4" />{pt ? "Criar relatório" : "Create report"}</Button>}
      </div>
    );
  }

  const r = job.json;
  const usage = usageTag(r.consumo, pt);
  return (
    <article className="rounded-md border bg-card p-5 lg:p-7">
      {/* toolbar: meta à esquerda, ações à direita */}
      <div className="flex flex-wrap items-center gap-2">
        {r.tlp && (
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
            TLP:{r.tlp}
          </Badge>
        )}
        <span className="text-xs font-medium text-muted-foreground">{job.type === "vuln" ? (pt ? "Vulnerabilidade" : "Vulnerability") : job.type === "campaign" ? (pt ? "Campanha" : "Campaign") : (pt ? "Análise" : "Analysis")}</span>
        {job.subtype && job.subtype !== "auto" && (
          <Badge variant="outline" className="text-[10px]">
            {{
              malware: "Malware/Infostealer",
              phishing: "Phishing",
              ransomware: "Ransomware/APT",
              cve_unica: pt ? "CVE única" : "Single CVE",
              cve_varias: pt ? "Várias CVEs" : "Multi-CVE",
            }[job.subtype]}
          </Badge>
        )}
        <div className="ml-auto"><ExportMenu job={job} pt={pt} /></div>
      </div>
      <h2 className="mt-5 max-w-[65ch] text-xl font-semibold leading-snug xl:text-2xl">
        {r.titulo || job.title || job.url}
      </h2>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-b pb-5 text-xs text-muted-foreground">
        {/* Publicação da FONTE. Rotulada porque sem isso vira sósia da data acima —
            e um advisory de dois anos passaria por novidade. */}
        {r.source_published && fmtDate(r.source_published, pt) && (
          <span className="text-xs text-muted-foreground" title={pt ? "Publicação da fonte" : "Source published"}>
            {pt ? "Fonte publicada em" : "Source published on"} {fmtDate(r.source_published, pt)}
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
      </div>
      <BoletimView report={r} />
      <ReportRelations job={job} pt={pt} />
      <details className="mt-8 border-t pt-4 text-xs text-muted-foreground"><summary className="cursor-pointer">{pt ? "Dados de geração" : "Generation details"}</summary><div className="mt-3 flex flex-wrap items-center gap-3">{r.generated_at && <span>{pt ? "Gerado em" : "Generated on"} {fmtDate(r.generated_at, pt)}</span>}{job.template && <span>Template: {job.template}</span>}{usage}</div></details>
    </article>
  );
}

export default ReportPane;
