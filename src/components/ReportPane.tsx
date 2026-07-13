import React from "react";
import { Download, ExternalLink, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BrandMark } from "@/components/BrandMark";
import { BoletimView } from "@/components/BoletimView";
import { PostEditor } from "@/components/PostEditor";
import { boletimToDraft } from "@/services/boletimMarkdown";
import { useLanguage } from "@/contexts/LanguageContext";
import type { BoletimJob } from "@/services/threatApi";

// Host da URL pra exibição compacta ("fortiguard.com" em vez do link inteiro).
export const hostOf = (url?: string): string => {
  try { return url ? new URL(url).host : ""; } catch { return ""; }
};

const fmtDate = (iso: string | undefined, pt: boolean) => {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(+d) ? "" : d.toLocaleDateString(pt ? "pt-BR" : "en-US");
};

// Painel de leitura da workstation: toolbar com meta/ações + BoletimView.
// `job === null` (ou sem JSON) mostra o estado vazio.
export function ReportPane({ job, isAdmin, onDownload }: {
  job: BoletimJob | null;
  isAdmin: boolean;
  onDownload: (job: BoletimJob) => void;
}) {
  const { language } = useLanguage();
  const pt = language === "pt";

  if (!job || !job.json) {
    return (
      <div className="flex min-h-[420px] flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border/60 p-8 text-center">
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
  return (
    <div className="rounded-xl border bg-card/40 p-5 lg:p-6">
      {/* toolbar: meta à esquerda, ações à direita */}
      <div className="flex flex-wrap items-center gap-2">
        {r.tlp && (
          <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
            TLP:{r.tlp}
          </Badge>
        )}
        <Badge variant="secondary" className="font-mono text-[10px] uppercase">{job.type}</Badge>
        {r.generated_at && <span className="text-xs text-muted-foreground">{fmtDate(r.generated_at, pt)}</span>}
        {r.source_url && (
          <a
            href={r.source_url} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
          >
            {hostOf(r.source_url)} <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        )}
        <div className="ml-auto flex items-center gap-2">
          {isAdmin && (
            <PostEditor
              key={job.id}
              initial={boletimToDraft(r)}
              trigger={
                <Button variant="outline" size="sm" className="gap-1.5">
                  <Sparkles className="h-3.5 w-3.5" />
                  {pt ? "Salvar como Advisory" : "Save as Advisory"}
                </Button>
              }
              onSaved={() => toast.success(pt ? "Rascunho salvo em Advisories" : "Draft saved to Advisories")}
            />
          )}
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onDownload(job)}>
            <Download className="h-3.5 w-3.5" /> JSON
          </Button>
        </div>
      </div>

      <h2 className="mt-4 text-lg font-semibold leading-snug">
        {r.titulo || job.title || job.url}
      </h2>

      <BoletimView report={r} />
    </div>
  );
}

export default ReportPane;
