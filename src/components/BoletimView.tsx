import React from "react";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, ShieldAlert } from "lucide-react";
import type { BoletimReport } from "@/services/threatApi";

const SEVERITY_STYLES: Record<string, string> = {
  Crítica: "bg-red-500/10 text-red-500 border-red-500/20",
  Critical: "bg-red-500/10 text-red-500 border-red-500/20",
  Alta: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  High: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  Média: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  Medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  Baixa: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  Low: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

const Section: React.FC<{ title: string; count?: number; children: React.ReactNode }> = ({ title, count, children }) => (
  <div className="mt-4 first:mt-0">
    <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
      {title}{typeof count === "number" ? ` (${count})` : ""}
    </h4>
    {children}
  </div>
);

// Visualizador inline do JSON do boletim — mostra o que foi coletado (sumário,
// produto/CVE, IOCs por Pirâmide da Dor, TTPs MITRE, referências). O meta
// (TLP/data/fonte) fica com quem embute (ReportPane). Tolerante a campos
// ausentes e aos dois deck_types.
export const BoletimView: React.FC<{ report: BoletimReport }> = ({ report }) => {
  const r = report || {};
  const iocs = r.iocs || [];
  const ttps = r.mitre_ttps || [];
  const refs = r.referencias_coletadas || [];
  const tech = r.tecnologias_afetadas || [];
  const surface = r.superficie_de_ataque || [];
  const killChain = r.cyber_kill_chain || [];
  const iocSources = r.iocs_fontes || [];
  const ator = r.ator;
  const recomendacoes = r.recomendacoes || [];

  return (
    <div className="mt-4 text-sm">
      {r.sumario_executivo && (
        <Section title="Sumário executivo">
          <p className="text-muted-foreground leading-relaxed">{r.sumario_executivo}</p>
        </Section>
      )}

      {/* campaign: objetivo da campanha */}
      {r.objetivo && (
        <Section title="Objetivo da campanha">
          <p className="text-muted-foreground leading-relaxed">{r.objetivo}</p>
        </Section>
      )}

      {r.descricao && (
        <Section title="Descrição">
          <p className="text-muted-foreground leading-relaxed whitespace-pre-line">{r.descricao}</p>
        </Section>
      )}

      {/* campaign: bloco do ator */}
      {ator && (ator.threat_actor || ator.tipo || ator.motivation || (ator.sectors && ator.sectors.length) || ator.diferencial) && (
        <Section title="Ator da ameaça">
          <div className="space-y-0.5 text-muted-foreground">
            {ator.threat_actor && ator.threat_actor !== "N/A" && (
              <div><span className="text-foreground font-medium">Ator:</span> {ator.threat_actor}</div>
            )}
            {ator.tipo && ator.tipo !== "N/A" && (
              <div><span className="text-foreground font-medium">Tipo:</span> {ator.tipo}</div>
            )}
            {ator.motivation && ator.motivation !== "N/A" && (
              <div><span className="text-foreground font-medium">Motivação:</span> {ator.motivation}</div>
            )}
            {ator.sectors && ator.sectors.length > 0 && (
              <div><span className="text-foreground font-medium">Setores:</span> {ator.sectors.join(", ")}</div>
            )}
            {ator.diferencial && ator.diferencial !== "N/A" && (
              <div><span className="text-foreground font-medium">Diferencial:</span> {ator.diferencial}</div>
            )}
            {ator.onion && ator.onion.length > 0 && (
              <div className="font-mono text-xs break-all"><span className="font-sans text-foreground font-medium">Onion:</span> {ator.onion.join(", ")}</div>
            )}
          </div>
        </Section>
      )}

      {/* vuln: produto/CVE */}
      {tech.length > 0 && (
        <Section title="Tecnologias afetadas" count={tech.length}>
          <div className="space-y-1.5">
            {tech.map((t, i) => (
              <div key={i} className="flex flex-wrap items-center gap-1.5">
                <span className="font-medium">{[t.fabricante, t.software].filter(Boolean).join(" ")}</span>
                {t.versao && <span className="text-muted-foreground">{t.versao}</span>}
                {t.cve && t.cve !== "N/A" && <Badge variant="secondary" className="text-[10px]">{t.cve}</Badge>}
                {t.cvss && t.cvss !== "N/A" && (
                  <Badge variant="outline" className={SEVERITY_STYLES[t.severidade || ""] || SEVERITY_STYLES.Low}>
                    CVSS {t.cvss}{t.severidade ? ` · ${t.severidade}` : ""}
                  </Badge>
                )}
                {t.cwe && t.cwe !== "N/A" && <span className="text-xs text-muted-foreground">{t.cwe}</span>}
                {t.kev && (
                  <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20 text-[10px]">
                    <ShieldAlert className="h-3 w-3 mr-1" /> CISA KEV
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* campaign: cyber kill chain (seções do template SRR) */}
      {killChain.length > 0 && (
        <Section title="Cyber Kill Chain">
          <ol className="space-y-1">
            {killChain.map((k, i) => (
              <li key={i} className="text-muted-foreground">
                <span className="font-mono text-xs text-primary mr-1.5">{String(i + 1).padStart(2, "0")}</span>
                <span className="font-medium text-foreground">{k.fase}</span>
                {k.contexto ? ` — ${k.contexto}` : ""}
              </li>
            ))}
          </ol>
        </Section>
      )}

      {/* campaign: superfície de ataque */}
      {surface.length > 0 && (
        <Section title="Superfície de ataque" count={surface.length}>
          <div className="space-y-1">
            {surface.map((s, i) => (
              <div key={i} className="text-muted-foreground">
                <span className="font-medium text-foreground">{s.tecnologia}</span>
                {s.categoria ? ` · ${s.categoria}` : ""}{s.utilizacao ? ` — ${s.utilizacao}` : ""}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* vuln: pré-requisitos de exploração */}
      {Array.isArray(r.pre_requisitos) && r.pre_requisitos.length > 0 && (
        <Section title="Pré-requisitos de exploração" count={r.pre_requisitos.length}>
          <ul className="list-disc pl-5 space-y-0.5 text-muted-foreground">
            {r.pre_requisitos.map((p, i) => <li key={i}>{p}</li>)}
          </ul>
        </Section>
      )}

      {Array.isArray(r.impactos) && r.impactos.length > 0 && (
        <Section title="Impactos" count={r.impactos.length}>
          <ul className="list-disc pl-5 space-y-0.5 text-muted-foreground">
            {r.impactos.map((im, i) => <li key={i}>{im}</li>)}
          </ul>
        </Section>
      )}

      {recomendacoes.length > 0 && (
        <Section title="Recomendações">
          <div className="space-y-2.5">
            {recomendacoes.map((g, i) => (
              <div key={i}>
                {g.titulo && <div className="font-medium text-foreground mb-0.5">{g.titulo}</div>}
                <ul className="list-disc pl-5 space-y-0.5 text-muted-foreground">
                  {(g.itens || []).map((it, j) => <li key={j}>{it}</li>)}
                </ul>
              </div>
            ))}
          </div>
        </Section>
      )}

      {(iocs.length > 0 || iocSources.length > 0) && (
        <Section title="Indicadores de comprometimento" count={iocs.length}>
          {iocSources.length > 0 && (
            <p className="mb-1.5 text-xs text-muted-foreground">
              IOCs coletados de{" "}
              {iocSources.map((src, i) => (
                <React.Fragment key={i}>
                  {i > 0 && ", "}
                  <a href={src} target="_blank" rel="noopener noreferrer"
                     className="inline-flex items-center gap-1 hover:underline break-all">
                    {src} <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                </React.Fragment>
              ))}
            </p>
          )}
          {iocs.length > 0 && (
          <div className="overflow-hidden rounded-md border">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 text-muted-foreground">
                <tr><th className="text-left font-medium px-2 py-1">Categoria</th><th className="text-left font-medium px-2 py-1">Tipo</th><th className="text-left font-medium px-2 py-1">Valor</th></tr>
              </thead>
              <tbody>
                {iocs.map((io, i) => (
                  <tr key={i} className="border-t">
                    <td className="px-2 py-1 text-muted-foreground">{io.categoria}</td>
                    <td className="px-2 py-1 text-muted-foreground">{io.tipo}</td>
                    <td className="px-2 py-1 font-mono break-all">{io.valor}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          )}
        </Section>
      )}

      {ttps.length > 0 && (
        <Section title="MITRE ATT&CK" count={ttps.length}>
          <div className="flex flex-wrap gap-1.5">
            {ttps.map((t, i) => (
              <a key={i} href={t.url || `https://attack.mitre.org/techniques/${(t.id || "").replace(".", "/")}/`}
                 target="_blank" rel="noopener noreferrer"
                 className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted/50"
                 title={t.descricao || ""}>
                <span className="font-mono text-primary">{t.id}</span>
                <span className="text-muted-foreground truncate max-w-[200px]">{t.nome}</span>
              </a>
            ))}
          </div>
        </Section>
      )}

      {refs.length > 0 && (
        <Section title="Referências" count={refs.length}>
          <ul className="space-y-0.5">
            {refs.map((rf, i) => (
              <li key={i} className="truncate">
                <a href={rf.url} target="_blank" rel="noopener noreferrer" className="text-xs text-muted-foreground hover:underline inline-flex items-center gap-1">
                  {rf.titulo || rf.url} <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
};

export default BoletimView;
