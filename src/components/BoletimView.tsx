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

// Auto-link CVE (-> NVD) and ATT&CK ids (-> attack.mitre) inside prose, so the
// analyst never adds a link by hand. One combined regex; keep the delimiters.
// Exploração em curso pinta o selo de vermelho; "PoC público" ou similar fica neutro.
const ACTIVE_EXPLOIT_RE = /ativa|explorad|in the wild|kev|weaponiz/i;

const REF_RE = /(CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)/gi;
const refHref = (token: string) =>
  /^cve/i.test(token)
    ? `https://nvd.nist.gov/vuln/detail/${token.toUpperCase()}`
    : `https://attack.mitre.org/techniques/${token.toUpperCase().replace(".", "/")}/`;

const linkifyRefs = (text?: string): React.ReactNode => {
  if (!text) return text;
  // split() with a capture group puts the CVE/TTP tokens at odd indices.
  return text.split(REF_RE).map((part, i) =>
    i % 2 === 1 ? (
      <a key={i} href={refHref(part)} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{part}</a>
    ) : (
      <React.Fragment key={i}>{part}</React.Fragment>
    ),
  );
};

const Section: React.FC<{ title: string; count?: number; children: React.ReactNode }> = ({ title, count, children }) => (
  <div className="mt-4 first:mt-0">
    <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
      {title}{typeof count === "number" ? ` (${count})` : ""}
    </h4>
    {children}
  </div>
);

// A superfície de ataque vem como objeto (motor atual) ou como tabela de
// tecnologias (sidecar antigo). Normaliza os dois em pares label/valor.
const SURFACE_FIELDS: [string, string][] = [
  ["vetor_inicial", "Vetor inicial"],
  ["superficie", "Superfície"],
  ["ativos_alvo", "Ativos-alvo"],
  ["ttps_principais", "TTPs principais"],
  ["perfil_vitimas", "Perfil das vítimas"],
];

const surfaceRows = (s: BoletimReport["superficie_de_ataque"]): [string, string][] => {
  if (Array.isArray(s)) {
    return s
      .filter((row) => row.tecnologia)
      .map((row) => [row.tecnologia!, [row.categoria, row.utilizacao].filter(Boolean).join(" — ")]);
  }
  const obj = (s || {}) as Record<string, string | undefined>;
  return SURFACE_FIELDS
    .map(([key, label]) => [label, (obj[key] || "").trim()] as [string, string])
    .filter(([, value]) => value && value !== "N/A");
};

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
  const surface = surfaceRows(r.superficie_de_ataque);
  const iocSources = r.iocs_fontes || [];
  const ator = r.ator;
  const recomendacoes = r.recomendacoes || [];

  return (
    <div className="mt-4 text-sm">
      {r.sumario_executivo && (
        <Section title="Sumário executivo">
          <p className="text-muted-foreground leading-relaxed">{linkifyRefs(r.sumario_executivo)}</p>
        </Section>
      )}

      {/* vuln: estado de exploração — sinal de urgência, vem antes do resto.
          O motor usa "Não informado" como default, que não vale um bloco. */}
      {r.estado_exploracao && r.estado_exploracao !== "Não informado" && (
        <Section title="Estado de exploração">
          <Badge
            variant="outline"
            className={ACTIVE_EXPLOIT_RE.test(r.estado_exploracao)
              ? "bg-red-500/10 text-red-500 border-red-500/20"
              : "bg-slate-500/10 text-slate-400 border-slate-500/20"}
          >
            {r.estado_exploracao}
          </Badge>
        </Section>
      )}

      {/* campaign: objetivo da campanha */}
      {r.objetivo && (
        <Section title="Objetivo da campanha">
          <p className="text-muted-foreground leading-relaxed">{linkifyRefs(r.objetivo)}</p>
        </Section>
      )}

      {r.descricao && (
        <Section title="Descrição">
          <p className="text-muted-foreground leading-relaxed whitespace-pre-line">{linkifyRefs(r.descricao)}</p>
        </Section>
      )}

      {/* campaign: bloco do ator */}
      {ator && (ator.threat_actor || ator.tipo || ator.motivation || (ator.sectors && ator.sectors.length) || ator.origem || ator.nivel_atividade || ator.diferencial) && (
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
            {ator.origem && ator.origem !== "N/A" && (
              <div><span className="text-foreground font-medium">Origem:</span> {ator.origem}</div>
            )}
            {ator.nivel_atividade && ator.nivel_atividade !== "N/A" && (
              <div><span className="text-foreground font-medium">Nível de atividade:</span> {ator.nivel_atividade}</div>
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
                {t.versao_corrigida && t.versao_corrigida !== "N/A" && (
                  <span className="text-emerald-500" title="Versão corrigida">
                    → {t.versao_corrigida}
                  </span>
                )}
                {t.cve && t.cve !== "N/A" && (
                  <a href={refHref(t.cve)} target="_blank" rel="noopener noreferrer">
                    <Badge variant="secondary" className="text-[10px] hover:bg-secondary/80">{t.cve}</Badge>
                  </a>
                )}
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

      {/* campaign: superfície de ataque */}
      {surface.length > 0 && (
        <Section title="Superfície de ataque">
          <div className="space-y-0.5 text-muted-foreground">
            {surface.map(([label, value], i) => (
              <div key={i}>
                <span className="text-foreground font-medium">{label}:</span> {linkifyRefs(value)}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* vuln: pré-requisitos de exploração */}
      {Array.isArray(r.pre_requisitos) && r.pre_requisitos.length > 0 && (
        <Section title="Pré-requisitos de exploração" count={r.pre_requisitos.length}>
          <ul className="list-disc pl-5 space-y-0.5 text-muted-foreground">
            {r.pre_requisitos.map((p, i) => <li key={i}>{linkifyRefs(p)}</li>)}
          </ul>
        </Section>
      )}

      {Array.isArray(r.impactos) && r.impactos.length > 0 && (
        <Section title="Impactos" count={r.impactos.length}>
          <ul className="list-disc pl-5 space-y-0.5 text-muted-foreground">
            {r.impactos.map((im, i) => <li key={i}>{linkifyRefs(im)}</li>)}
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
                  {(g.itens || []).map((it, j) => <li key={j}>{linkifyRefs(it)}</li>)}
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
