import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

// SIS-01: o produto tinha cinco desenhos para o mesmo bloco de números —
// Vulnerabilidades, Patch Tuesday, Correções SAP, Mapa de Ransomware e Atores —,
// cada tela escolhendo tipografia, ícone e alinhamento por conta própria: 2xl
// contra 3xl, negrito contra black, rótulo em 10px contra 12px, com ícone e sem.
//
// Um desenho, três tamanhos. As regras, para não voltarem a divergir:
//
//   • rótulo em maiúsculas pequenas, sempre acima do número
//   • número com `tabular-nums`, para a coluna não dançar quando o valor muda
//   • linha de apoio opcional, para o que explica o número
//   • cor semântica só quando o número exige ação — nunca por decoração

export type MetricTone = "neutral" | "critical" | "warning" | "positive";

const TONE: Record<MetricTone, string> = {
  neutral: "text-foreground",
  // Tons -700 no claro: os -600 medem abaixo de 4,5:1 e a auditoria pegou isso
  // nos rótulos de status (DEN-06).
  critical: "text-red-700 dark:text-red-400",
  warning: "text-amber-700 dark:text-amber-400",
  positive: "text-emerald-700 dark:text-emerald-400",
};

const SIZE = {
  sm: { value: "text-xl", pad: "p-3", label: "text-[10px]" },
  md: { value: "text-2xl md:text-3xl", pad: "p-4", label: "text-[11px]" },
  lg: { value: "text-3xl md:text-4xl", pad: "p-5", label: "text-xs" },
};

export interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  /** o que explica o número: "de 422 CVEs", "contra a janela anterior" */
  hint?: string;
  icon?: LucideIcon;
  tone?: MetricTone;
  size?: keyof typeof SIZE;
  className?: string;
  title?: string;
}

export const MetricCard = ({
  label, value, hint, icon: Icon, tone = "neutral", size = "md", className, title,
}: MetricCardProps) => {
  const s = SIZE[size];
  return (
    <div
      title={title}
      className={cn("rounded-xl border border-border/60 bg-card", s.pad, className)}
    >
      <div className="flex items-center justify-between gap-3">
        <span className={cn("font-bold uppercase tracking-wider text-muted-foreground", s.label)}>
          {label}
        </span>
        {Icon && <Icon className={cn("h-4 w-4 shrink-0", tone === "neutral" ? "text-muted-foreground" : TONE[tone])} />}
      </div>
      <div className={cn("mt-1.5 font-bold tabular-nums leading-none", s.value, TONE[tone])}>
        {value}
      </div>
      {hint && <p className="mt-1.5 text-xs leading-snug text-muted-foreground">{hint}</p>}
    </div>
  );
};
