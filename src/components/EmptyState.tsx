import { ReactNode } from "react";
import { LucideIcon } from "lucide-react";

interface EmptyStateProps {
  /** Ícone mudo, só para dar peso ao bloco. */
  icon?: LucideIcon;
  /** O que está vazio, em uma linha. */
  title: ReactNode;
  /** O próximo passo: o que fazer para a tela deixar de estar vazia. */
  description?: ReactNode;
  /** Botão ou link, quando o próximo passo cabe em um clique. */
  action?: ReactNode;
  /**
   * Sem moldura, para dentro de célula de tabela — a tabela já tem a dela, e
   * duas bordas tracejadas encaixadas ficam sujas.
   */
  bare?: boolean;
  className?: string;
}

/**
 * O estado vazio do produto, em um desenho só. Vinte e cinco blocos escreviam o
 * próprio, com nove paddings e três tamanhos de texto entre eles, e a metade
 * que só dizia "Nenhum resultado" não contava o que fazer a seguir (EST-04 da
 * auditoria).
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  bare = false,
  className = "",
}: EmptyStateProps) {
  const frame = bare
    ? "py-12"
    : "rounded-lg border border-dashed border-border py-12";
  return (
    <div className={`flex flex-col items-center gap-2 px-6 text-center ${frame} ${className}`}>
      {Icon && <Icon className="h-5 w-5 text-muted-foreground/70" aria-hidden />}
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && (
        <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">{description}</p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
