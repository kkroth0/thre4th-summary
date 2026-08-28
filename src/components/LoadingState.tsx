import { Loader2 } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * Carga inicial de uma lista ou tabela: barras do tamanho das linhas que vão
 * entrar, para a tela não pular quando o dado chega. Quinze lugares mostravam
 * um "Carregando…" centralizado com cinco paddings diferentes, e cada um deles
 * empurrava o conteúdo para baixo no momento em que a resposta voltava.
 */
export function LoadingRows({ rows = 5, className = "" }: { rows?: number; className?: string }) {
  return (
    <div className={`space-y-2 py-2 ${className}`} role="status" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-11 w-full" />
      ))}
      <span className="sr-only">Carregando</span>
    </div>
  );
}

/**
 * Espera disparada pelo usuário — atualizar, salvar, reprocessar. Aqui o
 * rodinha é certo: ele diz que o clique foi recebido, coisa que um bloco cinza
 * não diz.
 */
export function LoadingInline({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-4 text-sm text-muted-foreground" role="status">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> {label}
    </div>
  );
}
