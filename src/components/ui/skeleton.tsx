import { cn } from "@/lib/utils";

/** Bloco cinza que pulsa, do tamanho do conteúdo que vai entrar no lugar. */
function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("animate-pulse rounded-md bg-muted", className)} {...props} />;
}

export { Skeleton };
