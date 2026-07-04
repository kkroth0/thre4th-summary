import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// Render de Markdown com a tipografia do Tailwind. react-markdown (v10) NÃO
// renderiza HTML bruto por padrão — o corpo do post é confiável (só admin
// escreve), mas manter assim evita qualquer superfície de XSS. GFM habilita
// tabelas, listas de tarefas, ~~strike~~ e autolink.
export function Markdown({ children, className = "" }: { children: string; className?: string }) {
    return (
        <div
            className={
                "prose prose-neutral dark:prose-invert max-w-none " +
                "prose-headings:scroll-mt-20 prose-a:text-primary prose-a:no-underline hover:prose-a:underline " +
                "prose-code:text-primary prose-code:before:content-none prose-code:after:content-none " +
                "prose-pre:bg-muted prose-pre:text-foreground prose-img:rounded-lg prose-hr:border-border " +
                className
            }
        >
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{children || ""}</ReactMarkdown>
        </div>
    );
}
