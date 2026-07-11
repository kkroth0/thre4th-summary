import type { BoletimReport, PostInput } from "@/services/threatApi";

// Converte um BoletimReport (saida do Gerador de Relatorios) num rascunho de
// Advisory em Markdown: título, resumo, corpo e tags. Usado pelo botão "Salvar
// como rascunho de Advisory" na pagina de relatorios. Só monta seções que têm
// conteúdo, então boletins parciais não geram tabelas vazias.

const esc = (s: unknown) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n+/g, " ").trim();

// Monta uma tabela GFM a partir de cabeçalhos + linhas (arrays de células).
function table(headers: string[], rows: (unknown[])[]): string {
    if (!rows.length) return "";
    const head = `| ${headers.join(" | ")} |`;
    const sep = `| ${headers.map(() => "---").join(" | ")} |`;
    const body = rows.map((r) => `| ${r.map(esc).join(" | ")} |`).join("\n");
    return `${head}\n${sep}\n${body}`;
}

export function boletimToDraft(report: BoletimReport): Pick<PostInput, "title" | "summary" | "body" | "tags"> {
    const r = report || {};
    const parts: string[] = [];

    // Cabeçalho de metadados (fonte + TLP + data).
    const meta: string[] = [];
    if (r.tlp) meta.push(`**TLP:** ${r.tlp}`);
    if (r.cve_id) meta.push(`**CVE:** ${r.cve_id}`);
    if (r.source_url) meta.push(`**Fonte:** [${r.source_url}](${r.source_url})`);
    if (meta.length) parts.push(meta.join(" · "));

    if (r.sumario_executivo) parts.push(`## Sumário executivo\n\n${r.sumario_executivo}`);
    if (r.descricao) parts.push(`## Descrição\n\n${r.descricao}`);

    if (r.impactos?.length) parts.push(`## Impactos\n\n${r.impactos.map((i) => `- ${i}`).join("\n")}`);

    if (r.tecnologias_afetadas?.length) {
        const rows = r.tecnologias_afetadas.map((t) => [
            [t.fabricante, t.software].filter(Boolean).join(" "), t.versao || "—",
            t.cve || "—", t.cvss || "—", t.severidade || "—", t.kev ? "Sim" : "—",
        ]);
        parts.push(`## Tecnologias afetadas\n\n${table(["Produto", "Versão", "CVE", "CVSS", "Severidade", "KEV"], rows)}`);
    }

    if (r.ator?.threat_actor) {
        const a = r.ator;
        const lines = [`**${a.threat_actor}**${a.tipo ? ` — ${a.tipo}` : ""}`];
        if (a.motivation) lines.push(`- **Motivação:** ${a.motivation}`);
        if (a.sectors?.length) lines.push(`- **Setores-alvo:** ${a.sectors.join(", ")}`);
        if (a.diferencial) lines.push(`- **Diferencial:** ${a.diferencial}`);
        parts.push(`## Ator de ameaça\n\n${lines.join("\n")}`);
    }

    if (r.superficie_de_ataque?.length) {
        const rows = r.superficie_de_ataque.map((s) => [s.categoria || "—", s.tecnologia || "—", s.utilizacao || "—"]);
        parts.push(`## Superfície de ataque\n\n${table(["Categoria", "Tecnologia", "Uso"], rows)}`);
    }

    if (r.mitre_ttps?.length) {
        const rows = r.mitre_ttps.map((t) => [
            t.url ? `[${t.id || "?"}](${t.url})` : (t.id || "—"),
            t.nome || "—", t.tatica || "—", t.contexto || t.descricao || "—",
        ]);
        parts.push(`## MITRE ATT&CK\n\n${table(["TTP", "Nome", "Tática", "Contexto"], rows)}`);
    }

    if (r.iocs?.length) {
        const rows = r.iocs.map((io) => [io.tipo || io.categoria || "—", io.valor || "—"]);
        parts.push(`## Indicadores de comprometimento\n\n${table(["Tipo", "Valor"], rows)}`);
    }

    if (r.recomendacoes?.length) {
        const blocks = r.recomendacoes.map((rec) => {
            const items = (rec.itens || []).map((i) => `- ${i}`).join("\n");
            return `### ${rec.titulo || "Recomendações"}\n\n${items}`;
        });
        parts.push(`## Recomendações\n\n${blocks.join("\n\n")}`);
    }

    if (r.referencias_coletadas?.length) {
        const refs = r.referencias_coletadas
            .filter((ref) => ref.url)
            .map((ref) => `- [${ref.titulo || ref.url}](${ref.url})`).join("\n");
        if (refs) parts.push(`## Referências\n\n${refs}`);
    }

    // Tags: tipo de deck, CVE, ator e algumas técnicas.
    const tags = [
        r.deck_type,
        r.cve_id,
        r.ator?.threat_actor,
        ...(r.mitre_ttps || []).slice(0, 2).map((t) => t.id),
    ].filter((t): t is string => !!t);

    return {
        title: r.titulo || "Rascunho de Advisory",
        summary: r.sumario_executivo?.slice(0, 280) || "",
        body: parts.join("\n\n"),
        tags: [...new Set(tags)],
    };
}
