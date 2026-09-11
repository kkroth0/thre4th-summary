// The PT-BR labels and prose the SAP Security Patch Day deck is built from —
// priority/CVSS labels, the category glossary and the per-note speaker notes.
// It lives here, apart from the PPTX writer, so the PowerPoint export and the
// CTIFLOW JSON export compose the same labels from the same data and can never
// disagree.
import type { AnalyzedSapNote, SapReportAnalysis } from './sapPatchAnalysis';

export const SAP_REPORT = 'SAP Security Patch Day';

export const allCves = (note: { cves: string[] }): string =>
    note.cves.length > 0 ? note.cves.join(', ') : 'Não informada';

export const priorityLabel = (priority: string): string => {
    if (/hot news/i.test(priority)) return 'Crítica (Hot News)';
    if (/critical/i.test(priority)) return 'Crítica';
    if (/high/i.test(priority)) return 'Alta';
    if (/medium/i.test(priority)) return 'Média';
    if (/low/i.test(priority)) return 'Baixa';
    return priority;
};

export const cvssLabel = (cvss: number | null): string => (cvss == null ? 'Não informado' : cvss.toFixed(1));

export const CATEGORY_EXPLANATIONS: Record<string, string> = {
    'RCE / Corrupção de memória': 'Execução de código ou comprometimento de memória.',
    'Configuração / Credenciais': 'Riscos associados a autenticação, senhas ou configuração.',
    'Ausência de autorização': 'Validações insuficientes de acesso ou privilégio.',
    'Injeção': 'Entrada não confiável interpretada por aplicações.',
    'Traversal / Divulgação': 'Acesso indevido a caminhos ou exposição de informações.',
    'Falsificação / Redirecionamento': 'Manipulação de identidade, tráfego ou destino.',
    'Outras': 'Demais tipos de vulnerabilidade publicados no ciclo.',
};

// "RCE / Corrupção de memória: Execução de código ou comprometimento de
// memória." — the bullets under "Descrição Executiva da Vulnerabilidade".
export const categoryGlossaryLines = (analysis: SapReportAnalysis): string[] =>
    analysis.categoryCounts.map(({ category }) => `${category}: ${CATEGORY_EXPLANATIONS[category] ?? ''}`.trim());

// "12 RCE / Corrupção de memória", top four — the consolidated slide's right column.
export const categoryMixLines = (analysis: SapReportAnalysis): string[] =>
    analysis.categoryCounts.slice(0, 4).map(({ category, count }) => `${count} ${category}`);

// The speaker-notes block for the highlights slide: every note reaches the
// presenter, including the ones the six-card grid could not hold.
export const noteSpeakerNotes = (notes: AnalyzedSapNote[]): string =>
    notes
        .map((note) =>
            [
                `SAP Note ${note.note}`,
                `Título completo: ${note.title}`,
                `CVE: ${allCves(note)}`,
                `Severidade: ${priorityLabel(note.priority)} · CVSS ${cvssLabel(note.cvss)}`,
                `Categoria: ${note.category} · Produto: ${note.product}`,
                note.isUpdate ? 'Nota atualizada' : 'Nota nova neste ciclo',
            ].join('\n')
        )
        .join('\n\n');
