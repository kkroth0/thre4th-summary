import type { SapNote, SapPatchSummary } from "@/services/sapApi";

export type SapRiskCategory =
    | "RCE / Corrupção de memória"
    | "Configuração / Credenciais"
    | "Ausência de autorização"
    | "Injeção"
    | "Traversal / Divulgação"
    | "Falsificação / Redirecionamento"
    | "Outras";

export interface AnalyzedSapNote extends SapNote {
    category: SapRiskCategory;
    product: string;
    primaryCve: string;
}

export interface SapReportAnalysis {
    notes: AnalyzedSapNote[];
    topThree: AnalyzedSapNote[];
    products: string[];
    categoryCounts: Array<{ category: SapRiskCategory; count: number }>;
    executiveSummary: string;
    immediatePriorities: string[];
    recommendations: Array<{ title: string; body: string }>;
}

const CATEGORY_ORDER: SapRiskCategory[] = [
    "RCE / Corrupção de memória",
    "Configuração / Credenciais",
    "Ausência de autorização",
    "Injeção",
    "Traversal / Divulgação",
    "Falsificação / Redirecionamento",
    "Outras",
];

const CATEGORY_RULES: Array<{ category: SapRiskCategory; terms: RegExp }> = [
    { category: "RCE / Corrupção de memória", terms: /remote code execution|\brce\b|memory corruption|code execution/i },
    { category: "Configuração / Credenciais", terms: /credential|password|configuration|misconfiguration|authentication/i },
    { category: "Ausência de autorização", terms: /missing authorization|authorization check|privilege/i },
    { category: "Injeção", terms: /injection|\bxss\b|cross-site scripting|\bsql\b|\bcss\b/i },
    { category: "Traversal / Divulgação", terms: /traversal|disclosure|information exposure|\bpath\b/i },
    { category: "Falsificação / Redirecionamento", terms: /spoofing|smuggling|redirect/i },
];

const PRODUCT_RULES: Array<{ name: string; terms: RegExp }> = [
    { name: "SAP NetWeaver AS ABAP", terms: /netweaver(?: as)? abap/i },
    { name: "SAP NetWeaver AS Java", terms: /netweaver(?: as)? java/i },
    { name: "SAP Approuter", terms: /approuter/i },
    { name: "SAP Commerce Cloud", terms: /commerce cloud/i },
    { name: "SAP Integration Suite", terms: /integration suite|edge integration cell/i },
    { name: "SAProuter", terms: /saprouter/i },
    { name: "SAP S/4HANA", terms: /s\/4hana/i },
    { name: "SAP Fiori", terms: /fiori/i },
    { name: "SAP CRM", terms: /\bcrm\b/i },
    { name: "SAP UI5", terms: /\bui5\b|webcomponents/i },
    { name: "SAP HANA", terms: /\bhana\b/i },
];

const RECOMMENDATION_TITLES = [
    "Correção emergencial",
    "Proteção de integração e borda",
    "Higiene de credenciais e configuração",
    "Componentes descontinuados ou sem correção indicada",
    "Aplicações de negócio ABAP/Java",
    "Implantação e governança",
] as const;

const priorityRank = (priority: string): number => {
    if (/hot news/i.test(priority)) return 4;
    if (/critical/i.test(priority)) return 3;
    if (/high/i.test(priority)) return 2;
    if (/medium/i.test(priority)) return 1;
    return 0;
};

const noteNumber = (value: string): number => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
};

const compareNotes = (left: AnalyzedSapNote, right: AnalyzedSapNote): number =>
    (right.cvss ?? -1) - (left.cvss ?? -1)
    || priorityRank(right.priority) - priorityRank(left.priority)
    || noteNumber(left.note) - noteNumber(right.note)
    || left.note.localeCompare(right.note);

const noteCount = (count: number): string => `${count} ${count === 1 ? "nota" : "notas"}`;

const noteCountWithArticle = (count: number): string =>
    `${count === 1 ? "a" : "as"} ${noteCount(count)}`;

export function classifySapNote(note: SapNote): SapRiskCategory {
    return CATEGORY_RULES.find((rule) => rule.terms.test(note.title))?.category ?? "Outras";
}

export function identifySapProduct(note: SapNote): string {
    return PRODUCT_RULES.find((rule) => rule.terms.test(note.title))?.name ?? "Componente SAP não especificado";
}

const recommendationBodies = (analysis: {
    total: number;
    urgent: number;
    products: string[];
    configuration: number;
}): string[] => {
    const products = analysis.products.length > 0
        ? analysis.products.join(", ")
        : "os componentes SAP inventariados";

    return [
        analysis.urgent > 0
            ? `Priorizar ${noteCountWithArticle(analysis.urgent)} de severidade Crítica (Hot News/Critical) ou Alta (High) e validar a aplicação das correções.`
            : "Priorizar notas de severidade Crítica (Hot News/Critical) ou Alta (High) quando publicadas e validar a aplicação das correções.",
        `Validar controles de integração e borda para ${products} e registrar os resultados.`,
        analysis.configuration > 0
            ? `Validar credenciais e configurações para ${noteCountWithArticle(analysis.configuration)} classificada${analysis.configuration === 1 ? "" : "s"} nessa categoria.`
            : "Validar credenciais e configurações quando aplicável e registrar os resultados.",
        "Inventariar componentes descontinuados ou sem correção indicada e registrar o tratamento aplicável.",
        `Validar aplicações de negócio ABAP/Java entre ${products} e aplicar as correções indicadas.`,
        analysis.total > 0
            ? `Inventariar ${noteCountWithArticle(analysis.total)}, priorizar a implantação e registrar as validações.`
            : "Inventariar as notas publicadas, priorizar a implantação e registrar as validações.",
    ];
};

export function buildSapReportAnalysis(summary: SapPatchSummary): SapReportAnalysis {
    const notes = summary.notes
        .map<AnalyzedSapNote>((item) => ({
            ...item,
            category: classifySapNote(item),
            product: identifySapProduct(item),
            primaryCve: item.cves[0] ?? "Não informada",
        }))
        .sort(compareNotes);
    const products = [...new Set(notes.map((item) => item.product))];
    const categoryCounts = CATEGORY_ORDER
        .map((category) => ({ category, count: notes.filter((item) => item.category === category).length }))
        .filter((item) => item.count > 0);
    const urgent = notes.filter((item) => priorityRank(item.priority) >= 2).length;
    const configuration = notes.filter((item) => item.category === "Configuração / Credenciais").length;
    const productText = products.length > 0 ? products.join(", ") : "nenhum produto identificado";
    const bodies = recommendationBodies({ total: notes.length, urgent, products, configuration });

    return {
        notes,
        topThree: notes.slice(0, 3),
        products,
        categoryCounts,
        executiveSummary: `${noteCount(notes.length)} analisada${notes.length === 1 ? "" : "s"}; ${urgent} com severidade Crítica (Hot News/Critical) ou Alta (High); produtos: ${productText}.`,
        immediatePriorities: [
            urgent > 0
                ? `Priorizar ${noteCountWithArticle(urgent)} de severidade Crítica (Hot News/Critical) ou Alta (High).`
                : "Validar a prioridade das notas publicadas e aplicar as correções oficiais conforme o risco.",
            products.length > 0
                ? `Validar correções para ${productText}.`
                : "Confirmar os componentes afetados no inventário antes da implantação.",
            notes.length > 0
                ? "Registrar as validações, a implantação e as evidências do ciclo."
                : "Registrar a avaliação do ciclo e monitorar a próxima publicação oficial.",
        ],
        recommendations: RECOMMENDATION_TITLES.map((title, index) => ({ title, body: bodies[index] })),
    };
}
