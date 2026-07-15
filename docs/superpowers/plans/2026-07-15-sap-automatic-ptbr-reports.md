# Relatórios SAP automáticos em pt-BR — Plano de implementação

> **Para trabalhadores agênticos:** SUB-SKILL OBRIGATÓRIA: use `superpowers:subagent-driven-development` (recomendado) ou `superpowers:executing-plans` para implementar este plano tarefa por tarefa. As etapas usam caixas de seleção (`- [ ]`) para acompanhamento.

**Objetivo:** gerar automaticamente um PowerPoint executivo de seis slides e um Excel aprimorado, ambos em pt-BR, neutros e derivados exclusivamente das notas públicas do SAP Security Patch Day.

**Arquitetura:** um novo módulo puro transformará `SapPatchSummary` em `SapReportAnalysis`, concentrando classificação, produtos, Top 3 e recomendações. Builders injetáveis de PPTX e XLSX consumirão essa mesma análise, deixando download e imports dinâmicos nas funções de borda existentes.

**Stack:** TypeScript 5.8, node:test, esbuild, PptxGenJS 4, ExcelJS 4, Vite 6.

## Restrições globais

- Todo texto apresentado nos novos PPTX/XLSX deve estar em português do Brasil, exceto CVE, CVSS, SAP Note e nomes oficiais de produtos.
- O PowerPoint deve conter exatamente seis slides, na mesma sequência da especificação.
- A análise deve ser determinística e usar apenas os dados já coletados da fonte pública SAP.
- Nenhum elemento, texto, autor ou metadado dos arquivos de referência pode ser copiado.
- O criador dos artefatos deve ser `ThreatSumm4ry`.
- Os exports devem continuar carregados sob demanda.
- Não adicionar dependências.

---

## Estrutura de arquivos

- Criar `src/utils/sapPatchAnalysis.ts`: tipos e regras puras de análise do relatório.
- Criar `src/utils/sapPatchAnalysis.test.ts`: cobertura unitária das regras, fallbacks e ordenação.
- Modificar `src/utils/sapPatchExport.ts`: builders injetáveis e composição visual dos PPTX/XLSX.
- Criar `src/utils/sapPatchExport.test.ts`: fakes estruturais para validar slides, abas, cabeçalhos, metadados e neutralidade.
- Modificar `src/pages/SapPatch.tsx`: bloquear export vazio com mensagem pt-BR e manter o carregamento sob demanda existente.
- Criar `src/pages/sapPatchExportGuard.test.ts`: contrato textual do bloqueio e dos rótulos de export.

### Tarefa 1: Motor determinístico de análise

**Arquivos:**

- Criar: `src/utils/sapPatchAnalysis.ts`
- Criar: `src/utils/sapPatchAnalysis.test.ts`

**Interfaces:**

- Consome: `SapPatchSummary` e `SapNote` de `src/services/sapApi.ts`.
- Produz:

```ts
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

export function classifySapNote(note: SapNote): SapRiskCategory;
export function identifySapProduct(note: SapNote): string;
export function buildSapReportAnalysis(summary: SapPatchSummary): SapReportAnalysis;
```

- [ ] **Etapa 1: escrever testes que falham para categorias e precedência**

Criar helpers `note()` e `summary()` no teste e cobrir todos os termos da especificação:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { classifySapNote } from "./sapPatchAnalysis.ts";
import type { SapNote } from "@/services/sapApi";

const note = (title: string): SapNote => ({
  note: "1000000",
  noteUrl: "https://me.sap.com/notes/1000000",
  title,
  cves: [],
  priority: "Medium",
  cvss: null,
  cvssVector: null,
  isUpdate: false,
});

test("classifica títulos SAP com precedência determinística", () => {
  assert.equal(classifySapNote(note("Remote Code Execution and SQL Injection")), "RCE / Corrupção de memória");
  assert.equal(classifySapNote(note("Sample credentials in Commerce Cloud")), "Configuração / Credenciais");
  assert.equal(classifySapNote(note("Missing Authorization check")), "Ausência de autorização");
  assert.equal(classifySapNote(note("Cross-Site Scripting (XSS)")), "Injeção");
  assert.equal(classifySapNote(note("Directory Traversal and Information Disclosure")), "Traversal / Divulgação");
  assert.equal(classifySapNote(note("HTTP Request Smuggling")), "Falsificação / Redirecionamento");
  assert.equal(classifySapNote(note("Improper error handling")), "Outras");
});
```

- [ ] **Etapa 2: executar o teste e confirmar a falha**

Executar:

```bash
npm run test:unit
```

Esperado: falha de resolução para `./sapPatchAnalysis.ts`.

- [ ] **Etapa 3: implementar categorias e produtos mínimos**

Usar tabelas ordenadas de expressões regulares e catálogo de produto:

```ts
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
  { name: "SAP S\/4HANA", terms: /s\/4hana/i },
  { name: "SAP Fiori", terms: /fiori/i },
  { name: "SAP CRM", terms: /\bcrm\b/i },
  { name: "SAP UI5", terms: /\bui5\b|webcomponents/i },
  { name: "SAP HANA", terms: /\bhana\b/i },
];
```

- [ ] **Etapa 4: escrever testes que falham para produto, Top 3 e fallbacks**

Adicionar casos que validem:

```ts
test("identifica produtos conhecidos e usa fallback neutro", () => {
  assert.equal(identifySapProduct(note("HTTP Request Smuggling in SAP Approuter")), "SAP Approuter");
  assert.equal(identifySapProduct(note("Security issue in an unnamed component")), "Componente SAP não especificado");
});

test("ordena Top 3 por CVSS, prioridade e número da nota", () => {
  const analysis = buildSapReportAnalysis(summary([
    noteWith({ note: "4", cvss: 8.0, priority: "High" }),
    noteWith({ note: "3", cvss: 9.0, priority: "High" }),
    noteWith({ note: "2", cvss: 9.0, priority: "Critical" }),
    noteWith({ note: "1", cvss: null, priority: "Critical", cves: [] }),
  ]));
  assert.deepEqual(analysis.topThree.map((item) => item.note), ["2", "3", "4"]);
  assert.equal(analysis.notes.at(-1)?.primaryCve, "Não informada");
});
```

O helper `noteWith()` deve apenas sobrescrever o fixture completo de `SapNote`, e `summary()` deve recalcular os campos necessários do fixture sem invocar código de produção.

- [ ] **Etapa 5: implementar a análise agregada e recomendações**

Implementar `buildSapReportAnalysis()` com:

```ts
const RECOMMENDATION_TITLES = [
  "Correção emergencial",
  "Proteção de integração e borda",
  "Higiene de credenciais e configuração",
  "Componentes descontinuados ou sem correção indicada",
  "Aplicações de negócio ABAP/Java",
  "Implantação e governança",
] as const;
```

As frases devem usar somente quantidades, severidades, produtos identificados e verbos neutros (`priorizar`, `validar`, `aplicar`, `inventariar`, `registrar`). Quando não houver evidência para um bloco, usar orientação geral sem afirmar a presença de falha. Manter `categoryCounts` na ordem do tipo `SapRiskCategory`, omitindo categorias com contagem zero.

- [ ] **Etapa 6: executar testes e confirmar sucesso**

Executar:

```bash
npm run test:unit
npm run typecheck
```

Esperado: todos os testes unitários passam e TypeScript retorna código 0.

- [ ] **Etapa 7: commit**

```bash
git add src/utils/sapPatchAnalysis.ts src/utils/sapPatchAnalysis.test.ts
git commit -m "feat(sap-patch): add deterministic pt-BR report analysis"
```

### Tarefa 2: Builder do PowerPoint executivo de seis slides

**Arquivos:**

- Modificar: `src/utils/sapPatchExport.ts`
- Criar: `src/utils/sapPatchExport.test.ts`

**Interfaces:**

- Consome: `SapPatchSummary`, `SapReportAnalysis` e construtor compatível com PptxGenJS.
- Produz:

```ts
export type PptxFactory = new () => PptxGenJS;
export function buildSapPatchPresentation(
  summary: SapPatchSummary,
  PptxLib: PptxFactory,
): PptxGenJS;
```

- `exportSapPatchPPTX()` continua sendo `Promise<void>`, importa PptxGenJS dinamicamente, chama o builder e grava o arquivo.

- [ ] **Etapa 1: escrever fake e teste estrutural que falha**

O fake deve registrar slides, textos, tabelas, formas, masters e metadados sem renderizar um arquivo real:

```ts
class FakeSlide {
  texts: string[] = [];
  tables: unknown[][][] = [];
  addText(text: string | Array<{ text: string }>) {
    this.texts.push(typeof text === "string" ? text : text.map((run) => run.text).join(""));
  }
  addTable(rows: unknown[][]) { this.tables.push(rows); }
  addShape() {}
  addChart() {}
  addTextBox() {}
}

class FakePptx {
  static ShapeType = { rect: "rect", roundRect: "roundRect", line: "line" };
  static ChartType = { bar: "bar" };
  slides: FakeSlide[] = [];
  author = "";
  company = "";
  subject = "";
  title = "";
  lang = "";
  layout = "";
  defineLayout() {}
  defineSlideMaster() {}
  addSlide() { const slide = new FakeSlide(); this.slides.push(slide); return slide; }
}
```

Teste:

```ts
test("cria seis slides na sequência aprovada e com metadados neutros", () => {
  const pptx = buildSapPatchPresentation(sample, FakePptx as never) as unknown as FakePptx;
  assert.equal(pptx.slides.length, 6);
  assert.deepEqual(pptx.slides.map((slide) => slide.texts[0]), [
    "SAP Security Patch Day",
    "Sumário executivo",
    "Consolidado de vulnerabilidades",
    "Highlights de vulnerabilidades",
    "Conclusão e recomendações",
    "Referências",
  ]);
  assert.equal(pptx.author, "ThreatSumm4ry");
  assert.equal(pptx.lang, "pt-BR");
  assert.equal(pptx.company, "");
});
```

- [ ] **Etapa 2: executar o teste e confirmar a falha**

```bash
npm run test:unit
```

Esperado: falha porque `buildSapPatchPresentation` não existe.

- [ ] **Etapa 3: extrair builder e criar o master Executivo claro**

No builder:

```ts
const COLORS = {
  blue: "1565C0",
  navy: "172033",
  slate: "526274",
  pale: "F3F6FA",
  border: "DCE3EE",
  white: "FFFFFF",
  critical: "C62828",
  high: "E66A21",
  medium: "C58A00",
  low: "2E7D32",
} as const;

pptx.defineLayout({ name: "SAP_EXECUTIVO", width: 13.333, height: 7.5 });
pptx.layout = "SAP_EXECUTIVO";
pptx.author = "ThreatSumm4ry";
pptx.company = "";
pptx.lang = "pt-BR";
pptx.subject = "Relatório automático do SAP Security Patch Day";
pptx.title = `SAP Security Patch Day — ${formatReportMonth(summary.releaseDate)}`;
```

O master de conteúdo deve conter apenas linha superior azul, rodapé neutro `SAP Security Patch Day`, data do ciclo e número do slide.

- [ ] **Etapa 4: compor os slides 1 a 3**

Criar helpers internos focados:

```ts
function addCoverSlide(pptx: PptxGenJS, summary: SapPatchSummary): void;
function addExecutiveSummarySlide(pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void;
function addConsolidatedSlide(pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void;
```

O slide 3 deve usar gráfico de barras nativo para `analysis.categoryCounts` e três cards para `analysis.topThree`. Se uma nota não tiver CVSS, exibir `Não informado`; se não tiver CVE, exibir `Não informada`.

- [ ] **Etapa 5: compor os slides 4 a 6**

Criar:

```ts
function addHighlightsSlide(pptx: PptxGenJS, analysis: SapReportAnalysis): void;
function addRecommendationsSlide(pptx: PptxGenJS, analysis: SapReportAnalysis): void;
function addReferencesSlide(pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void;
```

O slide 4 deve conter todas as notas em tabela nativa, com `CVE`, `Título`, `CVSS` e `Produto/Componente`. Usar fonte de 8 pt para até 20 notas; de 7 pt acima de 20; truncar somente a exibição do título a 100 caracteres com reticências. O slide 6 deve listar apenas `summary.url`, links deduplicados de `noteUrl` e data/hora de geração em `pt-BR`.

- [ ] **Etapa 6: testar conteúdo, fallbacks e neutralidade**

Adicionar asserções:

```ts
const allText = pptx.slides.flatMap((slide) => slide.texts).join("\n");
assert.match(allText, /Não informado|9\.9/);
assert.match(allText, /Fonte oficial SAP/);
assert.doesNotMatch(allText, /cliente|consultoria/i);
assert.equal(pptx.slides[3].tables.length, 1);
```

O fixture de teste não deve importar texto dos arquivos privados; criar dados SAP sintéticos diretamente no teste.

- [ ] **Etapa 7: integrar o download e executar testes**

`exportSapPatchPPTX()` deve terminar com:

```ts
const pptx = buildSapPatchPresentation(summary, PptxGenLib);
await pptx.writeFile({ fileName: `${baseFilename(summary)}.pptx` });
```

Atualizar `baseFilename()` para `SAP-Security-Patch-Day-AAAA-MM`, derivando ano e mês de `releaseDate` com fallback `mais-recente`.

Executar:

```bash
npm run test:unit
npm run typecheck
```

Esperado: testes e typecheck passam.

- [ ] **Etapa 8: commit**

```bash
git add src/utils/sapPatchExport.ts src/utils/sapPatchExport.test.ts
git commit -m "feat(sap-patch): generate six-slide pt-BR executive deck"
```

### Tarefa 3: Workbook executivo em pt-BR

**Arquivos:**

- Modificar: `src/utils/sapPatchExport.ts`
- Modificar: `src/utils/sapPatchExport.test.ts`

**Interfaces:**

- Consome: `SapPatchSummary`, `SapReportAnalysis` e um namespace compatível com ExcelJS.
- Produz:

```ts
export interface ExcelWorkbookFactory {
  Workbook: new () => ExcelJS.Workbook;
}

export function buildSapPatchWorkbook(
  summary: SapPatchSummary,
  ExcelLib: ExcelWorkbookFactory,
): ExcelJS.Workbook;
```

- [ ] **Etapa 1: ampliar os fakes e escrever teste que falha**

Reutilizar o padrão de `src/utils/attackSurfaceExport.test.ts`, adicionando suporte a `mergeCells`, `views`, `autoFilter`, `columns`, `getCell`, `getRow`, `addRow` e hyperlinks.

```ts
test("cria workbook executivo em pt-BR com duas abas", () => {
  const workbook = buildSapPatchWorkbook(sample, FakeExcelLib) as unknown as FakeWorkbook;
  assert.deepEqual(workbook.worksheets.map((sheet) => sheet.name), [
    "Visão executiva",
    "Notas de segurança",
  ]);
  assert.equal(workbook.creator, "ThreatSumm4ry");
  assert.deepEqual(
    workbook.getWorksheet("Notas de segurança")?.columns.map((column) => column.header),
    ["Nota", "CVE", "Título", "CVSS", "Prioridade", "Categoria", "Produto/Componente", "Atualização", "Vetor CVSS", "URL da SAP Note"],
  );
});
```

- [ ] **Etapa 2: executar e confirmar a falha**

```bash
npm run test:unit
```

Esperado: falha porque `buildSapPatchWorkbook` não existe.

- [ ] **Etapa 3: implementar a aba Visão executiva**

Adicionar título, data do ciclo, fonte, KPIs, distribuição por prioridade, distribuição por categoria e Top 3. Usar somente células e estilos nativos; configurar:

```ts
workbook.creator = "ThreatSumm4ry";
workbook.company = "";
workbook.subject = "Relatório automático do SAP Security Patch Day";
workbook.title = `SAP Security Patch Day — ${formatReportMonth(summary.releaseDate)}`;
workbook.lang = "pt-BR";
workbook.created = new Date();
```

A aba deve usar azul `1565C0` no título/cabeçalhos e manter fundo branco, bordas `DCE3EE` e textos grafite.

- [ ] **Etapa 4: implementar a aba Notas de segurança**

Preencher exatamente as dez colunas do contrato. Valores ausentes devem ser `Não informada` para CVE, `Não informado` para CVSS e `Componente SAP não especificado` para produto. `Nota`, `CVE` e `URL da SAP Note` devem usar hyperlinks quando houver destino. Congelar a primeira linha, ativar autofiltro e colorir prioridade/CVSS sem alterar os valores.

- [ ] **Etapa 5: testar linhas, links, filtros e metadados**

Adicionar:

```ts
const notes = workbook.getWorksheet("Notas de segurança")!;
assert.equal(notes.getRow(2).getCell(1).value.text, sample.notes[0].note);
assert.equal(notes.getRow(2).getCell(6).value, "RCE / Corrupção de memória");
assert.equal(notes.getRow(2).getCell(7).value, "SAP NetWeaver AS ABAP");
assert.deepEqual(notes.autoFilter, { from: { row: 1, column: 1 }, to: { row: 1, column: 10 } });
assert.equal(workbook.company, "");
```

- [ ] **Etapa 6: integrar download e executar testes**

`exportSapPatchExcel()` deve importar ExcelJS dinamicamente, chamar `buildSapPatchWorkbook()`, obter `writeBuffer()` e usar `triggerDownload()` com o mesmo nome-base do PPTX.

Executar:

```bash
npm run test:unit
npm run typecheck
```

Esperado: tudo passa.

- [ ] **Etapa 7: commit**

```bash
git add src/utils/sapPatchExport.ts src/utils/sapPatchExport.test.ts
git commit -m "feat(sap-patch): add pt-BR executive Excel workbook"
```

### Tarefa 4: Guardas da interface e cópia pt-BR

**Arquivos:**

- Modificar: `src/pages/SapPatch.tsx`
- Criar: `src/pages/sapPatchExportGuard.test.ts`

**Interfaces:**

- Consome: `SapPatchSummary | null` da página.
- Produz:

```ts
export function canExportSapPatch(data: SapPatchSummary | null): boolean;
```

- [ ] **Etapa 1: escrever teste que falha para o bloqueio**

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { canExportSapPatch } from "./SapPatch.tsx";

test("só permite export quando existem notas", () => {
  assert.equal(canExportSapPatch(null), false);
  assert.equal(canExportSapPatch(emptySummary), false);
  assert.equal(canExportSapPatch(summaryWithOneNote), true);
});
```

Fixtures devem implementar integralmente `SapPatchSummary`.

- [ ] **Etapa 2: executar e confirmar a falha**

```bash
npm run test:unit
```

Esperado: falha porque `canExportSapPatch` não existe.

- [ ] **Etapa 3: implementar guarda e textos finais**

```ts
export const canExportSapPatch = (data: SapPatchSummary | null): boolean =>
  Boolean(data?.notes.length);
```

Aplicar `disabled={!canExportSapPatch(data) || !!exporting}`. Usar `Exportar`, `PowerPoint`, `Excel`, `Exportando…` e mensagem de erro `Não há notas SAP para exportar neste ciclo.` quando a função for chamada sem notas. Preservar traduções da página para navegação, mas os nomes internos dos artefatos permanecem pt-BR em qualquer idioma da UI.

- [ ] **Etapa 4: verificar carregamento sob demanda**

Confirmar que `sapPatchExport.ts` mantém apenas imports de tipo no topo e imports dinâmicos dentro de `exportSapPatchPDF/PPTX/Excel`. Não importar `pptxgenjs` ou `exceljs` estaticamente.

- [ ] **Etapa 5: executar testes e commit**

```bash
npm run test:unit
npm run typecheck
git add src/pages/SapPatch.tsx src/pages/sapPatchExportGuard.test.ts
git commit -m "fix(sap-patch): guard exports and use pt-BR labels"
```

Esperado: testes e typecheck passam antes do commit.

### Tarefa 5: Validação integrada dos artefatos

**Arquivos:**

- Modificar: `src/utils/sapPatchExport.test.ts`

**Interfaces:**

- Consome: os builders concluídos nas tarefas 2 e 3.
- Produz: teste de regressão que inspeciona todo texto e metadado exposto pelos fakes.

- [ ] **Etapa 1: escrever teste de aceitação com fixture julho de 2026 normalizado**

Criar um fixture sintético local com pelo menos quatro notas representando Critical, High, Medium e CVSS ausente. Não copiar cabeçalhos, textos institucionais nem metadados dos arquivos em Downloads.

```ts
test("artefatos mantêm sequência, pt-BR e neutralidade", () => {
  const pptx = buildSapPatchPresentation(julySummary, FakePptx as never) as unknown as FakePptx;
  const workbook = buildSapPatchWorkbook(julySummary, FakeExcelLib) as unknown as FakeWorkbook;
  const corpus = collectFakeArtifactText(pptx, workbook);

  assert.equal(pptx.slides.length, 6);
  assert.match(corpus, /Sumário executivo/);
  assert.match(corpus, /Conclusão e recomendações/);
  assert.match(corpus, /Visão executiva/);
  assert.doesNotMatch(corpus, /customer|executive summary|security updates/i);
  assert.doesNotMatch(corpus, /cliente|consultoria/i);
});
```

- [ ] **Etapa 2: executar a verificação completa**

```bash
npm run test:unit
npm run test:server
npm run lint
npm run typecheck
npm run build
```

Esperado: todos os comandos retornam código 0. Avisos de bundle já existentes podem ser registrados, mas nenhum novo erro ou falha é aceito.

- [ ] **Etapa 3: inspecionar o diff e confirmar o escopo**

```bash
git diff --check
git status --short
git diff --stat HEAD~4..HEAD
```

Esperado: sem whitespace errors; somente os arquivos SAP e este plano aparecem no escopo da feature. O diretório `.claude/` preexistente deve permanecer intocado e fora dos commits.

- [ ] **Etapa 4: commit final dos testes de aceitação**

```bash
git add src/utils/sapPatchExport.test.ts
git commit -m "test(sap-patch): verify pt-BR report artifacts"
```

- [ ] **Etapa 5: revisão final do branch**

Executar novamente:

```bash
npm run test:unit
npm run test:server
npm run lint
npm run typecheck
npm run build
git status --short
```

Esperado: toda a verificação passa; `git status --short` mostra apenas mudanças preexistentes fora do escopo, se houver.
