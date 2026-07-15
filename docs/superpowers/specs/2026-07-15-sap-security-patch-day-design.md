# SAP Security Patch Day — Design dos relatórios automáticos

**Data:** 15/07/2026

**Status:** aprovado em brainstorming; aguardando revisão da especificação escrita

## Objetivo

Evoluir a feature SAP Patch para gerar automaticamente um PowerPoint e um Excel
executivos em português do Brasil. O PowerPoint deve manter os mesmos tópicos e
a mesma sequência do PDF de referência fornecido, mas usar um template visual
novo, neutro e próprio do produto.

Nenhum relatório, código, texto, marca, rodapé, propriedade de arquivo ou metadado
pode mencionar organizações ou identidades privadas presentes nos arquivos de
referência. Os arquivos de referência servem apenas para definir a estrutura do
conteúdo.

## Decisões validadas

- A geração será totalmente automática, sem upload mensal de XLSX.
- O conteúdo usará apenas os dados públicos coletados da página mensal da SAP.
- Não haverá dependência de IA generativa nem de enriquecimento externo para
  produzir o texto dos relatórios.
- Toda a comunicação será em português do Brasil, exceto identificadores e
  nomes técnicos oficiais, como CVE, CVSS, SAP Note e nomes de produtos.
- O PowerPoint seguirá a direção visual **Executivo claro**: fundo branco,
  azul e grafite, alta legibilidade e componentes editáveis.
- O PowerPoint terá exatamente seis slides, na sequência definida nesta
  especificação.
- O Excel usará a mesma identidade visual e conterá uma visão executiva e uma
  listagem completa.

## Fonte e modelo de dados

O backend existente continuará consultando a página pública do SAP Security
Patch Day correspondente ao ciclo mensal mais recente. O parser fornece:

- número e URL da SAP Note;
- título oficial;
- CVEs mencionadas;
- prioridade;
- CVSS e vetor CVSS, quando publicados;
- indicação de nota atualizada;
- data do ciclo e URL da fonte.

O modelo do frontend será ampliado apenas com dados derivados de maneira
determinística. Nenhum dado ausente será apresentado como fato confirmado.

## Análise automática

Um módulo puro e testável transformará as notas normalizadas em uma análise de
relatório. Ele será compartilhado pelos exports PPTX e XLSX para evitar
divergência entre os arquivos.

### Categorias

As notas serão classificadas pelo título, sem distinção entre maiúsculas e
minúsculas, nesta ordem de precedência:

1. **RCE / Corrupção de memória:** `remote code execution`, `RCE`, `memory
   corruption`, `code execution`.
2. **Configuração / Credenciais:** `credential`, `password`, `configuration`,
   `misconfiguration`, `authentication`.
3. **Ausência de autorização:** `missing authorization`, `authorization
   check`, `privilege`.
4. **Injeção:** `injection`, `XSS`, `cross-site scripting`, `SQL`, `CSS`.
5. **Traversal / Divulgação:** `traversal`, `disclosure`, `information
   exposure`, `path`.
6. **Falsificação / Redirecionamento:** `spoofing`, `smuggling`, `redirect`.
7. **Outras:** quando nenhuma regra anterior for aplicável.

Uma nota pertence a somente uma categoria. A ordem de precedência torna o
resultado estável quando o título contiver termos de mais de uma categoria.

### Produto ou componente

O produto será extraído do título oficial por um catálogo de nomes SAP
conhecidos, incluindo NetWeaver AS ABAP, NetWeaver AS Java, Approuter, Commerce
Cloud, Integration Suite, SAProuter, S/4HANA, Fiori, CRM, UI5 e HANA. Quando
nenhum nome puder ser identificado com segurança, o relatório usará
`Componente SAP não especificado`, sem inventar um produto.

### Seleção e recomendações

- O Top 3 será formado pelas três notas com maior CVSS; empates serão
  resolvidos por prioridade e depois pelo número da nota.
- Os highlights serão ordenados por CVSS decrescente, prioridade e número da
  nota. Todas as notas do ciclo aparecerão na tabela; o gerador poderá reduzir
  fonte e altura das linhas dentro de limites de legibilidade previamente
  testados.
- As prioridades imediatas citarão somente quantidades, severidades, produtos
  identificados e a necessidade de validar/aplicar a correção oficial.
- As recomendações serão montadas por regras a partir das categorias presentes.
  Não serão criadas versões mínimas, prazos, status de exploração ou instruções
  de remoção que não estejam nos dados coletados.

## PowerPoint

O PPTX usará layout widescreen 16:9, tipografia segura do sistema, formas e
tabelas nativas editáveis. Não usará imagens rasterizadas do PDF de referência.

### 1. Capa

- Título: `SAP Security Patch Day`.
- Subtítulo: `Avaliação de riscos de vulnerabilidades`.
- Mês e data do ciclo em formato pt-BR.
- Faixa azul discreta e fundo grafite/branco da identidade Executivo claro.
- Sem logotipo, nome de consultoria, organização, autor ou unidade privada.

### 2. Sumário executivo

- Frase automática com total de notas e distribuição por prioridade.
- Lista deduplicada de produtos/componentes afetados identificados.
- Três prioridades imediatas geradas por regras.
- Destaque visual para críticas, altas e CVSS máximo.

### 3. Consolidado de vulnerabilidades

- Total de notas do ciclo.
- Gráfico horizontal da distribuição por categoria.
- Explicações curtas e estáveis para as categorias efetivamente presentes.
- Top 3 com CVE principal, CVSS, produto e título resumido sem alterar o sentido
  do título oficial.

### 4. Highlights de vulnerabilidades

- Tabela com CVE, título oficial, CVSS e produto/componente identificado.
- Indicação visual de notas atualizadas.
- Cores de severidade consistentes com os KPIs.
- Caso uma nota tenha várias CVEs, todas serão mantidas na mesma célula.

### 5. Conclusão e recomendações

Seis blocos, sempre na mesma ordem:

1. Correção emergencial.
2. Proteção de integração e borda.
3. Higiene de credenciais e configuração.
4. Componentes descontinuados ou sem correção indicada.
5. Aplicações de negócio ABAP/Java.
6. Implantação e governança.

Quando um bloco não tiver evidência específica no ciclo, usará uma orientação
geral de validação e inventário, sem afirmar que existe determinada falha.

### 6. Referências

- URL da página oficial SAP usada na coleta.
- Links das SAP Notes presentes no ciclo, agrupados de maneira legível.
- Data e hora da geração em pt-BR.
- Nenhuma fonte não consultada será listada.

## Excel

O arquivo XLSX conterá:

- **Visão executiva:** título, data, KPIs, distribuição por prioridade e por
  categoria e Top 3.
- **Notas de segurança:** Nota, CVE, Título, CVSS, Prioridade, Categoria,
  Produto/Componente, Atualização, Vetor CVSS e URL da SAP Note.

As duas abas terão cabeçalhos em pt-BR, filtros, painéis congelados, larguras
adequadas, hyperlinks e cores de severidade. O workbook não reutilizará estilos,
fontes, imagens ou propriedades do XLSX de referência.

## Neutralidade e metadados

- O autor/criador dos arquivos será `ThreatSumm4ry`.
- Título, assunto, empresa e descrição conterão apenas a finalidade genérica do
  relatório SAP.
- Comentários, notas do apresentador e propriedades personalizadas não serão
  copiados de arquivos de referência.
- Os nomes dos arquivos seguirão `SAP-Security-Patch-Day-AAAA-MM.pptx` e
  `SAP-Security-Patch-Day-AAAA-MM.xlsx`.
- Testes inspecionarão o conteúdo textual gerado para impedir as expressões
  privadas conhecidas no artefato final.

## Arquitetura

1. `src/utils/sapPatchAnalysis.ts` concentrará classificação, extração de
   produtos, ordenação, Top 3 e textos estruturados de recomendação.
2. `src/utils/sapPatchExport.ts` consumirá essa análise e ficará responsável
   somente pela composição visual e gravação de PPTX/XLSX.
3. Os exports continuarão sendo carregados sob demanda para não aumentar o
   bundle inicial da página.
4. Funções pequenas de layout cuidarão de cabeçalho, rodapé, KPIs, tabela,
   quebra de texto e cores de severidade.

## Tratamento de limites

- Nenhuma nota: o export será bloqueado com mensagem clara na interface.
- CVSS ausente: mostrar `Não informado`, sem convertê-lo em zero.
- CVE ausente: mostrar `Não informada`.
- Produto não identificado: usar o texto neutro definido nesta especificação.
- Mais conteúdo do que cabe no slide 4: ajustar a tabela dentro de limites de
  fonte e espaçamento testados; se o limite ainda for excedido, condensar o
  título visualmente sem remover linhas, preservando o título completo no XLSX.
- Texto derivado nunca substituirá ou alterará os dados originais armazenados.

## Testes e critérios de aceitação

- Testes unitários cobrirão cada categoria, precedência, produto conhecido,
  fallback de produto, Top 3, empates, CVSS/CVE ausentes e recomendações.
- Um teste de PPTX verificará seis slides e a ordem dos respectivos títulos.
- Um teste de XLSX verificará nomes das abas, cabeçalhos, quantidade de linhas,
  filtros, hyperlinks e valores derivados.
- Os arquivos compactados PPTX/XLSX serão inspecionados para garantir a ausência
  dos nomes privados presentes nas referências e de seus termos equivalentes
  definidos nos testes.
- Os textos de interface e export serão verificados em pt-BR.
- A saída será validada com o fixture de julho de 2026 e com casos sintéticos
  pequenos para garantir que o template continue funcionando em outros meses.
- O comando de build e a suíte de testes existente deverão continuar passando.

## Fora de escopo

- Upload ou edição manual de XLSX.
- Histórico e seletor de mês.
- Enriquecimento NVD, EPSS, KEV ou fontes jornalísticas.
- Geração de narrativa por IA.
- Cópia de elementos visuais ou de identidade dos arquivos de referência.
