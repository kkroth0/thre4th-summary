# Hunting: KQL ancorada em mapeamento e relatório da execução

Data: 2026-08-13
Status: aprovado no brainstorming, pronto para virar plano

## Problema

O gerador de hunt manda ao modelo apenas nome de tabela e de coluna, em ordem
de dump, e valida a resposta com `unknownTables()`. Isso impede alucinação de
tabela, mas não produz KQL boa: o modelo não sabe para que serve cada tabela,
qual campo é pivô e qual é ruído, nem que formato de saída o analista lê.

E o resultado da caça não vira documento. O analista fecha a execução com
achados em texto livre; o relatório que ele entrega hoje é montado à mão fora
do app, com hipótese, objetivo, janela investigada, resultado, consultas
executadas e recomendações.

Existem três planilhas de mapeamento do workspace Sentinel e um formulário de
threat hunting em PDF que resolvem os dois lados — desde que virem dado do app
em vez de anexo de e-mail.

## Decisões tomadas

| Decisão | Escolha |
|---|---|
| Onde os mapeamentos vivem | Convertidos e commitados no repo (privado), anonimizados no script de conversão |
| Mecanismo principal | Biblioteca curada navegável **e** gerador ancorado nos mesmos dados |
| Âncora do relatório | A execução (run), não a hunt |
| Campos do formulário | Estruturados no modelo; identidade (empresa, investida, analista) fora dele |
| Consultas por hunt | Lista (`queries[]`), não campo único |

Restrição transversal: nenhum artefato — dado, prompt, tela ou PDF — pode
conter "EY" ou "Votorantim". A regra é verificada por teste, não por revisão.

## Arquitetura

Quatro peças novas, cada uma consumível sozinha, ligadas por dois arquivos de
dados. Nada de serviço novo, nenhuma dependência nova.

```
hunting-docs/*.xlsx  (insumo, fora do git)
        │
        ▼  server/scripts/build-hunting-refs.mjs   (conversão + anonimização)
        │
        ├──► server/data/huntingContext.json   45 tabelas: propósito, casos de uso, campos-chave por papel
        └──► server/data/kqlLibrary.json       41 queries: pergunta, objetivo, KQL, parâmetros, validação
                    │                     │
                    ▼                     ▼
        server/huntGenerator.js      /api/hunts/kql (aba Queries)
        (prompt ancorado +           origem "Curadas" ao lado das 237 do repo
         unknownColumns como aviso)
                    │
                    ▼
        server/hunts.js  ── modelo cresce ──►  src/utils/huntReportExport.ts ──► PDF
        (hunt: objetivo, escopo, exclusões,     (6 seções + anexo técnico)
         prioridade, tipo, intelSource, queries[];
         run: janela, recomendações, evidence[], 5 outcomes)
```

### 1. Conversão dos mapeamentos

`server/scripts/build-hunting-refs.mjs`, no mesmo padrão de
`server/scripts/build-actors.mjs`: XLSX é insumo de build, JSON é o artefato
versionado. Lê com `exceljs`, que já é dependência.

**Entradas** (`hunting-docs/`, listado no `.gitignore`):

- Mapeamento de KQLs → aba `Catálogo Completo`, cabeçalho na linha 4, dados nas
  linhas 5–45: `Seção | Pergunta / O que responde | Tabela(s) | Objetivo | KQL
  pronta para copiar | Parâmetros | Cobertura`.
- Mapeamento Contextualizado → aba `Contexto por Tabela`, cabeçalho na linha 4,
  dados nas linhas 5–49: `Tabela | Domínio | Categoria operacional | Descrição
  objetiva | Propósito para hunting | Casos de uso recomendados | Campos-chave
  reais | Validação / cautela`.
- Mapeamento Completo → aba `Dicionário de Campos`, dados nas linhas 5–557:
  `Tabela | Domínio | Campo | Tipo lógico | Uso investigativo`.

**Saída `server/data/huntingContext.json`**

```json
{
  "generated_at": "2026-08-13T00:00:00.000Z",
  "tables": [{
    "table": "TrendMicro_XDR_OAT_CL",
    "domain": "Endpoint e Sistemas",
    "category": "Endpoint / EDR",
    "purpose": "Investigar telemetria de endpoint associada a artefato ou IOC.",
    "useCases": ["Execução suspeita", "Movimentação lateral"],
    "caution": "Usar somente campos presentes no esquema mapeado.",
    "keyFields": [
      { "name": "TimeGenerated", "type": "datetime", "role": "pivot" },
      { "name": "detail_processCmd_s", "type": "string", "role": "filter" },
      { "name": "detail_riskLevel_s", "type": "string", "role": "filter" }
    ]
  }]
}
```

`role` sai do tipo lógico do dicionário: `datetime` → `pivot`, `numeric` →
`metric`, `dynamic` → `parse`, resto → `filter`. É a informação que o prompt
usa para ordenar as colunas; sem ela o mapeamento de campos seria só uma lista.

**Saída `server/data/kqlLibrary.json`**

```json
{
  "generated_at": "2026-08-13T00:00:00.000Z",
  "queries": [{
    "id": "kql-04-01",
    "section": "4. Rede, SASE e WAF",
    "question": "Tráfego de ou para IP",
    "objective": "Dimensionar conexões, portas, ações e bytes",
    "tables": ["CommonSecurityLog"],
    "query": "let ip=\"<IP>\"; CommonSecurityLog | where TimeGenerated > ago(30d) | ...",
    "params": ["IP", "janela"],
    "validation": "Validada pelo esquema"
  }]
}
```

`id` é derivado da seção + posição, estável entre execuções do script: é o que
a UI usa como chave e o que o prompt cita ao dizer de onde tirou o exemplo.

**Anonimização.** Dois padrões — `/\bEY\b/gi` e `/votorantim\w*/gi` — aplicados
a todo texto antes de escrever, substituindo por vazio ou pelo termo genérico
quando a frase precisar de sujeito ("o cliente"). Depois
da substituição, o script varre o JSON serializado e **falha** se qualquer
padrão sobreviver — regenerar não reintroduz nome. Nomes de produto
(Cloudflare, Netskope, CyberArk, Orca, TrendMicro, SAP) ficam: identificam
integração, não cliente. Os XLSX não contêm IP, e-mail nem domínio interno;
a varredura cobre o caso de uma planilha futura passar a conter.

### 2. Gerador ancorado

`server/sentinelTables.js` — `renderCatalogForPrompt` passa a aceitar o
contexto. Para cada tabela: propósito e casos de uso em uma linha, depois as
colunas **começando pelos campos-chave, anotados com o papel**, e só então o
resto até o teto de `maxColumns`. O orçamento de contexto não muda; o que muda
é o que cabe nele. Sem o contexto carregado (arquivo ausente), a função
devolve exatamente o que devolve hoje.

`server/huntGenerator.js`:

- `pickExamples({ library, hypothesis, sources, catalog })` — até 3 queries da
  biblioteca, ranqueadas por (a) tabela da query presente nas fontes escolhidas
  e (b) sobreposição de palavras entre a hipótese e `question` + `objective`.
  Contagem, não embedding: determinístico, testável, sem chamada extra.
- `GENERATOR_SYSTEM` ganha duas exigências que são o que separa KQL boa de KQL
  que roda: janela temporal explícita e `project` dos campos-chave da tabela.
- `unknownColumns(kql, catalog)` — identificadores usados em `where`,
  `project` e `summarize ... by` que não existem em nenhuma tabela citada pela
  consulta, descontando os que a própria consulta define (`let`, `extend`,
  `<nome> =` dentro de summarize, `project-rename`). **Não bloqueia**: volta em
  `unknownColumns` no payload e aparece como aviso na tela, ao lado do aviso de
  tabela. Recebe comentário `ponytail:` nomeando o teto (heurística de linha) e
  a saída (parser de KQL) caso vire ruído.

Contrato de `/api/hunts/generate` inalterado; a resposta ganha
`unknownColumns: string[]` e `examplesUsed: string[]` (ids da biblioteca).

### 3. Biblioteca curada na tela

Nova rota `GET /api/hunts/kql/curated` devolve `kqlLibrary.json` inteiro (41
itens, poucos KB — não precisa do carregamento sob demanda que as 237 do repo
precisam). Na aba **Queries** que já existe, um seletor de origem: "Curadas"
(as 41, com seção, pergunta, objetivo e cobertura) ou "Repositório" (as 237 de
hoje). Ao abrir uma curada, campos de texto para os parâmetros declarados
(`<IOC>`, `<UPN>`, `<IP>`, janela); a substituição acontece na cópia, sobre o
texto da query. Aba nova, nenhuma.

### 4. Modelo de hunt e execução

`server/hunts.js`, `normalizeHuntInput` — campos novos, todos opcionais:

| Campo | Tipo | Validação |
|---|---|---|
| `objective` | string | `clean`, 4000 |
| `scope` | string | `clean`, 4000 |
| `exclusions` | string | `clean`, 4000 |
| `priority` | enum | `'' \| baixa \| media \| alta \| critica` |
| `huntType` | enum | `'' \| hypothesis \| intel` |
| `intelSource` | `{ title, url }` | url só `http(s)`, 500 chars |
| `queries` | array | `{ id, label, query }`, teto 20, KQL 100000 |

`withDefaults()` migra na leitura: hunt sem `queries` mas com `query` ganha
`queries: [{ id: 'q1', label: '', query }]`. `query` continua sendo escrito
como espelho de `queries[0].query` enquanto o detalhe da hunt e
`/api/hunts/by-technique` o lerem — some quando os dois pararem.

`normalizeRunInput` — campos novos:

| Campo | Tipo | Validação |
|---|---|---|
| `windowStart` / `windowEnd` | ISO string | datas válidas; fim não antes do início |
| `recommendations` | string | `clean`, 5000 |
| `evidence` | array | `{ queryId, result }`, teto 20, result 300 chars |

`RUN_OUTCOMES` cresce de `none | suspicious | incident` para incluir
`falsepositive` e `legitimate`, cobrindo os quatro resultados do formulário.
É aditivo: `monthlySummary` conta por chave e execução gravada antes continua
significando o mesmo.

Identidade do relatório (empresa, investida, analista) fica em `localStorage`
na página de Hunting, como a página de Atores já faz com os perfis de
organização (`actor-threat-profiles`). São constantes entre relatórios e não
têm por que ser gravadas por hunt no servidor. Nenhum store novo, nenhuma rota
nova.

### 5. Relatório PDF

`src/utils/reportPdf.ts` — a parte genérica extraída de `exportBoletimPDF`:
paginação, quebra de bloco, tabela via `jspdf-autotable`, `import()` dinâmico
das libs. O tipo `Block` ganha `code` (KQL em monoespaçada com fundo) e
`fields` (grade rótulo/valor). Boletim e hunt passam a dividir o renderer,
cada um com seu cabeçalho. É a mudança de maior risco do plano: mexe num
export que já roda, então `boletimExport.test.ts` tem que passar antes e
depois, sem alteração no teste.

`src/utils/huntReportExport.ts` — `huntReportSections(hunt, run, identity)`
devolve `ReportSection[]` na ordem do formulário:

1. **Identificação** — id da hunt, data de abertura, analista, empresa,
   investida, prioridade, tipo, janela investigada, resultado, origem de
   inteligência.
2. **Hipótese e escopo** — hipótese, objetivo, escopo, exclusões.
3. **Resultados e conclusões** — achados, eventos, hosts.
4. **Fontes de dados** — tabelas citadas pelas consultas, via `extractTables`.
5. **MITRE ATT&CK** — técnicas com link para attack.mitre.org; nome quando a
   tela já carregou a cobertura, id sozinho quando não.
6. **Tratativas e recomendações** — `run.recommendations`.
7. **Anexo A — consultas realizadas** — por consulta: "KQL-01 — rótulo", a KQL
   passada por `formatKql` (que já existe) em bloco `code`, e "Resultado
   observado: …" vindo de `evidence`.

Seção sem conteúdo não é impressa, como no boletim. Rodapé: CONFIDENCIAL,
empresa do perfil, página X de Y. Marca do app; nunca EY.

### 6. Telas

- **Formulário da hunt**: campos novos em um bloco "Documentação" recolhível,
  para não alongar o caminho de quem só quer salvar uma hunt; editor de
  consultas com rótulo + KQL, adicionar e remover, e o gerador preenchendo a
  primeira.
- **`FinishRunDialog`**: janela investigada com `<input type="datetime-local">`
  nativo, os cinco resultados, recomendações, e uma linha de evidência por
  consulta da hunt.
- **Botão "Relatório PDF"** no card da execução fechada e no detalhe da hunt
  (usando a execução mais recente fechada).

## Testes

| Alvo | Onde | O que trava |
|---|---|---|
| Conversão XLSX → JSON | `server/test/huntingRefs.test.js` | papel de campo derivado do tipo; id estável; **anonimização**: nenhum termo proibido sobrevive |
| Prompt ancorado | `server/test/huntGenerator.test.js` | campo-chave vem antes do resto; contexto ausente = comportamento de hoje |
| Escolha de exemplo | idem | ranking determinístico; teto de 3; fonte errada não entra |
| `unknownColumns` | idem | alias de `let`/`extend`/`summarize` não vira falso aviso; coluna inventada aparece |
| Modelo | `server/test/hunts.test.js` | enums, janela invertida, migração `query` → `queries[]`, outcome novo no `monthlySummary` |
| Relatório | `src/utils/huntReportExport.test.ts` | ordem das seções, seção vazia sai fora, anexo casa consulta com evidência |
| Não-regressão | `src/utils/boletimExport.test.ts` | passa sem alteração depois da extração do renderer |

## Fases

1. **Dados** — script de conversão, os dois JSON, teste de anonimização.
2. **Gerador** — prompt ancorado, exemplos, `unknownColumns`, avisos na tela.
3. **Biblioteca** — rota `curated`, origem na aba Queries, parâmetros.
4. **Modelo** — campos novos em hunt e run, migração, validação, testes.
5. **Relatório** — extração do renderer, seções, botão, telas dos campos novos.

Cada fase é entregável sozinha: 1–3 melhoram a KQL sem tocar no relatório;
4–5 entregam o documento.

## Fora de escopo

- Print de tela anexado ao relatório (a evidência é digitada).
- Geração do PDF no servidor (jsPDF no cliente é o padrão da casa).
- Substituir o gerador por seleção de receita fixa da biblioteca.
- Migração dos dados gravados: tudo novo é opcional e migrado na leitura.
