# Task 3 — Workbook executivo SAP em pt-BR

## Status

Implementado `buildSapPatchWorkbook()` com duas abas, metadados pt-BR serializáveis por `workbook.language`, conteúdo executivo integralmente estilizado, análise de notas, fallbacks, hyperlinks, filtro, congelamento, bordas e cores nativas do ExcelJS. `exportSapPatchExcel()` preserva o import dinâmico e usa o mesmo nome-base do PPTX.

## Evidência TDD

- RED — `npm run test:unit`: exit 1 em `sapPatchExport.test.ts`, com `No matching export ... for import "buildSapPatchWorkbook"`.
- GREEN focado — `npx esbuild src/utils/sapPatchExport.test.ts --bundle --platform=node --format=esm --outfile=/tmp/sapPatchExport.test.js && node --test /tmp/sapPatchExport.test.js`: 9 testes, 9 passaram, exit 0.
- RED da revisão — o mesmo teste focado: 12 testes, 10 passaram e 2 falharam; `language` permaneceu `""` e o preenchimento branco executivo era `undefined`.
- GREEN da revisão — teste focado: 12 testes, 12 passaram, exit 0. Cobertura adicionada para estilos, `created`, fallbacks, hyperlinks ausentes, Atualização/Vetor, seções executivas e `xlsx.writeBuffer()` injetado.
- Typecheck — `npm run typecheck`: exit 0, sem diagnósticos.
- Suíte global — `npm run test:unit`: 61 testes, 60 passaram e 1 falhou fora do escopo (`config/seo.test.ts`: expectativa não contém a rota `/sap-patch`, já presente no catálogo). Os 12 testes de export SAP passaram, incluindo os 7 de PPTX.

## Arquivos

- `src/utils/sapPatchExport.ts`
- `src/utils/sapPatchExport.test.ts`

## Autocrítica e preocupações

- A aba executiva usa somente células e estilos nativos, sem gráficos; todas as células com conteúdo em ciclo/fonte, KPIs, distribuições e Top 3 têm fundo branco, borda `DCE3EE` e texto grafite.
- O link de CVE aponta para o registro público em `cve.org`, inferido do identificador porque o contrato de entrada não fornece URL própria.
- O teste de integração usa `xlsx.writeBuffer()` injetado no factory, evitando inventar globais DOM em Node; o fluxo de download continua isolado no exportador de borda.
- A falha global de SEO não foi alterada para evitar expandir o escopo desta task.
- `.claude/` permaneceu intocado e fora do commit.
