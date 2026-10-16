# OT/ICS Patch Day — validação

## Dados reais e fontes

- Distribuição oficial Schneider: metadata, changes.csv, index.txt e três
  JSONs testados retornaram HTTP 200 neste ambiente. O índice tem 293 entradas;
  outubro contém dois avisos novos e uma revisão de aviso de 2025.
- Exemplos: SEVD-2026-286-02 (13/10/2026); SEVD-2025-252-01 (publicado em
  09/09/2025, última revisão em 13/10/2026); SEVD-2025-224-05 (revisão em
  11/08/2026, modelo BMXNOE0110 identificado pelo `model_numbers`).
- Coleta real local das quatro fontes completou dois lotes, sem falhas
  pendentes. Após limitar Cisco ao escopo industrial/rede, outubro contém
  32 avisos consolidados. São dados públicos de teste, não estatística fixa
  prometida ao usuário; podem mudar com as atualizações das fontes.
- Portal Rockwell real: 299 avisos. Parser por DOM de fragmentos foi substituído
  por análise textual delimitada: teste isolado 596 → 37 ms, RSS final do
  processo 254 → 87 MiB, heap limitado a 128 MiB. Não é benchmark do ETL completo.

## Verificação

- 798 testes de backend passaram. Casos novos cobrem publicação/revisão,
  correção versus mitigação, model_numbers e relacionamentos CSAF, correspondência
  exata sem prefixos falsos, fronteiras de URL, índice Schneider, cache diário,
  single flight, reinício persistido, falha de fonte, deduplicação e privacidade.
- 257 testes de frontend passaram no comando local (inclui os sete de marca).
  Excel gerado/reaberto preservou versões, orientação, fonte, data e fórmulas
  externas como texto literal. Typecheck e build passaram. Lint: zero erros,
  16 avisos preexistentes.

## Implantação e cliques

- Release `a2dc980`: CI `38911010490`, VPS `38911331416` e Cloudflare
  `38911332217` aprovados; SHA confirmado. A varredura de dependências separada
  permanece com os achados preexistentes, sem mudança de manifests.
- Quatro índices disponíveis na VPS, incluindo Schneider às 10:56:03 de
  Fortaleza. Coleta de outubro concluiu com 32 avisos, 4 sinais KEV e sem
  arquivos pendentes/falhos. Filtro Schneider mostrou exatamente os três
  documentos esperados; datas inicial/revisão e produto/versão SAGE exibidos.
  EPSS de 0,15% veio do catálogo local e apareceu no detalhe.
- Excel real baixado pela interface e reaberto: três avisos, duas abas,
  23 colunas, versões SAGE, EPSS e datas preservados; zero fórmulas.
- Conferência encontrou link de um CISA apontando a orientação genérica em
  vez do advisory. Correção usa o identificador oficial, cobre ICSMA e
  repara os links já persistidos sem refazer a coleta. A busca também passa
  a incluir os códigos de modelo do CSAF além do nome comercial.

## Conferência final

- Release `a2f2d50`: CI `38912118052` aprovado (799 backend, 250 frontend
  unitários e 7 de marca). VPS `38912352059` e Cloudflare `38912351826`
  aprovados; SHA da VPS confirmado. API devolveu 32 avisos de outubro,
  as quatro fontes com estado `ok`, zero pendências/falhas e sem erro de
  persistência. Link corrigido de ICSA-26-281-02 confirmado na resposta real.
- Seletor nativo de mês testado em agosto de 2026: 50 avisos, um com modelo
  explícito do catálogo. Filtro de modelos e busca `BMXNOE0110` encontraram
  SEVD-2025-224-05, com publicação em 12/08/2025 e revisão em 11/08/2026.
- Segundo Excel real baixado e reaberto: uma linha, ID e código BMXNOE0110
  completos, CVE-2025-6625 e versão corrigida 6.80 preservados. Captura
  local da interface foi mantida fora do commit por incluir a sessão da conta.
