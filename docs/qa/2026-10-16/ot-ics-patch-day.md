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

Validação da implantação e dos cliques em produção: pendente.
