# ETL e exportação Excel — 16/10/2026

## Diagnóstico e alterações

- Auditoria somente leitura antes das alterações: Actions `38903671732`.
  Ciclo das 09:43:05 de Fortaleza: 297.099 ms; extração 144.086 ms,
  3.388 recalculadas e zero reaproveitadas. As outras duas extrações medidas
  levaram 6.590 e 6.790 ms. O ciclo completo também depende de rede e publicação;
  esses números não são uma promessa de duração depois da alteração.
- Cache de extração persistido em `.feed-cache/extraction.bin`, limitado a
  6.000 entradas / 32 MiB. Reinício pode restaurar resultados quando código,
  dependências, catálogos e entradas permanecem iguais. Hash das dependências
  locais de `index.js` e dos manifests invalida resultados após mudanças de
  backend. O conteúdo dos índices identifica o catálogo; uma nova data da
  coleta não obriga a recalcular evidências idênticas. KEV/EPSS continuam fora
  do cache, aplicados a cada ciclo. Cache indisponível resulta em recálculo.
- Textos completos: 27–39 falhas em 40 tentativas nos três ciclos anteriores.
  Fila alterna editores, prioriza entradas ainda não tentadas e espaça falhas
  repetidas entre 1 h e 24 h. Resumo modificado inicia nova tentativa. Estado
  leve de tentativas no SQLite sobrevive à poda do cache; versões boas de
  texto e suplementos de IOCs permanecem preservadas.
- Exportação: relacionamentos agregados na mesma leitura SQL, eliminando a
  preparação de uma consulta por linha. Mantidos período, ordem, fontes,
  evidências independentes e isolamento por conta.
- Excel de notícias/base de IOCs montado e compactado em Web Worker. A tela
  permanece responsiva; worker termina ao concluir/falhar, com prazo de 120 s
  e mensagem de recuperação. O arquivo segue contendo todas as linhas.

## Evidências locais e no navegador

- Antes da mudança, reprodução em produção baixou um Excel válido: 29.814
  linhas de evidências, 1.838.568 bytes; abas IOCs e Resumo, zero fórmulas.
  O erro original relatado não se repetiu nesse ensaio. Não atribuir uma
  causa específica sem a mensagem original; a correção remove bloqueio
  conhecido da interface e custo desnecessário da exportação.
- Comparação sintética, 30.000 observações com quatro relações por observação:
  consulta anterior 767 / 757 / 817 ms; nova 262 / 259 / 285 ms. JSONs completos
  com hashes SHA-256 iguais. Medição local, não latência de produção.
- Worker real no navegador, bundle de produção: 30.000 linhas geradas em
  1.585 ms; 16 atualizações do contador da interface durante a geração.
  Arquivo de 1.346.888 bytes reaberto com ExcelJS: 30.000 linhas e último hash
  integralmente preservado. O ensaio usa dados sintéticos, sem expor insumos
  privados da conta.
- 783 testes de backend passaram, incluindo reinício/invalidação do cache,
  falha de escrita, backoff, preservação do corpo e exportação por conta.
  Seis testes específicos de Excel passaram com leitura do ZIP gerado.
  Typecheck, lint dos arquivos frontend alterados e build passaram.

## Fontes avaliadas

[Mapeamento de fontes](../../product/actor-ioc-source-gaps.md) ampliado com
SophosLabs e WithSecureLabs. A coleta dedicada continua em Unit 42 e Arctic
Wolf; as sete candidatas não foram ativadas. Não confundir fonte de notícias
já cadastrada com parser dos arquivos do repositório implementado.

Validação de implantação e de integridade após a publicação: pendente.
Não se conclui precisão semântica de todas as atribuições ou cobertura
integral de textos bloqueados a partir de uma auditoria de persistência.
