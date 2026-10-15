# Reaproveitamento da extração de notícias

O ciclo anterior instrumentado gastou 168.694 ms em extração, apesar de muitas
publicações repetirem o mesmo conteúdo. Esta alteração evita repetir scoring,
classificação, match de atores/malware/campanhas e extração de IOCs quando os
insumos continuam iguais. Não altera as regras de extração ou de correlação.

## Invalidação e isolamento

- Chave canônica de todos os campos da publicação, corpo coletado, suplementos
  de IOCs, versão do extrator e revisão do catálogo. Apenas `collectedAt`,
  `collectionStatus` e `articleCollectionStatus` são telemetria: os valores
  atuais continuam aparecendo no resultado.
- Malware/campanhas são indexados no boot; atualização de código reinicia o
  cache. A atualização do catálogo CTI.fyi muda a revisão de atores. Cada passe
  captura o índice de atores e sua revisão para evitar mistura durante yields.
- Guarda apenas campos derivados; não duplica o corpo da notícia no cache.
  Cache em memória, até 6.000 entradas e 32 MiB de buffers/identificadores
  contabilizados, além do overhead dos objetos do processo. LRU e substituição
  de revisão por URL. Nada é truncado na base ou nos exports por esses limites.
- Serialização V8 separa os resultados do cache de mutações posteriores em
  arrays/objetos, incluindo pontuação/reasons de KEV. KEV e EPSS seguem fora
  do cache e são consultados/aplicados em cada ciclo.
- Resultados vazios também são reaproveitados; falha de extração não instala
  resultado parcial. Sem revisão de catálogo explícita, a extração não usa cache.
- A extração manual completa continua sem este cache. Os suplementos salvos
  por ela entram na identidade do próximo passe automático.

## Verificação

731 testes backend aprovados localmente. Regressões exercitam match real de
atores/malware/campanhas, novos IOCs no corpo/anexo, famílias declaradas em
repositórios, metadados/categorias, revisão de regras/catálogos, resultados sem
IOCs, ausência de KEV antigo, EPSS zero, mutação do consumidor e limites LRU.
Testes existentes de recuperação, extração/correlação e isolamento continuam
aprovados. Nenhuma dependência adicionada.

O auditor `extraction` executa um replay somente em memória, em amostra estável
de até 120 entradas públicas dos caches RSS da VPS e corpos retidos. Usa os
catálogos embarcados, sem rede, escrita de cache, alteração de inventário ou
correlação. Compara os resultados frios e reaproveitados por valor, imprimindo
somente contagens/tempos. Não mede o ciclo completo e não inclui o catálogo
CTI.fyi dinâmico do processo. A configuração local não tem entradas RSS para
esse replay; a conferência com insumos reais é feita após o deploy na VPS.

Os ciclos reais passam a registrar `reused`, `recomputed`, `evictions`, `entries`
e `bytes`, junto com os tempos já existentes. O primeiro ciclo após restart
precisa preencher o cache; o benefício recorrente depende da proporção de
conteúdo/catálogos inalterados. Rede e persistência continuam com custos próprios.

Resultados de CI, deploy e auditoria de produção serão registrados abaixo.
