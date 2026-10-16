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

## Implantação inicial e investigação de memória

- Release `3a1a8d1`: CI `38904432345`, VPS `38904669142` e Cloudflare
  `38904669215` concluídos com sucesso. SHA confirmado no deploy.
- Excel da base unificada baixado novamente na versão publicada, sem erro
  exibido. O arquivo foi reaberto: 29.814 evidências, 12 colunas, abas IOCs e
  Resumo, zero fórmulas. A mensagem original do usuário continua sem reprodução.
- Auditoria `38905057571` identificou vários encerramentos anteriores por
  `JavaScript heap out of memory`, inclusive em 16/10 às 05:43, 09:37 e 09:51
  de Fortaleza. Isso também fazia a extração começar fria após cada reinício.
  Atribuir o recálculo observado exclusivamente à data do catálogo seria
  incorreto: os reinícios foram confirmados pelos logs.
- Auditoria `38905391627`: host com 1.000.542.208 bytes de RAM. Publicações
  e eventos somam 26.934.038 bytes de JSON no SQLite (7.976 / 5.422 documentos).
  Não foram impressos dados brutos, segredos ou evidências privadas.
- Segunda otimização: evitar ler a cópia JSON legada quando SQLite já é a
  fonte primária; validar o snapshot uma vez no boot; ler/verificar payloads
  SQLite com iteradores; manter somente IDs/hashes antigos no reconciliador;
  destacar documentos um a um; escrever cópias de recuperação em blocos de
  aproximadamente 256 KiB, com rename atômico e preservação da versão anterior
  em caso de falha. Revisões, hashes e transação conjunta continuam verificados.
- Ensaio sintético com 8.000 publicações, 5.400 eventos e 27.146.825 bytes de
  JSON, heap limitado a 256 MiB: pico de RSS 452.416 → 399.944 KiB (redução
  de 11,6%); duração 968 → 1.044 ms. Integridade aprovada em ambas as versões.
  É uma medição local do caminho de persistência, não prova de eliminação de
  todos os encerramentos em produção. Telemetria por fase foi acrescentada
  ao diagnóstico do ciclo para acompanhar os próximos picos.
- Auditoria `38906390603` (primeira release): arquivo persistido restaurou
  3.396 extrações, 4.411.675 bytes, zero erros de leitura, sem reiniciar o
  serviço para o ensaio. É o mesmo construtor de restauração do boot, chamado
  somente para leitura. C2Agent manteve 32 hashes no histórico e no evento.
  O ciclo às 10:12:35 de Fortaleza tentou 40 textos em 40 sites; 27 tiveram
  sucesso e 13 falharam, contra 15 sucessos e 25 falhas no ciclo anterior.
  Não é uma comparação controlada de disponibilidade dos editores.
  Serviço sem reinícios automáticos desde a primeira implantação às 10:03.

## Segunda implantação

- Release `768533e`: CI `38906249980` aprovado (787 testes de backend,
  249 unitários de frontend e 7 de marca; typecheck/build aprovados).
  VPS `38906567956` e Cloudflare `38906568468` aprovados, SHA confirmado.
  A varredura separada de dependências segue com os 49 achados preexistentes;
  manifests de dependências não foram alterados. Gitleaks passou na primeira
  release; verificação local de valores de credenciais no diff também passou.
- Integridade `38906947067`, geração 131: 7.982 publicações / 5.426 eventos;
  cópias JSON iguais ao SQLite, zero fontes órfãs, aliases conflitantes ou
  fontes duplicadas. Inventário: 7.982 publicações processadas, 368 com IOCs,
  3.635 menções normalizadas válidas, 3.443 valores distintos derivados das
  notícias, 8.139 vínculos de entidades esperados; zero ausências ou vínculos
  obsoletos. Os 10 indicadores rejeitados pela normalização permanecem no
  histórico bruto. Esses números não abrangem todos os IOCs das APIs externas.

- Auditoria `38907798141`: ciclo completo às 10:25:10 de Fortaleza, 390.136 ms,
  sem reinícios desde a implantação. Pico do serviço: 572.329.984 bytes.
  Cache persistido restaurou 3.407 entradas / 4.448.076 bytes, zero erros.
  Os 32 hashes do C2Agent permanecem no histórico e no evento. Esse primeiro
  ciclo é frio após a mudança de código; não representa a latência com cache.
Não se conclui precisão semântica de todas as atribuições ou cobertura
integral de textos bloqueados a partir de uma auditoria de persistência.
