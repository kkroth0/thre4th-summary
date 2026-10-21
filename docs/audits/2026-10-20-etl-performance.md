# Auditoria de desempenho do ETL — 20/10/2026

A plataforma já tem deduplicação, retomada e reaproveitamento de extrações. O
principal risco de crescimento está no trabalho que ainda depende do tamanho do
acervo inteiro, executado no mesmo processo que atende às telas. A correção deve
preservar as evidências, o escopo privado e as relações entre notícias, IOCs,
malwares e atores.

## Medições em produção

Leituras sem alteração na origem Axur ou no conteúdo da base. Auditorias
[39489903074](https://github.com/kkroth0/thre4th-summary/actions/runs/39489903074)
e [39490259225](https://github.com/kkroth0/thre4th-summary/actions/runs/39490259225),
às 17:12 e 17:14 de Fortaleza. São amostras pontuais em um servidor com carga;
não representam percentis de latência nem um teste de capacidade.

| Item | Resultado |
| --- | --- |
| Host | 2 CPUs; 954 MiB de RAM total; 316 MiB livres na primeira amostra |
| Disco disponível | 28,1 GiB |
| Base de inteligência | 851 MiB; WAL de 35,7 MiB |
| Observações visíveis para a conta auditada e escopo público | 342.056 |
| Axur persistida | 281.931 observações; marcador de 275.000 registros percorridos |
| Última sincronização de notícias observada | 9.492 publicações examinadas; 8 alteradas |
| Memória do processo no início do ciclo de notícias | RSS de 414 MiB; heap usado de 299 MiB |
| Contagem de observações por provedor | 12,36 s na primeira amostra; 7,49 s na seguinte |
| Contagem de evidências do ator Akira | 20 resultados: 10,91 s com plano por escopo; 207,85 ms com buscas pela chave primária |
| GET local de status dos provedores | HTTP 200; 13,68 s e 3,57 s |
| GET local do perfil Akira | HTTP 200; 8,80 s e 907 ms |

Os tempos HTTP variaram mesmo antes da publicação da segunda correção. Não se
atribui toda essa variação ao ajuste SQL: coletas concorrentes, cache de disco e
carga do servidor afetam as amostras. A mudança de plano foi confirmada com
`EXPLAIN QUERY PLAN`: a consulta passa a procurar `observations(id=?)` para os
IDs ligados ao ator, em vez de percorrer `observations_scope(scope=?)`.

## Correções executadas nesta etapa

1. **Consulta de evidências por entidade.** A seleção começa pelos vínculos da
   entidade e exige buscas pela chave primária das observações. O filtro `IN`
   sozinho não foi suficiente: a auditoria mostrou que o otimizador ainda
   escolhia o índice por escopo. Não há corte de evidências antigas; os testes
   mantêm mais de 10 mil referências e o isolamento entre contas.
2. **Abertura do perfil de ator.** Um ator conhecido é resolvido no catálogo sem
   varrer todas as entidades importadas. A tela de um perfil também deixa de
   solicitar em paralelo toda a atividade geral de atores.
3. **Retomada Axur.** Lotes de 5.000 podem cair para 1.000, 500 e 100 após falhas
   de comunicação, tamanho ou tempo. O deslocamento é preservado exatamente;
   autenticação e limites de chamadas mantêm suas esperas. Não se reinicia a
   importação nem se apagam os dados salvos.
4. **Relatórios Axur reutilizados.** Cache privado por conta e revisão de
   credencial, com validade de 24 horas, evita buscar novamente o mesmo relatório
   entre páginas e reinícios. Mantém apenas os campos necessários à correlação.
5. **Correspondências reutilizadas no lote.** Atores, malwares e CVEs de um
   relatório compartilhado são resolvidos uma vez por página. O mesmo vale para
   um rótulo repetido de família de malware. Todas as relações por IOC continuam
   sendo gravadas.
6. **Diagnóstico da importação.** O marcador registra etapa, categoria da falha,
   tempos de consulta/conversão/gravação e próxima tentativa. A interface mostra
   a espera e o tamanho do lote, sem expor chaves ou respostas completas.

A auditoria inicial encontrou cinco falhas consecutivas no lote antigo de 5.000,
com marcador preservado em 275.000, acima dos 125.000 mostrados anteriormente.
O erro genérico antigo não permite afirmar a causa exata dessas cinco falhas.
Uma consulta direta de 5.000 registros havia excedido 55 segundos; isso motivou
o lote adaptativo, mas não prova que todas as interrupções tiveram essa causa.

### Conferência após publicação

O deploy de servidor
[39490896789](https://github.com/kkroth0/thre4th-summary/actions/runs/39490896789)
e o de interface
[39490896782](https://github.com/kkroth0/thre4th-summary/actions/runs/39490896782)
concluíram com sucesso, com o código `56d3b86`.
Na auditoria
[39491432247](https://github.com/kkroth0/thre4th-summary/actions/runs/39491432247),
a consulta das mesmas 20 evidências levou 134,81 ms; o GET local do perfil,
198 ms. O status de provedores ainda levou 9,90 s nessa amostra, reforçando que
o problema geral de contenção não foi eliminado.

Na sessão autenticada, o marcador da Axur confirmou o avanço para **276.000
registros percorridos**, lote de **1.000**, **283.065 evidências processadas**,
estado `running`, nenhuma falha consecutiva e sucesso em
`2026-10-20T20:23:16.473Z`. O lote completo levou 56.528 ms: consulta de IOCs
50.418 ms, relatórios 596 ms, conversão 109 ms e gravação 5.392 ms. A carga
destravou, mas a consulta da origem continua próxima do limite de 55 segundos.
O contador não é o total de IOCs únicos nem indica conclusão dos cerca de
4,3 milhões de registros da fonte.

Validação: **875 testes de servidor aprovados**, verificações de tipos,
lint, testes de interface e build aprovados no CI. No teste de um relatório
compartilhado por 100 IOCs, as 100 relações de ator e as 200 relações de malware
foram preservadas; o ator foi resolvido uma vez, em vez de uma vez por IOC.
O perfil Akira também apresentou seus aliases, referências, endereço onion e
contadores de evidências na interface autenticada.

A auditoria final de persistência
[39491767889](https://github.com/kkroth0/thre4th-summary/actions/runs/39491767889)
passou: 283.921 observações Axur persistidas, 276.554 indicadores únicos,
5.087 vínculos com 177 atores e 5.811 vínculos com 1.024 CVEs; nenhuma observação
Axur no escopo público. São leituras durante a importação, sem snapshot
transacional entre contagens. Depois dessa leitura, a interface já mostrava
278.000 registros percorridos e 285.074 evidências processadas, em andamento.

### Revisão após os timeouts das 22h — 20/10

O acompanhamento posterior encontrou o lote reduzido a apenas 100 registros,
com 51.096 ms por página: 47.911 ms aguardando a consulta de IOCs e 2.267 ms
na gravação. O marcador avançava, mas a política de redução definitiva havia
degradado a vazão. A auditoria
[39528581964](https://github.com/kkroth0/thre4th-summary/actions/runs/39528581964)
confirmou 310.500 registros percorridos nesse estado. O usuário também relatou
novo timeout em 310.700, mesmo com lote de 100.

O código `0a27a47`, publicado com sucesso no
[servidor](https://github.com/kkroth0/thre4th-summary/actions/runs/39529670895)
e na [interface](https://github.com/kkroth0/thre4th-summary/actions/runs/39529670911),
substitui a política anterior: a consulta em segundo plano aceita até 240
segundos, e timeouts de rede não diminuem o lote. Esse prazo também aparece no
script de referência fornecido pelo usuário; não constitui SLA do fornecedor.
Três páginas saudáveis permitem aumentar o lote até 5.000, com releitura
controlada quando o marcador não se alinha ao novo tamanho. Apenas os registros
depois da posição já comprometida são gravados e contados. A proteção de 32 MiB
continua reduzindo lotes quando há excesso real de tamanho da resposta.

A validação passou em **883 testes de servidor**, tipos, lint e build. Os novos
testes cobrem recuperação de lotes, fronteiras desalinhadas, reinício após
gravação parcial, excesso de tamanho, resposta interrompida, respeito a espera
por limite de chamadas e término de página sobreposta. A fonte continua sendo
consultada sequencialmente e apenas por GET.

Em produção, a
[segunda leitura leve](https://github.com/kkroth0/thre4th-summary/actions/runs/39530173732)
confirmou 313.000 registros e lote de 1.000 concluído em 57.978 ms.
A [leitura seguinte](https://github.com/kkroth0/thre4th-summary/actions/runs/39530403913)
confirmou 315.000, sem falhas consecutivas, já com lote de 5.000: a consulta
levou **70.448 ms**, acima do limite antigo, e concluiu corretamente. Essa
primeira página maior continha 4.000 registros anteriores; somente os 1.000
restantes avançaram o contador. Isso verifica a recuperação do tamanho e a
preservação do marcador. As leituras de acompanhamento agora podem usar uma
consulta direta ao estado salvo, sem recontar o inventário ou sondar rotas HTTP.

A [conferência final às 23h](https://github.com/kkroth0/thre4th-summary/actions/runs/39530569392)
confirmou **320.000 registros percorridos e 328.210 evidências processadas**, em
andamento, sem falhas consecutivas. Um lote completo de **5.000 registros novos**
levou **99.901 ms**: 70.224 ms na consulta de IOCs, 579 ms nos relatórios, 278 ms
na conversão e 28.673 ms na gravação. A ampliação deixou de ser apenas configurada:
o lote maior foi efetivamente consultado e persistido. É uma amostra de vazão,
sem promessa de prazo para toda a carga; a latência da origem, as pausas por
limites e a contenção local ainda podem variar.

## Próximas otimizações, por prioridade

| Prioridade | Fluxo e evidência no código | Mudança proposta | Como validar |
| --- | --- | --- | --- |
| P1 | API e coletores usam o mesmo processo; vários agendadores disparam em intervalos de um minuto | Coordenar tarefas pesadas, espaçar ciclos e impor orçamento de CPU/tempo; separar ETL em trabalhador com fila durável e um único escritor coordenado | Medir atraso do event loop, espera da fila e p95 das rotas durante importação; matar/reiniciar trabalhador e conferir retomada sem perda |
| P1 | `/api/actors/activity` monta notícias, publicações de APIs e atividade geral a cada chamada | Agregados por entidade/período, atualizados com as observações alteradas; cache por conta e geração da base | Comparar totais antes/depois, inclusive correções e remoções de vínculo; conferir que dados privados não atravessam contas |
| P1 | Listagem de IOCs usa `COUNT(DISTINCT)`, agrupamento e ordenação do escopo completo; uma consulta adicional de entidades por item | Resumo por indicador e escopo, atualização incremental e paginação por cursor; buscar entidades da página em lote | p95 com acervo crescente, estabilidade da ordenação, deduplicação entre fontes e escopos |
| P1 | Exportação de IOCs carrega todos os resultados com `.all()`; Excel é montado no navegador | Exportação em tarefa, leitura em blocos e escrita progressiva, com período e progresso | Conferir quantidade, correlações e formatação; medir pico de memória e retomada de falha |
| P1 | Publicação de notícias percorre e valida todo o snapshot, reconstrói visões e faz backup JSON síncrono | Propagar conjunto alterado, preservar transação de notícias/eventos e produzir backup versionado fora do atendimento da API | Repetir testes de falha antes/depois do commit, geração obsoleta e restauração; medir publicação e RSS |
| P2 | `ingestNews` já evita regravação, mas calcula fingerprints e consulta estado para as 9.492 publicações | Passar só links alterados; manter verificação integral periódica como reconciliação | Ciclo sem mudanças faz trabalho proporcional ao delta; reprocessamento de catálogo continua atualizando vínculos |
| P2 | Perfil de ator entrega todos os indicadores/referências; paginação ocorre na tela | Paginação no servidor por tipo de evidência, preservando contadores agregados | Conferir todas as páginas, exportação completa e limites de payload |
| P2 | Malware tem cache e single-flight de overview, mas listagem/detalhe recompõem correlações globais | Consultar evidências das famílias relevantes; cache com invalidação por versão/escopo | Preservar aliases ambíguos, famílias agregadas, dados recentes e vínculos antigos |
| P2 | Um relatório Axur ausente impede avanço de toda a página | Fila durável de relações pendentes, com reconsulta e estado explícito de correlação incompleta | Simular relatório ausente e recuperado; proibir indicação de importação completa enquanto houver pendências |
| P2 | Após a varredura Axur completa não existe ciclo incremental implementado | Verificar filtros de atualização suportados pela origem; se indisponíveis, reconciliação periódica com sobreposição e deduplicação | Simular inclusão/alteração durante paginação e manter histórico e procedência |
| P2 | Telemetria fragmentada por coletor | Painel com throughput, idade do último sucesso, erros por etapa, chamadas evitadas, filas, memória e crescimento DB/WAL | Alarmes baseados em atraso real e falhas persistentes; sem conteúdo sensível nos logs |

Separar processos exige coordenação dos snapshots e do escritor; iniciar vários
processos copiando a configuração atual poderia criar contenção e sobrescritas.
Não foi implantada uma migração de banco nesta etapa. Primeiro devem ser medidos
os ganhos dos índices, agregados e paginação. O host de aproximadamente 1 GB merece
revisão de capacidade antes de elevar concorrência ou completar milhões de
registros, mas esta amostra não determina sozinha o tamanho necessário.

## O que já funciona e deve ser preservado

- Normalização e deduplicação de observações, com procedência e escopo privado.
- SQLite em WAL, gravação em blocos com cessão do processo e retomada persistida.
- Cache de RSS, textos e extrações por conteúdo/revisão do catálogo.
- Limite de corpos de notícias por ciclo e concorrência limitada para leitura.
- KEV/EPSS consultados em lote e fontes externas com agendas e esperas próprias.
- Cache de enriquecimento de cinco minutos, isolado por conta/credencial, com
  chamadas simultâneas iguais compartilhadas e limite de memória.
- Cache de overview de malware e de catálogos externos; não devem ser descritos
  como fluxos sem cache.
- Relação `mentioned-with` não é promovida a atribuição confirmada. Domínios onion
  permanecem metadados de infraestrutura publicados pela fonte, sem navegação Tor
  ou promoção automática a IOC malicioso.

## Rastreabilidade

Arquivos principais: `server/axurIntelligence.js`, `server/iocIntelligence.js`,
`server/index.js` (ciclo de notícias, rotas de atores e agendadores),
`server/sqliteNewsStores.js`, `server/newsPersistence.js`,
`server/malwareCatalog.js`, `server/lookupCache.js` e `src/pages/Actors.tsx`.

O workflow manual **ETL performance audit** permite repetir as leituras de
contagens, planos, espaço e estado das coletas. Não executa a consulta antiga
mais custosa, apenas inspeciona seu plano. Também não lê o conteúdo de relatórios
nos resultados nem cria sessões de usuário. As duas rotas HTTP medidas são GETs
locais públicos; o tempo da interface autenticada precisa de validação separada.
