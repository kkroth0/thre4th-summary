# Desempenho da coleta e leitura de notícias

## Medição anterior à mudança

Auditoria somente leitura [38760766034](https://github.com/kkroth0/thre4th-summary/actions/runs/38760766034),
em 15/10/2026 às 15:29 UTC: geração 7, 7.494 publicações arquivadas e 5.022 eventos.

- Leitura validada do snapshot SQLite: 29.501 ms.
- Composição do feed: 695 ms; serialização: 513 ms; gzip: 992 ms.
- Resposta completa: 6.038 publicações, 9.520.378 bytes, 1.494.229 bytes gzip.
- EPSS local: 6.568 dos 6.665 CVEs, atualizado às 05:44 UTC; 97 ausentes.
- Cinco ciclos anteriores completos: 553.810–663.444 ms.
- Logs agregados: sem falha registrada do coletor/EPSS nessa janela; 231 respostas
  HTTP 403 ao buscar corpos. Essa indisponibilidade externa limita a extração.

O erro intermitente do navegador anterior não informou o status HTTP. Os números
acima identificam custos reais, mas não provam sozinhos a causa desse erro.

## Alterações

- Canonicalização calculada uma vez por transação. A comparação ainda verifica
  hashes, IDs, igualdade e relacionamentos antes de confirmar a publicação.
- Leitura verifica payloads, manifesto e relacionamentos sem refazer a mesma
  serialização/comparação. Publicações usam o resultado da transação confirmada;
  uma geração externa e a inicialização ainda exigem leitura validada do banco.
- Resposta HTTP do feed reutilizada para a mesma revisão, dono, preferências e
  filtros, limitada a oito entradas e 32 MiB de payload. Mudanças em arquivo,
  snapshot ao vivo ou eventos invalidam a projeção. Evidências não são truncadas.
- EPSS consulta o catálogo diário em worker, inclusive CVEs ainda ausentes do NVD.
  Somente valores faltantes/desatualizados chegam à API: lotes de 100, concorrência
  dois e orçamento remoto de 20 s com abort. Cache diário para resultados, uma
  hora para ausências e cinco minutos para falhas; scores antigos preservados
  como fallback. Ausência nunca vira zero.
- Ciclos registram tempos agregados por etapa, sem payloads privados ou segredos.
- Erro HTTP do frontend inclui o status para diagnóstico de uma nova ocorrência.

## Regressões

CI [38762317521](https://github.com/kkroth0/thre4th-summary/actions/runs/38762317521):
719 testes backend e 255 frontend/marca aprovados, TypeScript/build aprovados,
lint sem erros e com 16 avisos existentes. Inclui rejeição de relações inválidas
com hash válido. Sem dependências novas.

## Publicação e conferência

- Release `06870a273c916cb15c665a4ac840f25ddcb12c38`.
- [VPS 38762671714](https://github.com/kkroth0/thre4th-summary/actions/runs/38762671714)
  e [Cloudflare 38762671819](https://github.com/kkroth0/thre4th-summary/actions/runs/38762671819)
  concluídos com sucesso.
- Auditoria [38764219161](https://github.com/kkroth0/thre4th-summary/actions/runs/38764219161):
  leitura validada caiu de 29.501 para 13.589 ms nessa medição; resposta HTTP fria
  1.662 ms e reutilização abaixo de 1 ms (arredondada para zero), com payload
  integral igual ao anterior. Isso mede o processamento isolado, não latência
  completa da rede nem o tempo total do coletor.
- Integridade [38764462779](https://github.com/kkroth0/thre4th-summary/actions/runs/38764462779):
  geração 8, 7.499 publicações e 5.025 eventos; zero ausências, diferenças,
  fontes órfãs, aliases conflitantes ou fontes duplicadas. JSON de recuperação
  em paridade com SQLite.
- Navegador autenticado: após reload, 5.044 eventos visíveis, sem novo erro de
  carregamento; abertura de evento com 11 fontes, atores/malwares/domínios de
  evidência, e outra notícia com CVE e duas fontes. Esse teste não é um gabarito
  de precisão de todas as correlações.
- Segurança: Gitleaks passou. NPM Audit/Trivy/OSV continuam com falhas preexistentes;
  o push informou 49 avisos de dependência. Nenhuma dependência foi alterada.

## Gargalo adicional identificado pelo primeiro ciclo instrumentado

Auditoria [38765879518](https://github.com/kkroth0/thre4th-summary/actions/runs/38765879518):
o ciclo concluído às 12:56:11 de Fortaleza levou 694.277 ms. Etapas: feeds
110.775 ms; scrapers 1.403 ms; corpos 14.399 ms; extração 102.245 ms; contexto
de vulnerabilidades 3.360 ms; publicação 435.301 ms; inventário 21.323 ms.
A auditoria posterior [38766273063](https://github.com/kkroth0/thre4th-summary/actions/runs/38766273063)
isolou 373.309 ms na correlação desse ciclo, antes da gravação SQLite.

A correção seguinte indexa candidatos por CVE, campanha, IOC forte, termo do
título e título normalizado. Todas as regras de aceite compartilham ao menos
um desses sinais; o índice só elimina comparações impossíveis e a decisão
continua na mesma função. Atualizações exclusivamente editoriais atualizam
metadados/agregados sem remover e recomparar a fonte contra todo o catálogo.
Mapas de propriedade das fontes são atualizados também após merges e splits.

Comparação local com a implementação anterior: igualdade integral na amostra
pública de 61 publicações, inclusive replay com score/hash alterados. Em 1.000
matérias sintéticas: montagem inicial 846 → 39 ms, replay 845 → 33 ms, com mesmo
resultado. Esses números são do ambiente local, não estimativa de ganho em VPS.

### Publicação da correção de correlação

- Release `36c71c0bb746f6045fcfb2a65bfda5bd2b250b39`.
- CI [38777206641](https://github.com/kkroth0/thre4th-summary/actions/runs/38777206641):
  721 backend + 255 frontend/marca, TypeScript e build aprovados; lint sem erros.
- [VPS 38777475683](https://github.com/kkroth0/thre4th-summary/actions/runs/38777475683)
  e [Cloudflare 38777475104](https://github.com/kkroth0/thre4th-summary/actions/runs/38777475104)
  concluídos com sucesso.
- Integridade após reinício [38777959145](https://github.com/kkroth0/thre4th-summary/actions/runs/38777959145):
  geração 15, 7.539 publicações, 5.057 eventos; paridade SQLite/JSON e todos os
  vínculos válidos. Esta conferência antecede a conclusão do primeiro novo ciclo.
- Navegador: 5.076 eventos carregados; busca C2Agent mantém a referência original
  da Unit 42 e as famílias no evento, sem novo erro de carregamento. Não foi
  recontada a totalidade dos hashes pela interface nesse reteste.
- Evidência visual: `news-feed-performance-production.png`.

A proposta de camada editorial e clientes foi avaliada em
`docs/product/editorial-ai-and-client-workspaces.md`; não há ativação de LLM ou
envio externo nesta release.

### Regressão de ordem de chaves depois do cutover

O primeiro ciclo de `36c71c0` concluiu às 14:40:35 de Fortaleza: 636.080 ms,
com 227.757 ms na correlação e 283.966 ms na publicação. A auditoria
[38779489068](https://github.com/kkroth0/thre4th-summary/actions/runs/38779489068)
confirmou processo ativo, sem erro de inicialização, e snapshot avançado à geração 16.
A auditoria [38779728410](https://github.com/kkroth0/thre4th-summary/actions/runs/38779728410)
conferiu também o hash do módulo de correlação contra o blob Git da release.
O índice sozinho, portanto, não resolveu o custo de reprocessamento real.

Causa adicional encontrada: a comparação por `JSON.stringify` considerava a
ordem das propriedades de objetos dentro de listas de atores, vendors e IOCs.
SQLite grava essas chaves canonicamente; o extrator as constrói em outra ordem.
Evidência igual passava a parecer alterada depois da leitura do banco, tanto na
correlação quanto no arquivo. O fingerprint da ingestão também dependia da ordem.

A correção compara valores JSON sem depender de ordem das propriedades, mantém
a ordem de arrays, trata propriedades omitidas e ainda detecta qualquer mudança
real. O fingerprint de ingestão passa a ser canônico. A mudança pode provocar uma
única reingestão dos fingerprints antigos, sem mudar os IDs das observações.

Regressões cobrem reutilização da mesma instância de evento/fonte após reload
canônico, ausência de gravação redundante do arquivo, fingerprint estável no
inventário e aplicação de mudanças reais nos hashes/atribuições. 725 testes backend
passaram. Benchmark local de 1.000 publicações com entidades e reload canônico:
776 → 15 ms, resultado igual e 1.000 eventos reaproveitados. A medição em VPS será
registrada após a publicação desta correção.
