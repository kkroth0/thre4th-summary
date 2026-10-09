# Avaliação da correlação — 9 de outubro de 2026

A auditoria encontrou mistura de eventos e causas concretas no correlacionador.
As correções foram implementadas e verificadas localmente. Esta avaliação não
é uma medição da instância de produção nem confirma um deploy.

## Amostra e método

Foram coletadas 370 publicações RSS/Atom de 12 fontes públicas: Microsoft MSRC,
FortiGuard PSIRT/Threat Signal, Cisco PSIRT, BleepingComputer, SecurityWeek,
The Hacker News, Dark Reading, SANS ISC, Chrome Releases, HIPAA Journal e
CISO Advisor BR. 273 passaram pela janela de 14 dias e filtro existente.
Foram feitas 40 tentativas de corpo conforme o orçamento do coletor: 21
funcionaram e 19 falharam, incluindo bloqueios HTTP 403. O RSS foi preservado.

O replay final dessas 273 publicações produziu 257 eventos, com 9 agrupamentos
de várias publicações. Os títulos, URLs e evidências de 61 publicações foram
selecionados para regressão: casos errados observados e coberturas legítimas.
Não foram adicionados corpos completos ao repositório.

Os rótulos foram revisados nesta implementação; não constituem anotação humana
independente. São 48 eventos esperados, 18 pares do mesmo evento e 1.812 pares
de eventos diferentes. É uma amostra direcionada a defeitos encontrados,
não uma amostra aleatória para estimar qualidade global.

| Medida na seleção de 61 publicações | Antes: RSS / regras v2 | Depois: extração / regras v3 |
| --- | ---: | ---: |
| Pares de eventos distintos unidos | 113 | 0 |
| Pares do mesmo evento separados | 4 | 0 |
| Publicações perdidas ou repetidas | 0 | 0 |

A comparação inclui tanto as regras quanto o enriquecimento: o baseline não
tinha os corpos usados na avaliação final. Zero erros nesta seleção não
significa precisão/recall de 100% em todo o feed.

## Casos corrigidos

- NetScaler CVE-2026-107406: três veículos no mesmo card; CVEs antigas ficam
  como contexto pesquisável, sem colar os avisos 88771/88772 e 88779.
- Seis incidentes de saúde independentes deixam de se unir pelo falso malware
  “Action RAT”, extraído de “class action”, e pela palavra genérica “health”.
- Windows e AnyDesk não se unem por T1190 e “access”. KillSec e Qilin não se
  unem por T1486 e “alleged”. Campanhas de phishing/npm distintas se separam.
- Avisos Cisco de produtos/CVEs distintos não se unem através de um resumo de
  patches, de boletins de hardening ou de manchetes genéricas.
- Chrome beta/stable/dev de dias/canais diferentes permanecem separados.
- Midnight Mimosa une duas coberturas com títulos diferentes pela campanha
  explicitamente nomeada, mesmo sem entrada prévia no catálogo ATT&CK.
- AhsayCBS, Atlassian, Exchange, Pixel/Pwn2Own e a divulgação sobre as ferramentas
  Flax Typhoon continuam agrupados por evidências específicas.

## Reproduzir e operar

```sh
node server/auditCorrelations.mjs
node --test server/test/newsCorrelation.test.js
# Ou npm run audit:correlations
```

A CLI é offline e não escreve no histórico. Aceita caminho de JSON com
`{items, evaluationAt}` ou array de publicações já enriquecidas. Rótulos
`expectedEvent` habilitam precisão/recall; sem rótulos, essas métricas são nulas.
O processo termina com código 1 se detectar erro nos pares rotulados,
publicações duplicadas ou publicações sem evento.

O próximo refresh migra histórias anteriores à versão 3. A migração mantém
evidências por fonte, remove aliases de malware inseguros e impede que um ID
resolva dois eventos após uma separação. A extração v4 e o cache de corpos v2
invalidam os snapshots/textos anteriores quando necessário.

Os logs de `[feed] cycle` incluem `correlation.version`, `elapsedMs`, `events`,
`retainedEvents`, `multiSourceEvents`, `publications` e `unassigned`. O detalhe de um evento
inclui `correlationDecisions`: regra, evidência e URLs do par correlacionado.
Se gravar as histórias falhar, o ciclo preserva o último feed publicado.

A simulação com armazenamento em arquivo das 273 publicações verificou três
ciclos: migração do histórico v2 (292 ms), recarga após reinício (23 ms) e
atualização de scores (322 ms). Todos mantiveram 257 eventos, sem publicação
perdida/repetida e sem conflitos de IDs/aliases. Esses tempos medem somente a
correlação/persistência local, excluindo rede e enriquecimento; não são SLA.

Validação final: 483 testes de backend passaram, incluindo regressões de
correlação, falha de escrita, reprocessamento e separação após atualizar uma
URL. Typecheck e build passaram; lint sem erros e com 18 avisos preexistentes.

## Limites ainda presentes

O motor continua determinístico e depende de evidências explícitas. Traduções
de títulos, grafias de vítimas, campanhas sem nome e corpos bloqueados podem
fragmentar cobertura. A CVE principal é inferida pela manchete e pelos primeiros
parágrafos que identificam a falha; não é análise semântica do texto completo.
Campanha e IOC compartilhados podem conectar ações distintas da mesma operação.
É necessário ampliar o conjunto revisado, sobretudo para vítimas/produtos/ações,
e oferecer revisão manual de agrupamentos antes de prometer deduplicação global.
