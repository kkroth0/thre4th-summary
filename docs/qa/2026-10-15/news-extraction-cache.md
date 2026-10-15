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

## Primeira publicação e replay real

Release `1a35c5ec449626433e4e93d20fac31746ae02b02`:
[CI 38786247221](https://github.com/kkroth0/thre4th-summary/actions/runs/38786247221)
aprovado, 731 backend e 255 frontend/marca; lint sem erros (16 avisos existentes),
TypeScript/build aprovados. Deploy
[VPS 38786469709](https://github.com/kkroth0/thre4th-summary/actions/runs/38786469709)
e [Cloudflare 38786469990](https://github.com/kkroth0/thre4th-summary/actions/runs/38786469990)
aprovados. Nenhuma dependência alterada; o security scan continua apontando a
dívida de dependências já existente (Gitleaks aprovado).

[Replay 38786890588](https://github.com/kkroth0/thre4th-summary/actions/runs/38786890588):
120 entradas amostradas de 3.267 disponíveis, 19 com corpo retido, 98 publicações
relevantes. Extração fria 15.093 ms; reaproveitada 11 ms, evidência idêntica.
17 menções a atores, 18 a malware, 35 a CVEs; 9 IPs, 49 domínios e 45 hashes.
Sem suplementos de apêndice ou campanhas nessa amostra (cobertos pelos testes).
120 hits, 120 misses, 147.780 bytes contabilizados e nenhuma expulsão.
Esses tempos são do replay controlado, não da coleta inteira.

[Integridade 38788045338](https://github.com/kkroth0/thre4th-summary/actions/runs/38788045338),
18:45:30Z: geração 20, 7.563 publicações e 5.078 eventos; zero ausências,
diferenças, fontes órfãs, aliases conflitantes e fontes duplicadas. Backup igual
e confirmado na geração 20. A integridade estrutural não comprova a precisão
semântica de cada agrupamento.

Navegador autenticado: feed com 5.098 cards/eventos, busca de C2Agent e referência
original Unit42 presentes. A explicação de vínculos no detalhe ficou pendente;
este fluxo não foi considerado validado. Também foi observado um card de resumo
trimestral com 91 publicações e muitas entidades: requer auditoria semântica
própria, sem confundir integridade de armazenamento com identidade de incidente.

## Limite de rede encontrado durante a conferência

Até 18:52Z o processo novo permanecia ativo sem registrar um ciclo concluído;
RSS teve última escrita às 18:38Z e corpos às 18:40Z. Não há prova de que o replay
quente já representou um ciclo vivo inteiro. A auditoria leve está no branch
de diagnóstico `codex/news-extraction-cycle-audit`, sem deploy desse branch.
Uma primeira tentativa de diagnóstico isolando um processo por publicação teve
deadline de startup insuficiente e não permite atribuir falha ao extrator.
O replay corrigido
[38789060105](https://github.com/kkroth0/thre4th-summary/actions/runs/38789060105)
amortizou a inicialização: 33 entradas recentes concluíram em 19.091 ms, nenhuma
ficou travada. O corpo de BEC de 21.411 caracteres levou 5.409 ms. Isso limita a
conclusão à amostra, sem excluir textos antigos ou outras etapas.

A revisão encontrou `dns.lookup` antes do timeout HTTP nas fontes automáticas,
e caminhos de RSS/corpos usando o pool getaddrinfo do sistema. Um timeout de
socket não limita essa resolução prévia. A correção passa a usar resolvers DNS
independentes/canceláveis e deadline único de 12 s por requisição completa,
incluindo DNS e redirecionamentos. A documentação do
[Node.js](https://nodejs.org/api/dns.html#implementation-considerations) diferencia
o pool compartilhado de `dns.lookup` das consultas assíncronas `resolve*`.
É uma lacuna comprovada no código; a atribuição de toda a demora de produção
a essa lacuna ainda depende do reteste após publicação.

RSS, listagens, corpos e apêndices usam o mesmo transporte que fixa o IP validado
ao socket e revalida cada destino. Literais e respostas DNS mistas com endereços
privados continuam bloqueados. Limites de 8 MB/2 MB/40 KB preservados. Apêndices
relativos usam a URL final do artigo. RSS/scrapers fazem uma tentativa por ciclo;
o snapshot válido anterior permanece disponível nas falhas, e o próximo ciclo
substitui as três tentativas consecutivas e os backoffs do mesmo erro.
Isso pode aumentar fontes marcadas stale em falhas transitórias; não apaga suas
publicações ou evidências anteriores.

737 testes backend aprovados após essa correção, incluindo DNS que nunca retorna,
DNS lento em segundo hop, HTTP pendente, cancelamento isolado por fonte,
validação de destinos mistos/privados, IP fixado, ETag/304 e tamanho de apêndices.

## Reteste do ciclo recorrente e correção de versões

Release de rede `332d498`: CI 38790299524, VPS 38790786678 e Cloudflare
38790786532 aprovados. O detalhe de C2Agent voltou a concluir; o de Ivanti
CVE-2026-104935 apresentou nove fontes e evidências compartilhadas. A conferência
identificou cinco versões de Ivanti classificadas como IPs, além do endereço real
108.165.147.64. A correção reconhece listas explícitas de versões, inclusive
separadas por vírgulas/linhas; uma menção independente como IOC permanece válida.

A revisão única `news-version-lists-v1` atualiza histórico e eventos em transação
SQLite, preserva aliases e hashes, e reaplica o histórico canônico ao inventário.
Observações independentes das APIs mantêm seus escopos. O marcador só é gravado
após a atualização do inventário, permitindo retomar uma interrupção entre etapas.
741 testes backend aprovados: cobertura de listas de versões, 32 hashes retidos,
divisão de agregado legado, hashes exclusivos de fontes e rollback de falha SQL.

[Auditoria leve 38793260480](https://github.com/kkroth0/thre4th-summary/actions/runs/38793260480),
19:21:55Z, confirmou o ciclo recorrente encerrado às 19:19:18Z:

| Medida | Primeiro ciclo após reinício | Ciclo recorrente seguinte |
| --- | --- | --- |
| Extração | 135.066 ms | 3.507 ms |
| Reaproveitadas / recalculadas | 0 / 3.246 | 3.206 / 42 |
| Ciclo completo | 383.195 ms | 192.975 ms |

Sem expulsões do cache (4.193.323 bytes contabilizados) ou falhas de ciclo nesse
recorte. Os ciclos tiveram entradas/carga diferentes; a queda do tempo total não
é atribuível somente ao cache. Rede ainda levou 119 s e persistência/publicação
28 s no segundo ciclo. Houve 38 falhas de corpos e 1.195 adiados: não significa
que todas as fontes ou artigos foram obtidos. As evidências anteriores permanecem.

## CVEs na interface de notícias

Tabela e cards fechados mostram até três CVEs e o número oculto; o botão abre o
detalhe completo. Cards começam fechados, inclusive o destaque. O drawer contém
uma seção própria com todas as CVEs e links ao catálogo interno. O agrupamento,
a busca e as exportações continuam recebendo a lista completa. Nenhum LLM é
necessário para listar as CVEs no drawer. Validação visual de produção registrada
após o deploy desta revisão.

Release da interface `b3d1c8b`: [CI 38793728563](https://github.com/kkroth0/thre4th-summary/actions/runs/38793728563)
aprovada (741 backend, 255 frontend/marca), TypeScript/build aprovados e 16 avisos
de lint existentes. [VPS 38794040214](https://github.com/kkroth0/thre4th-summary/actions/runs/38794040214)
e [Cloudflare 38794039987](https://github.com/kkroth0/thre4th-summary/actions/runs/38794039987)
concluídos. Na mesma busca de Patch Tuesday, a linha do SOCRadar com 22 CVEs
passou de 1.320 para 165 px. A prévia exibiu três CVEs e +19; o drawer trouxe os
22 links. Em cards, três links recolhido, 22 expandido e novamente três ao
recolher. Evidências em `news-cve-preview-production.png` e
`news-cve-details-production.png`.

A conferência de busca por uma das CVEs ocultas detectou um problema anterior:
o filtro só consultava título, resumo e fonte. A revisão `989f552` acrescenta a
lista completa de CVEs extraídas à busca, sem mudar período/gravidade/fonte.
Teste com a 22ª CVE fora do título e do resumo aprovado.

## Segunda revisão da classificação de versões

O marcador v1 concluiu às 19:30:50Z: sete publicações corrigidas, 17 menções
retiradas e quatro eventos reconstruídos. A auditoria seguinte mostrou casos
adicionais em tabelas e narrativa; não foi uma comprovação de limpeza completa.
O inventário continuou com os 32 hashes de C2Agent, assim como histórico/evento.

`0717dd6` cobre comparadores em português, versões alfanuméricas, colunas de
versões em tabelas Markdown, listas de correções e referências narrativas ao
mesmo número de versão. Uma ocorrência independente como IP/IOC, endpoint,
linha de indicador ou conexão de rede continua válida. A classificação exige
evidência explícita de versão, sem bloquear faixas numéricas inteiras.
O marcador `news-version-lists-v2` reaplica a revisão ao histórico/eventos e ao
inventário usando a mesma transação e preservando escopos das APIs.
744 testes backend locais aprovados; o novo teste cobre a coleta seguinte com
suplementos antigos, preservação dos 32 hashes e IP real.

[Integridade 38819248330](https://github.com/kkroth0/thre4th-summary/actions/runs/38819248330),
22:45:57Z, geração 44: 7.746 publicações e 5.241 eventos. Zero ausências,
diferenças, fontes órfãs/duplicadas ou aliases conflitantes; cópia JSON igual.
Esse resultado precede v2 e não comprova a precisão semântica das correlações.

Release `989f552`: [CI 38820560778](https://github.com/kkroth0/thre4th-summary/actions/runs/38820560778)
aprovada, 744 backend e 256 frontend/marca; TypeScript/build aprovados, sem erros
de lint (16 avisos existentes). [VPS 38820799993](https://github.com/kkroth0/thre4th-summary/actions/runs/38820799993)
e [Cloudflare 38820800053](https://github.com/kkroth0/thre4th-summary/actions/runs/38820800053)
concluídos. Busca de CVE-2026-69435 passou a encontrar a publicação SOCRadar e a
do Cisco Talos, ausentes antes; o drawer do Talos exibiu todos os 182 links.

[Auditoria 38821161842](https://github.com/kkroth0/thre4th-summary/actions/runs/38821161842)
confirmou v2 concluída às 23:01:11Z: 11 publicações, 30 menções retiradas e três
eventos reconstruídos. Os 32 hashes de C2Agent permanecem no histórico, evento
e inventário. A amostra consultada por presença de 25.1.2.2 ficou sem versões
como IPs; isso não cobre todas as publicações que mencionam outras versões.
O detalhe ampliado de Ivanti ainda exibiu 25.1.1.2 e 25.1.3.1 como evidências
compartilhadas, exigindo comparar fontes do evento com o histórico mais amplo.

[Integridade 38821157046](https://github.com/kkroth0/thre4th-summary/actions/runs/38821157046),
23:04:50Z, geração 47: 7.746 publicações e 5.241 eventos, comparação canônica e
backup iguais, sem ausências, diferenças, órfãos, duplicatas ou aliases conflitantes.
