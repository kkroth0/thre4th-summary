# CTI.fyi e reteste do firmware no Mirai

Integração baseada nos endpoints públicos documentados em [cti.fyi/api](https://cti.fyi/api). O conector consulta somente a API HTTPS de metadados. Links de leak sites ficam como contexto de origem; não há visita a Tor, download de material vazado ou execução de amostras.

## Coleta e armazenamento

O coletor inicia após a janela de saúde do servidor e compartilha uma única coleta em andamento entre chamadas. A sincronização regular é horária; o catálogo de grupos é atualizado diariamente. O primeiro recorte cobre 60 dias de descobertas, com quatro páginas de 500 por ciclo. Cursores pendentes continuam em 15 minutos. Atualizações de registros antigos são buscadas por `updated_since`, também com páginas limitadas, e janela sobreposta de dois dias. O limite por ciclo é de nove requisições quando catálogo, descobertas e revisões precisam ser consultados. Não há espelhamento inicial irrestrito das dezenas de milhares de registros históricos.

O snapshot normalizado `.cti-fyi.json` preserva registros, grupos, cursores e horário da última sincronização entre reinícios. Ele está ignorado no Git e protegido nas listas de exclusão de deploy/rollback. A retenção local tem teto de 50 mil registros. Falhas preservam dados salvos; HTTP 429 respeita `Retry-After` com backoff. Os cabeçalhos de quota informam o restante por minuto; após o reset esse valor volta a desconhecido até uma nova resposta, sem inventar cotas diárias ou mensais.

## Correlação e interface

O painel de ransomware e o recorte LATAM combinam CTI.fyi e Ransomware.live, preservando a procedência. Uma coincidência conservadora de grupo/ator, domínio ou nome e proximidade temporal combina evidências de fontes diferentes. Reivindicações separadas da mesma fonte e ciclos distantes de reextorsão permanecem distintos. A contagem de grupos considera todos os grupos no recorte, independentemente das 12 linhas do ranking.

Nomes e aliases explícitos vinculam grupos ao catálogo de atores existente. Grupos sem correspondência recebem um perfil informado pela fonte. Aliases, referências e técnicas complementam o perfil; metadados MITRE existentes prevalecem em colisões. Táticas `TAxxxx` não viram técnicas `Txxxx`. O perfil identifica o contexto automatizado da fonte. A lista de vítimas oferece pivô para o ator, cujo histórico passa a reunir notícias, evidências das APIs anteriores e reivindicações CTI.fyi.

Domínios das vítimas têm papel `victim` e **não entram como IOCs maliciosos**. Reivindicações são `unverified`. País da vítima não vira país de origem do grupo. Publicação ausente permanece ausente, separada da descoberta UTC. Revisões mantêm a identidade pelo grupo e URL original; fragmentos de cartões diferentes são preservados. Atualizações marcadas `is_toxic` retiram o registro correspondente do snapshot exibido.

O estado do coletor aparece em Fontes de Dados e no painel de ransomware, com contagens salvas, última sincronização, estado parcial e quota por minuto. Essas consultas de estado leem memória local, sem novas chamadas à fonte.

## Validação

Teste real local do primeiro lote: 2.000 reivindicações em aproximadamente 4,2 segundos; 2.000 publicações ligadas aos atores e zero domínios de vítima em coleções de IOCs. O teste inicial usou 318 grupos com publicações; a implementação final consulta o catálogo completo, incluindo grupos sem publicações. O recorte inicial indicou paginação pendente, sem afirmar cobertura histórica completa.

Testes automatizados: UTC e granularidade, publicação ausente, identidade de revisões, domínios em papel de vítima, preservação de metadados MITRE, aliases de múltiplos grupos, correlação ator/publicação sem IOCs, deduplicação entre fontes, preservação de reivindicações distintas, contagem acima de 12 grupos, coalescência/cache, reinício, exclusão de registro sinalizado, paginação limitada e backoff. O teste visual adicional revelou um alias compartilhado que impedia o pivô de LockBit3: nomes principais e o vínculo explícito do grupo CTI.fyi passaram a ter precedência sobre aliases de outros perfis. Links de registro dos provedores deixam de aparecer como websites das vítimas; a coluna Fonte identifica a procedência por linha. Resultado completo após esses ajustes: **672 testes de backend aprovados**, além de TypeScript, lint dos arquivos alterados e verificação de sintaxe.

## Produção

A primeira publicação (`37c805a`) passou no [CI](https://github.com/kkroth0/thre4th-summary/actions/runs/38662321180), [deploy VPS](https://github.com/kkroth0/thre4th-summary/actions/runs/38662428092) e [Pages](https://github.com/kkroth0/thre4th-summary/actions/runs/38662428145).

A auditoria focada [38662743646](https://github.com/kkroth0/thre4th-summary/actions/runs/38662743646), somente leitura e sem benchmark/reprocessamento, confirmou:

- Publicação Cyble localizada; um evento correlacionado. O falso IP não constava na notícia arquivada, na fonte do evento nem no agregado. Havia **zero observações históricas atuais e zero vínculos Mirai** para o falso IP nessa fonte. Não há exclusão indiscriminada do endereço de evidências independentes; o teste mantém uma ocorrência real separada quando houver.
- CTI.fyi: **2.000 reivindicações persistidas, 407 grupos, 2.000 publicações ligadas a atores e zero domínios de vítima classificados como IOCs**.
- Painel de 30 dias: 1.636 registros, 1.584 com procedência CTI.fyi e 1.591 pivôs de ator na primeira versão. A ausência dos pivôs de aliases compartilhados motivou a correção subsequente. A coleta indicava paginação inicial pendente, não cobertura histórica completa.

O navegador autenticado mostrou a combinação `ransomware.live · CTI.fyi`, status de sincronização, 407 grupos, 2.000 registros salvos e quota observada de 56/60 no minuto da coleta. O filtro textual CTI.fyi localizou as reivindicações da fonte. O reteste final dos pivôs está detalhado abaixo.

### Reteste final

Correções finais publicadas em `eecfe6e9a892e965d566f1f181315c879a1963f6`, com [CI aprovado](https://github.com/kkroth0/thre4th-summary/actions/runs/38663086292), [VPS](https://github.com/kkroth0/thre4th-summary/actions/runs/38663220216) e [Pages](https://github.com/kkroth0/thre4th-summary/actions/runs/38663220211) concluídos. Não houve atualização de dependências; a checagem separada de segurança mantém os alertas preexistentes.

A segunda auditoria [38663490627](https://github.com/kkroth0/thre4th-summary/actions/runs/38663490627) repetiu os controles do firmware: publicação e evento localizados, falso IP ausente dos três níveis consultados, zero observações históricas atuais e zero vínculos Mirai nessa fonte. O snapshot CTI.fyi manteve os **2.000 registros e 407 grupos**, com a mesma sincronização de 21:55:02 Fortaleza após o novo deploy, comprovando a preservação entre reinícios. As 2.000 publicações continuaram ligadas a atores, sem domínios de vítimas em IOCs.

No recorte de 30 dias, a resposta final reuniu **1.616 registros de Ransomware.live Pro/CTI.fyi, 1.583 com procedência CTI.fyi e 1.616 pivôs de ator**. Uma consulta pública independente conferiu explicitamente **zero registros CTI.fyi sem `actorId`**, incluindo a ligação `lockbit3 → rl-lockbit3`. Os números são do instante do reteste, sujeitos à atualização dos feeds.

Fluxos no navegador autenticado:

- Filtro CTI.fyi no painel, fonte legível em cada linha e referências de ambos os provedores. Links de registro deixaram de aparecer no campo website da vítima.
- HYFLOCK: perfil novo informado pelo CTI.fyi, oito reivindicações persistidas e zero IOCs. Origem e descrição ausentes permaneceram não informadas; o país das vítimas não foi atribuído ao ator.
- Crinetics → LockBit3: pivô abriu o perfil existente `rl-lockbit3`, com as quatro reivindicações locais, aliases e 54 técnicas. A aba MITRE exibiu IDs, nomes e referências, e a aba Publicações preservou os quatro links CTI.fyi. O total de 1.952 reivindicações do dossiê é explicitamente o total registrado pela fonte, distinto das quatro no recorte local.
- Fontes de Dados: coletor sincronizado com 2.000 registros e 407 grupos. O saldo por minuto passou de 56/60 para desconhecido após o reset, enquanto a documentação do limite permaneceu disponível.

Provas inspecionadas: `cti-fyi-ransomware-browser.png`, `cti-fyi-actor-browser.png` e `cti-fyi-lockbit3-browser.png`. Os testes finais completos aprovaram **672 casos backend**; TypeScript e lint passaram. A coleta histórica inicial ainda tem cursor pendente, mostrado na interface; novos ciclos limitados completam o recorte e acompanham revisões sem recarregar toda a fonte.
