# Configurações de Monitoramento e contexto da organização — Design

**Objetivo:** dar ao app um modelo do que a organização é — setor, região, ativos de software, presença de OT — e usar esse modelo para calibrar o feed de Notícias de Segurança: subir o que casa com o contexto, explicar por que subiu, e permitir esconder o resto. Reunir num só lugar as configurações do que é monitorado, hoje espalhadas. Somar quatro fontes de pesquisa OT (Claroty Team82 e Nozomi Networks).

**Problema:** o feed pontua relevância só pelo conteúdo do artigo (`scoreArticle`) — uma falha crítica no Fortinet e uma falha crítica num produto que a organização não usa chegam com o mesmo peso. Não há nenhum lugar no app onde se declare o que a organização é, então nada pode ser priorizado por contexto. Em paralelo, a configuração do que é monitorado está em três ilhas: as fontes de coleta (`FeedSourcesManager`) moram dentro do card de Integrações em Settings > Admin, ao lado do gate premium; os ativos escaneados moram em `/attack-surface?mode=monitor`; e o contexto da organização não existe.

## Restrições

- Nenhuma dependência nova. `cheerio` (já usado em `ctiIntel.js`) cobre a raspagem; nada de headless browser.
- Sem chamada de LLM no caminho do refresh.
- `GET /api/newsletter` e `GET /api/news/stories` mantêm a forma atual. Sem perfil na query, a resposta é byte-a-byte a de hoje — nenhum cliente existente precisa mudar.
- O casamento é determinístico e puro: mesma entrada, mesma saída, sem rede, sem relógio, sem disco nos módulos de regra.
- O perfil **nunca esconde nada por padrão**. Ele reordena e explica; o filtro é opt-in.
- Persistência segue o padrão do `createWatchlistStore` / `createStoryStore`: `fs` por injeção, JSON com escrita atômica, arquivo corrompido vira store vazio e não derruba nada.
- Perfis são por usuário. Um usuário só lê e escreve os próprios perfis.

## Arquitetura

Dois módulos novos no servidor, dois no cliente. **O servidor não anota notícia nenhuma.** Ele guarda os perfis e devolve, para o perfil ativo, um *modelo de ameaças* compacto; o casamento roda no cliente, sobre os campos que cada item do feed já traz (`actors`, `sectors`, `newsCategories`, título e descrição).

| Módulo | Responsabilidade | Interface |
|---|---|---|
| `server/orgProfiles.js` | Validar e persistir perfis | `normalizeProfileInput(input, existing, now, owner)`; `createProfileStore({filePath, readFileSync, writeJsonAtomic})` |
| `server/orgThreatModel.js` | Derivar o modelo do perfil | `buildThreatModel(profile, actors)` → modelo serializável |
| `server/scrapeFeeds.js` | Fontes sem RSS | `SCRAPE_SOURCES`; `parseListing(html, source)`; `collectScraped({sources, fetchText, seen, now, maxNew})` |
| `src/utils/orgRelevance.ts` | Casamento e pesos | `orgRelevance(subject, model)` → `{score, matches}` |

```
feeds RSS ─┐
raspagem ──┼→ refreshNewsletterFeed()  →  cache único  →  GET /api/newsletter   ─┐
           ┘   [já existe]                                                       │
                                                                                 ↓
perfis  →  buildThreatModel(perfil, atores)  →  GET …/threat-model  →  orgRelevance(item, modelo)
                                                                                 ↓
                                                              orgScore / orgMatches no cliente
```

O casamento fica no cliente por três motivos. A tela de Notícias já agrupa histórias no navegador (`groupAdvisoriesIntoStories`) — ela nunca chama `/api/news/stories`. O `localStorage` acumula até 400 itens ao longo de dias, e uma anotação vinda do servidor ficaria velha assim que o usuário trocasse de perfil, enquanto o cálculo local reanota os 400 na hora. E o modelo é pequeno o bastante para trafegar (ids de atores, rótulos, termos das regiões escolhidas).

`orgRelevance.ts` não conhece rede, disco nem relógio. `orgThreatModel.js` é puro sobre o `ACTORS_CACHE`. `orgProfiles.js` cuida do arquivo. É o que torna os pesos testáveis com um perfil literal e um item literal.

## Perfil da organização

Um usuário tem N perfis (consultoria com vários clientes) e escolhe um ativo. O **perfil ativo vive no cliente**, em `localStorage`, e viaja como `?profile=<id>`; o servidor não guarda estado de sessão.

```js
{
  id: 'org_<16 hex>',
  ownerId, ownerLogin,
  name: 'Cliente X',                        // 1–80 chars, obrigatório
  sectors: ['Energy', 'Manufacturing'],     // rótulos de SECTOR_RULES (ctiIntel.js)
  regions: ['Brazil', 'Latin America'],     // rótulos de TARGET_REGION_LABELS (actorProfile.js)
  assets: [{ vendor: 'Fortinet', product: 'FortiGate' }, …],
  ot: { present: true, vendors: ['Siemens'], protocols: ['Modbus'] },
  actors: ['G0034'],                        // ids fixados à mão
  createdAt, updatedAt                      // ISO
}
```

O ponto central do desenho é **não inventar vocabulário**. `sectors` usa exatamente os rótulos que `scoreArticle` já carimba em cada notícia (`item.sectors`), e `regions` usa exatamente os que `actorTargeting` já deriva para cada ator (`actor.targets`). O join com atores e com notícias sai de graça; um vocabulário novo exigiria duas tabelas de tradução e envelheceria sozinho.

Valores fora do vocabulário são **rejeitados com 400**, não ignorados em silêncio — um setor digitado errado nunca casaria com nada e o usuário não teria como perceber.

### Limites e validação

Mesmo idioma do `exposureWatchlist.js` (`cleanText`, `createOrgError(status, mensagem)`):

| Campo | Limite |
|---|---|
| perfis por usuário | 10 |
| `name` | 1–80 chars |
| `assets` | 100 por perfil; `vendor` e `product` 1–60 chars cada |
| termo de ativo | mínimo 3 caracteres alfanuméricos |
| `ot.vendors`, `ot.protocols` | 30 itens, 40 chars cada |
| `actors` | 50 ids, cada um precisa existir em `actors.json` |

O mínimo de 3 caracteres em ativos existe pelo mesmo motivo documentado em `actorMatch.js`: abaixo disso um "alias" casa com meia língua. Ativos são casados com fronteira de palavra, então `SAP` não casa dentro de `sapphire`.

### Store

`createProfileStore` sobre `.org-profiles.json`, espelhando `createWatchlistStore`: `list(ownerId)`, `get(ownerId, id)`, `create(owner, input)`, `update(ownerId, id, input)`, `remove(ownerId, id)`. Toda leitura filtra por `ownerId`; `get` de um id de outro dono é 404, não 403 — não confirma que o perfil existe.

## Modelo de ameaças

`buildThreatModel(profile, actors)` é uma função pura sobre o `ACTORS_CACHE` que `loadActors()` já mantém em memória (1362 atores, já enriquecidos com `actorTargeting`). Sem I/O novo, sem dado novo. O retorno é **JSON puro**, porque viaja até o cliente:

```js
{
  actorIds: string[],                       // atores relevantes
  pinnedIds: string[],                      // subconjunto fixado à mão
  actors: [{id, name, country}],            // para a UI listar quem são
  sectors: string[],                        // ecoa o perfil
  regions: [{label, terms: string[]}],      // só as regiões escolhidas, com seus termos
  otPresent: boolean,
  assets: [{vendor, product}],              // ecoa o perfil
  techniques: string[],                     // união das técnicas dos atores relevantes
}
```

Um ator é relevante quando `actor.sectors ∩ profile.sectors ≠ ∅` **ou** `actor.targets ∩ profile.regions ≠ ∅`, ou quando está em `profile.actors`.

`regions` carrega os termos (`Brazil` → `['brazil','brazilian']`) porque só o servidor tem o `TARGET_REGIONS` de `actorProfile.js`; mandar apenas as regiões escolhidas mantém o payload em algumas linhas. Setor não precisa de termos: cada item do feed já chega com `item.sectors` carimbado por `scoreArticle`. OT também não: `item.newsCategories` já traz `OT/ICS`.

`techniques` não tem consumidor nesta entrega. É exposto porque custa uma linha e é a ponte para a biblioteca de hunting, que já indexa por técnica (`attackIndex.js`).

O modelo é memoizado no servidor por `(profileId, updatedAt)`: perfis mudam raramente e o cálculo varre 1362 atores.

## Relevância

`orgRelevance(subject, model)` roda no cliente, em `src/utils/orgRelevance.ts`, e recebe exatamente os campos que um `Advisory` já tem:

```ts
subject = { title, description, actors?: {id}[], sectors?: string[], newsCategories?: string[] }
```

Retorna `{ score, matches }`, com `matches` sendo exatamente o que a UI mostra como chip:

| Sinal | Peso | `match` |
|---|---|---|
| ativo do perfil citado no texto | 40 | `{kind:'asset', label:'FortiGate'}` |
| ator fixado à mão citado | 40 | `{kind:'actor', label:'Sandworm', pinned:true}` |
| ator relevante citado | 30 | `{kind:'actor', label:'Sandworm'}` |
| setor do perfil | 20 | `{kind:'sector', label:'Energia'}` |
| perfil tem OT **e** item é OT/ICS | 20 | `{kind:'ot', label:'OT/ICS'}` |
| região do perfil | 15 | `{kind:'region', label:'Brasil'}` |

Soma limitada a 100. Um ator conta uma vez só, pelo maior peso. Casamento de ativo e de região é por **fronteira de palavra**, sobre texto normalizado sem acento e em minúsculas, no molde do `normalize` de `actorMatch.js` — `SAP` não casa dentro de `sapphire`. `score: 0` com `matches: []` é resposta legítima e significa "fora do contexto" — não é erro.

`orgScore` é um campo **separado** de `score`, calculado na tela e nunca persistido no `localStorage`. Somar no `score` existente mudaria a severidade, os filtros de `minScore` e a experiência de quem não tem perfil nenhum. Não persistir é o que garante que trocar de perfil reanota os 400 itens em cache sem nenhuma invalidação.

Numa história (`StoryCard`), `orgScore` é o máximo entre suas fontes e `orgMatches` é a união, de-duplicada por `kind:label` — agregado em `groupAdvisoriesIntoStories`, junto de `score`, `cves` e `actors`, que já são agregados ali.

## Rotas

Todas exigem sessão autenticada; as de perfil não exigem premium, porque configurar não é consumir. A exceção é `/api/org/asset-suggestions`, que lê dados do watchlist e portanto herda o `requirePremium` dele.

| Rota | Efeito |
|---|---|
| `GET /api/org/profiles` | perfis do usuário |
| `POST /api/org/profiles` | cria (409 no limite de 10) |
| `PATCH /api/org/profiles/:id` | atualiza |
| `DELETE /api/org/profiles/:id` | remove |
| `GET /api/org/profiles/:id/threat-model` | o modelo serializável descrito acima |
| `GET /api/org/vocab` | `{sectors, regions}` — alimenta os selects da UI |
| `GET /api/org/asset-suggestions` | produtos já detectados no watchlist do usuário |

`/api/org/vocab` existe para a UI não baixar os 1362 atores de `/api/actors` só para ler as duas facetas.

`/api/org/asset-suggestions` varre os snapshots do watchlist do usuário no servidor e devolve `[{product, version, seenOn:[label]}]` de-duplicado por produto. Existe para o botão de importação não fazer N+1 no navegador — os produtos ficam em `finding.product` dentro dos snapshots, um por ativo, e hoje só há rota por ativo (`/api/exposure-watchlist/assets/:id/snapshots`). O Shodan raramente traz o fabricante separado, então a sugestão vem com `vendor` vazio e `product` preenchido; o usuário completa se quiser.

**`GET /api/newsletter` e `GET /api/news/stories` não mudam em nada.** Nenhum parâmetro novo, nenhum campo novo, nenhuma bifurcação por usuário no cache do feed. É a consequência de calcular no cliente, e o principal motivo para fazê-lo assim.

Um `activeId` velho no `localStorage` apontando para um perfil apagado responde 404 em `/api/org/profiles/:id/threat-model`; o cliente trata como "sem perfil", limpa o `activeId` e segue com o feed normal.

## Configurações de Monitoramento

Aba nova em `/settings?section=monitoring`, dentro do `Tabs` que `Settings.tsx` já tem — rota nova traria seu próprio guard de auth e seu próprio layout sem ganhar nada. Três cards, em `src/components/settings/MonitoringSettings.tsx`:

1. **Contexto da organização** — o CRUD de perfis e o seletor de perfil ativo (`OrgProfileEditor.tsx`). Único componente realmente novo. Inclui o botão **Importar do Watchlist**, que chama `/api/org/asset-suggestions` e propõe como ativos os produtos já detectados por Shodan; o usuário confirma quais entram. Proposta, não sincronização: o watchlist só enxerga o que está exposto na internet, e o perfil precisa conter também o que é interno.
2. **Fontes de coleta** — o `FeedSourcesManager` **movido** para cá, sem reescrita. Sai do card de Integrações do `AdminSettings.tsx`, onde não tem relação com o conteúdo vizinho. Leitura para qualquer conta autenticada, edição só para admin, exatamente como `/api/feeds` já se comporta.
3. **Ativos monitorados** — resumo do watchlist (quantos ativos, última varredura) e link para `/attack-surface?mode=monitor`. Card e link, não um segundo CRUD: a tela de resultados continua sendo dona do assunto.

### Perfil ativo, compartilhado

`src/hooks/useOrgProfile.ts` expõe `{ profiles, activeId, setActiveId, active, model, loading }`, com `activeId` em `localStorage` sob `org.activeProfile` e `model` buscado do endpoint de threat model sempre que `activeId` muda. É a peça que torna o contexto reaproveitável: cada consumidor futuro é uma chamada ao hook mais uma chamada a `orgRelevance`.

**Nesta entrega, o único consumidor é Notícias.** Ficam registrados como próximos passos, cada um de custo aproximado de uma linha, **fora do escopo**: Patch Tuesday/SAP (destacar CVEs dos vendors do perfil), Hunting (priorizar as técnicas do modelo), Boletim diário (ordenar sugestões pelo contexto), Threat Map (recorte pelas regiões).

### Notícias

Em `Newsletter.tsx` e `newsletterView.ts`:

- seletor de perfil na barra de filtros (oculto quando o usuário não tem nenhum perfil);
- chip no card com os matches — `Relevante: FortiGate · Energia`;
- ordenação **Relevante para mim** junto das existentes;
- toggle **Só o meu contexto**, desligado por padrão.

Sem perfil selecionado, a tela é exatamente a de hoje.

## Fontes OT

### Nozomi Networks — portal de segurança

`https://security.nozominetworks.com/rss.xml` é RSS válido e verificado. Entra em `CTI_FEEDS` como layer 1, `weight_boost` 20, junto dos outros PSIRT. **Zero código.**

### Claroty Team82 e blog da Nozomi — sem RSS

As três páginas são renderizadas no servidor e raspáveis; nenhuma publica feed:

| Fonte | URL | Datas |
|---|---|---|
| Claroty Team82 Research | `claroty.com/team82/research?team82_resources_tab=team82_research` | reais |
| Claroty Team82 White Papers | `claroty.com/team82/research?team82_resources_tab=team82_white_papers` | reais |
| Nozomi Networks Blog | `www.nozominetworks.com/blog` | primeira aparição |

`parseListing(html, source)` é puro sobre `cheerio`: extrai âncoras cujo `href` casa com o padrão da fonte e o `<h2>` de dentro como título, devolvendo `{title, link, source, layer, weight_boost}` — a mesma forma que `parseFeed` já produz. Com isso, score, atores, categorias, histórias e IOCs vêm de graça, sem tocar em `refreshNewsletterFeed`.

**Datas.** A configuração de cada fonte carrega `datedItems`:

- `datedItems: true` (Claroty) — para cada link novo, uma requisição à página do post lê `<meta property="article:published_time">`. Teto de 10 posts novos por rodada por fonte. Falha na leitura cai para primeira aparição.
- `datedItems: false` (blog da Nozomi) — o `datePublished` do JSON-LD é inconfiável (um post de dezembro/2024 chega como `"Aug 12, 2026"`), então a data é a **primeira aparição**, registrada em `.scrape-seen.json` (`{link: pubDate}`, podado em 2000 entradas, mais antigas primeiro).

**Partida a frio.** Numa fonte `datedItems: false` sem entradas no `.scrape-seen.json`, as URLs da listagem são semeadas em silêncio e **nada é emitido** — só posts vistos a partir dali entram no feed. É o preço de não fabricar data: uma fonte sem datas confiáveis não pode ser retroativa sem mentir sobre quando as coisas aconteceram. As duas fontes da Claroty, que têm data real, emitem normalmente já na primeira rodada.

A raspagem roda dentro do refresh, com o mesmo tratamento dos feeds RSS: uma fonte que quebra registra o erro em `feedHealth` e devolve zero itens. Uma mudança de layout do Claroty derruba aquela fonte, nunca o feed.

As três aparecem no catálogo de fontes com sua saúde, e podem ser desligadas pelo mesmo interruptor dos feeds RSS. Um raspador quebrado devolve zero itens em silêncio — sem aparecer na tela, ninguém perceberia. A costura é `feedListForClient()`, só de exibição: `catalogFeeds()` e `effectiveFeeds()` ficam intocados, para o coletor de RSS nunca tentar buscar uma página HTML como se fosse feed.

### Vocabulário OT

O `OT_ICS` de `newsCategories.js` ganha os fornecedores e protocolos que essas fontes efetivamente publicam, hoje ausentes: Phoenix Contact, Copeland, Danfoss, EnOcean, LonTalk, Emerson, Honeywell, Yokogawa, Mitsubishi Electric, Omron, WAGO, Beckhoff, Moxa, Advantech, IEC 61850, IEC 60870, EtherNet/IP, BACnet, e "building management system"/"BMS". Cada termo é inequívoco em prosa CTI, então entram na alternância existente sem exigir contexto.

## Erros

- Perfil inválido → 400 com mensagem pública específica (qual campo, qual limite). Nunca 500.
- Limite de 10 perfis → 409.
- Perfil de outro dono → 404.
- Perfil ativo apagado ou threat model indisponível → a tela de Notícias funciona sem contexto: sem chip, sem a ordenação nova, com o toggle desabilitado. O feed nunca falha por causa do contexto.
- Raspagem: erro de rede, HTML mudado ou zero âncoras → `feedHealth` registra e a fonte devolve `[]`.
- `.org-profiles.json` e `.scrape-seen.json` corrompidos → store vazio, log, segue.

## Testes

Servidor (`npm run test:server`, Node test runner, no molde dos 22 arquivos em `server/test/`):

- `orgProfiles.test.js` — validação por campo, limites, rejeição de vocabulário inválido, isolamento entre donos, store com `fs` falso.
- `orgThreatModel.test.js` — ator entra por setor, por região e por fixação; ator irrelevante fica fora; `regions` carrega os termos só das regiões escolhidas; perfil vazio dá modelo vazio.
- `scrapeFeeds.test.js` — `parseListing` contra HTML fixo salvo das três páginas (`server/test/fixtures/`); partida a frio não emite; segunda rodada emite só o novo; teto de itens novos respeitado.
- `newsCategories.test.js` — casos novos para os fornecedores OT acrescentados.

Cliente (`npm run test:unit`, esbuild + Node test runner, no molde dos `.test.ts` em `src/utils/`):

- `orgRelevance.test.ts` — cada peso isolado; ator contado uma vez pelo maior peso; teto de 100; modelo vazio dá score 0; ativo de 3 letras não casa dentro de outra palavra; região casa sem acento.
- `newsletterView.test.ts` — agregação de `orgScore`/`orgMatches` na história, ordenação por contexto e filtro "só o meu contexto".

## Fora de escopo

Tela própria de modelo de ameaças, e também o atalho para `/atores` com os filtros do perfil pré-preenchidos — o endpoint de threat model já devolve os atores relevantes, então a tela pode vir depois sem nada a refazer. Sugestão automática de setor a partir do domínio. Perfil compartilhado entre usuários. Ligação do perfil com Patch Tuesday, Hunting, Boletim e Threat Map. Alertas por e-mail quando uma notícia casa com o contexto.
