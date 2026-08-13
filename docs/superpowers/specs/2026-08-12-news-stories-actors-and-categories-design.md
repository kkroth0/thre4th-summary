# Notícias em histórias, atores e categorias — Design

**Objetivo:** transformar o feed de Notícias de Segurança, hoje uma lista de itens soltos de-duplicada só por URL, em histórias que agregam fontes diferentes e evoluem ao longo de semanas; casar cada história com atores de ameaça específicos; e segmentar o feed em sete categorias navegáveis. Renomear "Grupos de Ataque" para "Atores de Ameaça".

**Problema:** a mesma notícia publicada por Reuters, BleepingComputer e CISA vira três cards idênticos, porque a única de-duplicação é por URL. Não há como acompanhar como uma história evoluiu, nem filtrar o feed por tipo de ameaça, nem saber quais notícias falam do ator que está aberto na tela de Atores.

## Restrições

- Nenhuma dependência nova. Sem chamada de LLM no caminho do refresh.
- `GET /api/newsletter` mantém a forma atual; só ganha campos por item. A tela existente e o cache em `localStorage` continuam válidos sem migração.
- O agrupamento é determinístico: a mesma entrada produz o mesmo agrupamento em qualquer execução, hoje ou daqui a um mês.
- Os módulos de regra são puros e testáveis sem rede, sem relógio e sem disco.
- Persistência segue o padrão de `createEditionStore`: arquivo JSON com escrita atômica.

## Arquitetura

Quatro módulos novos no servidor. O único ponto de costura é `refreshNewsletterFeed()` em `server/index.js`, que já monta o `unifiedFeed`: depois de montar, ele enriquece cada item e funde no store de histórias. Nenhum outro consumidor do feed precisa saber que histórias existem.

| Módulo | Responsabilidade | Interface |
|---|---|---|
| `server/actorMatch.js` | Casar texto livre com atores | `buildActorIndex(actors)` → índice; `matchActors(texto, índice)` → `[{id, name, via}]` |
| `server/newsCategories.js` | Classificar um item | `categorize(item)` → `{categories: string[], primary: string}` |
| `server/newsStories.js` | Agrupar itens em histórias | `mergeIntoStories(stories, items, now)` → `stories` |
| `server/newsStoryStore.js` | Persistir e consultar | `createStoryStore({filePath, writeJsonAtomic})` |

```
feeds RSS
   ↓
refreshNewsletterFeed()          [já existe]
   ↓  itens enriquecidos (score, cves, threats, sectors, iocs)
   ├→ matchActors        → item.actors
   ├→ categorize         → item.categories, item.primaryCategory
   ↓
mergeIntoStories(store.all(), itens, now)
   ↓
store.save()  →  stories.json
   ↓
GET /api/newsletter        (itens, agora com storyId/actors/categories)
GET /api/news/stories      (histórias, filtráveis)
GET /api/news/stories/:id  (uma história + linha do tempo)
```

`newsStories.js` não conhece disco nem relógio: recebe `now` como argumento e devolve o novo estado. O store cuida do arquivo. Isso é o que torna o agrupamento testável com datas fixas.

## Agrupamento em histórias

### Sinais

Para cada item extraímos três conjuntos:

- **CVEs** — já vem em `item.cves`.
- **Atores** — ids vindos de `matchActors`.
- **Termos raros do título** — tokens do título com 4+ caracteres, minúsculos, sem acento, menos duas listas estáticas: stopwords PT/EN e um vocabulário CTI comum (`security`, `vulnerability`, `vulnerabilidade`, `attack`, `ataque`, `flaw`, `bug`, `patch`, `update`, `report`, `researchers`, `hackers`, `new`, `nova`, …).

As duas listas são **estáticas**, não derivadas da frequência no feed do dia. Frequência do dia faria o mesmo par de notícias agrupar diferente amanhã, quebrando o determinismo.

### Regra de união

Um item novo é comparado apenas com histórias **ativas** — última atividade nos últimos 14 dias. Une quando qualquer condição bate:

1. CVE em comum (sinal mais forte).
2. Ator em comum **e** pelo menos um termo raro em comum.
3. Jaccard dos termos raros ≥ 0,5.

A regra 3 só se aplica quando os dois títulos têm **pelo menos 2 termos raros** cada. Abaixo disso o Jaccard fica instável — um título de dois tokens casaria com meio feed por coincidência.

Se o item casar com duas ou mais histórias, elas se fundem em uma: um item que cita a CVE da história A e o ator da história B é a evidência de que A e B sempre foram a mesma coisa. A história resultante herda o `id` da mais antiga, para não quebrar links já compartilhados.

Se não casar com nenhuma, vira história nova.

### Forma da história

```js
{
  id,                    // hash curto e estável, derivado do link do primeiro item
  title,                 // título do item de maior score
  firstSeen, lastSeen,   // ISO
  cves: [],              // união
  actors: [{id, name, via}],
  categories: [], primaryCategory,
  score,                 // o maior entre os itens
  sources: [{ source, link, title, pubDate, score, severity }]
}
```

O corpo da notícia não é guardado: `sources[].link` abre a fonte original. Isso mantém o arquivo pequeno e evita reter texto de terceiros.

**Retenção:** 60 dias desde `lastSeen`, podados a cada refresh.

## Categorias

Sete categorias, nesta ordem de precedência — a primeira que bater vira a `primaryCategory`, e a história aparece em **todos** os filtros que bateram:

| Categoria | Vem de |
|---|---|
| Ransomware | `threats` contém Ransomware, ou termos de dupla extorsão / leak site |
| APTs | match de ator com regra distintiva, ou termos nation-state / state-sponsored |
| Data Leaks | `CAT3_BREACH_COMPROMISE` (data breach, vazamento) |
| OT/ICS | **vocabulário novo**: ICS, SCADA, PLC, Modbus, OPC UA, HMI, purdue, Siemens S7, Rockwell, Schneider Electric, safety instrumented |
| Vulnerabilities | tem CVE, ou `CAT9_VULN_CLASS`, ou `CAT1_CRITICAL_IMPACT` |
| Malware | `threats` contém Trojan/Infostealer/Wiper/Backdoor/Botnet/Spyware/Rootkit |
| Microsoft | `CAT7_CRITICAL_VENDORS` casou `microsoft`, ou um destes produtos: Windows, Exchange, SharePoint, Azure, Entra ID, Active Directory, Office 365, Microsoft 365, Teams, Outlook, Defender, Hyper-V |

Um item que não bate em nenhuma fica sem categoria e aparece apenas em "Todas" — é melhor que forçá-lo num balde errado.

## Match de atores

Índice construído uma vez a partir dos 1002 atores de `server/data/actors.json` (1840 nomes e aliases), particionado em dois conjuntos:

**Distintivo** — casa direto, em qualquer contexto:
- Codinomes: `APT-?\d+`, `UNC\d+`, `TAG-\d+`, `TA\d+`, `Storm-\d+`, `APT-C-\d+`, `APT-Q-\d+`, `ATK\d+`.
- Qualquer nome com duas ou mais palavras: *Scattered Spider*, *Volt Typhoon*, *Lazarus Group*.

**Comum** — nome de palavra única (*Akira*, *Medusa*, *Reaper*, *Mantis*, *Elfin*). Só casa se houver termo de contexto na mesma frase: `group`, `gang`, `ransomware`, `APT`, `campaign`, `threat actor`, `crew`, `operators`, `grupo`, `quadrilha`, `campanha`.

```
"the Akira ransomware gang"       → casa   (contexto: ransomware, gang)
"Akira Kurosawa retrospective"    → não casa
"Reaper drone strike"             → não casa
"Reaper APT targets telecom"      → casa   (contexto: APT)
```

Cada match carrega `via` — qual nome casou e por qual regra — para a tela poder explicar a atribuição em vez de afirmá-la sem prova. Nomes com menos de 3 caracteres são descartados do índice.

O índice é construído uma vez no boot, não por item.

## Superfície

**API**

- `GET /api/newsletter` — inalterado, mais `storyId`, `actors`, `categories`, `primaryCategory` por item.
- `GET /api/news/stories?category=&actor=&days=&limit=` — histórias ordenadas por `lastSeen`.
- `GET /api/news/stories/:id` — uma história com todas as fontes.

Ambas as rotas novas ficam atrás de `requirePremium`, como `/api/newsletter`.

**Notícias de Segurança** (`src/pages/Newsletter.tsx`)
- Itens da mesma história colapsam num card. Contador "5 fontes"; expandir abre a linha do tempo, uma linha por fonte com data e veículo.
- Barra de categorias no topo, com contagem por categoria.
- Chip de ator no card, clicável, filtra o feed por aquele ator.
- Card de história mostra por que as fontes foram unidas ("unida por CVE-2025-61882 e Cl0p").

**Atores de Ameaça** (`src/pages/Actors.tsx`, `src/components/Header.tsx`)
- Rename do rótulo em PT e ES. A rota `/atores` já está correta e não muda.
- No perfil do ator, bloco "Notícias recentes": as histórias que casaram com aquele ator, mais recentes primeiro.

## Erros e degradação

- `stories.json` corrompido ou ausente: começa vazio, mesmo comportamento de `createEditionStore`. O feed continua servindo itens.
- Falha no merge: registra e serve o feed sem `storyId`. Agrupamento é enriquecimento, não pode derrubar a notícia.
- `actors.json` ausente: índice vazio, match devolve `[]`, categoria APTs cai só nos termos nation-state.
- História sem categoria ou sem ator é estado normal, não erro.

## Testes

Cada módulo puro ganha teste em `node --test` pelo pipeline `test:unit` existente:

- `actorMatch`: casa codinome; casa multi-palavra; **não** casa palavra comum sem contexto; casa com contexto; ignora nome curto demais; `via` reporta a regra.
- `newsCategories`: precedência elege a principal certa; história multi-categoria aparece em todas; OT/ICS reconhece o vocabulário novo; item sem sinal fica sem categoria.
- `newsStories`: une por CVE; une por ator + termo raro; une por Jaccard; **não** une história com 15 dias de silêncio; funde duas histórias quando um item faz a ponte; o id sobrevivente é o da mais antiga; determinismo — a mesma entrada duas vezes dá a mesma saída; poda em 60 dias.
- `newsStoryStore`: arquivo corrompido vira store vazio; save é atômico.

## Fora de escopo

- **Fila de revisão manual dos matches de ator.** Adiciona UI, store de decisões e autorização; adianta pouco antes de medir a taxa de erro real. Reavaliar depois que o número aparecer.
- **Embeddings ou LLM para similaridade.** Custo por refresh e resultado não repetível. A regra determinística é o teto atual.
- **Agrupamento retroativo** do que já passou pelo feed antes desta mudança: as histórias começam a se formar do primeiro refresh em diante.
