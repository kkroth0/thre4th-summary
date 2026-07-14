# Redesign operacional do Threat Map

## Objetivo

Transformar `/threat-map` em uma tela operacional para leitura rapida de ransomware. A primeira dobra deve responder, sem rolagem longa: quem foi vitima, qual grupo reivindicou, onde ocorreu, quando apareceu, qual setor foi afetado e se existe evidencia/fonte para abrir.

O mapa continua existindo, mas deixa de ser protagonista. Ele vira contexto geografico lateral, enquanto a lista de vitimas recentes passa a ser o centro da experiencia.

## Problema atual

A pagina atual tem dados uteis, mas a hierarquia visual prioriza efeito e apresentacao:

- titulo e copy falam em "pulso/radar", mas nao mostram a fila operacional imediatamente;
- mapa grande ocupa a area principal antes da lista de vitimas;
- KPIs, insights e graficos aparecem antes da informacao que o analista quer bater o olho;
- a lista de reivindicacoes recentes fica no fim da pagina;
- ha elementos mais decorativos, como feixes do mapa e legenda, que competem com a informacao.

## Dados disponiveis

A mudanca nao precisa de backend novo. `fetchThreatMap` ja entrega:

- `victims`: vitimas recentes no recorte selecionado;
- `countries`: contagem por pais;
- `groups`: contagem por grupo;
- `sectors`: contagem por setor;
- `delta`: comparacao contra janela anterior;
- `latam`: vitimas, paises e grupos LATAM;
- `timeline`: buckets recentes;
- `insights`: sinais derivados.

Cada vitima ja pode expor nome, grupo, pais, setor, descoberta, permalink e evidencias como screenshot, press e infostealer.

## Abordagens consideradas

### Recomendada: Mesa SOC operacional

Primeira dobra com KPIs compactos no topo, tabela de vitimas como elemento principal e painel lateral de situacao atual. O mapa fica menor, no painel lateral ou logo abaixo dele.

Trade-off: menor impacto visual "uau", mas maior utilidade real para analista.

### Alternativa: Mapa ainda grande, lista lateral

Manter o mapa no centro e colocar vitimas em uma coluna lateral.

Trade-off: preserva a identidade visual atual, mas ainda obriga a tabela a disputar espaco com um elemento menos acionavel.

### Alternativa: Feed cronologico puro

Remover quase todo o dashboard e transformar a pagina em uma lista cronologica com filtros.

Trade-off: maxima objetividade, mas perde contexto agregado de paises, grupos, setores e tendencia.

## Design aprovado

A pagina passa a usar uma composicao de "operation desk":

1. Header compacto com titulo direto, fonte dos dados, horario de atualizacao, seletor de janela e botao atualizar.
2. Faixa de KPIs enxuta: vitimas no recorte, delta, paises, grupos ativos, LATAM.
3. Area principal em duas colunas no desktop:
   - coluna larga: tabela "Vitimas recentes";
   - coluna estreita: "Situacao agora" e mapa contextual.
4. Secao inferior com tendencia recente e rankings de paises, grupos e setores.

No mobile, a tabela vira lista compacta de linhas/cartoes, com os mesmos campos principais.

## Tabela de vitimas recentes

A tabela deve aparecer acima do mapa na hierarquia visual e listar ate 80 vitimas do recorte atual.

Colunas desktop:

- Vitima;
- Grupo;
- Pais;
- Setor;
- Descoberto;
- Evidencia;
- Fonte.

Comportamento:

- ordenacao padrao por descoberta mais recente, seguindo a ordem do backend;
- busca local por vitima, grupo, pais ou setor;
- filtros rapidos por grupo, pais e setor usando os valores do recorte;
- evidencias resumidas com badges: screenshot, press, infostealer;
- link "Fonte" abre `victim.permalink` quando existir;
- nomes longos truncam sem quebrar o layout.

## Painel de situacao

O painel lateral deve resumir o estado operacional:

- pressao: baixa, moderada ou alta, usando a logica ja existente;
- variacao contra janela anterior;
- grupo mais ativo;
- pais mais atingido;
- setor mais atingido;
- vitimas LATAM;
- ultima vitima.

O texto deve ser curto e utilitario, sem copy promocional.

## Mapa contextual

O mapa continua usando `ThreatWorldMap`, mas com menor area visual e menos enfase decorativa.

Regras:

- nao ocupar a coluna principal no primeiro viewport;
- manter paises vitima proporcionais ao volume;
- remover ou reduzir legenda/efeitos que nao ajudem a triagem;
- se o mapa falhar ao carregar, a tabela e os KPIs continuam funcionais.

## Secoes inferiores

Depois da primeira dobra:

- tendencia recente por bucket;
- ranking de paises;
- ranking de grupos;
- ranking de setores.

Essas secoes devem ser densas e comparaveis, com listas/tabelas simples. Cards continuam permitidos para itens repetidos, mas a pagina nao deve virar uma grade decorativa.

## Arquitetura

Manter `src/pages/ThreatMap.tsx` como a pagina principal. A implementacao pode extrair pequenos componentes locais no mesmo arquivo se isso reduzir duplicacao:

- `VictimTable`;
- `SituationPanel`;
- `RankingList`;
- `EvidenceBadges`.

Nao alterar backend nesta iteracao. Nao alterar `ThreatWorldMap` salvo se uma pequena prop for necessaria para modo compacto; a preferencia e controlar tamanho e prioridade pelo layout da pagina.

## Estados

- Loading inicial: mostrar skeleton ou mensagem compacta sem empurrar a tabela para baixo.
- Erro de carregamento: toast existente e estado vazio com acao de atualizar.
- Sem vitimas no recorte: mostrar KPIs zerados e uma tabela vazia com mensagem objetiva.
- Dados parciais: rankings e painel lateral devem cair para `-` sem quebrar.

## Testes e validacao

A implementacao deve incluir teste focado em estrutura operacional, preferencialmente leitura estatica do componente ou helper puro, validando que a pagina contem:

- titulo/copy operacional;
- tabela/lista de vitimas antes do mapa na fonte do componente;
- campos de vitima, grupo, pais, setor, descoberta, evidencia e fonte;
- controles de busca/filtro local;
- mapa mantido como contexto.

Validar tambem:

- `npm run test:unit` quando o estado local permitir;
- `npm run typecheck`;
- `npm run build`;
- teste visual manual em desktop e mobile, conferindo que a primeira dobra mostra vitimas sem depender de rolagem longa.

## Fora do escopo

- Criar endpoint novo;
- persistir filtros;
- exportar CSV/XLSX;
- adicionar enriquecimento externo por vitima;
- resolver alteracoes nao relacionadas ja presentes no worktree;
- redesenhar outras paginas.

## Criterios de aceite

- Em desktop, a primeira dobra mostra a tabela/lista de vitimas recentes como elemento principal.
- O mapa nao domina a tela e funciona como contexto.
- O analista consegue identificar rapidamente vitima, grupo, pais, setor, momento e fonte.
- Janela de tempo e atualizar continuam funcionando.
- Rankings e tendencia continuam disponiveis, mas abaixo da area operacional principal.
- A pagina fica mais densa, menos promocional e mais orientada a triagem.
