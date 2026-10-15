# Continuação do plano: vigilância e persistência das evidências

## Notícias alimentam sugestões privadas

O Monitoramento de domínios apresenta até 15 termos sugeridos a partir de
publicações de phishing dos últimos 90 dias relacionadas ao perfil: setor,
região, tecnologias, marcas ou atores acompanhados. Uma coincidência de setor
indica contexto, não que a marca pertença à organização. A decisão é do analista.
Cada sugestão inclui os eventos distintos, domínios de fontes, motivos do vínculo
e até cinco publicações de origem, com técnicas, campanha explicitamente nomeada
e padrões de host/path observados nos IOCs quando disponíveis.

`GET /api/phishing-watch/suggestions?profileId=...` exige premium e confere o
dono. Usa dados locais e cache de dez minutos invalidado por mudanças no perfil
ou no snapshot. Não faz consultas novas às APIs externas. As decisões ficam em
`watch_term_suggestions`, no mesmo SQLite, isoladas por conta/perfil.

`POST /api/phishing-watch/suggestions/:id/review` aceita `profileId` e decisão
`accepted`/`dismissed`. Aceitar inclui apenas o termo revisado nas marcas do
perfil; preserva o limite de oito e a busca existente com OR em uma consulta.
Dispensar não é um veredito de domínio legítimo/malicioso. Falha ao salvar o
perfil não avança a decisão. Excluir o perfil remove também suas sugestões.
Perfil JSON e decisões SQLite ainda não compartilham uma transação; se a gravação
da decisão falhar após atualizar o perfil, o termo já configurado é omitido das
novas sugestões. Repetir o aceite não duplica a marca.

## Migração gradual no banco do inventário

`news_documents` guarda as publicações e stories completos, incluindo IDs,
aliases, IOCs por fonte, versões e evidências. A ativação exige as três últimas
comparações shadow válidas e igualdade com os JSONs naquele instante. Uma instalação
sem documentos anteriores importa os arquivos existentes após validar os vínculos.
Se os critérios ainda não forem atendidos, a instalação permanece em shadow até
uma próxima inicialização; não apaga nem substitui a cópia divergente.

Após a ativação, leituras são carregadas do SQLite e mantidas em memória por geração;
os JSONs passam a ser cópias de recuperação. `news_storage_state` confirma a geração
e a ordem original de publicações/stories na mesma transação. A fila de publicação
serializa coletas e enriquecimentos assíncronos. Uma geração desatualizada é rejeitada.
O correlacionador prepara os dois snapshots sem publicá-los; só depois os grava
juntos no banco. Uma falha reverte ambos. `news_document_revisions` preserva a versão substituída
e a retirada de um story pela retenção; não cria uma revisão para dados iguais.
O registro de nomes processa apenas publicações alteradas a cada commit.

Reinícios verificam hashes de payloads, identidades, ordem, aliases e vínculos;
um banco inválido impede a inicialização dessa versão, sem importar JSON vazio
por cima. JSON ausente, antigo ou inválido é reconstruído do banco verificado.
Falha ao atualizar a cópia JSON não desfaz um commit SQLite nem anuncia falha
da publicação já salva; fica registrada como recuperação pendente no endpoint.
As duas cópias JSON não compartilham transação de filesystem. Antes de voltar a
uma versão antiga que lê JSON, executar a auditoria e exigir paridade de ambas.
Não apagar `.ioc-intelligence.sqlite`, WAL ou SHM para forçar uma reimportação.
Esta implementação pressupõe um único processo escritor da aplicação; não é uma
coordenação de coletas distribuídas entre réplicas.

`news_shadow_checks` guarda as últimas mil comparações de identidades, hashes e
payloads, além de fontes órfãs e colisões de aliases. O endpoint premium
`GET /api/intelligence/storage` mostra somente contagens e o último resultado.
O workflow manual **News persistence audit** lê o banco em uma transação somente
de leitura, valida o manifesto e os vínculos e compara separadamente os JSONs de
recuperação. A auditoria de phishing também recalcula as semanas a partir do SQLite
após ativação. `mode`, `generation`, `backup` e o último resultado permitem verificar
a troca sem expor conteúdo privado. A ingestão no inventário de IOCs continua
idempotente após o commit de notícias e é repetida ao iniciar o servidor; ela não
participa da mesma transação assíncrona da correlação.

`news_body_versions` retém o texto efetivamente coletado e os anexos/IOCs
suplementares por URL e hash. Na primeira execução, importa os corpos que ainda
existem no cache; arquivos ilegíveis são contabilizados e ignorados. As novas
coletas são preservadas antes da poda do cache de 1.500 entradas, e o SQLite é
usado quando esse arquivo não existe mais. Uma tentativa sem texto não sobrescreve
o corpo preservado; um fingerprint diferente no cache não reutiliza outro texto.
Isso protege o material disponível; não reconstrói corpos já perdidos.

## Registro de entidades

`intelligence_entity_names` registra IDs e nomes/aliases declarados dos catálogos,
das notícias e das observações de provedores. A origem e o escopo são preservados.
`GET /api/intelligence/entities?kind=actor&query=...` retorna até cem entidades
globais/da própria conta. Alias compartilhado mantém múltiplos IDs possíveis;
não mescla entidades, não atribui um ator ao IOC e não confere reputação maliciosa.
O registro é histórico de nomes observados, não uma confirmação independente.
Uma migração única também inclui os nomes já presentes em `entity_links` antes
da criação do registro, mantendo o escopo da observação. Consultas agrupam por
ID estável; variações de nome não criam uma nova identidade.

## Avaliação PT/EN antes de novas uniões

`node server/auditCrossLanguage.mjs publicacoes-rotuladas.json vetores-locais.json`
avalia pares revisados sem escrever no banco e sem carregar modelo ou chamar API.
A entrada de publicações é `{items:[...]}` (ou array), com `expectedEvent` revisado
independentemente do correlacionador e `language` igual a `pt`/`en`. `storyId`
produzido pela plataforma não é rótulo de verdade.

O arquivo de vetores contém `model:{id,revision,dimensions}`, `threshold` opcional
e `embeddings:[{link,model,revision,textHash,vector}]`. `textHash` deve ser gerado
por `semanticTextHash` do módulo sobre título e resumo/texto (até 16 mil caracteres).
Vetores de outro modelo, revisão, texto, dimensão ou com valores inválidos não
participam. O avaliador prepara cada vetor uma vez e limita a 500 publicações.

Similaridade só propõe união quando há também janela temporal, idiomas distintos
declarados e âncora documental independente (hash, campanha nomeada ou CVE com
produto). Ator compartilhado sozinho não basta; boletins não servem de ponte.
O relatório separa baseline v3, proposta, pares PT/EN e falsas uniões introduzidas.
O threshold padrão é configuração inicial de teste, não um valor validado.
Os testes com vetores artificiais verificam o algoritmo, não qualidade de um
modelo. Nenhum embedding real ou benchmark PT/EN suficiente foi fornecido nesta
etapa; uniões automáticas continuam desativadas e o correlacionador não foi alterado.

## Estado dos próximos passos

- Passos 1 e 2: séries, saúde, triagem, vínculos privados e sugestões entregues.
- Passo 0: avaliador e auditoria disponíveis; amostra independente/rotulada ainda
  necessária. A busca considera também observações OpenPhish já existentes.
- Passo 3: condicionado aos resultados e ao piloto; nenhum stream CT foi ativado.
- Passo 4: espelhamento, revisões, corpos duráveis, registro de nomes e troca
  condicionada para SQLite como origem de leitura/gravação entregues.
- Passo 5: avaliação offline preparada; faltam vetores de modelo fixado e corpus
  PT/EN revisado para decidir sobre a ativação.
