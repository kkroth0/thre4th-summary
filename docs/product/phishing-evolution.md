# Phishing: tendências e integração da vigilância

Primeira entrega do plano de evolução de 14/10/2026: tendências semanais,
histórico da coleta, inventário privado de candidatos e avaliação retrospectiva
de CT. A migração integral de notícias/stories, o stream de CT e os embeddings
continuam sendo etapas posteriores.

## Semanas e evidências

`GET /api/phishing/evolution` é premium, sem cache compartilhado. A tela Dashboard
de phishing apresenta um panorama global separado dos filtros de publicações.
Semanas usam domingo 00:00 UTC até domingo seguinte, com fim exclusivo. A semana
aberta é identificada como parcial e não é comparada com semanas completas.

O ciclo de notícias e a inicialização, após a revisão de evidências, calculam dez
semanas sobre o arquivo permanente. O caminho HTTP lê somente os snapshots SQLite.
A semana fechada mais recente é comparada às oito anteriores, somente quando há
histórico e versões de classificação/extração comparáveis. Datas inferidas/futuras
e conteúdo explicitamente não relevante são excluídos. O teto de 20 mil relatórios
é explícito e impede a publicação de percentuais quando atingido.
Backfill de notícias não comprova continuidade da coleta: uma semana comparável
também exige pelo menos um ciclo com fonte fresh/304 em cada um dos sete dias.
Isso é um mínimo de observação, não uma garantia de completude ou uptime.

Conta-se `storyId`, ou URL quando não há vínculo, uma vez por dimensão/semana.
Campanhas nomeadas não substituem a identidade do evento. Um evento observado
em duas semanas participa da cobertura das duas, sem representar dois ataques
novos. Domínios de fonte são uma aproximação de independência editorial.

`phishing_weeks` guarda totais, versões e membros (URL, evento, hash, fonte e
disponibilidade do corpo); revisões preservam snapshots substituídos. O endpoint
`/api/phishing/evolution/weeks/:week` entrega essas evidências. As últimas dez
semanas são recalculadas; semanas anteriores permanecem como snapshots históricos.
O botão **Baixar evidências JSON** consulta essa rota com a sessão atual, valida
a semana e a quantidade de membros e baixa o arquivo, sem navegar para a API.
Sem conteúdo original suficiente, uma mudança de regras não pode ser tratada
como uma série histórica homogênea.

`phishing_collection_cycles` guarda ciclos observados; `phishing_source_days`
acumula fresh/304/stale/failed por fonte habilitada. Ambos retêm 90 dias. Repetir
o mesmo identificador de ciclo é idempotente. Esse histórico começa no deploy;
não é uma reconstrução da disponibilidade passada nem uma medição de uptime.
Corpos antigos sem metadados são desconhecidos, não falhas presumidas.

## Candidatos, triagem e isolamento

O banco é o SQLite do inventário, usando a mesma conexão e WAL. `watch_candidates`
e `watch_candidate_revisions` preservam o histórico por dono/perfil, inclusive
após a poda da lista operacional. Não criam registros em `indicators`,
`observations` ou `entity_links` e não atribuem atores ou malwares automaticamente.

O status operacional new/confirmed/dismissed continua compatível com tickets.
O endpoint `POST /api/phishing-watch/hits/:id/verdict` acrescenta veredito e motivo:
malicioso/legítimo confirmado ou inconclusivo (duplicado, sem evidência, fora do
escopo). Confirmar phishing continua abrindo o ticket existente. Revisar um
veredito não encerra automaticamente um ticket que o analista já está tratando.
Confirmações antigas contam como confirmação manual; dispensas antigas não viram
legítimos confirmados. Mudança de status operacional não apaga um veredito.

Precisão é malicioso/(malicioso+legítimo), ou desconhecida sem casos conclusivos;
o denominador e os casos sem conclusão são apresentados. Não é uma estimativa
independente da acurácia global: existe seleção humana de quais casos revisar.

`GET /api/phishing-watch/hits/:id/context` cruza indicadores extraídos do arquivo
e observações globais/da própria conta para domínio, até oito IPs observados e
quatro nameservers, sem chamadas externas. Cada correspondência identifica seu
tipo; um IP compartilhado não confirma atividade maliciosa do domínio. NS/ASN compartilhados
apenas apresentam outros candidatos privados como contexto. O escopo é sempre o
usuário autenticado; retirar o perfil remove os candidatos e suas revisões.
A persistência JSON operacional e o SQLite não têm uma transação conjunta:
alterações são sincronizadas após a gravação JSON e reconciliadas no boot.

## CT: avaliação antes de infraestrutura

`node server/backtestPhishingCt.mjs input.json` é offline. Entrada: marcas e
amostras rotuladas com hostname, firstSeen, cohort, label e certificados crt.sh.
Só certificado com nome exato e `entry_timestamp` anterior ao marco participa.
Não há fallback para data de emissão ou wildcard. O timestamp é uma aproximação
de observação da fonte, não garantia do instante em que um detector próprio teria
recebido a mensagem. O resultado mede oportunidade retrospectiva.

A avaliação retorna recall amostral do filtro e falsos positivos somente quando
há exemplos legítimos. Precisão operacional permanece desconhecida em amostras
caso/controle. Certificado novo não prova registro novo nem campanha maliciosa.

O workflow manual `Phishing evolution audit` lê a base sem alterá-la e pode fazer
até oito consultas sequenciais, de oito segundos e 5 MB cada, ao crt.sh, usando
confirmações existentes e candidatos independentes reportados por ThreatFox ou
URLhaus para as marcas observadas. Candidatos dos provedores filtrados pela própria
regra aguardam revisão e não estimam recall independente; sem o timestamp original
não recebem antecedência calculada. Logs mostram somente agregados. Uma amostra
ausente, pequena ou sem exemplos legítimos não autoriza concluir ganho de CT.
É necessário um piloto prospectivo antes de decidir pela infraestrutura própria.

## Próximas etapas

- Ampliar e revisar as amostras positivas/legítimas do backtest.
- Sugestões de vigilância por campanha/marca com evidência e aceitação do dono.
- Piloto CT por marca e orçamento, condicionado aos resultados anteriores.
- Migração gradual do arquivo/stories, conferindo IDs, aliases e evidências.
- Avaliação PT/EN rotulada antes de ativar similaridade como sinal adicional.
