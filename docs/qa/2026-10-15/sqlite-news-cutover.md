# Notícias e eventos: SQLite como origem de leitura e gravação

## Validação local

- 710 testes de backend aprovados, incluindo nove casos novos de migração.
- Smoke HTTP real: modo SQLite, cópia de recuperação disponível, autorização,
  isolamento entre contas, exportação e aceite explícito de sugestões.
- Falha SQLite injetada ao inserir stories: publicações, revisões e geração
  permanecem no snapshot anterior. A fila volta a publicar após remover a falha.
- Três publicações concorrentes preservam todas as URLs e evidências por fonte.
- Falha de backup JSON seguida de fechamento/reabertura do arquivo SQLite:
  notícias e IOCs permanecem disponíveis e a cópia é reconstruída.
- Payload corrompido ou manifesto incompleto impede o uso silencioso do banco.
- Fonte órfã, fonte compartilhada entre eventos e geração antiga são rejeitadas.
- Ordem de stories, IDs, aliases e ligação notícia → ator → IOC preservadas.
- Lint dos arquivos alterados aprovado; sem dependências novas.

## Contrato operacional

A ativação de uma cópia existente exige três comparações shadow válidas e paridade
atual. Um banco novo importa os JSONs após validar vínculos. Depois da ativação,
o manifesto persistido controla a geração e a ordem, e JSONs são somente recuperação.
Não há troca automática de volta a JSON em caso de corrupção do banco.

A publicação é atômica para arquivo de notícias e eventos. A ingestão no inventário
de IOCs é idempotente e posterior, com repetição na inicialização; não foi convertida
em parte da mesma transação. Os JSONs de recuperação não são atomicamente trocados
como um par; a auditoria verifica separadamente sua paridade antes de rollback
para versões antigas. Uma única instância é responsável pelas gravações.

CT e correlação semântica PT/EN continuam condicionados à amostra revisada do plano.
Esta entrega não modifica regras de classificação nem configurações privadas.

## Produção

- Código: `1cf980f305faf1d1bd80e8f0ece9960471e887ba`.
- CI [38746975569](https://github.com/kkroth0/thre4th-summary/actions/runs/38746975569):
  710 testes backend, 242 testes frontend e sete testes de marca/i18n aprovados;
  TypeScript e build aprovados, lint com zero erros e 16 avisos existentes.
- [VPS 38747320900](https://github.com/kkroth0/thre4th-summary/actions/runs/38747320900)
  e [Cloudflare 38747320789](https://github.com/kkroth0/thre4th-summary/actions/runs/38747320789): sucesso.
- Auditorias de persistência
  [38747763040](https://github.com/kkroth0/thre4th-summary/actions/runs/38747763040) e
  [38748282612](https://github.com/kkroth0/thre4th-summary/actions/runs/38748282612): sucesso.
  Modo `sqlite`, geração 1, 7.447 publicações e 4.982 eventos. Zero registros
  ausentes/alterados/extras, fontes órfãs, aliases conflitantes ou fontes duplicadas.
  Cópias JSON iguais ao banco e backup confirmado na mesma geração.
- [Auditoria de phishing 38747769926](https://github.com/kkroth0/thre4th-summary/actions/runs/38747769926):
  sucesso, `newsStorage: sqlite`, dez semanas/494 publicações recalculadas.
  Nenhum candidato privado inserido como reputação maliciosa. CT segue sem amostras.
- UI autenticada após o deploy: busca da notícia sobre UAC-0226 → evidências
  do evento → perfil do ator → um IP e sete hashes, todos com a publicação
  `blog.synapticsystems.de` como referência. Nenhum erro de console observado.
  Provas: `sqlite-news-event-production.png` e `sqlite-news-actor-production.png`.
  O carregamento inicial do feed mostrou o cache resumido antes de servir o acervo;
  este teste não mediu nem promete resolver toda a latência desse endpoint.
- A coleta de corpos continuou: 614 publicações com texto na primeira auditoria,
  615 na segunda. Os totais de eventos/publicações acima são do instante da migração.
- Auditorias adicionais `38748702598` e `38749246757` passaram, ainda na geração 1;
  a última leu o estado às 14:13:39 UTC. O último ciclo completo observado na
  auditoria de phishing `38748708553` ainda era o das 13:58 UTC, anterior ao deploy.
  Portanto, esta evidência confirma a migração/leitura e a retenção de novos corpos,
  mas ainda não confirma um ciclo completo de novas publicações após a troca.
- A verificação posterior
  [38750814400](https://github.com/kkroth0/thre4th-summary/actions/runs/38750814400)
  confirmou o primeiro ciclo concluído após a troca às **14:14:57 UTC**:
  68 ciclos completos e uma falha histórica, 833.951 ms, 264 fontes/192 saudáveis,
  40 buscas de textos/39 falhas, 506 corpos reaproveitados e 1.202 diferidos.
  A persistência funcionou; o tempo de aproximadamente 14 minutos e as falhas
  de corpos continuam uma pendência de desempenho/cobertura.
- [Auditoria 38751349854](https://github.com/kkroth0/thre4th-summary/actions/runs/38751349854),
  às **14:27:03 UTC**, após novo deploy/reinício: modo SQLite, geração **2**,
  **7.449 publicações e 4.989 eventos**. Cópias JSON iguais ao banco; nenhum
  registro ausente/alterado/extra, fonte órfã, alias conflitante ou fonte duplicada.
  O commit das 14:14:43 alterou 363 documentos; 808 revisões estavam retidas no
  total e 622 publicações tinham corpo. O reinício manteve a geração, sem repetir
  o commit. Export XLSX real posterior incluiu o hash da publicação UAC-0226.
- [Continuous Security Scan 38746976216](https://github.com/kkroth0/thre4th-summary/actions/runs/38746976216):
  Gitleaks aprovado; NPM Audit, Trivy e OSV continuam falhando, como no run anterior
  `38738880021`. Dependências e lockfiles não foram alterados nesta entrega;
  esses alertas existentes não foram corrigidos por esta migração.
