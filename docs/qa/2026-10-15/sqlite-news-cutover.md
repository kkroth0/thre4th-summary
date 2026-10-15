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

Resultados de CI, deploy e auditorias serão registrados após execução real.
