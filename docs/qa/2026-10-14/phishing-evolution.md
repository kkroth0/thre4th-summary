# Phishing: primeira entrega do plano de evolução

## Escopo

Tendências semanais auditáveis, histórico de saúde da coleta, vereditos separados
do estado operacional e candidatos privados no SQLite do inventário. Detalhes e
limites em `docs/product/phishing-evolution.md`. Não é a migração integral do
arquivo/stories, um stream próprio de CT ou correlação semântica PT/EN.

## Verificação automatizada

O CI final do código `2650f04` aprovou **683 testes backend**, TypeScript,
testes frontend e build. Lint: zero erros, 16 avisos. Nenhuma dependência foi
adicionada ou alterada. A checagem dos arquivos preparados para commit não
encontrou correspondências com as sete credenciais configuradas.

Cobertura nova: evento único por semana/dimensão; campanhas distintas não unem
eventos; semanas UTC de domingo; datas inferidas/futuras; versões e histórico
insuficientes; persistência após reinício; membros e correções de IDs; ciclos
idempotentes; conta/perfil; candidatos não inseridos como IOCs maliciosos;
dispensas antigas sem veredito; falha de escrita JSON; vereditos inconclusivos;
rechecks DNS sem duplicar revisões; backfill sem continuidade da coleta; CT sem
fallback de emissão, wildcard ou precisão operacional inventada.

## Conferência em produção

O primeiro deploy revelou uma entrada nula em `campaigns` no arquivo legado,
que impedia construir o snapshot. A auditoria reproduziu o TypeError no servidor;
o normalizador passou a ignorar entradas sem nome e um teste de regressão cobre
esse caso. A API anterior de notícias/campanhas continuou respondendo.

Após a correção, o dashboard autenticado apresentou a semana fechada iniciada em
04/10/2026 com **80 eventos e 40 domínios de fontes**. São observações do arquivo,
não um total de ataques. A semana iniciada em 11/10 apareceu como parcial.
A revisão final também condiciona percentuais a oito semanas comparáveis com
coleta observada nos sete dias, sem considerar backfill prova de continuidade.

No Monitoramento de domínios, foi selecionado o perfil existente e executada uma
busca real das marcas já configuradas. A rodada terminou sem novos candidatos;
histórico, positivos e negativos permaneceram em zero e precisão desconhecida.
Não foram criados candidatos nem vereditos sintéticos em produção. A seleção
anterior do perfil (vazia) foi restaurada após a conferência. O caminho com
candidato, publicação correspondente e veredito inconclusivo foi verificado no
smoke test com servidor real e dados isolados.

## Limitações observadas

- O backtest não pode concluir antecedência ou precisão sem amostras rotuladas
  suficientes. O avaliador offline e a auditoria limitada estão disponíveis.
- A abertura direta do recurso JSON foi substituída por download autenticado
  dentro da plataforma. Reteste em 15/10 confirmou o arquivo da semana de 04/10:
  85 publicações/membros e 80 eventos distintos. Ver
  `../2026-10-15/phishing-evidence-download.md`.
- O workflow Continuous Security Scan continua falhando em alertas anteriores
  de dependências. CI funcional e publicação são verificações distintas.
- Saúde histórica começa nesta entrega. Dados anteriores sem disponibilidade
  de corpo registrada são desconhecidos, não falhas presumidas.
