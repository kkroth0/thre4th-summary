# Desempenho da coleta e leitura de notícias

## Medição anterior à mudança

Auditoria somente leitura [38760766034](https://github.com/kkroth0/thre4th-summary/actions/runs/38760766034),
em 15/10/2026 às 15:29 UTC: geração 7, 7.494 publicações arquivadas e 5.022 eventos.

- Leitura validada do snapshot SQLite: 29.501 ms.
- Composição do feed: 695 ms; serialização: 513 ms; gzip: 992 ms.
- Resposta completa: 6.038 publicações, 9.520.378 bytes, 1.494.229 bytes gzip.
- EPSS local: 6.568 dos 6.665 CVEs, atualizado às 05:44 UTC; 97 ausentes.
- Cinco ciclos anteriores completos: 553.810–663.444 ms.
- Logs agregados: sem falha registrada do coletor/EPSS nessa janela; 231 respostas
  HTTP 403 ao buscar corpos. Essa indisponibilidade externa limita a extração.

O erro intermitente do navegador anterior não informou o status HTTP. Os números
acima identificam custos reais, mas não provam sozinhos a causa desse erro.

## Alterações

- Canonicalização calculada uma vez por transação. A comparação ainda verifica
  hashes, IDs, igualdade e relacionamentos antes de confirmar a publicação.
- Leitura verifica payloads, manifesto e relacionamentos sem refazer a mesma
  serialização/comparação. Publicações usam o resultado da transação confirmada;
  uma geração externa e a inicialização ainda exigem leitura validada do banco.
- Resposta HTTP do feed reutilizada para a mesma revisão, dono, preferências e
  filtros, limitada a oito entradas e 32 MiB de payload. Mudanças em arquivo,
  snapshot ao vivo ou eventos invalidam a projeção. Evidências não são truncadas.
- EPSS consulta o catálogo diário em worker, inclusive CVEs ainda ausentes do NVD.
  Somente valores faltantes/desatualizados chegam à API: lotes de 100, concorrência
  dois e orçamento remoto de 20 s com abort. Cache diário para resultados, uma
  hora para ausências e cinco minutos para falhas; scores antigos preservados
  como fallback. Ausência nunca vira zero.
- Ciclos registram tempos agregados por etapa, sem payloads privados ou segredos.
- Erro HTTP do frontend inclui o status para diagnóstico de uma nova ocorrência.

## Regressões

718 testes backend aprovados antes do caso adicional de integridade na leitura;
11 testes SQLite aprovados depois, incluindo rejeição de relações inválidas com
hash válido. TypeScript e lint do frontend alterado aprovados. Sem dependências novas.
As provas finais de CI/deploy, integridade e navegador serão registradas após a publicação.
