# Axur: importação privada de IOCs e relatórios

Em Configurações → Chaves de API, salvar uma chave Axur inicia a carga para
a conta premium autenticada. A chave usa o armazenamento cifrado existente.
Não existe chave Axur compartilhada nem evidência Axur global.

O cliente só permite GET nos caminhos `/cyber-iocs/v2/iocs` e
`/cyber-insights/v1/insights/bulk/search`. São endpoints não documentados no
OpenAPI fornecido; paginação e formato foram verificados em 20/10/2026.
Uma mudança no contrato interrompe a página, sem avançar o marcador.
Não cria buscas, exportações, tickets ou alterações no ambiente Axur.

A leitura começa com páginas de 5.000 IOCs, até cinco por rodada, sem concorrência
entre importações. A política `latency-v2` permite até 240 segundos por consulta
de IOCs em segundo plano; relatórios mantêm limite de 55 segundos. A referência
`enriquecimento-de-iocs/axur.py` também usa 240 segundos e recomenda consultas
sequenciais. Não é um SLA da Axur: a margem evita cancelar respostas da fonte
que as medições mostraram próximas do limite antigo de 55 segundos.

Timeouts e falhas de rede não reduzem mais o lote. Na migração, lotes antigos de
100 ou 500 limitados por latência voltam a 1.000. Após três páginas bem-sucedidas,
o tamanho pode crescer na sequência 100 → 500 → 1.000 → 5.000. Se a posição não
estiver alinhada com o novo tamanho, relê-se uma faixa anterior, mas só a parte
ainda não comprometida é gravada e contada. O marcador preserva essa posição
mesmo se houver interrupção após uma gravação parcial.

Apenas a violação real do limite de 32 MiB da resposta reduz o lote e define um
teto para seu crescimento. Respostas de autenticação ou limite de chamadas
preservam sua espera. A correção não introduz consultas paralelas à Axur.
Os relatórios são agrupados em lotes de até 25 IDs únicos. Um cache privado de
24 horas, vinculado à credencial, evita consultar novamente os mesmos relatórios
entre páginas e reinícios. Guarda apenas os campos necessários à correlação.
Atores, famílias e CVEs de um relatório compartilhado são resolvidos uma vez
por página; a evidência de cada IOC continua sendo persistida individualmente.
O agendador tenta a cada minuto; consultas e ingestões cedem o processo
entre lotes. Falhas usam espera crescente
e respeitam Retry-After até 24 horas. A carga pausa se houver menos de 2 GiB livres.

O marcador registra a categoria e a etapa da falha, a próxima tentativa e os
tempos de consulta de IOCs, consulta de relatórios, conversão e gravação por
página. A etapa atual fica visível enquanto o lote está sendo processado;
o contador só avança após a persistência. Mensagens não contêm credenciais nem
respostas completas da fonte.
Relatórios ausentes ainda impedem o avanço da página para preservar os vínculos.

O marcador `axur-import-v1:<owner>` está em `intelligence_state` no SQLite
existente, preservado pelo deploy. Só avança depois de persistir todos os IOCs
válidos da página e os relatórios relacionados. Repetir uma página é idempotente.
Os contadores medem registros/evidências processados, não novos IOCs únicos.
Registros inválidos são contabilizados separadamente. Remover a chave interrompe
novas leituras, preservando os dados já importados e o marcador de retomada.

As observações guardam a fonte original, o identificador Axur, datas, confiança,
descrição, rótulo de detecção, técnicas MITRE e referências. Um rótulo genérico de
antivírus não cria uma família de malware. Atores e malwares estruturados nos
relatórios usam a identidade do catálogo quando houver correspondência exata;
os demais recebem identidade Axur. As relações do relatório são `mentioned-with`,
sem promover coocorrência a atribuição confirmada. CVEs mantêm seus IDs originais.
Conteúdo completo não necessário e todos os IOCs de um relatório não são
replicados em cada observação.

A paginação é por deslocamento sobre uma base viva, sem snapshot ou cursor
documentado. Uma varredura concluída não garante um retrato transacional de todos
os registros: a origem pode mudar durante a leitura. Não se deve apresentar o
contador como cobertura integral ou como número de fontes independentes: a Axur
também redistribui indicadores de fontes como MalwareBazaar e URLhaus.

O escopo inicial é uma varredura completa, retomável. Atualização incremental após
a conclusão e consulta Axur por IOC no enriquecimento em lote são etapas separadas;
os dados já persistidos ficam disponíveis pelos fluxos existentes de correlação.

O workflow manual **Axur import audit**, com login GitHub, verifica em modo
somente leitura a persistência, deduplicação, vínculos de entidades e ausência de
observações globais. Só imprime contagens e marcador; não imprime chaves ou IOCs.
