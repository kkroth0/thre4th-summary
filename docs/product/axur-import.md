# Axur: importação privada de IOCs e relatórios

Em Configurações → Chaves de API, salvar uma chave Axur inicia a carga para
a conta premium autenticada. A chave usa o armazenamento cifrado existente.
Não existe chave Axur compartilhada nem evidência Axur global.

O cliente só permite GET nos caminhos `/cyber-iocs/v2/iocs` e
`/cyber-insights/v1/insights/bulk/search`. São endpoints não documentados no
OpenAPI fornecido; paginação e formato foram verificados em 20/10/2026.
Uma mudança no contrato interrompe a página, sem avançar o marcador.
Não cria buscas, exportações, tickets ou alterações no ambiente Axur.

A leitura usa páginas de 5.000 IOCs, até cinco por rodada, sem concorrência
entre importações, e agrupa os relatórios em lotes de até 25 IDs únicos por
página. O agendador tenta a cada minuto; consultas e ingestões cedem o processo
entre lotes. Requisições têm limite de 55 segundos. Falhas usam espera crescente
e respeitam Retry-After até 24 horas. A carga pausa se houver menos de 2 GiB livres.

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
