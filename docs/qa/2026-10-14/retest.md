# Correções e reteste dos fluxos — 13 e 14/10/2026

Ambiente: produção, sessão autenticada da conta do usuário. Este documento complementa a [auditoria original](../2026-10-13/audit.md), preservada como registro das falhas encontradas.

## Correções publicadas

- Versões de software e aliases genéricos deixam de criar IPs/famílias falsos. AiCloud `2.0.0.39`, Rails `8.1.3.1`, HTTP 404 e USB são controles de regressão; Mirai passa a ser identificado na notícia japonesa. Evidências antigas foram revisadas, com backup e histórico das observações retiradas.
- Busca de notícias usa também o arquivo permanente. CVE-2026-83943 aparece na interface, com publicação em 08/10 às 11:00 de Fortaleza.
- O lote busca contexto após persistir as respostas externas; contexto e exportações incluem as novas evidências recebidas. Resposta documentada de registro inexistente no VirusTotal/Shodan é ausência de dados, preservando erros reais de autenticação/limite.
- JSON de boletim preserva todos os IOCs, sem o limite de 40 linhas do gerador. Relatórios antigos incompletos foram reparados com o acervo. Boletins reutilizam corpo arquivado e anexos determinísticos antes da síntese.
- Data sem horário do C2Agent permanece 09/10 em Publicações salvas. Sugestões automáticas do semanal exigem data de publicação confiável; escolhas editoriais existentes permanecem salvas.
- Perfil de malware mostra também coocorrências de múltiplas famílias, identificadas como evidência por fonte, sem atribuir automaticamente propriedade/C2.
- Gerador agora limita tempo decorrido de cada chamada de IA, além do timeout HTTP, e ativa fallback. No worker, até 20 segundos por chamada deixa espaço dentro do limite de 240 segundos. Em timeout de renderização, um PPTX concluído só é recuperado após validar estrutura ZIP/CRC.
- Tabelas RSS preservam separação de células e elementos de código. A revisão das notícias antigas recuperou IPs concatenados a rótulos; o caso Patchstack passou de quatro para cinco IPs, incluindo `204.8.96.109`. Arquivo, evento e inventário foram reconciliados.
- ThreatFox usa até sete dias na primeira coleta e janela incremental com sobreposição nas seguintes. O limite anterior de 8 MB rejeitava a resposta válida de sete dias; esse conector aceita 32 MB. Falhas transitórias recebem nova tentativa com espera crescente, mantendo os dados existentes e os limites informados pelo fornecedor.
- O gerador distingue propriedades de código, nomes de arquivo e domínios. `readme.txt`, `u.id`, `wordpress.org` e endpoints concatenados a descrições deixaram de aparecer como IOCs falsos no novo boletim WordPress.

## Auditoria ampliada de persistência

Workflow [38485406714](https://github.com/kkroth0/thre4th-summary/actions/runs/38485406714), verificação em 13/10 às 23:39 UTC. Seleção aleatória estratificada de dez publicações e quatro controles fixos. Todas as 14 tinham zero indicadores extraídos ausentes no inventário. Essa comparação valida persistência, não a precisão semântica de todos os textos do catálogo.

| Publicação | IOCs extraídos / persistidos |
| --- | --- |
| The Tale of Two INC Ransom Notes / Huntress | 2 / 2 |
| Two Lures, One Operator / NetSupport RAT | 14 / 14 |
| Star Blizzard / RedFlick | 1 / 1 |
| Kimsuky CHM Tradecraft | 13 / 13 |
| Tencent game security Android | 1 / 1 |
| Neural Override AI Orchestrated RAT | 7 / 7 |
| Cisco alerta para SQL Injection / CISO Advisor | 0 / 0 |
| Cisco CVE-2026-76461 / SOCRadar | 0 / 0 |
| Siemens Reyrolle 7SR5 / CISA | 0 / 0 |
| ClingSTUN / IoT proxy nodes | 0 / 0 |
| ASUS AiCloud / NIC — regressão | 13 / 13, Mirai e duas CVEs vinculados |
| Patch Reliability / Qualys — regressão | 4 / 4, sem USBStealer |
| Azure API Center / MSRC — regressão | 0 / 0; CVE pesquisável |
| C2Agent / Unit 42 — controle | 36 / 36, incluindo 32 SHA256 |

Base naquele instante: 15.467 indicadores, 16.911 observações, 124 atores com vínculos e 584 entidades de malware. Reprocessamento de 100 publicações existentes: 2,304 segundos, com 5.532 eventos retidos. Os coletores preservaram os dados anteriores mesmo quando ThreatFox registrou erro temporário no ciclo mais recente.

## Reteste pela interface

Além da amostra acima, foram pesquisadas doze notícias: Huntress AI Slop, Akira, NEKOBYTE, Silent Ransom/Luna Moth, Patchstack WordPress XSS, Rapid7 Metasploit, Claroty License to Kill, Cisco NX-OS, AWS AI vulnerability harness, CERT.PL toll fraud, Qualys e AiCloud. Os controles de aliases não reapareceram nas respectivas linhas.

O lote foi executado com quatro IPs e dois hashes reais de notícias. Após repetir uma consulta OTX que recebeu 502, terminou **6/6, zero falhas e zero parciais**. JSON final: `threatsumm4ry-bulk-2026-10-13T23-42-23-701Z.json`, na pasta Downloads. CSV também conferido: seis registros, incluindo campos extensos com respostas e contexto.

| Indicador | Fontes consultadas | Evidências no export | Publicações |
| --- | --- | --- | --- |
| 154.81.156.10 | 6 | 27 | 1 |
| 217.15.164.147 | 6 | 11 | 1 |
| 64.227.4.134 | 6 | 9 | 1 |
| 147.90.235.22 | 6 | 55 | 1 |
| 1f1bb322…600b600fba | 5 | 7 | 1 |
| d0083331…00bc3a4 | 5 | 9 | 1 |

Todas as 34 respostas de fonte incluem `rawPayload`; contexto sem erros. IPs consultaram geolocalização, VirusTotal, AbuseIPDB, OTX, Shodan e ThreatFox. Hashes consultaram VirusTotal, OTX, URLhaus, MalwareBazaar e ThreatFox. Ausência de dados permanece explícita, sem inventar resultados.

Akira: perfil abriu pelo vínculo da notícia; IP `64.227.4.134` tinha quatro referências — três pulsos OTX e a publicação Huntress. A notícia foi salva e permaneceu em Publicações salvas. NjRAT: o perfil passou a apresentar `217.15.164.147` na tabela; abrir o IP mostrou o pulso OTX `EbeeJuly2026 Pt2`. Isso reproduz o caso de coocorrência que faltava na auditoria original.

ThreatFox → inventário → malware: o novo IP `31.77.226.238`, observado em 14/10 às 14:44:55 UTC, aparece no inventário com AdaptixC2. O vínculo abre o perfil da família; a tabela contém o mesmo IP e a referência original `https://threatfox.abuse.ch/ioc/1964059/`. Prova: `threatfox-malware-browser.png`.

Patchstack → inventário → CVEs: `204.8.96.109` aparece com a publicação de 06/10, fonte Patchstack e vínculos para CVE-2026-93836 e CVE-2026-94504. Prova: `wordpress-ip-cves-browser.png`. A validação também encontrou que “Investigar indicador” abria a rota com `query`, mas não iniciava a consulta; a correção passa a consumir esse parâmetro uma vez por navegação, aguardando as preferências de fontes.

Após o deploy `2265902`, esse mesmo clique iniciou a consulta automaticamente. AbuseIPDB retornou 123 relatos; VirusTotal 7/92 detecções; OTX 44 pulsos; Shodan nove portas; ThreatFox indicou ausência de dados. Ao recarregar a base (evitando o cache de 30 segundos da navegação), o indicador tinha **49 evidências** e fontes **AbuseIPDB, IP Geolocation, OTX, Shodan, VirusTotal e news**. A publicação e as respostas externas permaneceram na mesma entrada. Provas: `ioc-pivot-enriched-browser.png` e `ioc-persisted-enrichment-browser.png`.

Semanal em 14/10: revisão 43, atualização automática ativa, 25 candidatos gerais e 25 de IA, nenhum candidato geral com data inferida. As dez notícias e cinco de IA já escolhidas permaneceram salvas. Seleções históricas por coleta continuam visíveis por terem sido escolhas anteriores; não são novas recomendações automáticas.

JSON do boletim histórico C2Agent baixado novamente em 14/10: **32/32 hashes esperados, zero ausentes**, com 46 linhas totais preservando indicadores adicionais da síntese. A conferência compara diretamente com o arquivo de controle dos 32 hashes.

## Validação e deploy

- Plataforma `f0b3563`: CI [38584682179](https://github.com/kkroth0/thre4th-summary/actions/runs/38584682179), VPS [38584947704](https://github.com/kkroth0/thre4th-summary/actions/runs/38584947704) e Pages [38584949270](https://github.com/kkroth0/thre4th-summary/actions/runs/38584949270) concluídos. **637 testes backend e 247 frontend** passaram, além de lint, typecheck e build. Inclui recuperação de tabelas, coletores incrementais e correção das datas de exportação.
- Atalho de investigação `2265902`: CI [38588643453](https://github.com/kkroth0/thre4th-summary/actions/runs/38588643453), VPS [38588842652](https://github.com/kkroth0/thre4th-summary/actions/runs/38588842652) e Pages [38588842089](https://github.com/kkroth0/thre4th-summary/actions/runs/38588842089) concluídos; clique e persistência retestados em produção.
- Gerador `1663c93`: **285 testes** passaram; CI [38580374934](https://github.com/kkroth0/bd-ppt-generator-cti/actions/runs/38580374934) e VPS [38580590405](https://github.com/kkroth0/bd-ppt-generator-cti/actions/runs/38580590405) concluídos. Inclui paginação completa, timeout decorrido e sanitização de artefatos.
- Diagnóstico de produção [38586897499](https://github.com/kkroth0/thre4th-summary/actions/runs/38586897499): revisão `news-table-v13` concluída às 15:03:17 UTC, cinco IPs Patchstack armazenados e os quatro coletores prontos. Na interface, ThreatFox, MalwareBazaar, AbuseIPDB e OTX mostravam “coleta ativa”; inventário com 19.516 indicadores naquele momento.
- A varredura de dependências da plataforma continua com a falha preexistente (49 alertas). Este reteste funcional não equivale a aprovação de segurança das dependências.

## Limites da validação

Fontes externas podem retornar ausência, 502, limites ou bloqueio de coleta. O reteste comprova os fluxos e controles desta amostra; não prova extração perfeita de toda página nem atribuição exclusiva de infraestrutura. Aliases e coocorrências exigem revisão contextual. A persistência de todos os valores não certifica que todos sejam IOCs maliciosos.

## Novas gerações reais em 14/10

- C2Agent: criado às 13:57:54 UTC, concluído às 14:01:02 UTC (189 segundos incluindo espera na fila). O log confirmou timeout de 20 segundos no DeepSeek, 429 no Qwen e uso do fallback Gemini. JSON novamente conferido: 32/32 hashes, zero ausentes. PDF e PowerPoint foram baixados; 13 páginas/slides e ZIP/XML íntegros. A revisão visual da capa e das três páginas de IOCs revelou que a tabela visual ainda aplicava 40 linhas: o corte também foi removido no gerador `c3add25`, com teste de renderização mantendo 32 hashes após 12 URLs.
- WordPress XSS / Patchstack: a primeira geração (191 segundos incluindo fila) revelou ruído de código e a diferença entre cinco IPs do documento e quatro do RSS arquivado. Ambos os problemas foram corrigidos e retestados: o novo JSON `SRR - Surface Risk Report - Four ways back in the WordPress XSS campaign that hides its own admin account.json` contém **26 indicadores/artefatos, os cinco IPs e ambas as CVEs**, sem `readme.txt`, `u.id`, `wordpress.org` nem os endpoints concatenados identificados. A notícia e o inventário também contêm o quinto IP. Prova: `wordpress-clean-browser.png`.
- Exportação por período: download de notícias e IOCs em JSON funcionou, mas a mudança manual de data ficava só no campo e a exportação usava a data anterior. Corrigido em `77d3efb`, sincronizando o evento nativo de entrada, com typecheck e CI aprovados. Reteste após deploy registrado a seguir.
- C2Agent após a paginação completa: criado às 14:10:06 UTC, concluído às 14:13:57 UTC (231 segundos incluindo fila e um deploy da plataforma). JSON, PPTX e PDF foram baixados novamente. **32/32 hashes em cada formato**, zero ausentes. PowerPoint íntegro, 12 slides; PDF legível, 12 páginas. As três páginas de IOCs foram renderizadas e inspecionadas, incluindo os quatro hashes que antes faltavam. Provas: `c2agent-complete-browser.png` e `c2agent-full-iocs-9.png` a `c2agent-full-iocs-11.png`.
- Exportação após deploy: alterar ambas as datas para 06/10–12/10 produziu nomes e intervalo corretos em notícias e IOCs. Intervalo UTC dos dias completos de Fortaleza: `2026-10-06T03:00:00.000Z` até `2026-10-13T02:59:59.999Z`. JSON: 937 publicações e 377 registros de IOCs. Arquivos: `threatsumm4ry-news-2026-10-06-2026-10-12.json` e `threatsumm4ry-iocs-2026-10-06-2026-10-12.json`, em Downloads.
- Após o deploy, o feed carregou normalmente com 4.652 sinais e atualização às 11:14 de Fortaleza. Worker e site ativos, `NRestarts=0`, `ExecMainStatus=0`; os três novos trabalhos constam como concluídos, sem erro.
