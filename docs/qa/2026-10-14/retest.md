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

Semanal em 14/10: revisão 43, atualização automática ativa, 25 candidatos gerais e 25 de IA, nenhum candidato geral com data inferida. As dez notícias e cinco de IA já escolhidas permaneceram salvas. Seleções históricas por coleta continuam visíveis por terem sido escolhas anteriores; não são novas recomendações automáticas.

JSON do boletim histórico C2Agent baixado novamente em 14/10: **32/32 hashes esperados, zero ausentes**, com 46 linhas totais preservando indicadores adicionais da síntese. A conferência compara diretamente com o arquivo de controle dos 32 hashes.

## Validação e deploy

- Plataforma `ddbc6d9`: CI [38485008234](https://github.com/kkroth0/thre4th-summary/actions/runs/38485008234), VPS [38485105560](https://github.com/kkroth0/thre4th-summary/actions/runs/38485105560) e Pages [38485105432](https://github.com/kkroth0/thre4th-summary/actions/runs/38485105432) concluídos. 633 testes backend e 247 frontend passaram, além de lint, typecheck e build.
- Gerador `f9025bf`: 282 testes passaram; CI [38575931095](https://github.com/kkroth0/bd-ppt-generator-cti/actions/runs/38575931095) e VPS [38576109510](https://github.com/kkroth0/bd-ppt-generator-cti/actions/runs/38576109510) concluídos.
- A varredura de dependências da plataforma continua com a falha preexistente. Ela não é uma aprovação de segurança deste teste funcional.
- Paginação completa `c3add25`: CI [38577508959](https://github.com/kkroth0/bd-ppt-generator-cti/actions/runs/38577508959) e VPS [38577728784](https://github.com/kkroth0/bd-ppt-generator-cti/actions/runs/38577728784) concluídos.
- Datas da exportação `77d3efb`: CI [38577811688](https://github.com/kkroth0/thre4th-summary/actions/runs/38577811688), VPS [38578052150](https://github.com/kkroth0/thre4th-summary/actions/runs/38578052150) e Pages [38578052152](https://github.com/kkroth0/thre4th-summary/actions/runs/38578052152) concluídos.

## Limites da validação

Fontes externas podem retornar ausência, 502, limites ou bloqueio de coleta. O reteste não prova extração perfeita de toda página nem atribuição exclusiva de infraestrutura: aliases e coocorrências exigem revisão contextual. A notícia Patchstack conserva quatro IPs do corpo armazenado; há uma diferença potencial com a tabela atual do editor, a verificar em próxima coleta integral.

A ampliação do teste encontrou ruído adicional no boletim WordPress: `readme.txt` e a propriedade de código `u.id` apareceram como domínios, e alguns endpoints vieram concatenados a descrições da tabela. Esse ponto não está aprovado semanticamente neste reteste e requer revisão do extrator de artefatos do gerador. A persistência de todos os valores não certifica que todos sejam IOCs maliciosos.

## Novas gerações reais em 14/10

- C2Agent: criado às 13:57:54 UTC, concluído às 14:01:02 UTC (189 segundos incluindo espera na fila). O log confirmou timeout de 20 segundos no DeepSeek, 429 no Qwen e uso do fallback Gemini. JSON novamente conferido: 32/32 hashes, zero ausentes. PDF e PowerPoint foram baixados; 13 páginas/slides e ZIP/XML íntegros. A revisão visual da capa e das três páginas de IOCs revelou que a tabela visual ainda aplicava 40 linhas: o corte também foi removido no gerador `c3add25`, com teste de renderização mantendo 32 hashes após 12 URLs.
- WordPress XSS / Patchstack: criado às 13:59:23 UTC, concluído às 14:02:34 UTC (191 segundos incluindo fila). Tipo vulnerabilidade, ambas as CVEs mencionadas e 34 indicadores/artefatos no JSON; PDF e PowerPoint disponíveis. O boletim inclui também `204.8.96.109`, ausente da extração armazenada na notícia. Portanto, a comparação de persistência continua distinta da comparação com o texto integral.
- Exportação por período: download de notícias e IOCs em JSON funcionou, mas a mudança manual de data ficava só no campo e a exportação usava a data anterior. Corrigido em `77d3efb`, sincronizando o evento nativo de entrada, com typecheck e CI aprovados. Reteste após deploy registrado a seguir.
- C2Agent após a paginação completa: criado às 14:10:06 UTC, concluído às 14:13:57 UTC (231 segundos incluindo fila e um deploy da plataforma). JSON, PPTX e PDF foram baixados novamente. **32/32 hashes em cada formato**, zero ausentes. PowerPoint íntegro, 12 slides; PDF legível, 12 páginas. As três páginas de IOCs foram renderizadas e inspecionadas, incluindo os quatro hashes que antes faltavam. Provas: `c2agent-complete-browser.png` e `c2agent-full-iocs-9.png` a `c2agent-full-iocs-11.png`.
- Exportação após deploy: alterar ambas as datas para 06/10–12/10 produziu nomes e intervalo corretos em notícias e IOCs. Intervalo UTC dos dias completos de Fortaleza: `2026-10-06T03:00:00.000Z` até `2026-10-13T02:59:59.999Z`. JSON: 937 publicações e 377 registros de IOCs. Arquivos: `threatsumm4ry-news-2026-10-06-2026-10-12.json` e `threatsumm4ry-iocs-2026-10-06-2026-10-12.json`, em Downloads.
- Após o deploy, o feed carregou normalmente com 4.652 sinais e atualização às 11:14 de Fortaleza. Worker e site ativos, `NRestarts=0`, `ExecMainStatus=0`; os três novos trabalhos constam como concluídos, sem erro.
