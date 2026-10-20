# Threat Hunting — validação de entrega

## Escopo

Dashboard `/hunting`, com hipótese prioritária, outras caças, recortes diário/semanal/mensal, consulta KQL, insumos, MITRE e retorno simples de utilidade. Catálogo inicial de 1.258 consultas únicas dos três repositórios solicitados, mantendo licença, commit e URL original.

## Verificação local

- Backend: 843 testes aprovados, incluindo seleção com o catálogo real, isolamento de feedback por usuário, persistência após reiniciar o serviço, orçamento de IA, cache, deduplicação e atribuição exata de KEV/EPSS por CVE.
- Frontend: 264 testes aprovados; TypeScript aprovado; build aprovado. Lint sem erros, com 16 avisos já existentes. O projeto não relacionado `transforma-mobile/`, não versionado, foi excluído da execução local de lint.
- Navegador: interface real com serviço real e insumos sintéticos em servidor local separado. Hoje, Semana e Mês alteram o recorte; a investigação abre KQL e licença/commit; os insumos mostram hora e ligação para o evento. O retorno Sim persistiu após recarregar e alterou a prioridade sem exigir formulário adicional.
- Botão Copiar KQL exibiu confirmação; leitura pela API de clipboard do navegador integrado retornou vazia, portanto não foi usada como prova de igualdade do clipboard. O manipulador passa o texto original ao clipboard, sem reformatação.
- Console do fluxo local sem erros.

## Limites da verificação

As consultas não foram executadas contra um ambiente Sentinel/Defender. As tabelas e técnicas importadas dependem da qualidade dos repositórios; somente técnicas explícitas comuns aos insumos e ao catálogo são mostradas como mapeamento. IA ordena/descreve candidatos e não substitui a KQL. Feedback influencia recomendações futuras; não treina pesos.

## Publicação

Implementação inicial: `9113571`; correção de metadados: `c206809`; seleção com termos específicos e ajuste da geração: `745f827`; restrição por CVE/tecnologia/comportamento: `21ab7f0`; respeito às escolhas da IA: `4a03327`.

O teste inicial em produção encontrou associação indevida entre uma notícia de Atlassian e KQL de AsyncRAT, motivada por palavras genéricas. O filtro agora exige cobertura dos termos principais, tecnologias citadas e âncoras específicas; consultas de CVEs conhecidas precisam citar uma CVE presente no insumo. Os casos reais viraram regressões automatizadas. A IA não devolve ao painel os candidatos que descartou.

A auditoria inicial confirmou resposta HTTP 200 do DeepSeek, porém `finish_reason=length` e JSON incompleto no limite de 3.500 tokens; a geração passou a usar esforço baixo e limite de 6.000 tokens. A segunda auditoria no VPS retornou HTTP 200, `finish_reason=stop`, 4.957 tokens totais de conclusão e sete escolhas válidas. Ela leu 251 publicações, sem alterar banco de produção ou preferências do usuário. A seleção foi refinada novamente após revisar os títulos e insumos desse diagnóstico.

A detecção de segredos passou após corrigir um falso positivo em texto público do catálogo. A exceção histórica em `.gitleaksignore` identifica apenas o commit/regra/arquivo/linha daquele achado; o novo catálogo e os commits seguintes continuam sendo analisados.

A auditoria final no VPS (`39449050550`) passou com 264 publicações, oito candidatos sustentados (ransomware, APT28, ClickFix, phishing e quatro verificações de exposição), HTTP 200, `finish_reason=stop` e oito escolhas válidas em 1.743 tokens de conclusão. Os exemplos de OpenSSL/WMIC/AsyncRAT indevidos não apareceram mais. O processamento sem cache mediu 3.993 ms nesse VPS; o painel reaproveita o resultado por cinco minutos e a resposta de IA por período/cache de insumos.

CI `39448148316`, publicação da API `39448666656` e publicação Pages `39448666466` concluídos com sucesso. O log do VPS confirmou `RELEASE_SHA=4a0332774dec01a1bf0b106ed2cf3c432379abf3`.

Na conta autenticada de produção, Hoje exibiu “Priorização por IA”, oito hipóteses e 264 publicações. A hipótese de APT28 abriu a KQL original, o commit BSD-3-Clause, três notícias com data/hora, dois eventos distintos e o vínculo para o perfil `G0007`; as duas notícias da mesma campanha mantiveram o mesmo evento. O atalho Phishing abriu diretamente a aba MITRE com T1566 e telemetria EmailEvents. Em tela estreita, largura do documento e rolagem mediram ambas 380 px; a alteração temporária de viewport foi restaurada.

Mês carregou oito hipóteses com “Priorização por IA”, três técnicas e 350 publicações processadas dos últimos 30 dias. Semana carregou o recorte de sete dias, 350 publicações e quatro técnicas; nessa chamada a IA ficou indisponível e o painel manteve a priorização local com o status correspondente. A causa dessa chamada específica não foi determinada nesta validação. A recuperação limita o trabalho às 350 publicações mais relevantes de cada janela.

O navegador integrado não conseguiu gerar a captura de produção após a verificação responsiva. A validação final usou o conteúdo renderizado e os estados dos controles; a aba publicada foi mantida aberta como entrega, e nenhum arquivo de imagem inexistente foi incluído como evidência.

O workflow separado de segurança continua falhando em alertas de dependências preexistentes (49 no push: 1 crítico, 24 altos, 18 moderados e 6 baixos). Esta entrega não altera dependências.
