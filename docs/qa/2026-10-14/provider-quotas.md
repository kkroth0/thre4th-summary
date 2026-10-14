# Cotas das fontes — 14/10/2026

Fontes de Dados recebeu uma tabela com saldo diário, saldo mensal/créditos, consumo, limite, renovação e última leitura. O botão Atualizar consulta os saldos novamente, com cache e limite de frequência para evitar chamadas repetidas.

## Saldos e unidades

- VirusTotal: janelas diária e mensal retornadas por `overall_quotas`. Não se calcula o saldo mensal multiplicando o diário. [Documentação oficial](https://docs.virustotal.com/docs/consumption-quotas-handled).
- Shodan: créditos de pesquisa mensais retornados por `api-info`, distintos de consultas de host. Renovação só aparece se informada. [Documentação oficial](https://developer.shodan.io/api).
- urlscan.io: pesquisas por minuto, hora e dia; nenhuma cota mensal é inventada. A chave pessoal do monitoramento tem preferência. [Documentação oficial](https://urlscan.io/docs/api/#rate-limiting).
- AbuseIPDB: consultas de IP, CIDR e blacklist têm saldos independentes. Os headers são capturados nas chamadas reais e nos erros 429, persistidos por credencial/operação e invalidados na renovação. Respostas do cache não sobrescrevem o saldo atual. [Documentação oficial](https://docs.abuseipdb.com/#api-daily-rate-limits).
- Who.is: saldo do bucket que financiou a chamada, que pode conter franquia mensal ou créditos comprados. Não se atribui uma renovação mensal a créditos que podem não expirar. [Documentação oficial](https://who.is/docs/api#rate-limit-headers).
- Outras integrações: saldo não consultável identificado explicitamente; ausência de informação não significa acesso ilimitado.

## Validação

- 644 testes backend passaram localmente. Cobrem janelas separadas, virada de dia/mês, reset em epoch convertido para ISO, saldo zero, credenciais isoladas, persistência após reiniciar o leitor, erros sem exposição de credenciais, cache e chamadas concorrentes.
- Typecheck e lint dos arquivos frontend alterados passaram.
- CI [38634847008](https://github.com/kkroth0/thre4th-summary/actions/runs/38634847008) aprovado para `f94b6d4`.
- Duas tentativas iniciais do deploy restauraram a versão anterior porque o backend não respondeu durante a janela curta de inicialização. O diagnóstico não registrou exceção da aplicação. `0ca51ea` ampliou a espera com limite definido e interrupção se o serviço falhar, preservando healthcheck e rollback. CI [38636229420](https://github.com/kkroth0/thre4th-summary/actions/runs/38636229420), VPS [38636413710](https://github.com/kkroth0/thre4th-summary/actions/runs/38636413710) e Pages [38636413719](https://github.com/kkroth0/thre4th-summary/actions/runs/38636413719) concluídos.
- A varredura de dependências mantém os alertas preexistentes; este registro valida a funcionalidade de cotas.

## Reteste autenticado em produção

Na sessão do usuário, a tela carregou os saldos reais. Em seguida foram executadas consultas de IP (`8.8.8.8`), CIDR (`8.8.8.0/24`) e WHOIS (`example.com`), e o botão Atualizar foi acionado novamente.

Leitura final em 14/10 às 18:03 de Fortaleza:

| Fonte/operação | Restante | Usado / limite | Janela |
| --- | ---: | ---: | --- |
| VirusTotal API | 489 | 11 / 500 | diária |
| VirusTotal API | 15.319 | 181 / 15.500 | mensal |
| Shodan, chave pessoal | 100 | 0 / 100 | créditos de pesquisa mensais |
| urlscan.io, chave pessoal | 980 | 20 / 1.000 | diária de pesquisa |
| urlscan.io | 120 | 0 / 120 | minuto |
| urlscan.io | 1.000 | 0 / 1.000 | hora |
| AbuseIPDB check | 991 | 9 / 1.000 | diária de IP |
| AbuseIPDB check-block | 98 | 2 / 100 | diária de CIDR |
| Who.is | 488 | 12 / 500 | bucket de créditos informado |

As duas janelas VirusTotal diminuíram após as consultas de teste; o refresh refletiu os novos saldos. A consulta CIDR não sobrescreveu o saldo de IP do AbuseIPDB. Coleta/blacklist ainda aguardava uma nova chamada real; a tela não inventou seu saldo. Who.is não informou renovação, e o urlscan.io não informou franquia mensal; ambas as ausências ficaram explícitas.

O teste inicial de CIDR `/32` sinalizou fonte indisponível; o `/24` retornou uma observação e confirmou o saldo da operação. Este registro não valida todos os formatos de resposta CIDR do fornecedor.

Prova visual: [provider-quotas-browser.png](provider-quotas-browser.png). A página Fontes de Dados foi mantida aberta para revisão; a aba temporária de consultas foi fechada.
