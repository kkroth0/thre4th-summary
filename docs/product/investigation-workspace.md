# Workspace de investigação

Estado implementado em 12/10/2026. Documentos de planejamento anteriores que mencionam Censys, Team Cymru, Hybrid Analysis, MetaDefender, CIRCL hashlookup ou Pulsedive não descrevem mais as integrações disponíveis.

## Navegação e enriquecimento

O workspace usa uma lateral de 224 px, recolhível para 56 px. A consulta em `/analyzer` abre diretamente o indicador; múltiplos indicadores têm abas individuais.

Domínios possuem Resumo e fontes, Subdomínios, DNS e WHOIS. Os subdomínios preservam as observações estruturadas do Shodan, com paginação; DNS é a resolução atual. WHOIS usa `GET https://api.who.is/v1/whois/{domain}` com Bearer no backend, cache de 30 minutos, data do snapshot e sem solicitar o refresh pago `live=true`.

CIDR IPv4 usa AbuseIPDB como base: `/api/abuseipdb/check-block` retorna os endereços com relatos nos últimos 90 dias. O bloco é normalizado, dividido visualmente em subblocos /24 e paginado por aritmética, sem expandir todos os IPs ou consultá-los individualmente. Shodan só é consultado quando o usuário escolhe o complemento, com limite de 100 serviços e sem validação TCP ativa. Ausência de relatos ou observações não é uma confirmação de segurança.

## Notícias e indicadores

`/newsletter` reúne Publicações, IPs e Domínios. As listas de indicadores usam os IOCs de cada publicação, deduplicam o indicador e preservam links das fontes. Atores e malware de um evento agregado não são herdados automaticamente por todas as fontes. É possível abrir a publicação a partir da evidência ou investigar o indicador no enriquecimento. Não se infere uma resolução IP/domínio a partir de mera coocorrência textual.

## Malware

`/malware` reúne o catálogo público de famílias, aliases e plataformas do Malpedia e os metadados de amostras do MalwareBazaar. Não há download nem execução de binários.

- Malpedia: catálogo público `/api/get/families`, sem chave, cache de 24 horas com fallback explicitamente marcado como desatualizado.
- MalwareBazaar: Auth-Key pessoal ou da plataforma; operações `get_recent` (100 amostras), `get_siginfo` (até 100 por assinatura) e `get_info` por hash. Cache de três minutos separado pela credencial.
- IPs e hosts: evidências do acervo de notícias que identificam uma única família de forma inequívoca. Aliases ambíguos e publicações com várias famílias não atribuem seus IOCs a todas elas.
- Contagens representam a cobertura consultada e o acervo local; não representam a telemetria total de um provedor nem confirmam função de C2. Fonte indisponível é diferente de fonte consultada sem resultado.

As rotas `/api/malware/families`, `/api/malware/family?id=...` e `/api/malware/sample/:hash` mantêm o controle de acesso do produto. Caches no frontend são separados por conta. O campo BYOK `abuse_ch` cifra a chave por usuário e tem prioridade no MalwareBazaar, ThreatFox e URLhaus.

## Phishing e monitoramento de domínios

`/phishing-analyzer` abre o dashboard de tendências: publicações por mês, técnicas, setores, regiões, marcas e MITRE citado/inferido. Os recortes são aplicados ao conjunto consultado, incluindo a exportação existente. Campanhas e análise de e-mail permanecem acessíveis.

Caça a domínios e tickets ficam em `/domain-monitoring`. Links antigos `?view=hunt` e `?view=tickets` são redirecionados. O monitoramento continua usando urlscan.io e os perfis da organização.

OpenPhish, PhishStats e PhishTank são integrações de reputação sob demanda no enriquecimento. Não são coletores de campanhas do dashboard. PhishStats usa `https://api.phishstats.info/api/phishing` com `X-API-Key`, cache de 90 minutos e recorte de até 100 candidatos, limitado a cinco correspondências exatas. OpenPhish compara URLs exatas ou limites de hostname, evitando falsos matches de substrings. PhishTank exige uma resposta estruturada e distingue relatos não verificados de phishing confirmado.

## Diretório e credenciais

`/vendors` deriva suas 12 fontes do mesmo catálogo usado pelas consultas. Os filtros usam os tipos efetivamente suportados; não existe filtro CVE sem integração correspondente. Configuração e última resposta são informações separadas. A atividade das três fontes de phishing registra somente data, HTTP e contagem de requisições ao provedor nesta execução do servidor, sem guardar URLs consultadas ou segredos e sem afirmar coleta automática. O cache varia por fonte.

O deploy recebe `ABUSE_CH_API_KEY`, `PHISHSTATS_API_KEY` e `WHOIS_API_KEY` pelos secrets do ambiente `vps-production`. Os valores são enviados por SSH stdin e gravados atomicamente no `.env` da raiz, utilizado pelo runtime. Não entram em bundles, logs ou arquivos versionados.
