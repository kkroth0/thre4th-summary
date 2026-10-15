# Fontes públicas adicionais de IOCs por ator

Verificação em 15/10/2026. A coleta de notícias e a ingestão dos arquivos de um
repositório são caminhos complementares. Todas as publicações aceitas passam
pela extração disponível e pelo histórico; o coletor de repositórios dedicado
contém Unit 42 e Arctic Wolf. Não significa que só esses dois editores alimentem
o inventário. Corpos indisponíveis, coleta adiada e entidades ainda não
reconhecidas limitam a cobertura: notícia salva não comprova extração integral.

| Prioridade | Fonte primária | Contribuição | Lacuna atual |
| --- | --- | --- | --- |
| 1 | [ESET malware-ioc](https://github.com/eset/malware-ioc) | IOCs de investigações, hashes e regras; diretórios de atores e famílias, incluindo Lazarus, OilRig e Mustang Panda | RSS WeLiveSecurity existe; repositório dedicado ausente |
| 1 | [Cisco Talos IOCs](https://github.com/Cisco-Talos/IOCs) | Arquivos de indicadores associados às pesquisas do blog | RSS Talos existe; repositório dedicado ausente |
| 1 | [Volexity threat-intel](https://github.com/volexity/threat-intel) | indicators.csv por publicação, além de regras | RSS Volexity existe; repositório dedicado ausente |
| 2 | [PRODAFT malware-ioc](https://github.com/prodaft/malware-ioc) | Relatórios/indicadores por ator, aliases, motivações e famílias | Repositório dedicado ausente; preservar datas históricas |
| 2 | [Sekoia Community](https://github.com/SEKOIA-IO/Community) | Diretório IOCs, relatórios e conteúdo de detecção | RSS Sekoia existe; arquivos dedicados ausentes |

ESET declara BSD-2-Clause e Talos CC0-1.0. PRODAFT apresenta MIT. Volexity
declara BSD-2-Clause para regras; Sekoia contém DRL 1.1 para regras. Conferir
escopo e avisos de cada artefato antes de redistribuir dados: acesso público não
equivale automaticamente à mesma licença para todo conteúdo vinculado.

MITRE ATT&CK e MISP Galaxy já compõem os catálogos de identidade/aliases;
não substituem fontes de observações recentes de IPs, domínios e hashes.
AbuseIPDB contribui reputação, sem atribuição de autoria. Uma menção conjunta
é associação investigativa, não comprovação de que todo IOC pertence ao ator.

Implementação proposta: manifestos de arquivos por SHA/ETag; download apenas
dos arquivos novos/alterados; parsers por layout e colunas; nenhum executável
ou amostra de malware; datas originais, referência ao relatório, licença,
confiança e escopo preservados. Deduplicar o indicador normalizado e manter
cada evidência separada. Repositório e notícia do mesmo relatório não devem
inflar a contagem de fontes independentes. Nenhuma dessas cinco integrações
foi ativada por esta avaliação.
