# Fornecedores e projetos reconhecidos pelo ETL

O catálogo curado em [vendorCatalog.js](../../server/vendorCatalog.js) tem 525
entidades e 1.261 nomes/aliases distintos. Inclui fornecedores e projetos de
software relevantes para avisos de vulnerabilidade e pesquisa CTI. Não é uma
lista de novas fontes RSS: as entradas reconhecem menções no texto coletado.

## Cobertura

| Setor | Entidades | Exemplos |
| --- | ---: | --- |
| Nuvem e plataformas | 25 | Microsoft, AWS, Google, Oracle, IBM, Cloudflare, Akamai |
| Segurança | 115 | Fortinet, Palo Alto Networks, Check Point, Ivanti, CrowdStrike, BeyondTrust, Okta, CyberArk, Axur |
| Redes | 42 | Cisco, Juniper, HPE, Arista, MikroTik, Ubiquiti, Huawei, Zyxel |
| Software corporativo | 88 | SAP, Adobe, Atlassian, ServiceNow, Citrix, VMware, TOTVS, Fortra, ConnectWise |
| Backup e armazenamento | 30 | Veeam, Commvault, Rubrik, Acronis, QNAP, Synology, NetApp |
| Desenvolvimento e dados | 79 | GitHub, GitLab, JetBrains, JFrog, Red Hat, Apache, OpenSSL, PostgreSQL, Grafana, n8n |
| Plataformas web | 41 | WordPress, Drupal, Joomla, Strapi, Sitecore, cPanel, Plesk, phpMyAdmin |
| Hardware e endpoints | 43 | Apple, Mozilla, Dell, HP, Lenovo, Intel, NVIDIA, Qualcomm, Hikvision |
| OT/ICS | 62 | Siemens, Schneider Electric, Rockwell, Honeywell, ABB, Yokogawa, Moxa, CODESYS |

Nomes presentes no [CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
e equipes de resposta do [FIRST](https://www.first.org/members/teams/) foram
consultados como referências para a seleção. O catálogo é mantido localmente;
essas referências não são sincronizadas automaticamente nem implicam que toda
entidade cadastrada está no KEV ou é membro do FIRST.

## Identificação e pontuação

[vendorMatch.js](../../server/vendorMatch.js) encontra todos os fornecedores
reconhecidos em título, resumo e corpo processado pelo ETL. Aliases de produtos
apontam para uma entidade canônica:

| Texto encontrado | Entidade registrada |
| --- | --- |
| Azure, SharePoint, Entra ID | Microsoft |
| AWS, Amazon EC2 | Amazon Web Services |
| FortiGate, FortiOS, FortiManager | Fortinet |
| PAN-OS, GlobalProtect | Palo Alto Networks |
| NetScaler | Citrix |
| MOVEit | Progress Software |
| ScreenConnect | ConnectWise |
| Confluence, Jira | Atlassian |
| TeamCity | JetBrains |
| ManageEngine | Zoho |
| Protheus | TOTVS |
| SIMATIC, Siemens S7 | Siemens |

A categoria `Critical Vendor` acrescenta **dez pontos uma única vez**, mesmo
quando cinco fornecedores ou vários aliases da mesma entidade são citados.
O limite geral de score e a penalização de marketing continuam ativos. Uma
menção a fornecedor não é sinal suficiente de incidente ou de exploração ativa.

`assets` devolve os nomes canônicos; `vendors` devolve `{id, name, sector,
matched}`. Os metadados ficam também nas evidências por publicação da história
e no arquivo permanente. A versão de extração passou para `feed-v6`, permitindo
atualizar a atribuição das URLs já coletadas e invalidar snapshots anteriores.

## Controle de ambiguidades

O reconhecimento respeita bordas de palavras Unicode e preserva pontuação de
nomes como Notepad++, B&R Automation e Pepperl+Fuchs. Aliases compostos aceitam
variações de caixa e espaços/quebras de linha.

Marcas que também são palavras comuns usam formas qualificadas: `Arm Cortex`,
`RSA SecurID`, `Progress Software`, `Chef Infra`, `Box.com`, `Ghost CMS`,
`Carrier Global` e `Zoom Workplace`. Siglas ambíguas como `SAP` exigem a caixa
correta quando aparecem isoladas; “tree sap” não deve identificar SAP. HPE e
HP têm aliases separados, e produtos como TeamCity não viram um segundo
fornecedor independente de JetBrains.

O catálogo mantém marcas históricas como referências próprias. Encontrar
VMware, Broadcom, Pulse Secure ou Ivanti não implica atribuir automaticamente
todas as marcas a um único grupo empresarial. Projetos de software livre
também não recebem uma empresa controladora inferida.

O resultado representa **menção textual**, não comprovação de fornecedor
afetado: uma publicação pode citar o pesquisador, uma integração, uma comparação
ou um produto usado pelo atacante. Distinguir esses papéis exige extração de
contexto adicional. O agrupamento de eventos não usa fornecedor isolado como
evidência para reunir incidentes distintos.

## Seleção pessoal de fornecedores

Em **Configurações → Monitoramento → Fornecedores nas notícias**, cada conta
pode escolher todas as notícias ou somente fornecedores selecionados. A busca
aceita marca e aliases de produtos; há filtro por setor e seleção dos resultados
visíveis. O botão **Salvar monitoramento** aplica a preferência à conta.

No modo selecionado, um evento aparece se alguma de suas fontes menciona um
fornecedor escolhido. A cobertura disponível daquele evento permanece junta,
incluindo fontes que não repetem o nome. A preferência se aplica ao feed,
à lista de histórias e às sugestões para curadoria de relatórios. O arquivo
histórico de pesquisa e consultas de indicadores continuam disponíveis como
acervo geral. O score e a coleta compartilhada não mudam por conta.

Nenhum fornecedor selecionado nesse modo produz um feed vazio; **Todas as
notícias** restaura a visão geral, incluindo notícias sem fornecedor identificado.
O feed informa quando uma seleção está ativa e oferece acesso às configurações.

`GET /api/news/monitoring` devolve catálogo e preferência da conta autenticada.
`PUT /api/news/monitoring` recebe `{mode: "all" | "selected", vendorIds: [...]}`.
IDs desconhecidos são rejeitados. O dono vem da sessão; não é aceito do cliente.
O estado fica em `server/.news-monitoring.json`, preservado no deploy e rollback.
Respostas pessoais usam `Cache-Control: private, no-store`; o cache local do feed
também é separado por conta e seleção.

## Manutenção do catálogo

Adicione uma entrada no setor correspondente. Uma linha apenas com o nome
reconhece esse nome; se houver aliases explícitos, apenas eles serão aceitos.
Inclua o nome da marca entre os aliases quando ele também for seguro isolado.
Evite termos genéricos, siglas ambíguas sem qualificação e aliases que já
pertencem a outra entidade. Alterações na atribuição devem atualizar a versão
de extração quando precisarem invalidar snapshots persistidos.

Produtos adicionais estão em [vendorProductAliases.js](../../server/vendorProductAliases.js).
A revisão de 09/10/2026 adicionou 426 nomes a 136 entidades, consultando o KEV
publicado em 08/10/2026 e catálogos oficiais dos fabricantes. A lista oficial
guarda uma URL de referência por entidade. Produtos ambíguos são qualificados:
`SolarWinds Orion`, `AMD Instinct`, `Commvault Command Center`; `Orion`, `Instinct`
e `Command Center` isolados não identificam fornecedor. Projetos sem nome
alternativo válido continuam reconhecidos pelo próprio nome, sem aliases artificiais.

Nas configurações, a busca inclui esses produtos. A coluna mostra nomes
reconhecidos em duas linhas, com a lista completa no título da célula e
visibilidade também em telas pequenas. Aliases com underscore, como `WS_FTP`,
usam a mesma normalização do texto coletado.

```bash
node --test server/test/vendorMatch.test.js server/test/ctiIntel.test.js server/test/feedEnrichment.test.js
```
