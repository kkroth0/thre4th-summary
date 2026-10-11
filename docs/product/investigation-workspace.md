# Workspace de investigação

O workspace usa os HTMLs do Hunt.io fornecidos como referência de navegação, densidade de informação e interação. A implementação mantém a marca threatsumm4ry e usa as APIs do projeto. Não importa os scripts, dados de conta, contagens ou integrações dos HTMLs salvos.

## Fluxos implementados

| Área | Fonte de dados | Interação |
| --- | --- | --- |
| Visão geral (`/dashboard`) | `/api/newsletter`, com autorização e fornecedores do usuário | Eventos, fontes, cobertura correlacionada, eventos com KEV, atividade de sete dias e abertura do evento no feed |
| Feed (`/newsletter`) | Coletor e agrupamento existentes | Tabela paginada ou cards; painel de todas as publicações; evidências de correlação quando disponíveis; salvar coleção e gerar relatório com todas as fontes |
| Campanhas de phishing | `/api/phishing/reports` | Filtros de período, técnica, região e filtros adicionais; tabela de campanhas/publicações; fontes e evidências no painel; exportação Excel do recorte completo |
| Software e malware (`/malware`) | `/api/actors/software-index` | Busca por software/ator, tabela paginada e abertura dos perfis relacionados |
| Atores (`/atores?actor=...`) | Catálogo de atores existente | Perfil aberto por link a partir de software ou notícia |
| Vulnerabilidades (`/cves`) | APIs de CVEs recentes e CISA KEV existentes | Tabelas paginadas, descrição, mitigação, prazo e referências no painel |
| Busca de indicadores (`/analyzer`) | Provedores de enriquecimento existentes | Formulário compacto, entrada de múltiplos indicadores e histórico |
| Enriquecimento em lote (`/bulk`) | Mesmos provedores do analisador, com compatibilidade por tipo | Importação TXT/LOG/CSV/JSON até 3,8 MB, extração e deduplicação, seleção de fontes, fila de até três indicadores, detalhes por fonte e exportação CSV/JSON/TXT |

## Contagem e interpretação

- Visão geral reflete o snapshot autorizado do feed, não o histórico completo. Fontes são veículos representados no snapshot, não o total de coletores configurados.
- Atividade de sete dias considera as datas de publicação presentes nesse snapshot; a janela usa o calendário local do navegador.
- Um evento com várias publicações preserva a identidade de agrupamento do coletor. O layout não cria novas correlações.
- Software do índice pode ser uma família maliciosa ou uma ferramenta legítima. Relações com atores são relações históricas do catálogo, não evidência de atividade atual.
- Dados ausentes, incluindo CVSS, são exibidos como não identificados ou `—`, sem preencher métricas presumidas.
- A exportação de phishing continua usando todo o recorte filtrado, independentemente da página da tabela.
- O lote consulta IPs públicos IPv4/IPv6, domínios, URLs e hashes MD5/SHA-1/SHA-256. E-mails, CIDRs e IPs privados/reservados são contabilizados como não consultados; nenhum bloco é expandido automaticamente. URLs não geram uma segunda consulta implícita ao host.
- Falhas de todas as fontes geram estado de falha; falhas de algumas fontes geram resultado parcial. Ausência de sinal não comprova segurança. Interromper bloqueia novas consultas e deixa as que já começaram terminarem.
- Os resultados do lote são locais à página e não criam jobs persistidos. Sair encerra a fila, mas consultas já em andamento podem consumir cota. CSV/JSON/TXT exportam todo o filtro visível, não somente a página; JSON preserva respostas e erros das fontes. CSV neutraliza fórmulas de planilha.

## Layout e acessibilidade

Tema escuro neutro por padrão para visitantes sem preferência salva; tema claro e preferências existentes continuam disponíveis. Navegação fixa e recolhível, submenu de phishing, rolagem independente da navegação, tabela com rolagem horizontal no celular, menu mobile e painéis com Escape, foco contido e retorno do foco ao elemento que os abriu.

## Expansões que exigem dados próprios

As referências de Host Radar, Registrar Radar, C2, histórico de certificados e SQL mostram capacidades adicionais. Implementar essas áreas exige definir coletores, proveniência, cobertura temporal e autorização das respectivas fontes. Os menus atuais expõem áreas que já têm uma API funcional; registros de exemplo são usados exclusivamente para validação local da interface.
