# Relatório semanal

O padrão de redação e revisão está em [Padrão editorial do boletim semanal](weekly-report-editorial.md): voz de revista semanal de segurança, em português brasileiro, com contexto, análise executiva e pontos de atenção específicos por matéria. Esse documento registra a orientação editorial; regras ainda não automatizadas exigem revisão antes da publicação.

`/relatorios?view=weekly` reúne o acervo de notícias correlacionadas, o catálogo local NVD/KEV/EPSS e as publicações de ransomware.live. Não dispara extração de artigos ou chamadas de LLM ao abrir a página.

## Seleção editorial

Cada semana oferece até 25 eventos gerais e 25 de inteligência artificial, classificados por relevância e deduplicados pelo evento correlacionado. A sugestão inicial marca os 10 gerais e 5 de IA mais relevantes. O usuário pode trocar, remover e confirmar as escolhas com **Salvar seleção**; após essa confirmação, **Gerar redação** lê os artigos selecionados e prepara as matérias e a síntese das seções. O PPTX fica disponível quando a redação termina sem matérias bloqueadas.

As escolhas ficam vinculadas à conta e à semana, persistem após reinícios e não são substituídas por notícias novas ou mudanças no ranking. Uma escolha que saiu das 25 sugestões permanece disponível para revisão. O JSON inclui as sugestões e a seleção; o PPTX inclui somente as notícias selecionadas.

## Atualizações e persistência

- Período: domingo 00h até o domingo seguinte 00h, com fim exclusivo, em America/Fortaleza.
- A primeira visita autenticada cria o plano automático. O servidor verifica novos insumos a cada 15 minutos, mesmo sem a página aberta.
- Fontes públicas compartilham uma coleta em andamento e cache de cinco minutos entre contas. Dados e relatórios privados permanecem restritos ao titular.
- Durante os dois primeiros dias da nova semana, a semana anterior também recebe insumos publicados naquele período e coletados com atraso. Seu destinatário e seleção editorial permanecem os mesmos.
- `.weekly-reports.sqlite` armazena planos, versões, escolhas e as alegações observadas de ransomware. O deploy e o rollback preservam o banco e seus arquivos WAL.
- Uma falha de atualização mantém a versão anterior. Uma falha no catálogo de vulnerabilidades mantém os dados anteriores dessa seção e informa a cobertura parcial.

## Conteúdo e exportação

O PPTX usa os objetos nativos do boletim EY aprovado: formato A4 vertical, fonte Overpass, capas, marca EY, divisórias, resumo executivo, três blocos de CVEs por página, mapa vetorial da América Latina, panorama de vítimas, dois gráficos editáveis de 12 semanas, painel de IA, TLP e aviso. Conteúdo variável é paginado no mesmo layout. As referências ficam nas notas e os títulos/fontes e CVEs têm links. O template distribuído contém 19 layouts sanitizados, sem notícias, números, destinatários ou planilhas da edição original. Cada exportação escreve os próprios dados nos gráficos e em suas planilhas Excel incorporadas. Não reutiliza os números do exemplo.

CVEs publicadas na semana e entradas novas no KEV são recortes separados: uma CVE antiga pode ter entrado no KEV nesta semana. O boletim mostra até três destaques, um de Java, PHP e Node.js, selecionados antes do corte das 50 prioridades do catálogo. O vínculo com o runtime usa produto, descrição e advisories oficiais para evitar confundir JavaScript com Java ou um plugin com o PHP. Se uma tecnologia não tiver CVE publicada na semana, o sistema informa a ausência. Outro slide mostra até três inclusões no KEV, de qualquer tecnologia, ordenadas pela quantidade de fontes distintas que citaram a CVE e depois por CVSS/EPSS, priorizando produtos diferentes. Uma PoC isolada não confirma exploração. Os totais globais e o catálogo permanecem completos. Correspondências com produtos monitorados exigem validação de versões e exposição. Ransomware.live fornece alegações não confirmadas; as contagens refletem os registros coletados, não um censo de todos os incidentes.

Datas das notícias mostram o horário publicado quando disponível, com conversão para Fortaleza. Fontes que fornecem apenas a data preservam esse dia e mostram **hora não informada**. Horários de primeira coleta e atualização permanecem identificados como tais.

## Verificação

Testes cobrem fronteiras da semana, limites editoriais, deduplicação, preservação de escolhas, isolamento por conta, retomada após reinício, atualização com atraso, falhas de fontes, tabelas paginadas, fonte de horário e ausência de conteúdo confidencial no template público. `news-pipeline-audit.yml` verifica os dados persistidos e a disponibilidade de candidatos e CVEs em produção sem criar relatórios de usuários.

## Histórico e setores do destinatário

A chave Pro da Ransomware.live permite consultar meses completos, além do feed de 100 registros recentes. O semanal reúne os meses que cobrem 12 semanas, compartilha requisições concorrentes e persiste as observações normalizadas em cache. O mês em andamento é revalidado a cada hora e os anteriores a cada dia. Meses truncados ou indisponíveis deixam a cobertura parcial e as semanas afetadas sem valor no gráfico. Nunca são apresentados como zero confirmado. As contagens usam `discovered` (observação pela fonte), preservando separadamente a data atribuída ao ataque.

Para perfis cujo nome identifica Grupo Ultrapar, o recorte solicitado usa os nomes conferidos no endpoint Pro `/listsectors`: `Financial Services` (financeiro), `Transportation` (logística e mobilidade), `Manufacturing` (indústria e manufatura) e `Energy & Utilities` (energia). Cada organização é contada uma vez. Outros perfis não herdam esse recorte. O perfil e os setores ficam registrados na versão semanal.

As chaves ficam somente no servidor. `NVD_API_KEY` e `RANSOMWARE_LIVE_API_KEY` são sincronizadas pelo workflow manual de segredos para a VPS. O navegador recebe os dados consolidados, nunca as credenciais.

## Redação com leitura das fontes

A redação é iniciada explicitamente em `POST /api/reports/weekly/editorial`, com autenticação, acesso premium e verificação de origem. O GET e o ciclo de atualização de quinze minutos não fazem chamadas de IA. A tarefa continua no servidor ao sair da página; a interface mostra o progresso e permite revisar os textos e as fontes antes de exportar.

O leitor reutiliza corpos do ETL, nunca o resumo curto como substituto de artigo, e consulta a URL quando necessário. As requisições usam a proteção existente contra SSRF, DNS privado e redirecionamentos inseguros. Cada matéria considera até quatro fontes; fontes indisponíveis ou adicionais ficam explicitamente identificadas. O corpo e a parcela fornecida à IA têm limites de tamanho registrados na evidência. Sem ao menos um corpo legível, a matéria fica bloqueada e não recebe texto genérico.

A IA recebe a voz editorial de revista semanal em português brasileiro e produz manchete, abertura, contexto, dois parágrafos de desenvolvimento e três pontos de atenção específicos. Dois trechos literais devem corresponder aos textos lidos; URLs não lidas, CVEs ausentes do corpo e versões de correção ausentes das evidências são rejeitadas. Uma tentativa de reescrita pode corrigir formato e extensão. Essa validação não equivale à checagem independente de todas as afirmações; a revisão editorial continua necessária.

Os advisories das seis CVEs selecionadas também são consultados quando disponíveis, além dos dados do catálogo. Sem texto do advisory, a seção usa apenas o catálogo e não pode inventar versões corrigidas. A síntese executiva e os textos de ransomware, histórico e IA usam as matérias redigidas e os dados estruturados da edição. Comparações numéricas com a semana anterior não aparecem como queda durante uma semana ainda em andamento.

Rascunhos e cache ficam isolados por conta em tabelas do mesmo `.weekly-reports.sqlite`, preservado no deploy. O cache inclui versão editorial, modelo, conteúdo e perfil; mudanças invalidam a redação. Uma tarefa interrompida pode ser retomada sem cobrar novamente por matérias idênticas já verificadas. Uma edição é processada por vez, com até duas matérias simultâneas. `OPENROUTER_WEEKLY_MODEL` pode selecionar o modelo; na ausência, utiliza a configuração já existente de `OPENROUTER_MODEL`. Chaves ficam no servidor.

O workflow manual `weekly-editorial-audit.yml` lê uma notícia pública e testa a IA em memória, sem criar ou alterar relatórios de clientes. As contagens desse teste são uma fixture, nunca uma edição publicável.

### Prioridade editorial das sugestões
As sugestões semanais priorizam ativos do perfil, setores monitorados, fontes oficiais e veículos especializados reconhecidos. Medium e textos predominantemente em escritas asiáticas ficam fora da seleção automática; a nacionalidade do fabricante ou do ator não é um critério de exclusão. A preferência não altera a ingestão geral nem remove escolhas manuais já salvas. A interface apresenta os motivos da prioridade. A lista de fontes é uma preferência editorial, não uma certificação automática de veracidade.

### Cliente e contexto da organização
O seletor Cliente usa os perfis privados da organização. O modelo existente relaciona atores por setores, regiões e atores fixados; o semanal reutiliza esse modelo em memória, sem consultas externas extras. Notícias recebem prioridade por ativos, atores, setores e ambiente OT. Para perfis com contexto, os três destaques de CVEs usam os ativos e as relações das publicações, seguidos de KEV/CVSS/EPSS; sem contexto, permanece o recorte Java/PHP/Node.js. As três exploradas continuam restritas ao KEV. Totais globais não são reduzidos pelo perfil.
As escolhas editoriais são guardadas por cliente e semana e restauradas ao voltar ao cliente. Trocar o perfil invalida a redação e bloqueia ações enquanto a atualização estiver pendente. Semanas anteriores preservam o contexto registrado. As relações são sinais de relevância, não prova de exposição ou atribuição.

### Período personalizado
Além das semanas de domingo a domingo, a tela aceita início e fim com data e hora em Fortaleza (UTC−3), até 31 dias. O início é inclusivo e o fim exclusivo. Fontes sem hora são incluídas pelos dias sobrepostos, sem atribuir uma hora de publicação inventada. O intervalo tem identificador próprio por cliente; seleção editorial, redação e exportação usam o mesmo recorte. O perfil deve ser escolhido antes do intervalo. Comparações percentuais com a semana anterior ficam indisponíveis para períodos personalizados, pois durações diferentes não são comparáveis. O histórico semanal continua apresentado como contexto separado.
