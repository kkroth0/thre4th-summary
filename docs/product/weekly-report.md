# Relatório semanal

O padrão de redação e revisão está em [Padrão editorial do boletim semanal](weekly-report-editorial.md): voz de revista semanal de segurança, em português brasileiro, com contexto, análise executiva e pontos de atenção específicos por matéria. Esse documento registra a orientação editorial; regras ainda não automatizadas exigem revisão antes da publicação.

`/relatorios?view=weekly` reúne o acervo de notícias correlacionadas, o catálogo local NVD/KEV/EPSS e as publicações de ransomware.live. Não dispara extração de artigos ou chamadas de LLM ao abrir a página.

## Seleção editorial

Cada semana oferece até 25 eventos gerais e 25 de inteligência artificial, classificados por relevância e deduplicados pelo evento correlacionado. A sugestão inicial marca os 10 gerais e 5 de IA mais relevantes. O usuário pode trocar, remover e confirmar as escolhas com **Salvar seleção**; o PPTX fica disponível após essa confirmação.

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
