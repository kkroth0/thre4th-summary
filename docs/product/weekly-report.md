# Relatório semanal

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

O PPTX usa oito layouts editáveis adaptados do template fornecido: capa, resumo, notícia, vulnerabilidades, ransomware, recomendações, entidades citadas e metodologia. Tabelas são paginadas; as URLs completas das fontes ficam nas notas dos slides. O modelo público foi sanitizado e não contém os incidentes, números ou destinatário do documento original.

CVEs publicadas na semana e entradas novas no KEV são recortes separados: uma CVE antiga pode ter entrado no KEV nesta semana. As prioridades usam KEV, CVSS e EPSS. Correspondências com produtos monitorados exigem validação de versões e exposição. Ransomware.live fornece alegações não confirmadas; as contagens refletem os registros coletados, não um censo de todos os incidentes.

Datas das notícias mostram o horário publicado quando disponível, com conversão para Fortaleza. Fontes que fornecem apenas a data preservam esse dia e mostram **hora não informada**. Horários de primeira coleta e atualização permanecem identificados como tais.

## Verificação

Testes cobrem fronteiras da semana, limites editoriais, deduplicação, preservação de escolhas, isolamento por conta, retomada após reinício, atualização com atraso, falhas de fontes, tabelas paginadas, fonte de horário e ausência de conteúdo confidencial no template público. `news-pipeline-audit.yml` verifica os dados persistidos e a disponibilidade de candidatos e CVEs em produção sem criar relatórios de usuários.
