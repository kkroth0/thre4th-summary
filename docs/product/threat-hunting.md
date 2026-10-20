# Threat Hunting — hipóteses para o analista

A entrada `/hunting` responde “O que caçar hoje”, com recortes de hoje em Fortaleza, últimos sete dias e últimos trinta dias. Usa publicações datadas do arquivo local, respeita o monitoramento de fornecedores da conta e cruza CVEs do catálogo NVD/KEV/EPSS. Não dispara nova coleta de notícias ao abrir a página.

## Catálogo KQL

Importação inicial dos repositórios cyb3rmik3/KQL-threat-hunting-queries (Sentinel, ThreatHunting, ThreatDetection e Defender), Bert-JanP/Hunting-Queries-Detection-Rules e reprise99/Sentinel-Queries. O snapshot em `server/data/hunting-library.json` mantém commit, caminho, autoria por repositório, URL imutável, licença e texto das licenças. Consultas idênticas na mesma plataforma são deduplicadas, mantendo as origens.

O script `server/scripts/sync-hunting-library.mjs` regenera o snapshot. Em produção, a atualização diária grava um cache em `.feed-cache/`; revisões iguais reaproveitam o conteúdo, e falhas preservam o catálogo anterior. Apenas texto publicado dos três repositórios fixos é lido. Nada é executado e URLs encontradas dentro dos arquivos não são acessadas.

## Hipóteses e IA

A recuperação usa técnicas explícitas em comum, CVEs e termos específicos. Favorece termos no título da consulta e reduz correspondências com atores específicos ausentes da notícia. Agrupa insumos que recomendam a mesma consulta, mantendo suas URLs e IDs de eventos independentes. Um resumo multivulnerabilidade não transfere o KEV ou EPSS de uma CVE para as demais.

O ranking inicial considera correspondência, atualidade, score da notícia, KEV, EPSS, CVSS e feedback pessoal. Até quatro consultas genéricas de exposição a CVEs entram no conjunto, para não excluir todas as caças comportamentais. Essas consultas usam somente IDs de CVE validados e não inferem técnicas MITRE.

Com `OPENROUTER_API_KEY`, o DeepSeek seleciona, ordena e descreve em português os candidatos, sem substituir a KQL importada. Modelo dedicado: `OPENROUTER_HUNTING_MODEL`, padrão `deepseek/deepseek-v4.1-flash`. O primeiro retorno é local; a geração ocorre em segundo plano e a página atualiza enquanto ela está em andamento. Ausência de IA, limite ou erro é informado na interface.

As chamadas recebem somente metadados de fontes públicas e candidatos, sem credenciais, telemetria do cliente ou dados de outras contas. O modelo não recebe ferramentas. IDs retornados devem existir no conjunto e identificadores inventados são rejeitados. Essa validação não comprova correção semântica de toda a descrição: as fontes permanecem visíveis para revisão.

O cache considera usuário, período, catálogo, publicações e feedback; geração é single-flight, tem limite de concorrência, timeout, cooldown de falhas e orçamento de até nove gerações por usuário por dia UTC. Saídas são guardadas em SQLite. O catálogo CVE é lido em lote com cache de cinco minutos.

## Feedback e limites

“Sim / Não” persiste em `.hunting.sqlite` por usuário e ID da consulta. Influencia a recuperação e aparece no contexto das próximas gerações. Não há treinamento automático dos pesos do modelo. O deploy preserva o banco.

A interface apresenta insumos, conexões com atores/malware/CVEs, referência MITRE, plataforma e proveniência. Copiar mantém a KQL original. Tabelas e plataforma extraídas do texto são heurísticas; conectores, funções, campos, janela temporal e falsos positivos precisam ser verificados no ambiente. Nenhuma consulta é executada no Sentinel/Defender e nenhuma regra de detecção é publicada por este módulo.

O serviço antigo removido continua desativado. Este módulo usa `/api/hunting/overview` e `/api/hunting/feedback`, ambos com autenticação e autorização equivalentes ao feed. Não reintroduz URLs de scraping fornecidas pelo usuário.
