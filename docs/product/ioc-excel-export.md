# Exportação direta para Excel

Em **Notícias e IOCs → Exportar por período**, Excel (.xlsx) é o formato inicial.
Funciona para publicações, IOCs extraídos das notícias e a Base de IOCs unificada.
O arquivo contém todas as páginas autorizadas do período escolhido, mantendo
o recorte de fornecedores do export existente e o isolamento entre contas.
Datas e horas ficam em ISO, junto da base da data, fontes, referências,
ID do evento, CVEs, atores e malware. Uma evidência por fonte continua sendo
uma linha, mesmo quando o indicador se repete; Resumo separa os dois totais.

Em **Enriquecimento em lote → Exportar → XLSX**, são exportadas todas as linhas
do filtro atual, com estados parciais, erros e dados disponíveis. As abas são:
Indicadores, Fontes, Publicações, Evidências e Resumo. As fontes preservam os dados
normalizados, resposta original, timeline e cota observada. Exportar usa os
resultados existentes e não repete consultas de enriquecimento.

Respostas maiores que 32.767 caracteres não são truncadas: a célula referencia
partes ordenadas de até 30 mil caracteres em Dados extensos, identificando aba,
linha, campo e número da parte. O conteúdo pode ser recomposto concatenando as
partes da mesma referência. Caracteres de controle incompatíveis com XML são
removidos, conforme o padrão dos demais exports. Dados de terceiros são escritos
como texto, nunca como objetos de fórmula ou hiperlink do ExcelJS. Hashes e IPs
permanecem texto. O limite de linhas de uma aba gera erro explícito, sem corte
silencioso; pode-se reduzir o período para exportar conjuntos menores.

O navegador usa o JSON autenticado dos mesmos endpoints de export e gera XLSX
com o ExcelJS já instalado, carregado sob demanda. CSV, JSON e TXT permanecem
disponíveis onde já existiam. Não foi adicionado um novo formato ao contrato HTTP
do backend: o download XLSX é uma funcionalidade da interface.
