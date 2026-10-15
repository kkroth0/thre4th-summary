# Exportação XLSX de IOCs e lote

Seis testes novos verificam a leitura de volta do XLSX gerado, hashes como texto,
datas/horas e limites do período, uma linha por evidência, fórmulas tratadas como
texto, limpeza XML, arquivo vazio válido, falhas de fontes e contexto, e resposta
grande com Unicode recomposta integralmente a partir das partes da planilha.

Não há dependências nem consultas externas novas. O navegador gera o arquivo
com os dados do export autenticado existente ou com os resultados do lote atual.
Dados privados reais eventualmente baixados nos testes de interface não devem
ser adicionados ao repositório; somente contagens e prova da interface.

CI, deploy e download real serão registrados após a publicação.
