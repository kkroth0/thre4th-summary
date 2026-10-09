# Avaliação do CTINexus

Data: 2026-10-09. Revisão estática do código e da documentação.
Commit analisado: `0c688536d85eae72f6055723492b573b0a1ff865`.
Nenhuma inferência, benchmark local ou chamada paga foi executada.

## Decisão

Faz sentido como candidato a **extrator de entidades e relações de relatórios
CTI**. Não substitui a correlação de notícias sobre o mesmo evento e não deve
entrar agora como dependência obrigatória do refresh do feed.

O projeto extrai triplas sujeito–relação–objeto, classifica entidades, tenta
alinhar nomes e prevê relações adicionais. Isso oferece uma base para contexto
de atores, malware, vulnerabilidades e técnicas. A implementação pública processa
cada relatório isoladamente; não fornece um catálogo persistente de eventos com
IDs estáveis e cobertura consolidada entre publicações.

Fontes: [repositório](https://github.com/peng-gao-lab/CTINexus),
[paper](https://arxiv.org/html/2410.21060v2),
[API pública](https://github.com/peng-gao-lab/CTINexus/blob/0c688536d85eae72f6055723492b573b0a1ff865/ctinexus/__init__.py).

## Encaixe no ThreatSumm4ry

| Necessidade | Encaixe |
| --- | --- |
| Coletar e manter feeds | Continua responsabilidade do nosso ETL |
| Deduplicar republicações | Continua responsabilidade do nosso ETL |
| Um card por evento, inclusive entre idiomas | Exige nosso correlacionador e avaliação específica |
| Extrair atores, malware e relações de relatórios | Bom candidato para prova de conceito |
| Normalizar aliases entre todos os documentos | Exige registro global e validação adicional |
| Grafo de contexto | Pode fornecer extrações; persistência e evidências ficam conosco |

Python 3.10–3.13, modelos e embeddings adicionam uma operação diferente do
backend atual em Node. Há suporte a provedores remotos e Ollama; suporte ao
provedor não garante qualidade equivalente entre modelos. A licença do CTINexus
é MIT; qualquer redistribuição de seu código deve preservar os avisos próprios.
Não foi incorporado código do CTINexus nesta mudança.

## Pontos a validar antes da integração

1. **Extração não equivale a evidência verificada.** O prompt de extração retorna
   triplas e tipos, sem exigir uma citação ou offsets para cada relação. Há
   metadados documentais no fluxo por URL, mas precisamos relacionar cada fato
   ao artigo e ao trecho de suporte. Validar CVEs e IOCs deterministicamente.
2. **Relação prevista precisa continuar identificada como inferência.** O pipeline
   padrão executa link prediction. A visualização distingue links previstos,
   porém a integração não deve tratá-los como fatos para juntar eventos. Para uma
   primeira prova de conceito, orquestrar as etapas de extração, tipagem e
   alinhamento separadamente; a API padrão não tem um parâmetro para pular LP.
3. **Texto integral e resumo não são equivalentes.** No processamento por URL,
   há extração de conteúdo e resumo por LLM antes da extração de inteligência.
   Preservar o documento original e testar perdas de informação.
4. **Recuperação de exemplos exige revisão.** No código analisado,
   `DemoRetriever.retrievekNNDemo` calcula similaridade entre demonstrações e
   chama `most_similar(0, ...)`; a consulta alvo recebida no construtor não
   participa dessa busca. Isso difere da seleção por proximidade com o relatório
   descrita no paper. Confirmar com um teste de consultas diferentes.
5. **Merge de entidades exige revisão.** `Merger.call` constrói conjuntos de
   vizinhos que podem se sobrepor e reatribui IDs de entidades compartilhadas.
   Testar A≈B, B≈C e A≉C para verificar se a partição e as relações finais são
   consistentes. O limiar de similaridade de entidades não é um limiar de
   identidade de eventos.
6. **O benchmark não mede nossa dor.** A avaliação do paper usa 150 relatórios
   de dez plataformas; não demonstra redução de cards duplicados em um feed
   incremental PT/EN. Precisamos medir custo, latência e qualidade no nosso corpus.

Referências de implementação:
[pipeline](https://github.com/peng-gao-lab/CTINexus/blob/0c688536d85eae72f6055723492b573b0a1ff865/ctinexus/utils/gradio_utils.py),
[processamento e recuperação](https://github.com/peng-gao-lab/CTINexus/blob/0c688536d85eae72f6055723492b573b0a1ff865/ctinexus/llm_processor.py),
[alinhamento](https://github.com/peng-gao-lab/CTINexus/blob/0c688536d85eae72f6055723492b573b0a1ff865/ctinexus/graph_constructor.py),
[prompt de extração](https://github.com/peng-gao-lab/CTINexus/blob/0c688536d85eae72f6055723492b573b0a1ff865/ctinexus/prompts/ie.jinja).

## Prova de conceito proposta

Selecionar 20–30 publicações reais, incluindo dez eventos com múltiplas fontes
quando disponíveis, PT/EN, follow-ups e incidentes distintos com entidades iguais.
Rotular evento, entidades e relações sustentadas por trechos. Comparar a extração
atual com CTINexus, sem alterar os cards apresentados ao usuário.

Executar em worker opcional, com fila, cache por hash + versão do extrator/modelo,
limites de custo e fallback para as regras existentes. Guardar fatos extraídos
e relações previstas separadamente. Usar relatório técnico integral como entrada
controlada, mantendo URL, datas e conteúdo original.

Avaliar precisão/recall de entidades e relações, aliases, evidência por relação,
latência e custo por documento. Depois verificar se os sinais melhoram a precisão
das uniões e reduzem a fragmentação dos eventos. Só adotar se houver ganho frente
às heurísticas em dados reais. Um grafo visual, sozinho, não demonstra esse ganho.
