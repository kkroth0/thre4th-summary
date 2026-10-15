# Direção do produto

ThreatSumm4ry é uma plataforma CTI open source para coletar feeds de segurança,
organizar pesquisa e produzir inteligência rastreável até as publicações originais.
A licença do projeto é AGPL-3.0-only; serviços e fontes de terceiros têm suas
próprias condições de uso.

## Fluxo principal

Feed → publicações salvas → relatórios. CVEs, atores, ransomware e consulta de indicadores
fornecem contexto para a pesquisa. A navegação e a entrada do produto priorizam
esse fluxo. A instância hospedada mantém os controles atuais de acesso por conta;
a licença do código não concede acesso automático a ela ou às APIs de terceiros.

## Estado atual

- Coleta de RSS/Atom e algumas páginas HTML, com cache persistente, concorrência
  limitada, validação HTTP e reaproveitamento da última coleta quando a fonte falha.
- Extração sobre o conteúdo disponível antes da correlação; evidências atribuídas
  por publicação, hash do texto processado e versão da extração.
- Agrupamento heurístico com janela entre publicações, atualização de fontes e
  aliases para IDs absorvidos. O frontend respeita o ID de história do backend.
- Feed, publicações salvas e geração de relatórios.

A implementação e seus limites estão em [ETL v2](./etl-v2.md). Esta etapa corrige
perda de evidências e inconsistências de agrupamento; a qualidade semântica ainda
precisa ser medida em um conjunto de eventos reais rotulados.

O registro de nomes/aliases de entidades e a persistência de notícias/stories
no SQLite estão disponíveis, com isolamento das observações privadas. A troca
para leituras/gravações principais no banco exige comparações shadow válidas;
publicações e eventos passam a compartilhar a mesma transação. Detalhes em
[persistência e sugestões](./news-persistence-and-watch-suggestions.md).
Não estão ativados: correlação semântica entre idiomas, grafo persistente de
ameaças e integração com CTINexus. A avaliação semântica offline não muda os merges.

## Prioridade: o mesmo evento aparece em vários cards

O objeto principal deve ser o **evento**, com várias publicações de suporte.
Deduplicação de um documento, identificação do mesmo evento e associação entre
eventos relacionados são operações diferentes. Compartilhar um ator ou CVE não
prova que duas notícias descrevem o mesmo incidente.

1. Preservar documentos e evidências: URL canônica, texto, fonte, datas de
   publicação/coleta, hash de conteúdo e versão da extração.
2. Corrigir a continuidade dos IDs: o frontend deve respeitar o ID de história do
   backend. Um agrupamento visual por fornecedor/data não pode redefinir eventos.
   Revisar também os IDs guardados no cache local.
3. Separar sinais de cada publicação do contexto agregado de um evento. Evitar
   atribuir a todas as fontes uma entidade mencionada por apenas uma delas.
4. Correlacionar candidatos por janela temporal, entidades normalizadas e contexto
   do incidente; usar similaridade textual como um sinal adicional. Uma cadeia
   A≈B≈C não autoriza reunir A e C automaticamente.
5. Atualizar eventos existentes com nova cobertura, evidências e mudanças de
   status. Oferecer correção manual de uniões e separações.
6. Medir contra casos reais rotulados antes de ampliar a automação.

O conjunto de avaliação deve incluir cobertura repetida em PT/EN, republicações,
follow-ups, incidentes distintos com a mesma CVE e notícias diferentes sobre o
mesmo ator. Medir fragmentação (cards extras por evento), precisão das uniões,
recall das coberturas e estabilidade dos IDs entre ciclos de coleta.

## Evolução posterior

Extração semântica opcional para relatórios técnicos, com referência ao trecho
de suporte; registro de entidades e aliases; relações entre eventos;
acompanhamento por temas e entregas de inteligência. O CTINexus é um candidato
para a extração, sujeito à [avaliação técnica](./ctinexus-evaluation.md).

O critério de valor inicial é concreto: o analista encontra a cobertura do mesmo
evento em um card e consegue conferir o que cada fonte realmente informou.
