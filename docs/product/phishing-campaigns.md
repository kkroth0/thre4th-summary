# Inteligência de campanhas de phishing

Em **Phishing → Campanhas**, selecione o período e os filtros e clique em
**Exportar Excel**. Datas finais incluem todo o dia, em UTC, como as datas do
arquivo. O workbook contém Resumo, Reports, Campanhas, TTPs, Fontes, Brasil,
Latam, recortes dos perfis cadastrados na conta e Premissas recortes. A exportação
usa todas as publicações do recorte, inclusive as páginas não abertas na tela.
O limite é 20 mil publicações e é informado na tela e no workbook quando atingido.

## Extração e matching

`server/phishingIntel.js` aplica regras determinísticas em inglês e português,
normaliza acentos e variantes de hífen e retém o termo, o trecho e o campo de
origem (título, resumo ou corpo). Técnicas incluem ClickFix, AiTM/BiTM, device
code, PhaaS, smishing, vishing, quishing, OAuth consent, BEC e iscas sociais.
RMM, SaaS e serviços de mensagens exigem contexto de incidente de phishing;
mencionar um serviço legítimo não o transforma em técnica de ataque.

Recomendações, treinamento, negações e rodapés de artigos não devem classificar
incidentes. Setores e regiões exigem contexto de alvo/vítima; o país de origem
do ator não define a região atacada. Marcas imitadas exigem contexto de engano.
Todos esses campos resultam de regras, não de uma probabilidade medida nem de
uma análise humana validada. Evidências podem ser revisadas por publicação.

MITRE IDs citados são distintos de inferências. O catálogo local fornece nomes
e táticas. As regras usam as definições oficiais de
[Phishing](https://attack.mitre.org/techniques/T1566/),
[Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/) e
[Web Portal Capture](https://attack.mitre.org/techniques/T1056/003/).
Uma inferência indica compatibilidade com a descrição, não confirmação da execução.

## Correlação e contagens

`server/phishingDataset.js` prioriza uma campanha do catálogo explicitamente
mencionada na publicação. Caso contrário, preserva o `storyId` do correlacionador
do ETL. Sem vínculo, a publicação permanece individual. Duas publicações com a
mesma marca, técnica, malware ou ator não são automaticamente o mesmo evento.
Um grupo não equivale necessariamente a uma campanha confirmada.

Publicações são deduplicadas por URL. Contagens de campanhas/eventos, fontes,
meses e MITRE são calculadas sobre o mesmo recorte. Uma publicação pode conter
múltiplas técnicas; somar técnicas não equivale a contar publicações únicas.
O resumo de um grupo é o texto de sua publicação mais recente, não uma síntese
validada de todas as fontes. O workbook preserva os links de todas as publicações.

## Recortes privados

`GET /api/phishing/reports` exige sessão e o mesmo acesso do arquivo de notícias.
Perfis são carregados exclusivamente pelo dono da sessão, com `private, no-store`.
O recorte explica coincidências de setor, região, tecnologia, marca ou ator fixado
no perfil. Isso indica relevância para a organização, não que ela foi vítima.
Não há nomes ou premissas de organizações particulares embutidos no catálogo.

## Histórico e limites

O ETL usa `feed-v6`; metadados de phishing têm versão `phishing-v1`. No início do
servidor o histórico é reclassificado uma vez por versão usando título, resumo e
corpos já disponíveis no cache. URLs, datas, vínculos e `archivedAt` são preservados;
uma falha de gravação não avança o estado em memória. Não são feitas requisições
em massa para recuperar textos antigos. Novas coletas persistem os campos e
evidências extraídos. O texto completo permanece no cache de artigos.

Publicações antigas podem ter somente o título, e nem todos os corpos foram
coletados. Campos sem evidência são **Não identificado**. O pipeline não importa
automaticamente a planilha de referência, não reproduz seus números e não
completa atribuições, campanhas ou TTPs por suposição. A cobertura das regras
e a correlação ainda podem exigir revisão do analista.
