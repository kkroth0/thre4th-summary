# Boletim global ThreatSumm4ry

O boletim do site é uma revista mundial de segurança cibernética. Não tem cliente destinatário, seleção de organização ou prioridades baseadas em ativos de um perfil. O aplicativo local permanece separado.

## Identidade e exportação

`src/utils/weeklyThreatSumm4ry.ts` constrói um PowerPoint A4 vertical nativo, com Aptos Display nos títulos e Aptos no conteúdo e nos dados, azul profundo, laranja e branco. A capa usa arte original e o logotipo ThreatSumm4ry. Sumário navegável, matérias em duas colunas, síntese analítica em destaque, três pontos de atenção e painéis de dados compõem uma identidade própria. O exportador não lê, recolore ou reutiliza o template de referência. Gráficos e textos permanecem editáveis. Manchetes e referências têm links.

A exportação exige redação concluída a partir dos artigos lidos e recusa relatórios direcionados a clientes. Até dez matérias gerais e cinco de IA são escolhidas pelo analista entre as sugestões do período. Não há corte automático de parágrafos.

## Dados e redação

O serviço do site usa `scope: global` e `.weekly-global-reports.sqlite`, separado do histórico anterior. A seleção e os rascunhos continuam privados por conta. Nenhum rascunho antigo direcionado a cliente é reutilizado como publicação global. Mudanças de versão editorial invalidam a redação anterior e exigem nova geração. A versão editorial e as chaves de cache incluem o escopo. A versão editorial 3 solicita de três a quatro parágrafos desenvolvidos de até 420 caracteres por matéria, com mecanismo, evidência, consequência e limites. Fontes insuficientes bloqueiam a matéria em vez de gerar preenchimento genérico. Os três pontos de atenção aceitam até 180 caracteres cada.

Os gráficos de ransomware usam todos os países e setores disponíveis. LATAM e Brasil permanecem campos regionais adicionais, sem representar o total mundial. O histórico mantém períodos sem cobertura como lacunas. Alegações não equivalem a incidentes confirmados. O mapa mundial usa a geometria pública já distribuída com a plataforma. Todos os setores disponíveis aparecem em páginas balanceadas, com até 14 categorias por página. Uma amostra identificada das 12 publicações mais recentes mostra organizações, países, grupos e datas; o JSON mantém a listagem completa. A tabela da interface carrega cinquenta registros por etapa.

As três CVEs prioritárias consideram repercussão e gravidade em qualquer tecnologia. As três exploradas exigem KEV. A pontuação editorial global distribui 40 pontos para impacto, 30 para evidências, 23 para qualidade e 7 para atualidade, sem peso por cliente.

## Validação

Testes de seleção, persistência, redação e rejeição de escopos incorretos, verificação de tipos, build e conferência da interface no navegador. As prévias de design usam dados demonstrativos e não constituem uma edição factual. A revisão de uma edição exportada deve conferir encaixe e estrutura no PowerPoint.

O filtro editorial avalia o idioma do título separadamente do resumo e do corpo, para que texto em inglês não mascare um título não suportado. A mesma política é aplicada aos snapshots e seleções já salvos, antes da exibição, exportação ou redação. Coberturas em idioma suportado podem representar o mesmo evento; publicações em inglês de fontes asiáticas continuam elegíveis. A coleta e o acervo originais permanecem disponíveis.


## Composição editorial v4

A capa apresenta chamadas reais e links para as páginas. O sumário conecta capítulos e destaques. O editorial interpreta a semana e diferencia NVD, KEV e alegações de ransomware. As páginas de CVEs exibem mecanismo, consequência, correção publicada, exploração e fontes técnicas. O capítulo de ransomware inclui panorama mundial, mapa, setores, organizações citadas e histórico; o capítulo de IA inclui categorias, ferramentas e gravidade. Páginas sem registros de CVEs não são acrescentadas só para preencher o documento. Referências e setores são distribuídos para evitar continuações quase vazias.

O encaixe da matéria considera a extensão da manchete e do lead. O texto e os dados são nativos do PowerPoint; o mapa é uma imagem vetorial gerada da geometria geográfica. Links permanecem ativos sem sublinhado tipográfico automático. O campo opcional `previewNote` identifica demonstrações baseadas em material de referência; o serviço de produção não o adiciona aos relatórios normais.


## Refinamento visual v5

A publicação usa uma hierarquia tipográfica sem serifa em todas as seções. Nas matérias, a interpretação aparece ao lado de uma marca vertical e as três implicações compõem uma faixa contínua, com textos mais largos. As CVEs usam blocos com identidade do produto, CVSS em destaque, estado de exploração, mecanismo e correção em colunas. O painel de IA usa indicadores com contraste, categorias com quantidades legíveis e uma coluna de ferramentas com CVSS e IDs de referência. Os rankings horizontais exibem os maiores valores no topo. Os dados, textos e limites editoriais permanecem os mesmos durante a comparação de layout.
