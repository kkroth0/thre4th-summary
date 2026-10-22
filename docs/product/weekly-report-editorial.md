# Padrão editorial do boletim semanal

Referências fornecidas pelo usuário em 22/10/2026: `Boletim_Semanal_EY_Edicao02 (1).pdf` e `Boletim_Semanal_EY_Ultrapar_22-10-2026.pdf`. A edição 02 é a referência mais consistente para a construção jornalística. O Ultrapar complementa a estrutura com o recorte do destinatário e a apresentação de seis vulnerabilidades.

Este documento registra a orientação de escrita aprovada pelo usuário. Sua existência não significa que o gerador já aplique todas as regras automaticamente. A análise é editorial, sem validar as alegações ou os números dos PDFs. Os exemplos não autorizam reutilizar dados de outra edição nem dados internos de outro cliente.

## Identidade e voz

Somos uma revista semanal de segurança cibernética para um leitor executivo. O texto acompanha o leitor do acontecimento à sua consequência, com contexto suficiente para compreender a relevância. A precisão técnica sustenta a narrativa, mas o vocabulário precisa ser acessível a quem não trabalha em segurança.

O tom é humanizado, executivo, explicativo e sóbrio. Executivo não significa telegráfico. Os parágrafos desenvolvem uma ideia e se conectam naturalmente. A notícia pode ter detalhes técnicos quando eles explicam uma consequência concreta: interrupção da operação, acesso de fornecedores, exposição de dados, perda de acesso a serviços ou abuso de credenciais.

Evitar frases de efeito, adjetivos de urgência repetidos, siglas sem explicação, caixa alta em títulos e a mesma recomendação reaproveitada em matérias diferentes. A informação específica deve sustentar a importância do caso.

O idioma é português brasileiro. Usar “equipe”, “arquivos”, “disponibilização” e “interromper”, por exemplo. Preservar nomes de produtos, grupos, versões e identificadores. Explicar termos como MFA, OAuth, MCP e DLL side-loading na primeira ocorrência relevante, sem transformar a matéria em um glossário.

## Construção de cada seção

### Capa e período

Identificar edição, data de publicação, período coberto e destinatário. A capa anuncia a revista, sem promessas de cobertura integral. Distinguir semana em andamento de semana encerrada. A data de fechamento deve acompanhar os dados utilizados.

### Sobre o boletim

Apresentar o propósito e o percurso da leitura em prosa institucional acolhedora. Explicar o que o leitor encontrará e como fato, análise e pontos de atenção se relacionam. As limitações cabem em uma nota breve, sem ocupar toda a abertura. Evitar descrever banco de dados, rotinas de coleta e detalhes da implementação.

### Sumário e divisórias

Usar títulos e chamadas em português, com o acontecimento central de cada matéria. O nome da ferramenta sozinho não explica por que ler. Divisórias antecipam o conteúdo da seção e mantêm a navegação correta após inclusões ou remoções.

### Resumo executivo

Abrir com uma leitura da semana: o que mais merece atenção e por quê. Selecionar os acontecimentos que sustentam essa leitura e conectar as seções. Uma boa síntese permite compreender a edição antes de percorrer os gráficos e as matérias.

Os números apoiam a história, sem substituí-la. Cada parágrafo deve acrescentar uma interpretação: onde se concentrou a atividade, que tipo de acesso apareceu ou qual dependência de negócio merece acompanhamento. Evitar apenas repetir os indicadores do painel.

O nível de ameaça precisa de critérios explícitos e evidências. A presença de CVEs no KEV, isoladamente, não mede exposição do destinatário. Não declarar ausência de incidentes, citações ou comprometimento sem uma verificação que sustente exatamente essa afirmação.

### Título de uma notícia

Construir uma manchete informativa: quem fez ou sofreu o quê, com a consequência mais relevante. Traduzir o título da fonte com fidelidade, sem copiar mecanicamente a sintaxe inglesa. Usar caixa de frase e nomes próprios com sua grafia normal. Não usar identificador CVE como substituto da explicação do fato.

### Abertura da notícia

Apresentar o acontecimento principal, os envolvidos, a fonte e a data quando fizerem diferença para a compreensão. Situar o leitor antes de aprofundar a técnica. A abertura não precisa conter todas as versões ou todos os identificadores.

O primeiro parágrafo da seção seguinte deve acrescentar informação, evitando repetir a abertura quase palavra por palavra.

### Contexto e análise

Explicar por que o caso merece espaço nesta edição. Desenvolver a relação entre a técnica e o negócio: qual acesso ela oferece, que informação pode alcançar, que dependência operacional está envolvida e em quais condições isso se aplica.

O vínculo com o destinatário deve vir do setor, da tecnologia confirmada ou de uma relação verificada. Não inserir o nome do cliente em uma frase genérica para aparentar personalização. Se o uso de uma ferramenta não estiver confirmado, essa condição precisa permanecer clara.

Exemplo de construção editorial, sem afirmar exposição de um cliente: “Aplicações de acesso remoto concentram permissões para administrar outros sistemas. Quando esse acesso é comprometido, o alcance pode ir além do servidor inicialmente afetado, especialmente se a mesma conta atende diferentes ambientes.”

### O que aconteceu

Contar a sequência do caso em parágrafos conectados. Apresentar a entrada, o mecanismo relevante, o alcance observado e a resposta conhecida quando a fonte trouxer esses elementos. Selecionar detalhes que ajudem o leitor a compreender a situação.

Traduzir a técnica pela sua função. Uma biblioteca executando comandos pode permitir que o atacante controle o servidor. Uma chave roubada pode manter o acesso mesmo após a troca da senha de um usuário. A consequência deve respeitar as condições descritas na fonte.

Separar o que o pesquisador observou do que considera possível. Distinguir tentativa de exploração, acesso confirmado, retirada de dados e publicação de dados. Não transformar “a empresa não identificou evidências” em uma certeza de que o evento não ocorreu.

Como referência de densidade, uma matéria completa pode ocupar aproximadamente 220 a 400 palavras, conforme o espaço do template e a complexidade. A distribuição entre blocos depende do caso. O limite visual exige reescrita editorial, e não cortes automáticos com reticências que removam condições importantes.

### Pontos de atenção

Manter pelo menos três pontos específicos da matéria. Cada título nomeia um cenário reconhecível; o texto explica onde o risco aparece e por que importa. Não transformar todos os cartões em ordens de atualização, monitoramento e revisão de permissões.

Exemplos de títulos específicos presentes na lógica das referências: “Senhas guardadas no código”, “Acesso de fornecedores” e “Extorsão sem paralisação”. Um cartão normalmente comporta duas frases relacionadas, com cerca de 25 a 45 palavras, ajustadas ao layout.

Quando houver uma ação, apresentar sua finalidade e a condição de aplicação. Evitar “é vital”, “é indispensável”, “prioridade máxima” e “medidas obrigatórias” como substitutos de uma explicação. As orientações técnicas precisam ter suporte na fonte e ser compatíveis com o contexto, especialmente em OT/ICS.

### Dados de apoio e referências de custo

Escolher um indicador que acrescente contexto ao assunto. Um custo médio de pesquisa é uma referência externa, e não o prejuízo do caso ou uma estimativa do impacto no cliente. Identificar fonte, ano, recorte geográfico, setor e unidade quando relevantes.

O padrão visual dos PDFs não obriga a usar um número financeiro em toda notícia. Se a relação for fraca, preferir uma informação verificável sobre alcance, janela de exploração ou comportamento observado. Não reciclar a mesma estatística só para preencher um espaço.

### Ransomware: panorama da semana

Interpretar os dados: onde se concentram as organizações citadas, quais grupos aparecem e qual relação setorial merece acompanhamento. A lista de vítimas e o mapa sustentam essa leitura.

Apresentar as publicações dos grupos como alegações, enquanto não houver confirmação independente. Coincidência de setor não comprova vínculo comercial ou impacto no destinatário. Mencionar ausência de empresas do grupo somente se a busca tiver abrangência suficiente para sustentar essa conclusão.

### Ransomware: histórico e tendências

Ler os gráficos em prosa: posição da semana no histórico, concentração e mudança relevante entre grupos. Diferenciar número de publicações, data de observação e data atribuída ao incidente.

Comparar períodos equivalentes. Uma semana ainda em andamento não demonstra queda de ataques em relação a uma semana completa. Cobertura incompleta também não equivale a zero. Explicar a limitação perto da comparação, sem deixar que uma manchete sugira uma tendência que os dados ainda não sustentam.

### Inteligência artificial

Separar vulnerabilidades em ferramentas de IA, uso de IA por atacantes e comportamento de agentes dentro das organizações. Explicar o papel da ferramenta no caso antes de usar termos como “agêntica”. O leitor precisa entender quais dados, acessos e tarefas ela alcança.

No painel de CVEs, interpretar concentração e gravidade. Um lote de falhas publicado em um único produto pode explicar um pico, sem representar aumento de ataques. Ausência no KEV não confirma ausência de exploração. Relacionar a prioridade ao uso, às versões e à exposição efetiva.

### Vulnerabilidades em destaque

Apresentar as três selecionadas, incluindo Java, PHP e Node.js quando existirem registros aplicáveis no período. Explicar o que é afetado, o que a falha permite e em quais condições. Notas CVSS e identificadores acompanham a explicação, sem dominar o texto.

As correções devem trazer versões verificadas ou o encaminhamento oficial específico. Não inventar versões para completar o cartão. Registrar claramente a origem da nota técnica e manter os links para os advisories e registros.

### Vulnerabilidades exploradas

Apresentar as três selecionadas com confirmação de exploração e diversidade de produtos. Distinguir a data de publicação da CVE da entrada no KEV. Explicar por que o produto e o tipo de acesso interessam a uma organização, sem concluir que ela usa aquele produto.

Uma prova de conceito pública não confirma exploração real. A ausência de uma CVE no KEV também não é prova de ausência de ataques. Atualizações posteriores ao fechamento precisam ser identificadas como tais.

### Encaminhamentos e encerramento

Os encaminhamentos ajudam o leitor a decidir o que precisa de avaliação interna. Devem decorrer dos fatos apresentados. O aviso de limitações e o TLP ficam nos espaços próprios, com redação consistente, sem repetir um parágrafo defensivo em todas as matérias.

## Diferenças identificadas nas referências

- A edição 02 desenvolve melhor a sequência entre fato, mecanismo e consequência. Seus pontos de atenção mudam conforme a matéria e há conexões entre assuntos da mesma semana.
- O PDF do Ultrapar acrescenta contexto em notícias específicas, mas ainda mistura títulos em português e inglês, caixa alta e caixa de frase, além de português brasileiro e português europeu.
- Alguns trechos do Ultrapar repetem o fato inicial no desenvolvimento; outros recorrem a urgência genérica e recomendações que poderiam servir para qualquer notícia.
- Chamadas como “CVEs citadas nas publicações” e “fontes registradas no evento” descrevem o funcionamento da plataforma. Na revista, precisam dar lugar a informação que ajude a compreender o caso, quando existir evidência para isso.
- As referências de custo da edição 02 são um recurso editorial útil quando relacionadas ao tema. Sua repetição em todos os casos não deve se tornar uma regra automática.

## Verificação antes de publicar

1. A abertura permite compreender o acontecimento sem consultar outra página?
2. O desenvolvimento acrescenta contexto em vez de repetir o primeiro parágrafo?
3. O texto explica a consequência de negócio sem presumir exposição do cliente?
4. Há pelo menos três pontos de atenção específicos, sustentados pelo caso?
5. As siglas e os termos técnicos essenciais estão compreensíveis?
6. Manchetes, chamadas e corpo estão em português brasileiro consistente?
7. Datas, números, versões e estados de exploração têm fonte e recorte adequados?
8. As comparações usam períodos e coberturas equivalentes?
9. Os links estão corretos e nenhuma ressalva essencial foi cortada para caber?
10. A edição pode ser lida como uma revista coerente, com interpretações próprias em cada seção?
