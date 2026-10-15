# Domínios semelhantes na investigação

A consulta de domínio ganhou a aba **Domínios semelhantes**, ao lado de Subdomínios. Variações de TLD, omissão e troca de letras são verificadas passivamente. A lista contém somente nomes com evidência DNS (A, AAAA ou NS), com pivô para investigar o resultado e exportação JSON. A semelhança não atribui propriedade nem malícia.

O nome registrável usa a public suffix list (`tldts`), inclusive `.com.br` e `.co.uk`. Rótulos IDN permanecem em punycode e não recebem mutações de letras. A consulta tem limite de 32 candidatos, seis verificações concorrentes e prazo de 6,5 segundos para a fase DNS. Somente resultados observados recebem RDAP, até 12, com seis consultas concorrentes e timeout de três segundos por chamada. O backend compartilha chamadas simultâneas por domínio base e mantém até 128 resultados em cache: seis horas para resposta completa, cinco minutos para parcial e um minuto para indisponibilidade. No máximo três buscas diferentes ficam em andamento.

Registrador e expiração vêm dos registros RDAP quando disponíveis. **Consultar WHOIS** por linha usa a integração Who.is existente, somente mediante clique; não há consulta paga automática para cada variação. O JSON inclui evidências, escopo, horário e resultados parciais. TLD sem RDAP ou campo ausente não recebe informação inventada. Um domínio registrado sem DNS pode não aparecer; ausência na busca não significa disponibilidade para registro.

Teste real local: `votorantimcimentos.com`, 32 candidatos, aproximadamente 1,8 segundo, encontrou `.com.br`, `.co` e `.cn`. `.com.br` retornou expiração em 29/05/2030 via RDAP. Duas verificações DNS tiveram falha parcial, indicada na resposta. Os domínios encontrados não foram acessados por HTTP.

Validação automatizada: geração limitada/PSL/IDN/entradas inválidas; DNS IPv4/IPv6 e NS sem endereço; falha de registro preservando DNS; cache e coalescência; limite de consultas de registro e interrupção da fase DNS. Os testes completos do backend passaram (663); regressões de agrupamento de notícias passaram (37 testes do módulo). TypeScript e lint foram executados nos arquivos alterados.

Durante a navegação entre o panorama de malware e uma notícia, a tela ficou em branco devido a uma entidade nula em uma coleção. O feed agora filtra slots de entidade inválidos, preservando metadados ausentes para compatibilidade com a correlação; o frontend normaliza as associações do cache, da resposta e do agrupamento. As regressões verificam que atores, malwares e campanhas válidos continuam presentes.

## Produção

Código publicado em `ef84cda3e997b039a3a3caf050f56cb9077b136d`. [CI](https://github.com/kkroth0/thre4th-summary/actions/runs/38659886042), [VPS](https://github.com/kkroth0/thre4th-summary/actions/runs/38660032601) e [Cloudflare Pages](https://github.com/kkroth0/thre4th-summary/actions/runs/38660032787) concluíram com sucesso. A checagem pública de saúde retornou HTTP 200 após a janela de reinício (houve 502 temporário durante o deploy).

Na conta autenticada, a versão final verificou os 32 candidatos sem falhas e encontrou quatro domínios: `votorantimcimentos.com.br`, `.co`, `.cn` e `.com.tr`. O clique em WHOIS do `.cn` completou o registrador **北京新网数码信息技术有限公司** e a expiração **22/01/2027**. O filtro `.cn` retornou uma linha; removê-lo restaurou as quatro. O clique no nome abriu a investigação do `.cn`, reaproveitando o WHOIS já consultado.

O botão JSON gerou `votorantimcimentos.com-similar-domains.json`. A leitura do arquivo baixado confirmou quatro registros, 32 verificações, zero falhas e os campos WHOIS do `.cn` (incluindo expiração `2027-01-22T09:11:00Z` e fonte Who.is). Não foram feitas consultas WHOIS automáticas às demais variações.

Prova visual: `similar-domains-browser.png`. O reteste de malware também abriu Mirai com 25 IPs, 7 hosts, 237 SHA256 e 210 publicações; o falso IP de firmware `2.6.0.4` não apareceu na tabela completa. Prova: `malware-mirai-linked-browser.png`.
