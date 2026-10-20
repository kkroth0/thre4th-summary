# Aliases de atores e referências onion

O catálogo mantém os IDs existentes. `server/data/actor-sources.json` acrescenta
nomes e referências de MITRE ATT&CK, ETDA e Rapid7, mais os perfis do ICIC e o
repositório `marktsec/Ransomware_Official_Domains`.

Os nomes adicionais aparecem em AKA e nas buscas, no cruzamento das notícias e
na resolução dos nomes retornados pelas APIs. Só entram na atribuição automática
quando há um ator correspondente e o nome não é reivindicado por outro perfil
ou por registros não resolvidos da fonte. Nomes de software não viram novos
aliases de grupos. IDs MITRE desconhecidos não são substituídos por um palpite.

O ICIC combina algumas entidades que o catálogo mantém separadas, como Lazarus
e APT38. Seus nomes entram como associações contextuais, visíveis em
**Detalhes → Nomes nas fontes**, e não alimentam o matcher. Conflitos das outras
fontes também ficam nesse grupo. Aliases legados do catálogo são preservados.

A ETDA informa CC BY-NC-SA 4.0 e data de atualização de agosto de 2025. O usuário
confirmou autorização para uso no produto em 20/10/2026. Essa confirmação e a
licença original ficam registradas no snapshot, junto à fonte e às datas.
Não se copiam descrições ou relatórios completos dessas páginas.

Os sites onion aparecem na aba **Onion** do perfil, com opção de copiar o host,
fonte, referência ao commit consultado e estado informado no repositório.
Endereços históricos, offline e apreendidos mantêm essa distinção. Não há
acesso Tor, consulta DNS, enriquecimento, teste de disponibilidade ou coleta de
conteúdo desses destinos. Contatos, chaves de acesso e parâmetros de URL não
são importados. A lista não é inserida como infraestrutura C2 confirmada.
Grupos não resolvidos unicamente não recebem endereços por semelhança de nome.

No início do servidor, observações existentes com identidades criadas pelas
fontes podem ser vinculadas ao ID canônico quando seu nome corresponder a um
único alias. IDs de atores já catalogados e subgrupos são preservados. A revisão
mantém o vínculo anterior em `observation_revisions`, conserva fonte, payload,
relação e escopo de acesso, e não faz novas chamadas às APIs. O processamento
cede o servidor a cada lote de 200 vínculos e só roda novamente se os aliases
do catálogo mudarem.

Para atualizar o snapshot, execute `node server/scripts/update-actor-sources.mjs`,
revise a mudança e publique. A atualização não executa JavaScript de terceiros,
fixa o README do GitHub em um commit, valida a cobertura mínima de cada fonte e
substitui o arquivo de forma atômica. O servidor usa o snapshot local, sem buscar
essas páginas a cada abertura de perfil. O build principal do catálogo continua
independente: atualizações de MITRE/MISP não removem esta camada complementar.
