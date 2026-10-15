# Continuação: sugestões e persistência das notícias

## Escopo da release

Entrega principal `2cb634930baf60d6a1605f701e34d1fa90e08425`, complementada por
backfill dos nomes das observações anteriores e agrupamento por ID estável.
Revisão final de código: `f58082aab3aa462473d70bcd432e9b2bd90a79de`.

- Sugestões privadas de termos de marca a partir de notícias relacionadas ao
  perfil. A ação de aceitar altera apenas as marcas desse perfil, respeita o
  limite de oito e não inicia uma chamada extra às fontes externas.
- Espelhamento transacional do arquivo e dos eventos no SQLite do inventário,
  com revisões e comparação dos payloads/IDs/aliases. JSON segue como leitura
  principal durante a auditoria da migração.
- Retenção de corpos coletados por URL/hash, com importação do cache existente
  e recuperação após poda. Não reconstrói texto já perdido antes desta release.
- Registro de nomes e aliases globais/privados, sem mesclar IDs ambíguos.
- Avaliador offline PT/EN com versão/modelo/hash e rótulos independentes.
  Vetores artificiais nos testes não demonstram qualidade de modelo.

## Testes locais

700 testes backend passaram. TypeScript e lint dos arquivos alterados passaram.
Após acrescentar a regressão de migração de nomes legados, o
[CI final 38737635956](https://github.com/kkroth0/thre4th-summary/actions/runs/38737635956)
aprovou 701 testes backend, 242 frontend, sete de internacionalização,
TypeScript e build, sem erros de lint (16 avisos existentes).
O smoke com servidor real confirmou autenticação, isolamento de perfis,
cache privado, sugestões, aceite explícito, alteração da marca e remoção da
sugestão. A configuração do perfil foi restaurada dentro do teste isolado.

Testes de falha confirmam rollback dos dois snapshots SQLite, nenhuma revisão
para snapshot idêntico, preservação de revisões retiradas por retenção, bloqueio
de piloto com fontes órfãs/aliases em conflito, corpos após poda, fingerprints
incompatíveis, aliases privados e limite/falha de gravação de perfil.

## Conferência inicial em produção

Os deploys [VPS 38736667468](https://github.com/kkroth0/thre4th-summary/actions/runs/38736667468)
e [Cloudflare 38736667494](https://github.com/kkroth0/thre4th-summary/actions/runs/38736667494)
concluíram. O [CI 38736455806](https://github.com/kkroth0/thre4th-summary/actions/runs/38736455806)
aprovou 700 testes backend, 242 frontend, sete de internacionalização, TypeScript
e build; lint sem erros e com 16 avisos existentes.

A [auditoria de persistência 38737062696](https://github.com/kkroth0/thre4th-summary/actions/runs/38737062696)
conferiu **7.403 publicações, 4.945 eventos e 582 corpos preservados**.
As cópias são idênticas: zero registros ausentes, divergentes ou extras; zero
fontes órfãs e aliases conflitantes. Esse primeiro resultado foi obtido após a
importação inicial, não equivale a múltiplos ciclos completos validados.
A [auditoria de phishing 38737068801](https://github.com/kkroth0/thre4th-summary/actions/runs/38737068801)
também passou: dez semanas reconstruídas, 60 ciclos concluídos/um erro histórico
e nenhuma amostra suficiente de CT.

O navegador autenticado mostrou seis sugestões reais no perfil existente.
Foi aberta a evidência de uma sugestão com três publicações e três fontes;
os links, técnicas e motivos de relação com o perfil apareceram corretamente.
Não foram aceitas nem dispensadas sugestões na conta real. O aceite e sua
persistência foram testados no smoke isolado; a seleção original do perfil
(vazia) foi restaurada após a inspeção. Console sem erros. A captura da tela
ficou local, sem publicar configurações de monitoramento do perfil no Git.

## Resultado final após coleta e revisão de nomes legados

Deploys da revisão final concluídos:
[VPS 38737981185](https://github.com/kkroth0/thre4th-summary/actions/runs/38737981185)
e [Cloudflare 38737980799](https://github.com/kkroth0/thre4th-summary/actions/runs/38737980799).

A [auditoria final 38738487235](https://github.com/kkroth0/thre4th-summary/actions/runs/38738487235)
conferiu **7.410 publicações e 4.949 eventos**, com cópias idênticas, zero
fontes órfãs e zero aliases conflitantes. O histórico mostrou três comparações
consistentes (12:44:45, 12:49:43 e 12:55:04 UTC), incluindo a coleta real que
acrescentou sete publicações/quatro eventos. Foram preservadas 64 revisões;
a última repetição de snapshot não criou alterações extras. Os 582 corpos
continuaram retidos no SQLite.

A [auditoria final de phishing 38738494999](https://github.com/kkroth0/thre4th-summary/actions/runs/38738494999)
também passou: dez semanas/489 publicações reconstruídas, 61 ciclos concluídos e
um erro histórico. No último ciclo, 218/264 fontes estavam saudáveis; houve 558
corpos em cache, 40 tentativas de coleta de corpo, todas com falha, e 1.122
adiadas. A retenção não resolve essas falhas das fontes externas.

Após o deploy final, a interface foi recarregada e voltou a mostrar as seis
sugestões com referências, sem erros no console. A captura local foi atualizada
e a seleção de perfil restaurada. Nenhuma marca, veredito ou ticket real foi
alterado na validação. Nenhum resultado de precisão/antecedência de CT foi
inferido: a amostra segue vazia. Não houve ativação de merges semânticos.

## Limites de ativação

O espelhamento não troca automaticamente a origem das leituras. A auditoria de
produção confere a cópia sem gravar no banco. O avaliador PT/EN não participa do
correlacionador em produção e precisa de vetores de modelo fixado e amostra
revisada. CT segue condicionado a amostra e validação prospectiva. O scan de
dependências continua com os alertas anteriores; nenhum pacote foi alterado.
