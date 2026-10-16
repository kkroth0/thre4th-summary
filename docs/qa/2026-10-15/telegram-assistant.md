# QA do assistente de inteligência e Telegram

Revisão funcional inicial 7773e41. Bot real ainda não criado pelo usuário;
nenhum token Telegram real configurado e nenhuma entrega real confirmada.
Mensagens nos testes usam transporte simulado. Não confundir testes com ativação.

## Verificação local

- 770 testes backend aprovados antes do teste HTTP adicional; este também
  aprovado, incluindo startup real do backend em processo de teste isolado.
- Rotas: ausência de sessão → 401; conta sem premium → 403; origem externa →
  403; consulta autenticada recupera notícia arquivada sem bot; token inválido
  é recusado antes de chamada externa; assinatura de webhook inválida → 401,
  inclusive com payload UTF-8 superior a 10 KB no parser próprio de 64 KB.
- Vínculo privado com nonce expirável/uso único; grupos, bots e outro chat
  recusados. Update duplicado e ticks concorrentes produzem uma resposta.
- Desconexão durante geração e retirada de acesso impedem entrega posterior.
- Agendamento exige opt-in, aguarda o próximo horário selecionado e mantém
  deduplicação diária após reinício. Janela do briefing: últimas 24 horas.
- 429 respeita retry_after e reutiliza o texto salvo; timeout de envio é
  uncertain, sem reenvio silencioso. Reinício recupera processamento que ainda
  não enviou e marca envio interrompido como não confirmado.
- Cota de IA isolada por conta; consultas locais não chamam provedores de
  inteligência. Cache por conta/geração/opção de IA e compartilhamento da
  execução simultânea verificados.
- Validador rejeita fonte desconhecida e CVE/IP/hash não sustentado no trecho
  citado. Falha/budget de IA mantém resumo local; isso não certifica todos os
  fatos gerados por modelo.
- TypeScript, lint dos arquivos alterados e build frontend aprovados. Avisos
  existentes do build: Browserslist antigo e chunks de exportação grandes.

## Base unificada

newsInventoryAudit compara todas as publicações arquivadas com o inventário:
marca de processamento, observações por indicador normalizado, vínculos de
ator/malware/CVE, nomes registrados mesmo sem IOCs e evidências antigas
indevidas. Só lê observações globais de notícias, sem expor observações
privadas. Testes incluem fonte sem IOCs/score zero e falhas deliberadas de
sincronização; observação de outra conta não mascara ausência global.

A auditoria é de consistência, não de precisão semântica. A verificação anterior
do evento Ivanti encontrou advisories de outros produtos no agrupamento;
correção das versões classificadas como IP não resolve essas uniões. A
qualidade dos eventos permanece uma limitação. O seletor editorial posterior
preserva temas com CVEs de foco distintas mesmo dentro do mesmo storyId.

## Publicação e verificação real

Release inicial 7773e41: [CI 38825684763](https://github.com/kkroth0/thre4th-summary/actions/runs/38825684763)
aprovada com 771 backend, 249 frontend e sete testes de marca. TypeScript/build
aprovados e dezesseis avisos de lint existentes, sem erros. Gitleaks aprovado;
Trivy/OSV/npm audit continuam falhando com alertas de dependências preexistentes
(nenhuma dependência foi adicionada/atualizada nesta implementação).
[VPS 38825914779](https://github.com/kkroth0/thre4th-summary/actions/runs/38825914779)
e [Cloudflare 38825914461](https://github.com/kkroth0/thre4th-summary/actions/runs/38825914461)
concluídos, SHA do backend conferido.

[Auditoria 38826225069](https://github.com/kkroth0/thre4th-summary/actions/runs/38826225069),
23:54:12Z, geração 52: 7.754 publicações, todas com marca de processamento;
360 com IOCs válidos, 3.574 menções normalizadas e 3.379 indicadores distintos
vindos de notícias; 8.092 vínculos esperados de ator/malware/CVE. Zero
observações/vínculos ausentes ou antigos, entidades não registradas ou notícias
sem marca de processamento. Dez menções não aceitas pelo normalizador permanecem
na evidência arquivada, fora do inventário operacional. Snapshot/backup iguais,
5.249 eventos, sem órfãos ou aliases conflitantes.

Conferência pela interface autenticada: configuração de IA e cifragem prontas,
bot não configurado. /briefing respondeu localmente. A primeira seleção trouxe
páginas estáticas Horizon3 com data inferida; a revisão 3c9d1a5 exclui esses
registros do briefing e ranking recente, mantendo-os pesquisáveis. /ator Lazarus
retornou evidências locais. /malware Mirai revelou nomes repetidos de IDs de
origem; a revisão seguinte reúne rótulos exatamente iguais na consulta,
preserva variantes e oferece ID explícito para ambiguidade de identidade.

Em 16/10 às 00:01:59Z (15/10 às 21:01 em Fortaleza), /buscar Mirai com IA
produziu resposta real do OpenRouter, com três itens e referências válidas
N1/N3/N4. Diferenciou discussão teórica de IA/IoT de atividade observada. O
contador passou de zero a uma tentativa do dia, sem chamar APIs de IOCs.
Evidência visual em assistant-ai-production.png. Esse teste não é uma
validação independente de todos os fatos dos relatórios ou das sínteses.

Revisão local final: 776 testes backend aprovados. Um teste HTTP da suíte
paralela atingiu o orçamento curto de startup sob carga no Windows; a espera
passou a usar deadline limitado de 45 s e timeout por tentativa, preservando
todas as verificações de autenticação/escopo. Suíte completa passou na repetição.

## Revisão final publicada

Runtime a26f7c7: [CI 38827523450](https://github.com/kkroth0/thre4th-summary/actions/runs/38827523450)
aprovada, 776 backend e 256 frontend/marca; TypeScript/build aprovados, 16 avisos
de lint existentes e zero erros. [VPS 38827769818](https://github.com/kkroth0/thre4th-summary/actions/runs/38827769818)
e [Cloudflare 38827769928](https://github.com/kkroth0/thre4th-summary/actions/runs/38827769928)
concluídos; SHA do backend conferido nos metadados da publicação. A varredura
de dependências mantém os alertas preexistentes, separada da CI funcional.

Interface de produção atualizada e conferida na conta autorizada:

- /malware Mirai: quatro IDs com o mesmo rótulo, 71 IPs, dez domínios, 1.045
  SHA256 e 1.230 publicações/referências, com valores deduplicados e variantes
  ELF/Windows apresentadas separadamente. Referências incluem ThreatFox e
  MalwareBazaar. Não é uma afirmação de atividade/posse atual desses endereços.
- /malware Mirai (ELF): variante separada, 82 SHA256 e 83 referências. A ausência
  de IP/domínio nesse recorte é exibida como zero, sem inventar associação.
- IP público já coletado no caso Ivanti: seis evidências, notícias e OTX;
  entidade de ator e CVE recuperadas da evidência salva. Nenhuma chave ou
  referência de pulso potencialmente privada foi incluída nos screenshots.
- /cve CVE-2026-76519: CVSS 9.8, CRITICAL, KEV sim, EPSS explicitamente não
  informado, referências Cisco/CISA. A primeira espera curta do seletor de
  navegador expirou; a consulta concluiu e a interface apresentou a resposta.
- /briefing após a correção: Unit 42, inclusões CISA KEV, Silent Lynx e resposta
  a incidente no Cisco Secure Email Gateway; páginas estáticas com data
  inferida da coleta não apareceram. Data de coleta não foi promovida a publicação.
- Contador de IA manteve uma chamada após os reinícios/deploys.
- Webhook público sem segredo: 401 após publicação, sem desafio/intersticial
  do proxy. Uma chamada durante o restart havia respondido 502; a verificação
  foi repetida após conclusão e healthcheck. Não comprova entrega Telegram real.

Evidências públicas revisadas: assistant-ai-production.png,
assistant-ai-top-production.png e assistant-mirai-production.png.

[Auditoria final 38828098302](https://github.com/kkroth0/thre4th-summary/actions/runs/38828098302),
16/10 às 00:13:22Z (15/10 às 21:13 em Fortaleza), geração 54: 7.754 publicações
processadas, 3.574 menções de IOCs normalizadas, 3.379 valores distintos e 8.092
vínculos esperados. Zero ausências, vínculos antigos ou nomes não registrados;
5.247 eventos; comparação de snapshot e cópias de recuperação iguais, sem
órfãos, duplicatas de fonte ou aliases conflitantes. As dez menções recusadas
pelo normalizador continuam separadas do inventário operacional.

Entrega Telegram real permanece pendente: o usuário precisa criar/configurar
o bot e iniciar a conversa pelo vínculo autorizado. Briefing automático segue
desabilitado. Não foi criado um bot fictício nem registrado envio sem confirmação.
