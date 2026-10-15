# Camada editorial de IA e perfis de cliente: avaliação

Proposta avaliada em 15/10/2026 contra `orgProfiles`, `orgThreatModel`,
`weeklyReports` e o escopo das observações de `iocIntelligence`. Este documento
registra decisões propostas; não habilita IA, canais de entrega nem novos acessos.

## Prontidão de integração verificada em 15/10/2026

- **IA já implementada:** análise sob demanda de notícias e narrativa da edição
  diária via OpenRouter, além da geração de boletins pelo worker. A análise tem
  fallback quando a chave/provedor não está disponível. Código implementado não
  comprova que todas as chamadas em produção estejam usando um LLM.
- **Semanal implementado:** ranking de candidatas, escolha humana e exportação;
  isso ainda não é o agente editorial por cliente proposto neste documento.
- **Piloto editorial dentro da plataforma:** a base de notícias, evidências e
  seleção já permite avançar. Validar provedor, citações e custo em amostra antes
  de ampliar o uso; não bloquear coleta ou correlação pela disponibilidade da IA.
- **Telegram pessoal:** a implementação posterior está descrita em
  [telegram-assistant.md](telegram-assistant.md): webhook, vínculo privado,
  consultas à base, briefing diário com ativação explícita, fila persistida e
  confirmação de entrega. Ainda depende de criar/configurar o bot e validar
  entrega real. O usuário autorizou o canal pessoal e seu envio automático.
  Relatórios ainda usam conta/semana; separar por perfil/workspace antes de
  atender clientes diferentes. Esse canal não conclui a proposta multicliente.

## Direção

Coleta e enriquecimento públicos compartilhados; cálculo local de relevância por
cliente; IA editorial sobre candidatos fundamentados; aprovação antes da entrega
externa. Isso aproveita a base unificada e evita multiplicar chamadas por cliente.

## Diferenças entre a proposta e o código atual

| Tema | Situação verificada | Evolução necessária |
| --- | --- | --- |
| Ativos | Vendor/produto; até 100 ativos e 10 perfis por conta | Identidade estável do ativo, criticidade, exposição e opcionalmente versão; migração preservando valores desconhecidos |
| Relevância | Threat model cruza setor/região/atores; parte do filtro de notícias roda no navegador | Resultado determinístico persistido no servidor, com regra, revisão do evento, ativo e evidência do vínculo |
| Semanal | Relatórios e seleções usam chave `(owner, week)`; plano tem um perfil selecionado por conta | Chaves por conta e perfil/workspace, inclusive jobs, seleções, revisões e exportações; impedir sobreposição de clientes |
| Seleção | 25 candidatas gerais e 25 de IA; até 10 gerais e 5 de IA | Manter esses limites já pedidos pelo usuário; a sugestão de oito não substitui o requisito |
| Inventário | Notícias públicas globais; observações de APIs podem pertencer a um dono | Compartilhar somente evidências públicas; manter achados privados, chaves, stack, vereditos e resultados de cliente isolados |
| Entrega | Seleção editorial e snapshots não comprovam envio | Histórico próprio, aprovação, destinatário/canal autorizado e confirmação de entrega |

## Relevância e urgência

O vínculo deve explicar o que se sabe: produto identificado, versão afetada
confirmada ou não informada, criticidade, exposição, presença no KEV e evidência
da exploração. Match só por fabricante não confirma que o ativo está vulnerável.
PoC no GitHub não prova exploração ativa. EPSS é probabilidade estimada de
exploração, não prova de comprometimento nem confiança do match.

Exposição deve aceitar `desconhecida`, além de sim/não. Ativos antigos não podem
virar internos ou pouco críticos por ausência de dados. Score alto de phishing
continua sendo candidato à investigação, separado de veredito malicioso.

A proposta combina “nada sai sem aprovação” com “alerta urgente direto da regra”.
Separar alerta interno para o analista de envio externo resolve a ambiguidade:
ambos podem ser gerados automaticamente; envio externo permanece pendente de
aprovação. Uma futura política automática exige autorização explícita por
workspace, canal e tipo de alerta. Nenhuma integração é autorizada pelo anexo.

## Histórico, isolamento e custo

O histórico registra evento e revisão, candidato, perfil/workspace, motivos,
conteúdo aprovado, analista, horário, canal e resultado. Chave de idempotência e
outbox persistente evitam duplicatas em retries. Uma revisão material pode virar
atualização; o mesmo evento inalterado não volta como novidade todos os dias.
Seleção, aprovação e entrega são estados distintos.

Cache e jobs precisam incluir workspace, revisão do perfil, versão da regra,
revisão do evento e idioma; editor acrescenta versão de prompt/modelo. Calcular
somente revisões novas/alteradas. Falha ou orçamento de IA esgotado mantém o
rascunho determinístico disponível, sem bloquear coleta, consulta ou exportação.

Redação de notícias públicas pode ser reutilizada entre perfis. Justificativa
privada e exemplos editoriais ficam no escopo do cliente. Credenciais e limites
de API respeitam a origem do acesso; evidência privada não é promovida à base
global. A migração de workspace precisa testar busca, detalhe, export, worker,
relatório e canal com IDs de outro cliente.

## Contrato da IA editorial

- Entrada mínima: evidência pública e recorte necessário do candidato. A simples
  ocultação do nome não torna a combinação de produtos/setor/região anônima.
  Preferir gerar a redação pública uma vez e acrescentar a justificativa por
  ativo localmente; qualquer contexto privado enviado a provedor é decisão explícita.
- Texto coletado é conteúdo não confiável. O editor não recebe ferramentas de
  navegação, envio, mudança de perfil ou acesso a chaves; responde em esquema
  validado com IDs de candidatos/evidências permitidos.
- Não criar CVEs, IOCs, vínculos, urgências ou fontes. Item sem citação válida
  falha a validação e retorna ao rascunho para revisão.
- Guardar entrada, hashes, versões, saída, custo e edição aprovada. Versionar o
  prompt permite auditoria; não garante saída idêntica em nova execução do LLM.
- Exemplos não significam aprendizado automático: seleção revisada alimenta uma
  avaliação e, quando autorizado, exemplos recuperados no mesmo workspace.

## Sequência proposta

1. Concluir medição/estabilidade dos jobs e definir isolamento por cliente.
2. Acrescentar criticidade/exposição aos ativos e persistir relevância local
   explicável; preservar a seleção manual já existente.
3. Separar relatórios por perfil/workspace e criar histórico/aprovação/outbox
   antes de ligar canais de entrega.
4. Piloto editorial diário em modo de sugestão: três a cinco itens, com avaliação
   por perfil e período, sem envio automático.
5. Aplicar o mesmo contrato ao semanal: 25 candidatas por grupo, seleção humana,
   até 10 notícias e cinco de IA. Canal externo vem após configuração autorizada.

Medir precisão dos matches, itens relevantes omitidos, citações sustentadas,
aceitação/edição da seleção, tempo economizado, custo e duplicação de entrega.
Comparar com o ranking determinístico usando semanas separadas dos exemplos.
Só medir concordância da seleção pode esconder fatos incorretos e notícias omitidas.
