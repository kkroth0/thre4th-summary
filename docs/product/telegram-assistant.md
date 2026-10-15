# Assistente de inteligência e Telegram

Implementação de 15/10/2026 a pedido do usuário: consultas sob demanda e envio
automático de briefing pessoal, mediante ativação explícita. O usuário ainda
precisa criar seu bot no BotFather. Código e testes não comprovam entrega real
até configurar o token, vincular uma conversa e receber confirmação do Telegram.

## Ativação

Em Configurações → IA e Telegram, testar a consulta local, abrir BotFather e
criar um bot dedicado com /newbot. Cadastrar o token no campo protegido, gerar
o vínculo de uso único e tocar em Iniciar na conversa privada. O vínculo expira
em dez minutos; outro chat não pode consultar a conta. Ativar o briefing diário,
selecionar a hora de Fortaleza e salvar. O próximo horário posterior à ativação
é elegível; não envia um briefing atrasado imediatamente ao habilitar.

A opção de IA autoriza enviar ao OpenRouter a pergunta e trechos de notícias
públicas selecionadas. Evidências privadas de APIs e consultas a IOCs/perfis
ficam na resposta determinística local, destinada somente ao chat vinculado.
Token cifrado com a chave-mestra existente; nunca retorna ao navegador.

## Consulta e custo

- /briefing: até quatro notícias das últimas 24 horas, ordenadas por relevância,
  KEV/score e data de publicação, deduplicadas pelo evento e tema/CVEs de foco.
  Páginas com data inferida da coleta ou marcadas como não relevantes não
  entram no briefing nem no ranking de menções recentes; continuam pesquisáveis.
  CVEs de foco distintas não são ocultadas somente por compartilhar storyId.
- /briefing semana: mesma seleção para sete dias.
- /buscar termo e perguntas: recuperação lexical no acervo salvo. Não é busca
  semântica por embeddings nem navegação autônoma na internet.
- /ioc valor: observações públicas e da própria conta, referências e entidades,
  sem chamar novamente VT/OTX/AbuseIPDB/etc.
- /ator nome, /malware nome: entidades reconhecidas e evidências por fonte.
- /cve identificador: catálogo local de vulnerabilidades.
- /status: contagens e última sincronização. Perguntas sobre malwares/atores
  mais citados/recentes produzem um ranking local das menções na semana.

Índice de notícias reutilizado por geração do banco; até 128 respostas em cache
por dois minutos, isoladas por conta/revisão/opção de IA. Chamadas simultâneas
iguais compartilham a mesma execução. Quatro fontes por síntese, resumos de até
700 caracteres, vinte CVEs e doze nomes por tipo na entrada da IA; não modifica
as listas completas do banco nem exportações. Saída limitada a 950 tokens.
Teto de trinta tentativas de IA por conta/dia, persistido; até vinte comandos
por hora no bot e vinte prévias por hora na interface. Cache e respostas locais
não gastam chamada de IA. Preço e disponibilidade dependem do modelo/provedor.

OPENROUTER_ASSISTANT_MODEL pode definir modelo específico; o padrão reutiliza
OPENROUTER_MODEL. Ausência de chave, limite esgotado ou erro de geração mantém
o resumo local com fontes. O validador rejeita IDs de fontes desconhecidos e
CVEs/IPs/hashes ausentes do trecho citado; não é prova de ausência de alucinação.
O modelo não recebe ferramentas, credenciais, comandos de escrita ou envio.

## Execução na VPS

O backend existente recebe um webhook HTTPS autenticado por segredo próprio
do Telegram. APP_BASE_URL precisa apontar para a origem pública HTTPS já
encaminhada ao backend. Desenvolvimento HTTP mantém consultas locais, mas não
permite configurar webhook. Não precisa instalar MausBot, outro banco ou novo
daemon. O serviço atual e seu reinício pelo systemd mantêm o worker de entrega.

Conexões, jobs e cota de IA usam tabelas telegram_* no SQLite de inteligência,
já protegido pelas exclusões de deploy/rollback. Ociosidade não faz polling
externo. Webhook grava e confirma rapidamente; um worker assíncrono processa
uma consulta por vez. O agendamento verifica o banco a cada minuto e cria uma
única entrega por conta/dia. O ETL continua independente da disponibilidade do
Telegram/LLM. Instalação atual pressupõe um processo escritor/worker, como os
demais jobs da plataforma.

Update ID e chave diária deduplicam jobs. Resultado fica salvo antes do envio;
429 confirmado respeita retry_after e reutiliza o resultado sem regenerar IA.
Timeout/erro ambíguo de envio fica uncertain, sem retry automático. Isso evita
duplicatas por reenvio cego, sem prometer exactly-once da rede. Estados sent
incluem message_id confirmado; jobs/metadados ficam noventa dias. Mensagens de
grupo, outros chats, bots, assinaturas inválidas e códigos expirados são recusados.
Desconectar revoga acesso local e cancela a fila. Acesso premium é reavaliado
em cada comando/envio; vínculo por organização exige renovar a sessão após
expiração da autorização.

## Limites do piloto

A ingestão de todas as notícias aceitas alimenta o histórico e inventário, mas
RSS incompleto, corpos indisponíveis/adiados, nomes desconhecidos e qualidade
das uniões continuam afetando a cobertura. A auditoria newsInventoryAudit
compara evidências extraídas com o banco; não mede a precisão da extração ou
da autoria. Eventos indevidamente agrupados ainda exigem revisão semântica.
Menção conjunta é associação investigativa. Não inferir autoria apenas por IP
compartilhado ou por malware comum.

Este é um canal pessoal, com conversa privada e briefing geral. Não implementa
despacho para grupos/clientes diferentes, isolamento de relatórios por workspace,
seleção editorial multicliente ou o agente amplo proposto no plano de evolução.

Referências: [Telegram Bot API](https://core.telegram.org/bots/api),
[OpenRouter](https://openrouter.ai/docs/api/reference/overview),
[MausBot](https://mausbot.com/). MausBot foi avaliado como referência, sem
instalação ou concessão de acesso à VPS.
