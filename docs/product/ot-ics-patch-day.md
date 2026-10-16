# OT/ICS Patch Day

Feature em `/ot-patch-day`, no grupo **Correções**. Período padrão mensal,
considerando o mês corrente em America/Fortaleza. O seletor permite consultar
outros meses. Um aviso entra quando a publicação inicial ou a **última revisão**
informada pelo documento ocorre no mês. Não é reconstrução de cada versão
histórica do aviso.

## Fontes e atualização

- [CISA OT CSAF](https://github.com/cisagov/CSAF): distribuição ROLIE indicada
  no [provider metadata](https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json).
- [Rockwell Automation](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html):
  campos públicos do portal, incluindo Corrected e Workaround. Versões e
  instruções detalhadas permanecem acessíveis no aviso original.
- [Cisco CSAF](https://sec.cloudapps.cisco.com/security/center/csaf_20.xml):
  feed recente, limitado na tela a Catalyst, Industrial e IOS XE. Não há
  promessa de arquivo histórico integral deste fabricante.
- [Schneider Electric CSAF](https://www.se.com/.well-known/csaf/provider-metadata.json):
  [changes.csv](https://www.se.com/.well-known/csaf/changes.csv) e JSONs no
  diretório oficial `.well-known/csaf/`. Não depende do portal HTML que
  respondeu 403. A data do nome do arquivo auxilia somente a descoberta;
  as datas exibidas são as de `document.tracking`.

Os índices são consultados diariamente, com ETag, um refresh por vez e no
máximo 40 documentos novos/alterados por lote. O scheduler verifica pendências
a cada minuto. Falhas aguardam uma hora antes da repetição. Cache normalizado
em `.feed-cache/ot-patch-day.json`, preservado pelo deploy. Até 2.000 documentos
e 16 MiB de payloads normalizados; o HTML integral não é persistido. A Rockwell
é analisada por fragmentos, sem construir um DOM de 9 MB.

Na primeira consulta, o processamento é assíncrono e a tela informa as
pendências. Fontes indisponíveis, documentos com falha e erro de persistência
são explícitos. Dados anteriores sobrevivem a falhas. Recarregar a tela não
ignora o cache nem dispara nova coleta completa.

## Catálogo e aplicabilidade

`server/otAssetCatalog.json` contém somente fabricantes e modelos genéricos
derivados da planilha fornecida. Não contém cliente, local, endereço de rede,
quantidades de equipamentos nem firmware instalado. Rockwell/Allen-Bradley e
Schneider foram normalizados. Descrições ambíguas ficam na lista de revisão.

Correspondência explícita usa nome do produto e `model_numbers` do CSAF.
Fabricante sem modelo correspondente fica identificado como tal. Ausência de
resultado não confirma ausência de vulnerabilidades; presença no catálogo não
promete cobertura integral de todos os fabricantes. A exposição de uma versão
instalada depende de validação operacional fora deste catálogo genérico.

`vendor_fix` ou produto com status `fixed` indica correção publicada. Mitigação
ou workaround sem fix fica em categoria própria; silêncio da fonte fica como
correção não confirmada. Dados de versões, remediações e referências são
preservados. A mera presença de um advisory não significa patch disponível.

KEV/EPSS/CVSS adicionais vêm do catálogo local de vulnerabilidades, com cache
de cinco minutos; não há chamada externa por linha/visualização. Um sinal
ausente permanece desconhecido, não é declaração de CVE fora do KEV.

Uma republicação CISA só é consolidada quando há referência explícita ao
aviso original, fabricante comum e o mesmo conjunto de CVEs. Os dados completos
da republicação e as referências permanecem no resultado/exportação.
Compartilhar somente uma CVE não une avisos de produtos diferentes.

Excel usa o worker existente, inclui todas as linhas dos filtros, versões,
remediações, modelos citados, fontes, sinais e estado da coleta. Textos são
células literais. Campos grandes usam a aba Dados extensos sem truncamento.
