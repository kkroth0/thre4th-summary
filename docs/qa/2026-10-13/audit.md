# Auditoria real dos fluxos — 13/10/2026

Ambiente: produção, https://threatsumm4ry.app, sessão autenticada pelo usuário. Versão de origem: `5732c91`. Seleção aleatória estratificada de quatro publicações do acervo dos últimos 30 dias, mais o controle C2Agent. A seleção compara o que foi extraído com o que foi persistido; a validação semântica compara as extrações com os textos originais.

## Resultado

A persistência e os vínculos entre módulos funcionam na amostra, incluindo fontes externas consultadas durante o teste. A correlação semântica não passou: há falsos positivos propagados para o inventário, perfis e exportações. Portanto, a plataforma ainda não pode ser considerada integralmente validada.

| Amostra | Publicação | Evidência e resultado |
| --- | --- | --- |
| IP e atribuição | [ASUS AiCloud / NIC](https://blog.nicter.jp/2026/01/aicloud_vulnerability/) | 14/14 indicadores extraídos persistidos: 10 classificados como IPs e quatro SHA256. Contudo, `2.0.0.39` é uma versão do AiCloud, não um IP no contexto. `404` refere-se ao HTTP 404 e foi associado incorretamente a 404 Keylogger. Duas CVEs persistidas. |
| Hashes | [Patch Reliability / Qualys](https://blog.qualys.com/product-tech/2026/09/15/before-you-patch-why-patch-reliability-matters-for-confident-deployment) | 4/4 hashes persistidos. São hashes de pacotes de atualização do Windows; sua presença não os torna maliciosos. A referência a dispositivos USB foi associada incorretamente a USBStealer. O falso vínculo aparece na interface. |
| CVE | [CVE-2026-83943 / MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83943) | Arquivo de notícias e evento contêm a referência. Não há IOCs, portanto nenhuma associação IOC/CVE é esperada. O catálogo NVD encontra a CVE, CVSS 8,7 e EPSS 0,38%. A busca de notícias por CVE e por título não encontra a publicação arquivada. |
| Sem IOCs | [Tutorial Kubernetes / Habr](https://habr.com/ru/articles/1093932/) | Sem indicadores, atores ou malware inventados. Publicação visível na busca. Tema de tutorial geral sinaliza necessidade de melhorar a seleção de conteúdo de segurança. |
| Controle | [C2Agent / Unit 42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-09-C2Agent-malware.txt) | 36/36 indicadores persistidos: 32 hashes, dois domínios e duas URLs. Família C2Agent associada. Outros rótulos, como cmd e Shadow RAT, precisam de revisão contextual. |

## Caminho exercitado pela interface

1. Abrir a notícia AiCloud, clicar nos IPs, abrir `154.81.156.10` e seguir para o enriquecimento. O indicador foi transportado corretamente entre as telas.
2. A consulta trouxe dados reais de VirusTotal, AbuseIPDB, OTX e Shodan, além da geolocalização. ThreatFox retornou ausência de dados, não erro. O resultado final apresentou score 75 e divergência entre as fontes.
3. Executar lote com `154.81.156.10` e `217.15.164.147`: 2/2 concluídos, zero falhas, zero parciais; seis fontes compatíveis consultadas por IP.
4. Exportar JSON: seis registros de fontes por IP com `rawPayload`, uma publicação por IP e evidências correlacionadas. Primeiro IP: 27 evidências. Segundo: uma evidência no contexto inicial.
5. Recarregar o inventário: ambos os IPs mantiveram notícias + AbuseIPDB + IP Geolocation + OTX + Shodan + VirusTotal. Segundo IP passou a ter 11 evidências, com Armored Likho, UAT-7810 e njRAT recebidos do OTX. Seguir o vínculo Armored Likho abriu o perfil com o IP e a referência OTX de 08/08/2026.
6. Salvar C2Agent e abrir Publicações salvas: publicação presente após navegação. A data sem horário aparece incorretamente como 08/10 no salvo, enquanto o feed exibe 09/10.
7. Gerar um novo boletim C2Agent e acompanhar o trabalho na biblioteca. Concluiu dentro do limite de 240 segundos, após permanecer mais de 220 segundos em geração. A interface e o JSON exportado apresentam 40 indicadores, mas apenas 28 dos 32 hashes esperados. PDF e PPTX ficaram indisponíveis no menu desse relatório; o JSON foi baixado com sucesso.
8. Abrir semanal existente sem alterar escolhas: versão 4, semana 11–18/10, 10 notícias gerais, cinco de IA, 25 sugestões de cada. Exportar JSON e PPTX. PPTX: 40 slides, 105 XMLs legíveis e ZIP íntegro. Essa verificação é estrutural; não afirma revisão visual de todos os slides.

## Lacunas observadas

- **Extração e atribuição:** versões de software, códigos HTTP e termos comuns como USB/ftp viram indicadores ou famílias de malware. Requer contexto, separação de ferramentas legítimas e reprocessamento das evidências antigas.
- **Contexto do lote:** a consulta de evidências inicia antes das APIs e não é atualizada ao final. O export do segundo IP contém uma evidência inicial, enquanto o inventário já apresenta 11 e os perfis recebem as novas entidades. As respostas brutas estão exportadas, mas a coluna de entidades fica desatualizada durante esse lote.
- **Acervo versus busca:** publicação CVE arquivada não encontrada na interface de notícias; investigar regras de visibilidade e agregação.
- **Datas:** Publicações salvas desloca a data sem horário do C2Agent para o dia anterior. O semanal admite textos antigos por coleta recente, incluindo um relatório de junho na semana de outubro, embora mostre corretamente o rótulo “Coleta”.
- **Qualidade editorial:** feed de fontes amplas inclui tutoriais sem tema claro de segurança.
- **Boletim incompleto:** quatro hashes presentes na base não chegam ao relatório nem ao JSON: `70b726bc777779abddb7e9a4001f58a9f59faaf0f3a433859e149b0f44c655a3`, `9913432b854f344f3b3603a19aab9fec64a24f424b838bbe36ad9a1103e37079`, `3dcb6cd93093e01119614e40d2d8695ac29c6702482fb73b8c67bd6859d88c62` e `316c71f65517016ad58770410ca639b9c3bfb2f23ccd341cdaaf13375c829a26`. A geração precisa preservar deterministamente os IOCs extraídos, independentemente da síntese de IA.
- **Perfil de malware:** njRAT mostra o pulso OTX recebido durante o teste nas referências, mas o IP com atribuição a mais de uma família não entra na tabela restrita a publicações que mencionam somente uma família. A evidência está preservada, porém essa restrição reduz a visão de correlações oferecida ao usuário.

## Provas locais

- `enrichment-ip.png`: resultado individual e fontes.
- `bulk.png`: lote concluído.
- `actor-api.png`: perfil com IP proveniente do OTX.
- `qualys-false-malware.png`: falsa associação USBStealer.
- `missing-cve-news.png` e `cve-nvd.png`: diferença entre busca de notícias e catálogo.
- `saved-publication.png`: publicação salva.
- `weekly.png`: seleção semanal existente.
- `bulletin.png`: boletim C2Agent concluído.

Downloads do teste ficaram na pasta Downloads do usuário: `threatsumm4ry-bulk-2026-10-13T22-48-14-320Z.json`, `relatorio-semanal-2026-10-11.json` e `Relatorio_Semanal_2026-10-11_v4 (1).pptx`. Nenhuma chave de API ou sessão foi incluída nesta auditoria.

## Publicação da auditoria

Script de amostragem aleatória: commit `5732c91`; workflow de auditoria `38478793242`, CI `38478793271`, VPS `38478916147` e Pages `38478916201` concluídos com sucesso. A varredura de dependências mantém a falha preexistente; não é um resultado aprovado deste teste funcional.
