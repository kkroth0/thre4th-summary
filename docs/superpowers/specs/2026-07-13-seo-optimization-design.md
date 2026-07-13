# Otimizacao SEO do site

## Objetivo

Melhorar a base tecnica de SEO do ThreatSumm4ry para o dominio canonico `https://threatsumm4ry.app/`, com suporte explicito a portugues do Brasil e ingles. A mudanca cobre rastreabilidade, indexacao, metadados sociais, canonical, sinais de idioma conservadores, sitemap e testes automatizados. O objetivo imediato e reduzir metadados genericos de SPA e facilitar a descoberta das paginas publicas por mecanismos de busca.

## Contexto atual

O app e uma SPA React/Vite publicada na Cloudflare Pages, com rotas em `react-router-dom`. O `index.html` ja declara favicons, manifest, imagem Open Graph e uma descricao generica. O `robots.txt` permite crawling, mas nao referencia sitemap. A rota dinamica `/advisories/:slug` ja possui uma Cloudflare Pages Function que injeta title, description, Open Graph, Twitter e canonical por post.

Os principais problemas SEO encontrados sao:

- metadados base muito genericos para todas as rotas estaticas da SPA;
- ausencia de canonical no HTML base;
- ausencia de sitemap publico anunciado no `robots.txt`;
- URLs de imagem social relativas no HTML base;
- ausencia de uma estrategia clara para sinais de idioma enquanto o site nao possui URLs distintas por locale;
- inexistencia de uma fonte central para titles, descriptions e URLs indexaveis.

## Escopo

Sera implementada uma camada SEO pequena e centralizada para rotas publicas. O trabalho inclui:

- criar um catalogo em `src/config/seo.ts` com dominio canonico, idiomas suportados, rotas indexaveis e metadados por idioma;
- criar um componente `Seo` que atualiza `document.title`, description, Open Graph, Twitter, canonical e metadados de idioma no cliente conforme a rota e idioma atual;
- montar um `sitemap.xml` estatico em `public/` para as principais rotas publicas, com entradas absolutas e sinais conservadores de alternate quando aplicavel;
- atualizar `public/robots.txt` para apontar para `https://threatsumm4ry.app/sitemap.xml`;
- melhorar os metadados base de `index.html` para usar `pt-BR`, canonical, `og:url`, imagem absoluta e copy mais descritiva;
- ajustar a Pages Function de advisories para preservar consistencia com o dominio, a imagem social e os metadados existentes;
- adicionar ou atualizar testes que validem metadados, sitemap e robots.

Rotas privadas, rotas administrativas, login, perfil, configuracoes e recursos premium protegidos nao entram no sitemap por padrao. Elas podem continuar acessiveis diretamente, mas nao serao tratadas como paginas prioritarias de SEO.

## Rotas indexaveis iniciais

O sitemap e o catalogo devem incluir as rotas publicas com valor de busca:

- `/`
- `/analyzer`
- `/cves`
- `/atores`
- `/advisories`
- `/latam-threats`
- `/threat-map`
- `/patch-tuesday`
- `/vendors`
- `/dnsbl`
- `/attack-surface`
- `/phishing-analyzer`

As rotas legadas com redirect, como `/actors`, `/reports`, `/threat-brief`, `/signup` e `/daily-bulletin`, nao entram no sitemap. A rota `/advisories/:slug` continua sendo tratada pela Function dinamica e pode ganhar sitemap dinamico em um trabalho futuro se a API fornecer uma lista confiavel de posts publicados.

## Idiomas e hreflang

O site suporta conteudo em portugues do Brasil e ingles via estado de idioma no cliente, mas ainda nao usa URLs distintas por locale. Portanto, a primeira implementacao mantera canonicals unicos por rota e usara alternates de idioma de forma conservadora: `x-default` e o idioma padrao do HTML base apontarao para a URL canonica; metadados no cliente mudarao conforme o idioma ativo. Nao serao criadas URLs artificiais com parametros de idioma.

Como melhoria futura, se o produto passar a ter URLs por idioma, o caminho preferido sera subdiretorios como `/pt-BR/` e `/en/`, com canonicals auto-referenciais por locale. Essa mudanca fica fora do escopo atual porque afetaria roteamento, redirects, sitemap e navegacao.

## Metadados

Cada pagina indexavel tera:

- title unico com o termo principal e marca no fim;
- description unica, objetiva e alinhada ao conteudo da rota;
- canonical absoluto com `https://threatsumm4ry.app`;
- Open Graph e Twitter com title, description, URL e imagem social absoluta;
- `og:type="website"` nas rotas estaticas;
- `article` mantido para advisories dinamicos publicados;
- `alternate` RSS mantido para o feed de advisories.

A copy base deve priorizar termos naturais de busca para CTI, SOC, threat intelligence, IOC enrichment, CVE tracking, phishing analysis, DNSBL e attack surface monitoring, sem keyword stuffing.

## Arquitetura

`src/config/seo.ts` sera a fonte unica para:

- `SITE_URL`;
- imagem social padrao;
- idiomas suportados;
- lista de rotas indexaveis;
- metadados por rota e idioma;
- helpers para montar URL canonica e alternates.

`src/components/Seo.tsx` sera usado perto de `Routes` ou dentro de um wrapper global. Ele deve ler `location.pathname` e `language` para escolher os metadados corretos. Quando nao houver entrada especifica para a rota, usara os metadados padrao do site e marcara comportamento conservador.

O sitemap estatico em `public/sitemap.xml` sera gerado manualmente nesta etapa a partir do catalogo aprovado. Para evitar divergencia no futuro, a implementacao deve incluir teste que compare as rotas do sitemap com as rotas indexaveis do catalogo ou, no minimo, valide que as rotas aprovadas estao presentes.

## Testes

A implementacao sera validada com:

- teste unitario/Node para `index.html`, garantindo canonical, `og:url`, imagem social absoluta e idioma base;
- teste para `public/robots.txt`, garantindo `Sitemap: https://threatsumm4ry.app/sitemap.xml`;
- teste para `public/sitemap.xml`, garantindo XML valido em nivel basico, URLs absolutas e entradas das rotas indexaveis;
- teste para o catalogo SEO, garantindo titles e descriptions nao vazios e URLs canonicas consistentes;
- `npm run test:brand`, `npm run test:unit`, `npm run typecheck` e `npm run build`.

## Fora do escopo

Esta mudanca nao inclui:

- migrar a SPA para SSR ou SSG;
- criar URLs distintas por idioma;
- gerar sitemap dinamico de advisories publicados;
- integrar Google Search Console ou Bing Webmaster Tools;
- implementar schema JSON-LD;
- fazer auditoria de Core Web Vitals com PageSpeed;
- alterar layout visual ou navegacao.

## Riscos e mitigacoes

O principal limite e que metadados atualizados no cliente nao sao equivalentes a SSR para todos os crawlers. A mitigacao e melhorar o HTML base, manter a Function dinamica para advisories e deixar SSR/SSG como evolucao separada se SEO organico virar prioridade maior.

Outro risco e tentar declarar `hreflang` completo sem URLs distintas por idioma. A implementacao evita essa ambiguidade agora e registra URLs por idioma como evolucao separada.

## Criterios de aceite

- `index.html` declara `lang="pt-BR"`, canonical e metadados sociais absolutos para `https://threatsumm4ry.app/`.
- `public/robots.txt` referencia o sitemap canonico.
- `public/sitemap.xml` existe e lista as rotas publicas aprovadas com URLs absolutas.
- O app atualiza title, description, canonical e metadados sociais quando a rota muda.
- Titles e descriptions sao unicos para as rotas publicas principais.
- Testes e build relevantes passam sem alterar arquivos nao relacionados.
