# Integração dos ativos de marca

## Objetivo

Usar `threatsumm4ry-ui-toolkit` como fonte oficial da identidade visual do app. A mudança cobre logos, marca compacta, favicons, ícones instaláveis e imagem de compartilhamento social. O layout, a paleta da interface e os textos do produto permanecem como estão.

## Fonte dos ativos

Os arquivos prontos de `threatsumm4ry-ui-toolkit/brand` e `threatsumm4ry-ui-toolkit/favicons` serão copiados para `public`. Os arquivos em `brand/source` continuarão no toolkit como fontes de geração e não serão servidos pelo app.

O app usará:

- `threatsumm4ry-mark.svg` nos espaços compactos do cabeçalho, sidebar e menu móvel;
- as versões horizontais clara e escura quando a largura permitir uma assinatura completa;
- `threatsumm4ry-og-image-1200x630.png` nos metadados sociais;
- o pacote de favicon em SVG, PNG e ICO, além dos ícones Apple, Android, Safari e maskable;
- `site.webmanifest` e `browserconfig.xml` fornecidos pelo toolkit.

## Integração na interface

Os blocos que hoje desenham `t4` com texto e classes CSS serão substituídos pela marca SVG oficial. O cabeçalho escolherá a variação adequada ao espaço disponível sem alterar altura, navegação ou comportamento responsivo. A sidebar recolhida exibirá apenas a marca. A versão expandida poderá manter o nome e a descrição já existentes ao lado dela quando a assinatura horizontal não couber.

A página inicial receberá a mesma substituição para eliminar diferenças entre a navegação pública e o restante do produto. Imagens terão texto alternativo apropriado ou serão marcadas como decorativas quando o nome adjacente já identificar a marca.

## Metadados e compatibilidade

`index.html` passará a declarar favicon SVG com fallbacks PNG e ICO, Apple Touch Icon, Safari pinned tab, manifest, `theme-color`, título, descrição e imagem Open Graph. A função que monta metadados para advisories usará a nova imagem social em vez do favicon antigo.

Os nomes legados `logo.png`, `logo-full.jpg` e `favicon.png` só permanecerão se uma busca após a migração encontrar consumidores necessários. Caso contrário, serão removidos para evitar duas fontes de identidade no app. O build continuará copiando todos os ativos públicos para `dist`; arquivos gerados em `dist` não serão editados à mão.

## Verificação

A implementação será validada com:

- busca por referências aos ativos antigos e aos blocos textuais de marca substituídos;
- build e testes disponíveis no projeto;
- inspeção do app em larguras desktop e mobile, com sidebar expandida e recolhida;
- conferência dos temas claro e escuro;
- verificação dos links de favicon, manifest e imagem Open Graph no HTML gerado;
- inspeção visual dos SVGs e de uma captura atual do app.

## Fora do escopo

Esta mudança não redesenha os arquivos do toolkit, não altera a arquitetura da navegação e não modifica outras cores ou componentes da interface.
