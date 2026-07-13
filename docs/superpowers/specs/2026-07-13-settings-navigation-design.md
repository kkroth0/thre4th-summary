# Settings e simplificação da barra lateral

**Data:** 2026-07-13

## Objetivo

Remover os controles de idioma, tema e o atalho separado de Admin da barra lateral. Concentrar essas funções em Settings, com navegação segmentada e acesso administrativo condicionado à permissão do usuário.

## Abordagens consideradas

1. **Abas dentro de Settings (escolhida).** Usa uma única página com as seções Geral, Chaves de API e Admin. Mantém a navegação curta e deixa todas as preferências em um lugar previsível.
2. **Menu lateral interno em Settings.** Escala para muitas categorias, mas adiciona uma segunda barra lateral para apenas três seções.
3. **Rotas independentes sob `/settings/*`.** Facilita links diretos, mas aumenta a estrutura de rotas e repete o shell de Settings sem benefício para o escopo atual.

## Navegação

A barra lateral desktop exibirá um único item Settings para usuários autenticados. Ela não exibirá os controles de idioma e tema nem um item Admin separado. O rodapé manterá o perfil, as ações de autenticação e o botão de recolher ou expandir a barra.

O menu móvel seguirá a mesma regra. Usuários autenticados verão Perfil e Settings, sem controles soltos de idioma e tema e sem botão Admin separado.

Settings terá três abas:

- **Geral:** seleção de idioma e aparência clara ou escura.
- **Chaves de API:** conteúdo BYOK que já existe em Settings.
- **Admin:** painel administrativo existente, exibido apenas quando `auth.isAdmin` for verdadeiro.

A rota `/admin` redirecionará administradores para `/settings?section=admin`. Usuários sem permissão continuarão sem acesso ao conteúdo administrativo. O parâmetro `section` permitirá links diretos e preservará a aba ativa após recarregar a página. Valores inválidos cairão em Geral.

## Componentes

`Settings.tsx` será o shell da página e controlará a aba ativa. A seção Geral usará os contextos existentes de idioma e tema. Ela mostrará opções explícitas, com estado selecionado visível, em vez dos botões circulares atuais.

O conteúdo BYOK continuará responsável por carregar, salvar e remover chaves. A implementação poderá extrair esse conteúdo para um componente de seção para evitar que o shell acumule regras de rede.

O conteúdo de `Admin.tsx` será extraído para um componente administrativo reutilizável. O componente receberá a autenticação já validada pelo shell de Settings e manterá os fluxos atuais de allowlist, publicações, integrações e fontes. `Admin.tsx` ficará responsável apenas pelo redirecionamento compatível.

## Estado e permissões

O idioma continuará salvo em `localStorage` pela `LanguageContext`. O tema continuará salvo pela `ThemeProvider`. A página não criará uma segunda fonte de estado.

Settings continuará exigindo autenticação. A aba Admin só entrará na lista quando o usuário for administrador. Se um usuário sem permissão abrir `?section=admin`, Settings selecionará Geral sem renderizar ou buscar dados administrativos.

As chamadas de BYOK ocorrerão apenas quando a aba Chaves de API for aberta. As chamadas administrativas ocorrerão apenas quando um administrador abrir a aba Admin. Isso evita buscas desnecessárias ao entrar em Settings.

## Tratamento de estados

O shell mostrará o estado atual de verificação da sessão. Cada seção manterá seus próprios estados de carregamento e mensagens de erro. A troca de idioma ou tema terá efeito imediato por meio dos contextos atuais.

Os links antigos para `/admin` continuarão válidos. Usuários não autenticados irão para Login; usuários autenticados sem permissão voltarão para Settings na seção Geral.

## Acessibilidade e responsividade

As abas usarão os componentes acessíveis já disponíveis no projeto, com foco por teclado e indicação visual da seção ativa. Em telas estreitas, a lista de abas poderá rolar horizontalmente sem comprimir os rótulos. Os controles de idioma e aparência terão texto visível e área de clique adequada.

## Verificação

Os testes e a verificação cobrirão:

- sidebar desktop expandida e recolhida;
- menu móvel;
- seleção e persistência de idioma e tema;
- acesso e link direto para cada seção;
- proteção da seção Admin para usuário comum;
- carregamento sob demanda de BYOK e Admin;
- redirecionamento da rota `/admin`;
- lint, typecheck e build do frontend.

## Fora do escopo

Esta mudança não altera autenticação, formato das chaves, APIs administrativas ou o conteúdo funcional do painel Admin. Ela também não cria novas preferências de usuário no servidor.
