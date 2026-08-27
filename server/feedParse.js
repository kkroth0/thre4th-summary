/**
 * Parser de RSS/Atom.
 *
 * Devolve dois textos por item, de propósito: `description` é o resumo curto
 * que a UI mostra, e `text` é o corpo inteiro que o feed já entrega — que é o
 * que alimenta a extração de CVE, ator e IOC. Antes os dois eram a mesma
 * string cortada em 300 caracteres, então o corpo do post era baixado junto com
 * o XML e descartado sem ser lido.
 */

// HTML entity and XSS escaping helper
export const escapeHtml = (unsafe) => {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
};


const decodeEntities = (str) => {
    if (!str) return '';
    return str
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#039;/g, "'")
        .replace(/&apos;/g, "'")
        .replace(/&rsquo;/g, "'")
        .replace(/&ldquo;/g, '"')
        .replace(/&rdquo;/g, '"')
        .replace(/&ndash;/g, '-')
        .replace(/&mdash;/g, '--');
};

// Generic feed parser
// `description` é o resumo curto que a UI mostra; `text` é o corpo inteiro que
// o feed já entrega (content:encoded no RSS, content no Atom) e que alimenta a
// extração de CVE/ator/IOC. Antes os dois eram a mesma string cortada em 300
// caracteres, então metade do que o vendor publicou era baixada e descartada.
// `text` não sai daqui: é apagado antes de a resposta ir pro cache (ver
// refreshNewsletterFeed), porque inflaria o payload do /api/newsletter.
const ANALYSIS_TEXT_CAP = 20000;

export function parseFeed(xmlText, sourceName, layer) {
    const items = [];
    // `includes('<feed')` casava com <feedburner:origLink> e <feedblitz:...>,
    // que são elementos comuns DENTRO de um RSS. O feed do FortiGuard (servido
    // pelo FeedBlitz) era lido como Atom, procurava <entry> e devolvia zero item
    // com 10 <item> na mão. Exigir o delimitador depois do nome separa a raiz
    // <feed ...> do prefixo de namespace.
    const isAtom = /<entry[\s>]/i.test(xmlText) || /<feed[\s>]/i.test(xmlText);
    
    const cleanTag = (str) => {
        if (!str) return '';
        const stripped = str
             .replace(/<!\[CDATA\[/gi, '')
             .replace(/\]\]>/g, '')
             .replace(/<[^>]*>/g, '')
             .trim();
        return escapeHtml(stripped);
    };

    if (isAtom) {
        const entries = xmlText.split(/<entry>/i);
        for (let i = 1; i < entries.length; i++) {
            const entryHtml = entries[i].split(/<\/entry>/i)[0];
            const titleMatch = entryHtml.match(/<title(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
            const linkMatch = entryHtml.match(/<link[^>]*href=["']([^"']+)["']/i) || entryHtml.match(/<link>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/i);
            const dateMatch = entryHtml.match(/<(?:updated|published)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/(?:updated|published)>/i);
            const summaryMatch = entryHtml.match(/<(?:summary|content)(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/(?:summary|content)>/i);
            
            const title = decodeEntities(cleanTag(titleMatch ? titleMatch[1] : 'Untitled Alert'));
            const link = linkMatch ? linkMatch[1].trim() : '';
            const pubDate = dateMatch ? dateMatch[1].trim() : '';
            const description = decodeEntities(cleanTag(summaryMatch ? summaryMatch[1] : ''));

            if (title || link) {
                items.push({
                    title,
                    link,
                    pubDate: pubDate ? new Date(pubDate).toISOString() : new Date().toISOString(),
                    description: description.substring(0, 300) + (description.length > 300 ? '...' : ''),
                    text: description.slice(0, ANALYSIS_TEXT_CAP),
                    source: sourceName,
                    layer: layer
                });
            }
        }
    } else {
        const itemParts = xmlText.split(/<item>/i);
        for (let i = 1; i < itemParts.length; i++) {
            const itemHtml = itemParts[i].split(/<\/item>/i)[0];
            const titleMatch = itemHtml.match(/<title(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
            const linkMatch = itemHtml.match(/<link(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/i);
            const dateMatch = itemHtml.match(/<pubDate>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/pubDate>/i);
            const descMatch = itemHtml.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/i);
            // WordPress e a maioria dos blogs de vendor mandam o post inteiro aqui.
            const contentMatch = itemHtml.match(/<content:encoded(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/content:encoded>/i);
            
            const title = decodeEntities(cleanTag(titleMatch ? titleMatch[1] : 'Untitled Alert'));
            const link = (linkMatch ? linkMatch[1] : '').trim();
            const pubDate = (dateMatch ? dateMatch[1] : '').trim();
            const description = decodeEntities(cleanTag(descMatch ? descMatch[1] : ''));
            const content = contentMatch ? decodeEntities(cleanTag(contentMatch[1])) : '';

            if (title || link) {
                items.push({
                    title,
                    link,
                    pubDate: pubDate ? new Date(pubDate).toISOString() : new Date().toISOString(),
                    description: description.substring(0, 300) + (description.length > 300 ? '...' : ''),
                    // O maior dos dois: nem todo feed traz content:encoded, e quando
                    // traz ele contém a description.
                    text: (content.length > description.length ? content : description).slice(0, ANALYSIS_TEXT_CAP),
                    source: sourceName,
                    layer: layer
                });
            }
        }
    }
    return items;
}
