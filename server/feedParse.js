import * as cheerio from 'cheerio';
import { canonicalArticleUrl } from './feedCollector.js';

export const escapeHtml = (unsafe) => String(unsafe || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
const ANALYSIS_TEXT_CAP = 20000;
const plainText = (value) => {
    const $ = cheerio.load(String(value || ''));
    $('script, style, noscript').remove();
    $('br').replaceWith('\n');
    $('p, div, li, tr, h1, h2, h3').append('\n');
    return $.root().text().replace(/[ \t]+/g, ' ').replace(/\n\s*\n/g, '\n').trim();
};
const localName = (element) => String(element.name || '').split(':').pop().toLowerCase();

export function parseFeed(xmlText, sourceName, layer, { feedUrl, now = new Date(), maxItems = 200 } = {}) {
    const $ = cheerio.load(String(xmlText || ''), { xmlMode: true, decodeEntities: true });
    const elements = $('*').toArray();
    if (!elements.some((element) => ['rss', 'feed', 'rdf'].includes(localName(element)))) throw new Error('Response is not an RSS/Atom feed');
    const defaultBase = $('feed').attr('xml:base') || feedUrl;
    const entries = elements.filter((element) => ['entry', 'item'].includes(localName(element)))
        .map((entry) => {
            const dates = $(entry).children().toArray();
            const dateText = (...names) => {
                for (const name of names) {
                    const node = dates.find((child) => localName(child) === name);
                    if (node) return $(node).text();
                }
                return '';
            };
            const date = new Date(dateText('published', 'pubdate', 'date') || dateText('updated')).getTime();
            return { entry, time: Number.isFinite(date) && date <= now.getTime() + 86400000 ? date : now.getTime() };
        }).sort((a, b) => b.time - a.time).slice(0, Math.max(1, Math.min(1000, Number(maxItems) || 200)));
    const items = [];
    for (const { entry } of entries) {
        const children = $(entry).children().toArray();
        const value = (...names) => {
            for (const name of names) {
                const node = children.find((child) => localName(child) === name);
                if (node) return $(node).text();
            }
            return '';
        };
        const title = plainText(value('title'));
        const links = children.filter((node) => localName(node) === 'link');
        const preferred = links.find((node) => $(node).attr('href') && (!$(node).attr('rel') || $(node).attr('rel') === 'alternate') && (!$(node).attr('type') || /html/i.test($(node).attr('type'))));
        const rssLink = links.find((node) => !$(node).attr('href'));
        const guid = children.find((node) => localName(node) === 'guid' && $(node).attr('isPermaLink') !== 'false');
        const rawLink = preferred ? $(preferred).attr('href') : rssLink ? $(rssLink).text() : guid ? $(guid).text() : '';
        const base = $(entry).attr('xml:base') || defaultBase;
        const link = rawLink ? canonicalArticleUrl(rawLink, base) : null;
        if (!title || !link) continue;
        const published = value('published', 'pubdate', 'date');
        const updated = value('updated');
        const parsedDate = new Date(published || updated);
        const dateInferred = !Number.isFinite(parsedDate.getTime()) || parsedDate.getTime() > now.getTime() + 86400000;
        const description = plainText(value('description', 'summary', 'content', 'encoded'));
        const content = plainText(value('encoded', 'content'));
        items.push({
            title, link, source: sourceName, layer,
            pubDate: dateInferred ? now.toISOString() : parsedDate.toISOString(),
            dateInferred, updatedAt: Number.isFinite(new Date(updated).getTime()) ? new Date(updated).toISOString() : null,
            description: description.slice(0, 300) + (description.length > 300 ? '...' : ''),
            text: (content.length > description.length ? content : description).slice(0, ANALYSIS_TEXT_CAP),
            feedGuid: value('guid', 'id') || null,
        });
    }
    return items;
}
