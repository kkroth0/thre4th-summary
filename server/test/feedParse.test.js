import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFeed } from '../feedParse.js';

const rss = (body) => `<rss><channel><item>
  <title>Gateway VPN sob ataque</title>
  <link>https://vendor.example/post</link>
  <pubDate>Mon, 18 Aug 2026 10:00:00 GMT</pubDate>
  <description><![CDATA[Resumo curto do post.]]></description>
  ${body}
</item></channel></rss>`;

test('RSS: o corpo vem de content:encoded, não do resumo de 300 chars', () => {
    // O CVE e o IP moram no corpo do post, que é exatamente onde eles ficam num
    // writeup de vendor — e onde o parser não olhava.
    const corpo = `${'palavra '.repeat(80)}Explora CVE-2026-4471 a partir de 185.220.101.45.`;
    const [item] = parseFeed(rss(`<content:encoded><![CDATA[${corpo}]]></content:encoded>`), 'Vendor', 2);

    assert.equal(item.description, 'Resumo curto do post.');
    assert.match(item.text, /CVE-2026-4471/);
    assert.match(item.text, /185\.220\.101\.45/);
});

test('RSS sem content:encoded cai na description, sem perder o item', () => {
    const [item] = parseFeed(rss(''), 'Vendor', 2);

    assert.equal(item.text, 'Resumo curto do post.');
    assert.equal(item.source, 'Vendor');
});

test('description continua cortada em 300 para a UI, e text não', () => {
    const longo = 'a'.repeat(5000);
    const [item] = parseFeed(rss(`<content:encoded><![CDATA[${longo}]]></content:encoded>`), 'Vendor', 2);

    assert.equal(item.description.length, 'Resumo curto do post.'.length);
    assert.equal(item.text.length, 5000);
});

test('Atom: o content deixa de ser truncado em 300', () => {
    const corpo = `${'x'.repeat(600)} CVE-2026-9999`;
    const atom = `<feed><entry>
      <title>Alerta</title>
      <link href="https://vendor.example/a"/>
      <published>2026-08-18T10:00:00Z</published>
      <content><![CDATA[${corpo}]]></content>
    </entry></feed>`;

    const [item] = parseFeed(atom, 'Vendor', 1);

    assert.ok(item.description.endsWith('...'), 'a UI segue recebendo o resumo curto');
    assert.match(item.text, /CVE-2026-9999/);
});

test('o texto de análise é limitado, para o corpo não virar consumo de memória', () => {
    const [item] = parseFeed(rss(`<content:encoded><![CDATA[${'a'.repeat(50000)}]]></content:encoded>`), 'Vendor', 2);

    assert.equal(item.text.length, 20000);
});

// `includes('<feed')` casava com <feedburner:origLink>, que é elemento comum
// DENTRO de um RSS. O feed do FortiGuard, servido pelo FeedBlitz, era lido como
// Atom, procurava <entry> e devolvia zero item tendo dez <item> na mão.
test('RSS com elemento de namespace feedburner não é confundido com Atom', () => {
    const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss xmlns:feedburner="http://rssnamespace.org/feedburner/ext/1.0" version="2.0"><channel>
  <title>FortiGuard Labs Threat Research</title>
  <item>
    <title>Multi-Functional Linux Botnet</title>
    <link>https://www.fortinet.com/blog/threat-research/botnet</link>
    <pubDate>Wed, 27 Aug 2026 10:00:00 GMT</pubDate>
    <description>A new botnet targeting Linux hosts.</description>
    <feedburner:origLink>https://www.fortinet.com/blog/threat-research/botnet</feedburner:origLink>
  </item>
</channel></rss>`;

    const items = parseFeed(rss, 'FortiGuard Labs', 3);

    assert.equal(items.length, 1);
    assert.equal(items[0].title, 'Multi-Functional Linux Botnet');
    assert.equal(items[0].layer, 3);
});

// A raiz <feed ...> continua sendo Atom — o conserto foi no delimitador, não em
// desligar a detecção.
test('Atom de verdade continua sendo lido como Atom', () => {
    const atom = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Stable Channel Update</title>
    <link href="https://chromereleases.googleblog.com/update"/>
    <updated>2026-08-27T10:00:00Z</updated>
    <summary>Security fixes.</summary>
  </entry>
</feed>`;

    const items = parseFeed(atom, 'Chrome Releases', 1);

    assert.equal(items.length, 1);
    assert.equal(items[0].title, 'Stable Channel Update');
    assert.equal(items[0].link, 'https://chromereleases.googleblog.com/update');
});
