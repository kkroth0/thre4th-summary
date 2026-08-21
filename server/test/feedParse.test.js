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
