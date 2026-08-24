import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractReadableText,
  collectArtifactLinks,
  githubArtifact,
  extractIOCs,
} from '../ctiIntel.js';

// Shaped after the Arctic Wolf BoryptGrab report: the indicators are NOT in a
// <p>, and the link to the appendix says nothing about IOCs.
const ARTICLE_URL = 'https://arcticwolf.com/resources/blog/fake-github-repositories/';
const ARTICLE_HTML = `
<html><body>
  <nav><a href="https://twitter.com/arcticwolf">Follow us</a></nav>
  <article>
    <p>Arctic Wolf observed a campaign distributing an infostealer through fake GitHub repositories impersonating security vendors.</p>
    <p>Advertisement</p>
    <table>
      <tr><th>Type</th><th>Indicator</th></tr>
      <tr><td>C2</td><td>193.143.1[.]131</td></tr>
      <tr><td>Domain</td><td>targetroyena[.]com</td></tr>
    </table>
    <pre><code>e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2</code></pre>
    <h2>Appendix</h2>
    <p>The full indicator list is available in
      <a href="https://github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence/boryptgrab/">our official public GitHub repository</a>.</p>
    <p>Read more about our <a href="https://arcticwolf.com/solutions/mdr/">MDR service</a>.</p>
  </article>
</body></html>`;

test('extractReadableText keeps the IOC table and code block, not just paragraphs', () => {
  const text = extractReadableText(ARTICLE_HTML);

  assert.match(text, /fake GitHub repositories/);            // narrative survives
  assert.match(text, /193\.143\.1\[\.\]131/);                // table cell — was dropped before
  assert.match(text, /targetroyena\[\.\]com/);
  assert.match(text, /e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2/);
  assert.doesNotMatch(text, /Advertisement/);                // boilerplate still filtered
  assert.doesNotMatch(text, /Follow us/);                    // nav still stripped
});

test('collectArtifactLinks finds the appendix repo despite the anchor text never saying IOC', () => {
  const links = collectArtifactLinks(ARTICLE_HTML, ARTICLE_URL);

  assert.deepEqual(links, ['https://github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence/boryptgrab/']);
});

test('collectArtifactLinks ignores non-allowlisted hosts and bare profile links', () => {
  const html = `<article>
    <a href="https://evil.example.com/indicators.csv">indicators</a>
    <a href="https://github.com/rtkwlf">Arctic Wolf on GitHub</a>
    <a href="/local/page">internal</a>
  </article>`;

  assert.deepEqual(collectArtifactLinks(html, ARTICLE_URL), []);
});

test('collectArtifactLinks dedupes and caps at max', () => {
  const html = `<article>
    <a href="https://github.com/a/b/tree/main/x">one</a>
    <a href="https://github.com/a/b/tree/main/x#appendix">same, anchored</a>
    <a href="https://gist.github.com/a/1111">two</a>
    <a href="https://pastebin.com/abcd">three</a>
    <a href="https://github.com/c/d/blob/main/iocs.csv">four</a>
  </article>`;

  const links = collectArtifactLinks(html, ARTICLE_URL);
  assert.equal(links.length, 3);
  assert.equal(links[0], 'https://github.com/a/b/tree/main/x');
});

test('githubArtifact maps folder to contents API and file to raw', () => {
  assert.deepEqual(
    githubArtifact('https://github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence/boryptgrab'),
    { kind: 'dir', url: 'https://api.github.com/repos/rtkwlf/wolf-tools/contents/threat-intelligence/boryptgrab?ref=main' },
  );
  assert.deepEqual(
    githubArtifact('https://github.com/rtkwlf/wolf-tools/blob/main/iocs.csv'),
    { kind: 'raw', url: 'https://raw.githubusercontent.com/rtkwlf/wolf-tools/main/iocs.csv' },
  );
  assert.deepEqual(
    githubArtifact('https://github.com/rtkwlf/wolf-tools'),
    { kind: 'dir', url: 'https://api.github.com/repos/rtkwlf/wolf-tools/contents/' },
  );
  assert.equal(githubArtifact('https://pastebin.com/abcd'), null);
});

test('extractIOCs harvests the fetched appendix (real CSV shape) and skips e-mail domains', () => {
  const csv = [
    'Type,Indicator,Context',
    'Email (commit author),refija8987amira[@]gmail[.]com,Author email on the fake org commits',
    'Hashes (SHA-256),1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778,Delivery archive',
    'Network Indicator,193.143.1[.]131,"Hardcoded C2, Proton66"',
    'Network Indicator,hxxps://furiesniffer[.]com,Actor-controlled TDS domain',
  ].join('\n');

  const iocs = extractIOCs(csv);

  assert.deepEqual(iocs.hashes, ['1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778']);
  assert.deepEqual(iocs.ips, ['193.143.1.131']);
  assert.deepEqual(iocs.urls, ['https://furiesniffer.com']);
  assert.deepEqual(iocs.domains, ['furiesniffer.com']);   // gmail.com is not an IOC
});

test('extractIOCs plaintext mode harvests non-defanged appendix indicators; default does not', () => {
  // A real GitHub/MISP appendix lists indicators in plain form, one per line.
  const csv = [
    'type,value',
    'domain,evil-c2.com',
    'domain,login.evil-c2.com',
    'url,https://evil-c2.com/gate.php',
    'ip,193.143.1.131',
    'sha256,1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778',
    'file,payload.exe',                 // filename, not a domain
  ].join('\n');

  const plain = extractIOCs(csv, { plaintext: true });
  assert.ok(plain.domains.includes('evil-c2.com'));
  assert.ok(plain.domains.includes('login.evil-c2.com'));
  assert.ok(!plain.domains.includes('payload.exe'));       // extension guard
  assert.deepEqual(plain.urls, ['https://evil-c2.com/gate.php']);
  assert.ok(plain.ips.includes('193.143.1.131'));

  // Default (prose) mode: plain domains/URLs are noise and stay out; only the
  // unambiguous hash + public IP survive.
  const prose = extractIOCs(csv);
  assert.deepEqual(prose.domains, []);
  assert.deepEqual(prose.urls, []);
  assert.ok(prose.ips.includes('193.143.1.131'));
});

test('extractIOCs keeps attacker subdomains but drops the bare shared-platform apex', () => {
  const iocs = extractIOCs('redirector bentleyvazquezpvey[.]github[.]io and template <ref>[.]github[.]io');

  assert.ok(iocs.domains.includes('bentleyvazquezpvey.github.io'));  // real indicator
  assert.ok(!iocs.domains.includes('github.io'));                    // bare apex is noise
});

test('extractIOCs drops code hosting: um repositório GitHub não é indicador', () => {
  const appendix = [
    'Full list: https://github.com/vendor/threat-iocs',
    'raw: https://raw.githubusercontent.com/vendor/threat-iocs/main/c2.txt',
    'mirror on gist.github.com and gitlab.com/vendor/iocs',
    'c2: https://evil-c2.com/gate.php',
    'domain: evil-c2.com',
  ].join('\n');
  const iocs = extractIOCs(appendix, { plaintext: true });

  assert.deepEqual(iocs.urls, ['https://evil-c2.com/gate.php']);
  assert.deepEqual(iocs.domains, ['evil-c2.com']);
});

// Um apêndice que é PÁGINA (gist, release, pastebin) chega como HTML. É o
// caminho que publicava github.githubassets.com como domínio malicioso: ele só
// existe no <script src> da moldura do GitHub, nunca no conteúdo.
test('apêndice em HTML: a moldura da página não vira IOC, o conteúdo vira', () => {
  const gistHtml = `
<html><head>
  <link rel="stylesheet" href="https://github.githubassets.com/assets/light-0eace2f.css">
  <script src="https://github.githubassets.com/assets/wp-runtime-4f3b2c.js"></script>
</head><body>
  <header><a href="https://github.com/vendor">vendor</a></header>
  <table class="highlight"><tbody>
    <tr><td class="blob-code">command-and-control: evil-c2.com</td></tr>
    <tr><td class="blob-code">drop: https://payload-host.net/stage2.bin</td></tr>
    <tr><td class="blob-code">9f2c4a1b8e7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f</td></tr>
  </tbody></table>
</body></html>`;

  const iocs = extractIOCs(extractReadableText(gistHtml), { plaintext: true });

  assert.ok(!iocs.domains.includes('github.githubassets.com'));
  // O host da URL não se repete em domains — a varredura de domínio simples
  // roda depois de tirar as URLs, e é assim já antes desta mudança.
  assert.deepEqual(iocs.domains, ['evil-c2.com']);
  assert.deepEqual(iocs.urls, ['https://payload-host.net/stage2.bin']);
  assert.equal(iocs.hashes.length, 1);
});
