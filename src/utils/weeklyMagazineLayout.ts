import type PptxGenJS from 'pptxgenjs';
import type { WeeklyReportData, WeeklyCve } from '@/types/weekly-report';
import type { MagazinePage } from './weeklyThreatSumm4ry';
import { weeklyProductLogo } from './weeklyPptxLogos';

const C = { ink: '142737', orange: 'E96E25', teal: '167C85', pale: 'F1F4F5', muted: '556574', line: 'CED8DF', white: 'FFFFFF' };
const num = (n: number) => n.toLocaleString('pt-BR');
const day = (s: string) => new Date(s.length === 10 ? s + 'T12:00:00Z' : s).toLocaleDateString('pt-BR', { timeZone: 'America/Fortaleza' });
const pct = (n: number, total: number) => total ? (100 * n / total).toLocaleString('pt-BR', { maximumFractionDigits: 1 }) + '%' : '—';
const countryName = (code: string) => { try { return /^[A-Z]{2}$/i.test(code) ? new Intl.DisplayNames(['pt-BR'], { type: 'region' }).of(code.toUpperCase()) || code : code; } catch { return code; } };
const sectors: Record<string, string> = { Manufacturing: 'Manufatura', Healthcare: 'Saúde', Technology: 'Tecnologia', 'Financial Services': 'Serviços financeiros', Transportation: 'Transporte e logística', 'Energy & Utilities': 'Energia e serviços essenciais', Education: 'Educação', Government: 'Governo', Retail: 'Comércio', Services: 'Serviços', Construction: 'Construção', 'Business Services': 'Serviços empresariais', 'Not Found': 'Não informado', Unknown: 'Não informado', Other: 'Outros' };
type Mark = { data: string; width: number; height: number };
interface Assets { logo: string; logoLight: string; cover: string; marks: Map<string, Mark>; period: string; references: {title: string; url: string}[]; category: (n: WeeklyReportData['news'][number]) => string }

function textHeight(value: string, font: string, size: number, width: number, bold = false) {
  const ctx = document.createElement('canvas').getContext('2d');
  if (!ctx) return Math.ceil(value.length / (width * 72 / (size * .52))) * size * 1.22 / 72;
  ctx.font = `${bold ? 'bold ' : ''}${size}px ${font}`;
  let lines = 1, line = '';
  for (const word of value.split(/\s+/)) {
    const next = line ? line + ' ' + word : word;
    if (line && ctx.measureText(next).width > width * 72) { lines++; line = word; } else line = next;
  }
  return lines * size * 1.22 / 72;
}

/** Print-oriented editorial layouts. Charts use real aggregate denominators; no decorative risk scores. */
export async function renderWeeklyMagazine(deck: PptxGenJS, r: WeeklyReportData, pages: MagazinePage[], assets: Assets) {
  const sections = r.editorial!.sections!;
  const tx = (s: PptxGenJS.Slide, value: string, x: number, y: number, w: number, h: number, size = 11, more: PptxGenJS.TextPropsOptions = {}) => s.addText(value, { x, y, w, h, margin: 0, fontFace: 'Aptos', fontSize: size, color: C.ink, valign: 'top', lang: 'pt-BR', ...more });
  const rect = (s: PptxGenJS.Slide, x: number, y: number, w: number, h: number, color: string) => s.addShape(deck.ShapeType.rect, { x, y, w, h, fill: { color }, line: { color, transparency: 100 } });
  const rule = (s: PptxGenJS.Slide, y: number, x = .57, w = 7.13, color = C.line) => s.addShape(deck.ShapeType.line, { x, y, w, h: 0, line: { color, width: .6 } });
  const label = (s: PptxGenJS.Slide, value: string, x: number, y: number, w = 7.1, color = C.orange) => tx(s, value.toUpperCase(), x, y, w, .22, 8, { bold: true, charSpacing: 1.2, color });
  const heading = (s: PptxGenJS.Slide, value: string, section: string, subtitle = '') => {
    label(s, section, .57, 1.02);
    tx(s, value, .57, 1.42, 7.13, .9, 30, { fontFace: 'Aptos Display', bold: true });
    if (subtitle) tx(s, subtitle, .57, 2.43, 7.13, .6, 10.5, { color: C.muted });
  };
  const stat = (s: PptxGenJS.Slide, n: number | null, description: string, x: number, y: number, w = 2.15, dark = false) => {
    tx(s, n == null ? '—' : num(n), x, y, w, .58, 31, { bold: true, color: dark ? 'FFB478' : C.ink });
    tx(s, description, x, y + .7, w, .55, 9.5, { color: dark ? 'CFDAE1' : C.muted });
  };
  const chartOptions = { catAxisLabelFontFace: 'Aptos', valAxisLabelFontFace: 'Aptos', dataLabelFontFace: 'Aptos', legendFontFace: 'Aptos', titleFontFace: 'Aptos', catAxisLabelFontSize: 9, valAxisLabelFontSize: 9, dataLabelFormatCode: '0', showTitle: false, valGridLine: { color: 'E0E7EB' } };
  const bars = (s: PptxGenJS.Slide, rows: { name: string; count: number }[], x: number, y: number, w: number, h: number, color = C.orange) => {
    if (!rows.length) return tx(s, 'Sem registros disponíveis neste recorte.', x, y, w, .5, 10, { color: C.muted });
    s.addChart(deck.ChartType.bar, [{ name: 'Registros', labels: [...rows].reverse().map(v => v.name), values: [...rows].reverse().map(v => v.count) }], { ...chartOptions, x, y, w, h, barDir: 'bar', catAxisLabelFontSize: 9, chartColors: [color], showLegend: false, showValue: true });
  };
  const note = (s: PptxGenJS.Slide, value: string) => tx(s, value, .57, 10.66, 7.13, .38, 8, { color: C.muted });
  const storyPage = (id: string) => pages.findIndex(p => p.news?.id === id) + 1;
  const articleFor = (id: string) => r.editorial!.articles!.find(a => a.id === id)!;
  const items = [...r.news, ...r.aiNews];
  let worldMap: string | null = null;
  try {
    const [{ countryPaths, actorOrigin }, response] = await Promise.all([import('@/pages/actorOverview'), fetch('/data/world-countries-110m.json')]);
    if (!response.ok) throw Error('Map unavailable');
    const values = new Map(r.ransomware.byCountry.map(row => [actorOrigin(row.name), row.count]));
    const max = Math.max(1, ...values.values());
    const paths = countryPaths(await response.json()).map(row => {
      const count = values.get(actorOrigin(row.name)) || 0;
      const fill = !count ? '#455865' : count / max >= .6 ? '#F29542' : count / max >= .2 ? '#D8A86D' : '#AFA58C';
      return `<path d="${row.path}" fill="${fill}" stroke="#142737" stroke-width="0.5"/>`;
    }).join('');
    worldMap = `data:image/svg+xml;base64,${btoa(`<svg xmlns="http://www.w3.org/2000/svg" width="900" height="450" viewBox="0 0 900 450">${paths}</svg>`)}`;
  } catch { /* Geographic ranks remain available if the optional map asset cannot load. */ }

  pages.forEach((page, index) => {
    const s = deck.addSlide(); s.background = { color: C.white };
    if (page.kind !== 'cover') {
      s.addImage({ data: assets.logo, x: .57, y: .38, w: 1.9, h: .363 });
      tx(s, 'INTELIGÊNCIA CIBERNÉTICA  /  GLOBAL', 4.45, .46, 3.25, .2, 7, { align: 'right', color: C.muted, charSpacing: .8 });
      rule(s, .85);
      rule(s, 11.14);
      tx(s, assets.period + (r.previewNote ? '  ·  PRÉVIA EDITORIAL' : '  ·  ThreatSumm4ry'), .57, 11.32, 6.6, .18, 7.5, { color: C.muted });
      tx(s, String(index + 1).padStart(2, '0'), 7.1, 11.28, .6, .25, 11, { bold: true, align: 'right' });
    }
    if (page.kind === 'cover') {
      s.background = { color: C.ink };
      s.addImage({ data: assets.cover, x: 0, y: 0, w: 8.27, h: 11.69 });
      s.addImage({ data: assets.logoLight, x: .6, y: .55, w: 2.6, h: .497 });
      tx(s, r.previewNote ? 'PRÉVIA EDITORIAL  /  MATERIAL DE REFERÊNCIA' : `EDIÇÃO ${r.range.id.slice(0, 10)}  /  PANORAMA GLOBAL`, .6, 1.42, 7.07, .25, 9, { color: 'F9BF8D', charSpacing: 1.3 });
      tx(s, 'A semana\ncibernética', .57, 2, 7.13, 1.95, 51, { fontFace: 'Aptos Display', bold: true, color: C.white });
      rect(s, 0, 7.05, 8.27, 4.64, C.ink);
      label(s, 'Nesta edição', .6, 7.45, 6.9, 'F9BF8D');
      const coverStories = [...r.news.slice(0, 2), ...r.aiNews.slice(0, 1)].slice(0, 3);
      coverStories.forEach((n, i) => {
        const y = 7.95 + i * .77;
        tx(s, articleFor(n.id).title!, .6, y, 6.4, .7, 14, { color: C.white, fontFace: 'Aptos', bold: true, hyperlink: { slide: storyPage(n.id) } });
        tx(s, String(storyPage(n.id)).padStart(2, '0'), 7.15, y + .04, .5, .25, 12, { color: 'F9BF8D', align: 'right' });
      });
      tx(s, assets.period, .6, 10.55, 7, .3, 12, { color: 'F9BF8D', bold: true });
      tx(s, 'NOTÍCIAS  ·  VULNERABILIDADES  ·  RANSOMWARE  ·  INTELIGÊNCIA ARTIFICIAL', .6, 11.1, 7.1, .25, 7.8, { color: 'CFDAE1' });
    } else if (page.kind === 'contents') {
      heading(s, 'Os assuntos que conectam a semana', 'Guia de leitura');
      tx(s, 'A edição reúne a leitura dos acontecimentos, os mecanismos por trás das campanhas e os possíveis efeitos sobre dados e continuidade. As páginas de dados delimitam o período e a cobertura de cada fonte.', .57, 2.6, 7.13, .8, 12, { color: C.muted });
      const groups = [ ['Panorama', 'overview'], ['Notícias e campanhas', 'article'], ['Vulnerabilidades', 'cves'], ['Ransomware', 'ransomware'], ['Inteligência artificial', 'ai'], ['Método e referências', 'method'] ];
      groups.forEach(([name, kind], i) => {
        const target = pages.findIndex(p => p.kind === kind); if (target < 0) return;
        const y = 3.9 + i * .55;
        tx(s, name, .57, y, 5.8, .28, 13, { bold: true });
        tx(s, String(target + 1).padStart(2, '0'), 7.1, y, .6, .28, 13, { align: 'right', color: C.orange, hyperlink: { slide: target + 1 } });
        rule(s, y + .39);
      });
      label(s, 'Em destaque', .57, 7.6);
      items.slice(0, 3).forEach((n, i) => {
        const y = 8.08 + i * .78;
        tx(s, articleFor(n.id).title!, .57, y, 6.5, .38, 11.5, { fontFace: 'Aptos', hyperlink: { slide: storyPage(n.id) } });
        tx(s, `${n.sources[0]?.source || 'Fonte original'}  /  ${day(n.published)}`, .57, y + .43, 6.5, .18, 8, { color: C.muted });
      });
      note(s, 'A seleção é editorial. Frequência de menções, CVSS e volume de alegações representam sinais diferentes e não formam uma escala única de risco.');
    } else if (page.kind === 'overview') {
      heading(s, 'A leitura da semana', 'Editorial');
      tx(s, sections.executive.priority, .57, 2.6, 7.13, 1.25, 18, { fontFace: 'Aptos' });
      rule(s, 3.95);
      stat(s, r.vulnerabilities.total, 'CVEs publicadas na NVD no período', .57, 4.18);
      stat(s, r.vulnerabilities.kevCount, 'Vulnerabilidades incluídas no KEV', 3.05, 4.18);
      stat(s, r.ransomware.total, 'Organizações citadas no mundo por grupos de ransomware', 5.53, 4.18);
      label(s, 'O panorama e suas conexões', .57, 5.7);
      tx(s, sections.executive.overview.replace(/\n\s*\n/g, '\n'), .57, 6.15, 7.13, 3.65, 11, { fontFace: 'Aptos', paraSpaceAfter: 7, align: 'justify' });
      rule(s, 10.05);
      tx(s, `${r.news.length} matérias gerais  /  ${r.aiNews.length} matérias de IA  /  ${r.ransomware.byCountry.length} países identificados na fonte de ransomware`, .57, 10.26, 7.13, .3, 9, { bold: true, color: C.teal });
      note(s, 'NVD e KEV usam datas distintas: publicação e inclusão. Os registros de ransomware são alegações dos grupos, sem confirmação independente.');
    } else if (page.kind === 'article') {
      const a = page.article!, n = page.news!, urls = a.sourceUrls || [];
      const ai = r.aiNews.some(v => v.id === n.id);
      label(s, ai ? `Inteligência artificial  /  ${assets.category(n)}` : assets.category(n), .57, 1.02);
      const headlineSize = a.title!.length > 110 ? 24 : 27;
      const headlineHeight = Math.max(.8, Math.min(1.75, textHeight(a.title!, 'Aptos Display', headlineSize, 7.13, true) + .12));
      tx(s, a.title!, .57, 1.35, 7.13, headlineHeight, headlineSize, { fontFace: 'Aptos Display', bold: true, hyperlink: urls[0] ? { url: urls[0] } : undefined });
      const stamp = n.publicationTimeKnown !== false && /T\d\d:\d\d/.test(n.published) ? new Date(n.published).toLocaleString('pt-BR', { timeZone: 'America/Fortaleza', dateStyle: 'short', timeStyle: 'short' }) : day(n.published);
      const metaY = 1.35 + headlineHeight + .16, leadY = metaY + .33;
      const leadHeight = Math.max(.75, Math.min(1.05, textHeight(a.lead!, 'Aptos', 12, 7.13) + .15));
      const contextY = leadY + leadHeight + .18, bodyY = contextY + .88;
      const bodyHeight = 8.6 - bodyY;
      tx(s, `${stamp}  ·  ${n.sources.find(v => v.link === urls[0])?.source || n.sources[0]?.source || 'Fonte original'}`, .57, metaY, 7.13, .23, 9, { color: C.muted });
      tx(s, a.lead!, .57, leadY, 7.13, leadHeight, 12, { color: C.muted });
      rect(s, .57, contextY, .045, .78, C.teal);
      label(s, 'Em perspectiva', .76, contextY + .05, 1.35, C.teal);
      tx(s, a.context || '', 2.25, contextY + .03, 5.45, .74, 10.6);
      const body = a.body!, split = Math.ceil(body.length / 2);
      const columns = [body.slice(0, split), body.slice(split)];
      const bodySize = [11,10.5,10.2,9.9,9.6].find(size=>columns.every(parts=>parts.reduce((h,p)=>h+textHeight(p,'Aptos',size,3.41),0)+7*parts.length/72+.22<=bodyHeight)) || 9.6;
      columns.forEach((column, i) => tx(s, column.join('\n'), .57 + i * 3.72, bodyY, 3.41, bodyHeight, bodySize, { paraSpaceAfter: 7, align: 'justify' }));
      const signals = [...new Set([...n.actors, ...n.malware, ...n.cves].filter(Boolean))];
      if (signals.length) s.addNotes('Relações presentes nas fontes: ' + signals.join(' · '));
      rect(s, .57, 8.76, 7.13, 2.25, C.ink);
      label(s, 'Implicações do caso', .76, 8.95, 6.75, 'FFB478');
      a.attention!.forEach((point, i) => {
        const y = 9.33 + i * .55;
        tx(s, String(i + 1).padStart(2, '0'), .76, y, .35, .28, 12, { bold: true, color: 'FFB478' });
        tx(s, point.title, 1.27, y, 1.86, .54, 10.3, { bold: true, color: C.white });
        tx(s, point.text, 3.25, y, 4.22, .47, 9.5, { color: 'DFE7EC' });
      });
      s.addNotes(`Fontes efetivamente lidas:\n${urls.join('\n')}\n${a.evidence.map(v => `${v.status}: ${v.url} ${v.hash || ''}`).join('\n')}`);
    } else if (page.kind === 'cves') {
      const exploited = page.title === 'Exploração conhecida';
      heading(s, page.title, 'Vulnerabilidades');
      tx(s, exploited ? 'Seleção entre as inclusões no catálogo KEV durante o período. Exploração conhecida não significa presença em todos os ambientes.' : 'Três destaques da edição, considerando repercussão nas fontes e gravidade técnica. A aplicabilidade depende do produto, da versão e da configuração.', .57, 2.35, 7.13, .45, 10.5, { color: C.muted });
      page.cves!.forEach((c: WeeklyCve, i) => {
        const y = 3.03 + i * 2.55, draft = sections.cves.find(v => v.id === c.id), mark = assets.marks.get(weeklyProductLogo(c) || '');
        rect(s, .57, y, 7.13, 2.43, C.pale);
        rect(s, .57, y, .045, 2.43, c.kev ? C.orange : C.teal);
        let productX = .77;
        if (mark) { if(weeklyProductLogo(c)==='java')rect(s,.73,y+.13,.74,.46,C.ink); const scale = Math.min(.62 / mark.width, .32 / mark.height); s.addImage({ data: mark.data, x: .77, y: y + .19, w: mark.width * scale, h: mark.height * scale }); productX = 1.55; }
        const name = [c.vendor, c.product].filter(Boolean).filter((v,i,a)=>!i||v.toLowerCase()!==a[0].toLowerCase()).join(' ');
        tx(s, name || 'Produto em identificação', productX, y + .17, 6 - productX, .37, 13, { bold: true });
        tx(s, c.id, .77, y + .65, 4.15, .25, 11, { color: C.teal, hyperlink: { url: `https://nvd.nist.gov/vuln/detail/${c.id}` } });
        tx(s, c.cvss == null ? '—' : String(c.cvss).replace('.', ','), 6.55, y + .12, .94, .44, 25, { bold: true, align: 'right', color: C.ink });
        tx(s, 'CVSS', 6.55, y + .6, .94, .17, 8, { color: C.muted, align: 'right' });
        if (c.kev) tx(s, 'EXPLORADO', 5.05, y + .66, 1.25, .2, 8.5, { color: 'B44C21', bold: true, align: 'right' });
        label(s, 'Mecanismo e consequência', .77, y + .93, 4.3);
        const description = draft?.description || c.description;
        tx(s, description, .77, y + 1.17, 4.2, 1.03, description.length > 300 ? 9.5 : 10.2);
        label(s, 'Correção publicada', 5.32, y + .93, 2.17, C.teal);
        tx(s, draft?.action || c.action || 'Consultar o advisory do fabricante.', 5.32, y + 1.17, 2.17, 1.03, 9.8);
        const status = c.kev ? `KEV ${c.dateAdded ? day(c.dateAdded) : '· presença confirmada'}` : 'Sem registro de exploração no KEV';
        tx(s, `${status}${c.epss == null ? '' : `  ·  EPSS ${pct(c.epss, 1)}`}`, .77, y + 2.24, 5.55, .16, 7.7, { color: C.muted });
        if (c.references[0]) tx(s, 'Fonte técnica ↗', 6.1, y + 2.22, 1.39, .18, 8, { align: 'right', color: C.teal, hyperlink: { url: c.references[0].url } });
      });
      note(s, 'CVSS expressa gravidade técnica. EPSS é um modelo de probabilidade de exploração, não de impacto. Ausência no KEV não comprova ausência de ataques.');
    } else if (page.kind === 'ransomware') {
      heading(s, 'Ransomware pelo mundo', 'Panorama de extorsão');
      tx(s, sections.ransomware.overview, .57, 2.5, 7.13, 1.3, 10.5, { fontFace: 'Aptos', align: 'justify' });
      stat(s, r.ransomware.total, 'Organizações citadas nas publicações', .57, 4);
      stat(s, r.ransomware.byCountry.length, 'Países identificados na base', 3.05, 4);
      stat(s, r.ransomware.byGroup.length, 'Grupos identificados na fonte', 5.53, 4);
      rect(s, 0, 5.5, 8.27, 3.77, C.ink);
      if (worldMap) s.addImage({ data: worldMap, x: .57, y: 5.65, w: 7.13, h: 3.565 });
      else bars(s, r.ransomware.byCountry.slice(0, 6).map(v => ({ ...v, name: countryName(v.name) })), .57, 5.7, 7.13, 3.2);
      label(s, 'Países com mais registros', .57, 9.51);
      r.ransomware.byCountry.slice(0, 5).forEach((v, i) => {
        const x = .57 + i * 1.47;
        tx(s, countryName(v.name), x, 9.9, 1.25, .35, 9, { bold: true });
        tx(s, `${num(v.count)}  /  ${pct(v.count, r.ransomware.total)}`, x, 10.35, 1.3, .25, 12, { color: C.orange });
      });
      note(s, 'Mapa: maior intensidade indica mais registros. Áreas sem correspondência geográfica ficam sem destaque. São alegações dos grupos, não incidentes confirmados.');
    } else if (page.kind === 'sectors') {
      const rows = r.ransomware.bySector.slice(page.offset || 0, (page.offset || 0) + (page.count || 14));
      heading(s, page.title, 'Ransomware / distribuição setorial', 'A classificação é a informada pela fonte. O volume descreve organizações citadas e não mede a taxa de ataques de cada setor.');
      const total = r.ransomware.bySector.reduce((n, v) => n + v.count, 0);
      const max = Math.max(1, ...r.ransomware.bySector.map(v => v.count));
      label(s, 'Setor', .57, 3.4, 2.6); label(s, 'Registros e participação entre os classificados', 3.35, 3.4, 4.35);
      rows.forEach((v, i) => {
        const y = 3.95 + i * .39;
        tx(s, sectors[v.name] || v.name, .57, y, 2.7, .25, 10);
        rect(s, 3.35, y + .04, Math.max(.01, v.count / max * 2.8), .13, C.teal);
        tx(s, `${num(v.count)}  /  ${pct(v.count, total)}`, 6.4, y, 1.3, .25, 10, { align: 'right', bold: true });
        rule(s, y + .31);
      });
      const top = r.ransomware.bySector[0];
      tx(s, top ? `${sectors[top.name] || top.name} aparece à frente neste recorte, com ${num(top.count)} registros entre ${num(total)} classificados. A concentração pode refletir tanto a atividade dos grupos quanto a visibilidade das publicações acompanhadas.` : 'Não há classificações setoriais disponíveis neste recorte.', .57, 9.64, 7.13, .73, 11, { fontFace: 'Aptos' });
      note(s, `${r.ransomware.bySector.length} categorias na base. Esta página mostra ${rows.length}; categorias adicionais continuam nas páginas seguintes. A listagem não aplica prioridades por cliente.`);
    } else if (page.kind === 'victims') {
      heading(s, page.title, 'Ransomware / observações da fonte', 'Amostra das 12 publicações mais recentes disponíveis no período. O nome citado não confirma que o incidente tenha ocorrido.');
      const rows = [...r.ransomware.victims].sort((a, b) => (b.discovered || b.published).localeCompare(a.discovered || a.published)).slice(0, 12);
      const columns = [.57, 3.65, 4.7, 6.15];
      rect(s, .57, 3.35, 7.13, .39, C.ink);
      ['Organização citada', 'País', 'Grupo', 'Observação'].forEach((v, i) => tx(s, v, columns[i] + .08, 3.43, i ? 1.3 : 2.8, .2, 8.5, { bold: true, color: C.white }));
      rows.forEach((v, i) => {
        const y = 3.85 + i * .48;
        tx(s, v.name, .65, y, 2.87, .37, 8.5, { hyperlink: v.permalink ? { url: v.permalink } : undefined });
        tx(s, v.country || '—', 3.73, y, .8, .35, 9);
        tx(s, v.group, 4.78, y, 1.15, .35, 8.5);
        tx(s, day(v.discovered || v.published), 6.23, y, 1.35, .35, 8.5);
        rule(s, y + .39);
      });
      tx(s, 'As relações de setor e país ajudam a acompanhar padrões. Elas não demonstram vínculo comercial, acesso compartilhado ou impacto em outras organizações.', .57, 10.02, 7.13, .5, 11, { fontFace: 'Aptos' });
      note(s, `Exibindo ${rows.length} de ${r.ransomware.victims.length} organizações disponíveis. O JSON exportado contém a listagem completa. Fonte: Ransomware.live.`);
    } else if (page.kind === 'history') {
      heading(s, 'A evolução das publicações', 'Ransomware / histórico');
      tx(s, sections.ransomware.trend, .57, 2.5, 7.13, 1.3, 10.5, { fontFace: 'Aptos', align: 'justify' });
      const history = r.ransomware.history || [];
      label(s, 'Organizações citadas no mundo · 12 períodos semanais', .57, 4.05);
      if (history.some(v => v.available && v.global != null)) s.addChart(deck.ChartType.line, [{ name: 'Organizações citadas no mundo', labels: history.map(v => day(v.from).slice(0, 5)), values: history.map(v => v.available ? v.global ?? null : null) as number[] }], { ...chartOptions, x: .57, y: 4.45, w: 7.13, h: 2.1, chartColors: [C.orange], showLegend: false, showValue: false, displayBlanksAs: 'gap' });
      else tx(s, 'O histórico mundial não tem cobertura suficiente para comparação.', .57, 4.6, 7.13, .5, 11, { color: C.muted });
      tx(s, sections.ransomware.groups, .57, 6.95, 7.13, .85, 10.5, { fontFace: 'Aptos' });
      label(s, 'Grupos com mais registros na semana · até 6', .57, 8.15);
      bars(s, r.ransomware.byGroup.slice(0, 6), .57, 8.52, 7.13, 1.9);
      note(s, 'Lacunas indicam ausência de cobertura, não ausência de ataques. Uma semana parcial não deve ser comparada a uma semana completa como evidência de redução.');
    } else if (page.kind === 'ai') {
      heading(s, 'A superfície de risco da IA', 'Inteligência artificial');
      rect(s, .57, 2.53, 7.13, 1.34, C.ink);
      stat(s, r.vulnerabilities.ai.total, 'Registros no recorte temático', .77, 2.69, 2.05, true);
      stat(s, r.vulnerabilities.ai.critical, 'Vulnerabilidades críticas', 3.15, 2.69, 2.05, true);
      stat(s, r.vulnerabilities.ai.kevCount ?? null, 'Com presença no KEV', 5.53, 2.69, 1.96, true);
      tx(s, sections.ai.interpretation, .57, 4.17, 7.13, .8, 11.5);
      label(s, 'Superfícies acompanhadas', .57, 5.3, 2.8);
      tx(s, 'REG.', 3.28, 5.3, .45, .2, 8, { bold: true, align: 'right', color: C.muted });
      label(s, 'Ferramentas em destaque', 4.4, 5.3, 2.3);
      tx(s, 'CVSS', 6.9, 5.3, .8, .2, 8, { bold: true, align: 'right', color: C.muted });
      const categories = (r.vulnerabilities.ai.categories || r.vulnerabilities.ai.vendors).slice(0, 6);
      const max = Math.max(1, ...categories.map(v=>v.count));
      categories.forEach((v,i)=>{
        const y = 5.85 + i * .51;
        tx(s, v.name, .57, y, 2.82, .25, 9.7);
        tx(s, String(v.count), 3.43, y - .02, .3, .26, 12, { bold: true, align: 'right', color: C.teal });
        rect(s, .57, y + .33, 3.16, .07, 'DFE9EB');
        rect(s, .57, y + .33, Math.max(.01, 3.16 * v.count / max), .07, C.teal);
      });
      if (!categories.length) tx(s, 'Classificação temática ainda indisponível.', .57, 5.85, 3.16, .6, 10, { color: C.muted });
      const tools = r.vulnerabilities.ai.tools || [];
      tools.slice(0, 4).forEach((v, i) => {
        const y = 5.85 + i * .75;
        tx(s, v.name, 4.4, y, 2.3, .29, 11, { bold: true, hyperlink: { url: `https://nvd.nist.gov/vuln/detail/${v.id}` } });
        tx(s, v.cvss == null ? '—' : String(v.cvss).replace('.', ','), 6.9, y - .04, .8, .38, 20, { bold: true, align: 'right', color: C.orange });
        tx(s, `${v.count} ${v.count === 1 ? 'registro' : 'registros'}  ·  ${v.id}`, 4.4, y + .35, 3.3, .2, 8, { color: C.muted });
        rule(s, y + .61, 4.4, 3.3);
      });
      if (!tools.length) tx(s, 'Ferramentas ainda sem identificação suficiente neste recorte.', 4.4, 5.85, 3.3, .7, 10, { color: C.muted });
      rect(s, .57, 9.25, 7.13, 1.32, C.pale);
      label(s, 'O alcance das dependências', .77, 9.43, 6.73);
      tx(s, sections.ai.leadership, .77, 9.79, 6.73, .72, 10.7);
      note(s, 'Recorte temático sujeito à revisão. Os números ao lado das ferramentas mostram CVSS, de 0 a 10. Publicações de vulnerabilidades não equivalem a ataques.');
    } else if (page.kind === 'method') {
      heading(s, 'Como ler esta edição', 'Método e cobertura');
      const blocks = [
        ['Notícias e campanhas', 'A seleção editorial parte das publicações coletadas no período. A redação usa o conteúdo dos artigos efetivamente lidos e preserva as referências. Matérias sobre eventos anteriores continuam com seu recorte temporal explícito.'],
        ['Vulnerabilidades', 'O total da NVD acompanha a data de publicação. O KEV acompanha a inclusão no catálogo de exploração conhecida. Os destaques selecionam registros para leitura e não substituem o catálogo completo.'],
        ['Ransomware', 'As organizações são as citadas nas publicações acompanhadas. Registros são deduplicados; a fonte pode revisar nomes, setores e datas. O panorama não mede todos os incidentes do mundo nem confirma alegações criminosas.'],
        ['Inteligência artificial', 'O recorte agrupa ferramentas, bibliotecas, agentes, servidores de modelos e integrações relacionadas a IA. A classificação temática pode exigir revisão, especialmente quando ainda não há identificação completa do produto.'],
      ];
      blocks.forEach(([h, p], i) => { const y = 2.65 + i * 1.42; label(s, h, .57, y); tx(s, p, .57, y + .36, 7.13, .72, 11, { fontFace: 'Aptos' }); rule(s, y + 1.17); });
      label(s, 'Cobertura no fechamento', .57, 8.7);
      const status: Record<string, string> = { ready: 'Coletado', partial: 'Parcial', error: 'Indisponível', stale: 'Dados anteriores', pending: 'Pendente' };
      tx(s, `Notícias: ${num(r.coverage.news.publications)} publicações no acervo\nRansomware.live: ${status[r.coverage.ransomware.status] || r.coverage.ransomware.status}\nVulnerabilidades: ${status[r.coverage.vulnerabilities.status || 'pending'] || r.coverage.vulnerabilities.status}\nAtualizado em ${new Date(r.updatedAt).toLocaleString('pt-BR', { timeZone: 'America/Fortaleza' })} · Fortaleza (UTC−3)`, .57, 9.12, 7.13, 1.1, 10, { color: C.muted });
      note(s, r.previewNote || 'Análise global da ThreatSumm4ry. Possibilidades analíticas são apresentadas como possibilidades, sem presumir comprometimento de uma organização.');
    } else if (page.kind === 'sources') {
      heading(s, page.title, 'Referências verificáveis', 'Os links levam ao material original usado na edição. A data da publicação permanece separada do período dos eventos descritos.');
      assets.references.slice(page.offset || 0, (page.offset || 0) + (page.count || 14)).forEach((v, i) => {
        const y = 3.2 + i * .54;
        tx(s, String((page.offset || 0) + i + 1).padStart(2, '0'), .57, y, .35, .25, 9, { color: C.orange, bold: true });
        tx(s, v.title, 1.03, y, 6.67, .34, 10, { hyperlink: { url: v.url } });
        tx(s, new URL(v.url).hostname, 1.03, y + .36, 6.67, .16, 8, { color: C.muted, hyperlink: { url: v.url } });
      });
      s.addNotes(assets.references.slice(page.offset || 0, (page.offset || 0) + (page.count || 14)).map(v => `${v.title}: ${v.url}`).join('\n'));
    }
    s.addNotes(`ThreatSumm4ry · edição global · ${assets.period}. Sem perfil de cliente. Números limitados à cobertura disponível.`);
  });
}
