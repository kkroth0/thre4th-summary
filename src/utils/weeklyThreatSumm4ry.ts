import JSZip from 'jszip';
import type { WeeklyReportData, WeeklyNews, WeeklyCve, WeeklyEditorialArticle } from '@/types/weekly-report';
import { weeklyProductLogo } from './weeklyPptxLogos';
import { renderWeeklyMagazine } from './weeklyMagazineLayout';
import { A, P, first, parse, serialize } from './weeklyPptxXml';

/** Original website publication. No client template or local-generator dependency. */
export const WEEKLY_BRAND = {
  name: 'ThreatSumm4ry', version: 'global-editorial-5', format: 'A4 portrait',
  ink: '101B26', orange: 'F77700', muted: '526376', paper: 'FFFFFF',
  logoLight: '/templates/weekly-threatsumm4ry/logo-light.png',
  logoDark: '/templates/weekly-threatsumm4ry/logo-dark.png',
} as const;
const W = 8.27, H = 11.69;
const date = (value: string) => new Date(value).toLocaleDateString('pt-BR', { timeZone: 'America/Fortaleza' });
export const weeklyBrandPeriod = (r: WeeklyReportData) => `${date(r.range.from)} a ${date(new Date(Date.parse(r.range.to) - 1).toISOString())}`;
export const weeklyBrandFilename = (r: WeeklyReportData) => `ThreatSumm4ry_Boletim_Global_${r.range.id.replace(/[^\w-]/g, '_')}_v${r.revision}.pptx`;
export interface MagazinePage { kind: 'cover'|'contents'|'overview'|'article'|'cves'|'ransomware'|'sectors'|'victims'|'history'|'ai'|'method'|'sources'; title: string; article?: WeeklyEditorialArticle; news?: WeeklyNews; cves?: WeeklyCve[]; offset?: number; count?: number }

export function buildThreatSumm4ryWeeklySlides(r: WeeklyReportData): MagazinePage[] {
  if (r.scope !== 'global' || r.profile) throw Error('Atualize e redija o boletim global antes de exportar. Edições por cliente não usam este formato.');
  if (r.editorial?.status !== 'ready' || !r.editorial.sections) throw Error('Redija o boletim a partir das fontes antes de exportar.');
  const articles = (items: WeeklyNews[]) => items.map(news => {
    const article = r.editorial!.articles?.find(a => a.id === news.id && a.status === 'ready');
    if (!article?.title || !article.lead || !article.body || article.body.length < 2 || article.body.length > 4 || article.attention?.length !== 3) throw Error('Há matérias sem redação concluída. Gere a redação novamente.');
    return { kind: 'article' as const, title: article.title, article, news };
  });
  const highlights = (r.vulnerabilities.editorial?.highlights ?? r.vulnerabilities.priority).slice(0, 3);
  const exploited = (r.vulnerabilities.editorial?.exploited ?? r.vulnerabilities.kev).filter(c => c.kev).slice(0, 3);
  const sectorPageCount = Math.ceil(r.ransomware.bySector.length / 14);
  const sectorPageSize = sectorPageCount ? Math.ceil(r.ransomware.bySector.length / sectorPageCount) : 0;
  const pages: MagazinePage[] = [
    { kind: 'cover', title: 'A semana cibernética' },
    { kind: 'contents', title: 'Nesta edição' },
    { kind: 'overview', title: 'A leitura da semana' },
    ...articles(r.news),
    ...(highlights.length ? [{ kind: 'cves' as const, title: 'Vulnerabilidades em destaque', cves: highlights }] : []),
    ...(exploited.length ? [{ kind: 'cves' as const, title: 'Exploração conhecida', cves: exploited }] : []),
    { kind: 'ransomware', title: 'Ransomware pelo mundo' },
    ...Array.from({ length: sectorPageCount }, (_, i) => ({ kind: 'sectors' as const, title: i ? 'Distribuição por setor · continuação' : 'A distribuição entre os setores', offset: i * sectorPageSize, count: sectorPageSize })),
    ...(r.ransomware.victims.length ? [{ kind: 'victims' as const, title: 'Organizações citadas nas publicações' }] : []),
    { kind: 'history', title: 'O ritmo das publicações' },
    { kind: 'ai', title: 'Inteligência artificial em foco' },
    ...articles(r.aiNews),
    { kind: 'method', title: 'Como ler esta edição' },
  ];
  // All references remain visible and clickable; notes also preserve full URLs.
  const refs = referenceRows(r);
  const referencePageSize = Math.ceil(refs.length / Math.max(1, Math.ceil(refs.length / 14)));
  for (let i = 0; i < Math.max(1, refs.length); i += referencePageSize || 1) pages.push({ kind: 'sources', title: i ? 'Referências · continuação' : 'Referências da edição', offset: i, count: referencePageSize });
  return pages;
}
function referenceRows(r: WeeklyReportData) {
  return [...new Map([
    ...r.sources.map(s => ({ title: s.source || s.title, url: s.link })),
    ...(r.editorial?.articles || []).flatMap(a => (a.sourceUrls || []).map(url => ({ title: a.title || 'Matéria', url }))),
    ...[...(r.vulnerabilities.editorial?.highlights || r.vulnerabilities.priority.slice(0, 3)), ...(r.vulnerabilities.editorial?.exploited || r.vulnerabilities.kev.slice(0, 3))].flatMap(c => c.references.map(s => ({ title: c.id, url: s.url }))),
    { title: 'Ransomware.live · alegações publicadas', url: 'https://www.ransomware.live/' },
    { title: 'NVD · registros de vulnerabilidades', url: 'https://nvd.nist.gov/' },
    { title: 'CISA · Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  ].filter(s => /^https?:\/\//i.test(s.url)).map(s => [s.url, s])).values()];
}
export function weeklyMagazineCategory(n: WeeklyNews) {
  const text = `${n.title} ${n.categories.join(' ')}`;
  if (/ransom/i.test(text)) return 'RANSOMWARE';
  if (/phish/i.test(text)) return 'CAMPANHA DE PHISHING';
  if (/supply.chain|cadeia de supr/i.test(text)) return 'ATAQUE A SUPPLY CHAIN';
  if (/espion|\bapts?\b/i.test(text)) return 'ESPIONAGEM';
  if (/vulner|CVE-/i.test(text)) return 'VULNERABILIDADES';
  if (/data.leak|data.breach|vazamento/i.test(text)) return 'VAZAMENTO DE DADOS';
  return 'NOTÍCIAS E CAMPANHAS';
}
async function asset(path: string) {
  const response = await fetch(path);
  if (!response.ok) throw Error('Não foi possível carregar a identidade visual do boletim.');
  const bytes = new Uint8Array(await response.arrayBuffer());
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
  return `data:image/png;base64,${btoa(binary)}`;
}

export async function createThreatSumm4ryWeeklyPptx(r: WeeklyReportData): Promise<Blob> {
  const pages = buildThreatSumm4ryWeeklySlides(r);
  const [{ default: Pptx }, logo, logoLight, cover] = await Promise.all([
    import('pptxgenjs'), asset(WEEKLY_BRAND.logoDark), asset(WEEKLY_BRAND.logoLight), asset('/templates/weekly-threatsumm4ry/cover-v2.png'),
  ]);
  const deck = new Pptx();
  const productMarks = new Map<string, { data: string; width: number; height: number }>();
  await Promise.all([...new Set(pages.flatMap(p => (p.cves || []).map(weeklyProductLogo).filter((key): key is string => !!key)))].map(async key => {
    try {
      const data = await asset(`/templates/weekly-logos/${key}.png`);
      const bytes = Uint8Array.from(atob(data.split(',')[1]), c => c.charCodeAt(0));
      const view = new DataView(bytes.buffer), width = view.getUint32(16), height = view.getUint32(20);
      if (width && height) productMarks.set(key, { data, width, height });
    } catch { /* Keep the product name when its own verified mark is unavailable. */ }
  }));
  deck.defineLayout({ name: 'TS4_A4', width: W, height: H }); deck.layout = 'TS4_A4';
  deck.author = 'ThreatSumm4ry'; deck.company = 'ThreatSumm4ry'; deck.subject = 'Panorama global de inteligência cibernética';
  deck.title = `A semana cibernética · ${weeklyBrandPeriod(r)}`;
  deck.theme = { headFontFace: 'Aptos Display', bodyFontFace: 'Aptos' };
  await renderWeeklyMagazine(deck, r, pages, { logo, logoLight, cover, marks: productMarks, period: weeklyBrandPeriod(r), references: referenceRows(r), category: weeklyMagazineCategory });
  const raw = await deck.write({ outputType: 'uint8array' });
  const zip = await JSZip.loadAsync(raw);
  // PptxGenJS may emit overrides for unmaterialized masters. Remove only those orphan declarations.
  const types = await zip.file('[Content_Types].xml')!.async('string');
  zip.file('[Content_Types].xml', types.replace(/<Override\b[^>]*PartName="([^"]+)"[^>]*\/>/g, (all, part: string) => zip.file(part.replace(/^\//, '')) ? all : ''));
  // PptxGenJS links both the shape and its runs. Keep the shape link for clean print typography.
  for (const name of Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))) {
    const doc = parse(await zip.file(name)!.async('string'));
    for (const shape of Array.from(doc.getElementsByTagNameNS(P, 'sp'))) {
      const nv = first(shape, P, 'cNvPr');
      for (const properties of Array.from(shape.getElementsByTagNameNS(A, 'rPr'))) {
        const links = Array.from(properties.getElementsByTagNameNS(A, 'hlinkClick'));
        if (links.length && nv && !nv.getElementsByTagNameNS(A, 'hlinkClick').length) nv.appendChild(links[0].cloneNode(true));
        for (const link of links) link.parentNode?.removeChild(link);
        if (links.length) properties.setAttribute('u', 'none');
      }
    }
    zip.file(name, serialize(doc));
  }
  for (const name of Object.keys(zip.files).filter(n => /^ppt\/charts\/.*\.xml$/.test(n))) {
    const xml = (await zip.file(name)!.async('string')).replace(/<c:pt idx="\d+"><c:v><\/c:v><\/c:pt>/g, '');
    if (xml.includes('Organizações citadas no mundo')) {
      const missing = (r.ransomware.history || []).flatMap((row, i) => !row.available || row.global == null ? [i] : []);
      if (missing.length) {
        const rels = await zip.file(name.replace('/charts/', '/charts/_rels/') + '.rels')?.async('string');
        const target = rels?.match(/Target="\.\.\/embeddings\/([^"]+)"/)?.[1];
        if (target && zip.file(`ppt/embeddings/${target}`)) {
          const book = await JSZip.loadAsync(await zip.file(`ppt/embeddings/${target}`)!.async('uint8array'));
          const sheetPath = 'xl/worksheets/sheet1.xml';
          let sheet = await book.file(sheetPath)!.async('string');
          for (const i of missing) sheet = sheet.replace(new RegExp(`<c\\b[^>]*r="B${i + 2}"[^>]*>[\\s\\S]*?</c>`, 'g'), `<c r="B${i + 2}"/>`);
          book.file(sheetPath, sheet); zip.file(`ppt/embeddings/${target}`, await book.generateAsync({ type: 'uint8array' }));
        }
      }
    }
    zip.file(name, xml.replace(/<c:multiLvlStrRef>([\s\S]*?)<\/c:multiLvlStrRef>/g, (all, content: string) => (content.match(/<c:lvl>/g) || []).length === 1 ? `<c:strRef>${content.replace(/multiLvlStrCache/g, 'strCache').replace(/<\/?c:lvl>/g, '')}</c:strRef>` : all));
  }
  return zip.generateAsync({ type: 'blob', compression: 'DEFLATE', mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation' });
}
