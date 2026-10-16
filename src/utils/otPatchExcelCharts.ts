import JSZip from 'jszip';
import parts from './otPatchChartParts.json';
import { analyzeOtReport } from './otPatchIntelligence';
import type { NewsExcelPayload } from './iocExcelWorkbook';

const xml = (value: string) => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
const wrapVendor = (s: string) => s.split(' ').reduce((lines: string[], word) => { if (lines.length && lines.at(-1)!.length + word.length < 19) lines[lines.length - 1] += ' ' + word; else lines.push(word); return lines; }, []).join('\n');

// ExcelJS writes the report body. These two native chart parts were authored
// with Artifact Tool. Retain cell bindings and populate OOXML chart caches so
// Excel and viewers display the current snapshot before any recalculation.
export async function addOtPatchExcelCharts(buffer: Uint8Array, payload: NewsExcelPayload) {
  const zip = await JSZip.loadAsync(buffer), a = analyzeOtReport(payload.rows, payload.report);
  const chartData = [a.priorities, Array.from({ length: 5 }, (_, i) => ({ label: a.vendors[i] ? wrapVendor(a.vendors[i].label) : '', count: a.vendors[i]?.count ?? 0 }))];
  for (const [name, source] of Object.entries(parts)) {
    if (name === 'contentTypes') continue;
    let value = source;
    if (/\/charts\/chart[12]\.xml$/.test(name)) {
      const data = chartData[name.endsWith('chart1.xml') ? 0 : 1];
      value = value.replace(/<c:strCache>[\s\S]*?<\/c:strCache>/, `<c:strCache><c:ptCount val="${data.length}"/>${data.map((d, i) => `<c:pt idx="${i}"><c:v>${xml(d.label)}</c:v></c:pt>`).join('')}</c:strCache>`)
        .replace(/<c:numCache>[\s\S]*?<\/c:numCache>/, `<c:numCache><c:formatCode>0</c:formatCode><c:ptCount val="${data.length}"/>${data.map((d, i) => `<c:pt idx="${i}"><c:v>${d.count}</c:v></c:pt>`).join('')}</c:numCache>`)
        .replace(/(<c:valAx>[\s\S]*?<c:scaling>[\s\S]*?)(<\/c:scaling>)/, '$1<c:min val="0"/>$2');
    }
    if (zip.file(name)) throw Error('Conflito ao incluir os gráficos do relatório.');
    zip.file(name, value);
  }
  const types = await zip.file('[Content_Types].xml')!.async('string');
  const overrides = parts.contentTypes.match(/<Override\b[^>]*\/>/g)?.filter(s => /PartName="\/xl\/drawings\//.test(s)) || [];
  zip.file('[Content_Types].xml', types.replace('</Types>', overrides.join('') + '</Types>'));
  let sheet = await zip.file('xl/worksheets/sheet1.xml')!.async('string');
  if (!sheet.includes('xmlns:r=')) sheet = sheet.replace('<worksheet ', '<worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ');
  zip.file('xl/worksheets/sheet1.xml', sheet.replace('</worksheet>', '<drawing r:id="rIdOtReport"/></worksheet>'));
  const relPath = 'xl/worksheets/_rels/sheet1.xml.rels';
  let rels = zip.file(relPath) ? await zip.file(relPath)!.async('string') : '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>';
  rels = rels.replace(/<Relationships([^>]*)\/>/, '<Relationships$1></Relationships>');
  zip.file(relPath, rels.replace('</Relationships>', '<Relationship Id="rIdOtReport" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/></Relationships>'));
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
}
