// The team's report template: the chrome every generated deck and workbook
// shares, transcribed from the reference file in EMU converted to inches.
// Dark panel on a blurred colour field, yellow section titles over a
// yellow→magenta→cyan rule, Overpass throughout; the workbook answers it with a
// black header band, yellow Calibri and yellow tabs.
//
// Nothing here names a company: the deck is handed over and presented under the
// reader's own name, and `pptx.company` / `workbook.company` stay blank.
import type PptxGenJS from 'pptxgenjs';
import type ExcelJS from 'exceljs';
import { DECK_COVER_BG, DECK_PANEL_BG } from './patchTuesdayDeckArt';

export const DECK = {
    panel: '1A1A24', // dark panel that covers all but a thin frame of the artwork
    card: '242731', // highlight cards
    cardAlt: '222530', // the two wide cards on the executive summary
    cardLine: '454957',
    accent: 'FFE600', // section titles
    amber: 'FFC000', // KPI pills
    red: 'E53935', // card rules and CVE identifiers
    muted: 'B7BAC5',
    white: 'FFFFFF',
    ink: '1A1A24', // text on the amber pills
    logo: '2E2E38', // the reserved logo plate, bottom right
    green: '2DB757', // chart bars
} as const;

// Office resident fonts. A font PowerPoint does not have gets substituted, and
// the substitute's metrics move every line and every box on the slide — that is
// the "deck opened broken" report. Calibri and Calibri Light ship with Office on
// Windows and Mac, and the workbook already uses Calibri, so both artifacts read
// as one report.
export const FONT = 'Calibri';
export const FONT_LIGHT = 'Calibri Light';

// Every font this deck is allowed to name. Anything else risks substitution.
export const DECK_FONTS = [FONT, FONT_LIGHT];

// PowerPoint re-lays text out with its own metrics, so a fixed box is only safe
// when it also carries autofit: `fit: 'shrink'` emits <a:normAutofit/>, which is
// what makes PowerPoint shrink a long title into its card instead of spilling it
// over the next one. Every text box in the deck goes through here to get it.
export const deckText = (
    slide: PptxGenJS.Slide,
    content: string | PptxGenJS.TextProps[],
    options: PptxGenJS.TextPropsOptions = {}
): void => {
    slide.addText(content as string, { fontFace: FONT, wrap: true, fit: 'shrink', ...options });
};

export const CANVAS = { w: 10, h: 5.625 }; // LAYOUT_16x9, the reference canvas

export type PptxFactory = new () => PptxGenJS;

export interface NamedCount {
    name: string;
    count: number;
}

// ---- Free text ---------------------------------------------------------------

// Vendor titles and product names are free text we do not control. XML 1.0 has
// no legal representation for the C0 controls (not even `&#x7;`), so one of them
// in a title is enough for PowerPoint and Excel to declare the file corrupt and
// offer to repair it. Every builder scrubs its input before writing anything.
// eslint-disable-next-line no-control-regex
const XML_ILLEGAL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g;

export const scrubXml = <T>(v: T): T =>
    typeof v === 'string'
        ? (v.replace(XML_ILLEGAL, '') as T)
        : Array.isArray(v)
          ? (v.map(scrubXml) as T)
          : v && typeof v === 'object'
            ? (Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubXml(x)])) as T)
            : v;

// A title long enough to wrap breaks the fixed card height, so it is condensed
// and the untruncated text goes to the speaker notes.
export const condenseTitle = (title: string, max = 78) => (title.length > max ? `${title.slice(0, max - 1)}…` : title);

// ---- Dates -------------------------------------------------------------------

// Feeds hand over either a full timestamp (MSRC) or a bare day (SAP). A bare day
// is read as local midnight so the deck never prints the day before.
const parseDate = (value: string | null): Date | null => {
    if (!value) return null;
    const date = new Date(/T/.test(value) ? value : `${value}T00:00:00`);
    return isNaN(date.getTime()) ? null : date;
};

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export const NO_CYCLE = 'Ciclo mais recente';

export const fmtMonthPt = (value: string | null): string =>
    parseDate(value)?.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }) ?? NO_CYCLE;

const fmtDatePt = (value: string | null): string =>
    parseDate(value)?.toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' }) ?? NO_CYCLE;

// "12 de agosto de 2026" → "12 de Agosto de 2026", the cover's own capitalisation.
export const fmtLongDatePt = (value: string | null): string =>
    fmtDatePt(value).replace(/ de (\p{Ll})/u, (_, letter: string) => ` de ${letter.toUpperCase()}`);

// dd/mm/yyyy, the form the slide footer uses.
export const fmtShortDatePt = (value: string | null): string => parseDate(value)?.toLocaleDateString('pt-BR') ?? '';

// "agosto de 2026" → "Agosto/2026", the form the cover and the header band use.
export const monthSlashYear = (value: string | null): string => {
    const date = parseDate(value);
    if (!date) return NO_CYCLE;
    return `${capitalize(date.toLocaleDateString('pt-BR', { month: 'long' }))}/${date.getFullYear()}`;
};

// ---- Template chrome ---------------------------------------------------------

// The accent rule runs yellow → magenta → cyan. pptxgenjs has no gradient fill,
// so it is painted as abutting slices of the interpolated colour; at 0.07in tall
// the seams are not resolvable.
const GRADIENT_STOPS: [number, string][] = [
    [0, 'FFE600'],
    [0.46, 'FFE600'],
    [0.66, 'FF32FF'],
    [1, '32FFFF'],
];

const mixHex = (from: string, to: string, t: number): string =>
    [0, 2, 4]
        .map((o) => {
            const a = parseInt(from.substr(o, 2), 16);
            const b = parseInt(to.substr(o, 2), 16);
            return Math.round(a + (b - a) * t)
                .toString(16)
                .padStart(2, '0');
        })
        .join('')
        .toUpperCase();

const gradientAt = (t: number): string => {
    for (let i = 1; i < GRADIENT_STOPS.length; i++) {
        const [p0, c0] = GRADIENT_STOPS[i - 1];
        const [p1, c1] = GRADIENT_STOPS[i];
        if (t <= p1) return p1 === p0 ? c1 : mixHex(c0, c1, (t - p0) / (p1 - p0));
    }
    return GRADIENT_STOPS[GRADIENT_STOPS.length - 1][1];
};

const GRADIENT_SLICES = 40;

export const gradientBar = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    x: number,
    y: number,
    w: number,
    h: number,
    vertical = false
): void => {
    const span = (vertical ? h : w) / GRADIENT_SLICES;
    for (let i = 0; i < GRADIENT_SLICES; i++) {
        slide.addShape(pptx.ShapeType.rect, {
            x: vertical ? x : x + i * span,
            y: vertical ? y + i * span : y,
            w: vertical ? w : span + 0.005, // overlap so no hairline shows between slices
            h: vertical ? span + 0.005 : h,
            fill: { color: gradientAt(i / (GRADIENT_SLICES - 1)) },
            line: { type: 'none' },
        });
    }
};

// The reserved plate: the presenter drops their own mark in here.
const logoPlate = (pptx: PptxGenJS, slide: PptxGenJS.Slide, x: number, y: number, w: number, h: number): void => {
    slide.addShape(pptx.ShapeType.rect, { x, y, w, h, fill: { color: DECK.logo }, line: { color: DECK.accent, width: 0.75 } });
};

// Report name, cycle and date over the cover artwork, plate down the right edge.
export const coverSlide = (pptx: PptxGenJS, report: string, date: string | null): PptxGenJS.Slide => {
    const slide = pptx.addSlide();
    slide.background = { data: DECK_COVER_BG, path: 'preencoded.jpg' };
    logoPlate(pptx, slide, 8.428, 0, 1.571, 5.625);
    deckText(slide, 
        [
            { text: report, options: { breakLine: true } },
            { text: '', options: { breakLine: true } },
            { text: 'Cyber Threat Intelligence and Hunting' },
        ],
        { x: 0.67, y: 2.066, w: 4.654, h: 1.292, fontFace: FONT, fontSize: 24, color: DECK.white, lineSpacingMultiple: 0.85 }
    );
    deckText(slide, `Consolidado - ${monthSlashYear(date)}`, {
        x: 0.67, y: 3.529, w: 4.269, h: 0.588,
        fontFace: FONT, fontSize: 14, bold: true, italic: true, color: DECK.white,
    });
    deckText(slide, fmtLongDatePt(date), {
        x: 0.67, y: 4.288, w: 4.024, h: 0.202,
        fontFace: FONT, fontSize: 14, color: DECK.white,
    });
    return slide;
};

export const contentSlide = (pptx: PptxGenJS, title: string, page: number, date: string | null): PptxGenJS.Slide => {
    const slide = pptx.addSlide();
    slide.background = { data: DECK_PANEL_BG, path: 'preencoded.jpg' };
    slide.addShape(pptx.ShapeType.roundRect, {
        x: 0.264, y: 0.234, w: 9.472, h: 5.151,
        rectRadius: 0.106, fill: { color: DECK.panel }, line: { type: 'none' },
    });
    deckText(slide, title, {
        x: 0.539, y: 0.483, w: 8.9, h: 0.471,
        fontFace: FONT, fontSize: 21, bold: true, color: DECK.accent,
    });
    gradientBar(pptx, slide, 0.55, 0.969, 7.07, 0.07);

    const footer = { h: 0.101, fontFace: FONT_LIGHT, fontSize: 6, color: DECK.white, align: 'center' as const, valign: 'middle' as const };
    deckText(slide, fmtShortDatePt(date), { x: 0.816, y: 5.405, w: 1.046, ...footer });
    deckText(slide, 'Cyber Threat Intelligence & Cyber Threat Hunting', { x: 1.862, y: 5.405, w: 3.137, ...footer });
    deckText(slide, String(page), { x: 0.398, y: 5.405, w: 0.418, ...footer });

    logoPlate(pptx, slide, 8.428, 4.997, 1.571, 0.628);
    return slide;
};

export const attachmentNote = (slide: PptxGenJS.Slide, y = 4.96): void => {
    deckText(slide, 'A Listagem de Vulnerabilidades encontra-se no arquivo anexado ao e-mail.', {
        x: 0.469, y, w: 6.936, h: 0.227,
        fontFace: FONT, fontSize: 9, bold: true, italic: true, color: DECK.white,
    });
};

// A bar chart drawn straight onto a dark surface: the plot has to be painted the
// same colour as whatever sits behind it, or it shows up as a white block.
export const darkBarChart = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    rows: NamedCount[],
    box: { x: number; y: number; w: number; h: number },
    surface: string
): void => {
    // Charted bottom-up, so the largest count reads at the top of the axis.
    const data = [...rows].reverse();
    slide.addChart(
        pptx.ChartType.bar,
        [{ name: 'Total', labels: data.map((r) => r.name), values: data.map((r) => r.count) }],
        {
            ...box,
            barDir: 'bar', barGapWidthPct: 45, chartColors: [DECK.green],
            showLegend: false, showTitle: false,
            showValue: true, dataLabelColor: DECK.white, dataLabelFontFace: FONT, dataLabelFontSize: 7,
            catAxisLabelColor: DECK.white, catAxisLabelFontFace: FONT_LIGHT, catAxisLabelFontSize: 7,
            catAxisLineShow: false, valAxisHidden: true,
            catGridLine: { style: 'none' }, valGridLine: { style: 'none' },
            chartArea: { fill: { color: surface }, border: { pt: 0, color: surface } },
            plotArea: { fill: { color: surface }, border: { pt: 0, color: surface } },
        }
    );
};

export const kpiPill = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    value: string,
    label: string,
    box: { x: number; y: number; vw: number; lw: number; h: number; valueSize: number }
): void => {
    const pill = { fill: { color: DECK.amber }, line: { type: 'none' as const } };
    const text = { fontFace: FONT, bold: true, color: DECK.ink, align: 'center' as const, valign: 'middle' as const };
    slide.addShape(pptx.ShapeType.rect, { x: box.x, y: box.y, w: box.vw, h: box.h, ...pill });
    deckText(slide, value, { x: box.x, y: box.y, w: box.vw, h: box.h, fontSize: box.valueSize, ...text });
    slide.addShape(pptx.ShapeType.rect, { x: box.x + box.vw + 0.031, y: box.y, w: box.lw, h: box.h, ...pill });
    deckText(slide, label, { x: box.x + box.vw + 0.031, y: box.y, w: box.lw, h: box.h, fontSize: 12, ...text });
};

// A highlight card: red rule on top, then whatever the report puts inside it.
export const highlightCard = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    box: { x: number; y: number; w: number; h: number }
): void => {
    slide.addShape(pptx.ShapeType.roundRect, {
        ...box,
        rectRadius: 0.038, fill: { color: DECK.card }, line: { color: DECK.red, width: 0.8 },
        shadow: { type: 'outer', color: '000000', opacity: 0.18, blur: 3, offset: 0.5, angle: 45 },
    });
    slide.addShape(pptx.ShapeType.rect, { x: box.x, y: box.y, w: box.w, h: 0.096, fill: { color: DECK.red }, line: { type: 'none' } });
};

// Shared deck metadata. `company` stays blank on purpose.
export const deckMetadata = (pptx: PptxGenJS, report: string, date: string | null): void => {
    pptx.layout = 'LAYOUT_16x9'; // 10 × 5.625in, the reference deck's exact canvas
    pptx.author = 'ThreatSumm4ry';
    pptx.company = '';
    (pptx as PptxGenJS & { lang: string }).lang = 'pt-BR';
    pptx.subject = `Relatório automático do ${report}`;
    pptx.title = `${report} — ${fmtMonthPt(date)}`;
};

// ---- Workbook standard -------------------------------------------------------

// Sheet standard matching the deck: black header band, yellow bold Calibri 14,
// yellow tabs, thin border, frozen header row, autofilter, and no colour on the
// data rows — whoever reads it filters by column instead.
export const SHEET_HEADER = '000000';
export const SHEET_HEADER_TEXT = 'FFE600';
export const SHEET_BORDER = { style: 'thin' as const };
export const SHEET_TAB = { tabColor: { argb: `FF${SHEET_HEADER_TEXT}` } };

// Excel's own hyperlink look, so a link reads as a link without a theme.
export const LINK_FONT = { name: 'Calibri', color: { argb: 'FF0563C1' }, underline: true } as const;

// Deterministic from the CVE id, so a sheet builds them locally instead of
// asking a feed for a link it already knows how to write.
export const msrcCveUrl = (cve: string) => `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`;
export const nvdCveUrl = (cve: string) => `https://nvd.nist.gov/vuln/detail/${cve}`;

export const styleHeaderRow = (ws: ExcelJS.Worksheet, row: number, lastCol: number): void => {
    const r = ws.getRow(row);
    for (let c = 1; c <= lastCol; c++) {
        const cell = r.getCell(c);
        cell.font = { name: 'Calibri', bold: true, size: 14, color: { argb: `FF${SHEET_HEADER_TEXT}` } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: `FF${SHEET_HEADER}` } };
        cell.alignment = { horizontal: 'left', vertical: 'top' };
        cell.border = { top: SHEET_BORDER, left: SHEET_BORDER, bottom: SHEET_BORDER, right: SHEET_BORDER };
    }
    r.commit?.();
};

export const workbookMetadata = (wb: ExcelJS.Workbook, report: string, date: string | null, keywords: string): void => {
    wb.creator = 'ThreatSumm4ry';
    wb.lastModifiedBy = 'ThreatSumm4ry';
    wb.company = '';
    wb.subject = `Relatório automático do ${report}`;
    wb.title = `${report} — ${fmtMonthPt(date)}`;
    wb.keywords = keywords;
    wb.category = 'Relatório de segurança';
    wb.created = new Date();
    (wb as ExcelJS.Workbook & Pick<ExcelJS.WorkbookModel, 'language'>).language = 'pt-BR';
};
