// Excel supports 65,530 hyperlinks per worksheet. Leave room for navigation.
export const BULK_WORKSHEET_HYPERLINK_LIMIT = 60_000;
export const EXCEL_WORKSHEET_ROW_LIMIT = 1_048_576;
const linkKeys = new Set(['link', 'reference', 'url']);
const isLink = (key, value) => linkKeys.has(key) && typeof value === 'string' && /^https?:\/\/[^\s]+$/.test(value);

/** Stream complete records into bounded worksheets; overflow references use the final sheet and row. */
export function createBulkRawTable(wb, name, columns, {
  header, valuesFor, colors, progress = async () => {},
  hyperlinkLimit = BULK_WORKSHEET_HYPERLINK_LIMIT,
  rowLimit = EXCEL_WORKSHEET_ROW_LIMIT,
} = {}) {
  hyperlinkLimit = Math.min(BULK_WORKSHEET_HYPERLINK_LIMIT, Math.max(1, Math.floor(hyperlinkLimit)));
  rowLimit = Math.min(EXCEL_WORKSHEET_ROW_LIMIT, Math.max(2, Math.floor(rowLimit)));
  let ws, count, links, part = 0;
  const start = () => {
    ws = wb.addWorksheet(name + (part ? ' ' + (part + 1) : ''), {
      views: [{state: 'frozen', xSplit: 1, ySplit: 1, showGridLines: false}],
      properties: {tabColor: {argb: colors.teal}},
    });
    header(ws, columns).commit(); count = 1; links = 0; part++;
  };
  const finish = () => {
    ws.autoFilter = {from: {row: 1, column: 1}, to: {row: count, column: columns.length}};
    ws.commit();
  };
  start();
  return {
    async add(record) {
      const input = columns.map(column => record[column[0]]);
      // Values longer than a cell become overflow references, not hyperlinks.
      const incoming = input.filter((value, i) => isLink(columns[i][0], value) && value.length <= 32767).length;
      if (count >= rowLimit || links + incoming > hyperlinkLimit) { finish(); start(); }
      const row = ws.addRow(await valuesFor(input, ws.name, ++count, columns.map(column => column[0])));
      row.height = 38;
      row.font = {name: 'Arial', size: 10, color: {argb: colors.ink}};
      row.alignment = {vertical: 'top', wrapText: true};
      if (count % 2 === 0) row.fill = {type: 'pattern', pattern: 'solid', fgColor: {argb: colors.pale}};
      for (const [key] of columns) {
        const cell = row.getCell(key);
        if (isLink(key, cell.value)) {
          cell.value = {text: cell.value, hyperlink: cell.value};
          cell.font = {name: 'Arial', size: 10, color: {argb: 'FF0563C1'}, underline: true};
          links++;
        }
      }
      row.commit();
      if (count % 100 === 0) await progress(count);
    },
    finish,
  };
}
