#!/usr/bin/env node
/**
 * Converte os mapeamentos do workspace (XLSX, em hunting-docs/) nos dois JSON
 * que o app carrega. Mesmo contrato do build-actors.mjs: a planilha é insumo,
 * o JSON é o artefato versionado.
 *
 * Os arquivos de origem ficam fora do git e têm nome livre — o script acha
 * cada um por padrão no nome, então ninguém precisa renomear nada.
 *
 * Roda manualmente:
 *     node server/scripts/build-hunting-refs.mjs
 */
import ExcelJS from 'exceljs';
import { readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildTableContext, buildKqlLibrary, assertAnonymous } from '../huntingRefs.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCS_DIR = join(__dirname, '..', '..', 'hunting-docs');
const DATA_DIR = join(__dirname, '..', 'data');

// Cabeçalho na linha 4, dados a partir da 5 — vale para as três planilhas.
const HEADER_ROW = 4;

const MATCHERS = {
    kql: /kql/i,
    context: /contextualizad/i,
    dictionary: /completo/i,
};

function findWorkbookPath(kind) {
    const file = readdirSync(DOCS_DIR).find((name) => name.endsWith('.xlsx') && MATCHERS[kind].test(name));
    if (!file) throw new Error(`planilha de ${kind} não encontrada em hunting-docs/`);
    return join(DOCS_DIR, file);
}

const cellText = (cell) => {
    const value = cell?.value;
    if (value == null) return '';
    if (typeof value === 'object') return String(value.text ?? value.result ?? '').trim();
    return String(value).trim();
};

/** Linhas depois do cabeçalho, com número fixo de colunas e sem linha vazia. */
function rowsAfterHeader(sheet, columns) {
    const rows = [];
    sheet.eachRow((row, index) => {
        if (index <= HEADER_ROW) return;
        const cells = [];
        for (let column = 1; column <= columns; column += 1) cells.push(cellText(row.getCell(column)));
        if (cells.some(Boolean)) rows.push(cells);
    });
    return rows;
}

async function sheetRows(kind, sheetName, columns) {
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(findWorkbookPath(kind));
    const sheet = workbook.getWorksheet(sheetName);
    if (!sheet) throw new Error(`aba "${sheetName}" não encontrada na planilha de ${kind}`);
    return rowsAfterHeader(sheet, columns);
}

async function main() {
    const [contextRows, dictionaryRows, kqlRows] = await Promise.all([
        sheetRows('context', 'Contexto por Tabela', 8),
        sheetRows('dictionary', 'Dicionário de Campos', 5),
        sheetRows('kql', 'Catálogo Completo', 7),
    ]);

    const generated_at = new Date().toISOString();
    const tables = buildTableContext(contextRows, dictionaryRows);
    const queries = buildKqlLibrary(kqlRows);
    if (!tables.length) throw new Error('nenhuma tabela convertida — conferir a aba de contexto');
    if (!queries.length) throw new Error('nenhuma consulta convertida — conferir a aba de catálogo');

    const context = assertAnonymous({ generated_at, tables });
    const library = assertAnonymous({ generated_at, queries });

    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(join(DATA_DIR, 'huntingContext.json'), JSON.stringify(context, null, 0), 'utf8');
    writeFileSync(join(DATA_DIR, 'kqlLibrary.json'), JSON.stringify(library, null, 0), 'utf8');

    const withKeyFields = tables.filter((table) => table.keyFields.length).length;
    process.stderr.write(
        `Escreveu ${tables.length} tabelas (${withKeyFields} com campo-chave) e ${queries.length} consultas em ${DATA_DIR}\n`,
    );
}

main().catch((error) => {
    console.error('build-hunting-refs falhou:', error.message);
    process.exit(1);
});
