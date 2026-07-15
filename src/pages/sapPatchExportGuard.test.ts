import test from "node:test";
import assert from "node:assert/strict";
import type { SapNote, SapPatchSummary } from "@/services/sapApi";
import { canExportSapPatch } from "./SapPatch.tsx";
import { readFileSync } from "node:fs";

const note: SapNote = {
    note: "3747367",
    noteUrl: "https://me.sap.com/notes/3747367",
    title: "Security update for SAP component",
    cves: ["CVE-2026-1234"],
    priority: "High",
    cvss: 8.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    isUpdate: false,
};

const summary = (notes: SapNote[]): SapPatchSummary => ({
    url: "https://support.sap.com/security-notes.html",
    releaseDate: "2026-07-14",
    notes,
    summary: {
        total: notes.length,
        byPriority: notes.length ? { High: notes.length } : {},
        hotNews: 0,
        high: notes.length,
        maxCvss: notes.length ? 8.8 : 0,
        cveCount: notes.length,
    },
});

const emptySummary = summary([]);
const summaryWithOneNote = summary([note]);

test("só permite export quando existem notas", () => {
    assert.equal(canExportSapPatch(null), false);
    assert.equal(canExportSapPatch(emptySummary), false);
    assert.equal(canExportSapPatch(summaryWithOneNote), true);
});

test("carrega o módulo de exportação somente dentro de runExport", () => {
    const source = readFileSync(`${process.cwd()}/src/pages/SapPatch.tsx`, "utf8");
    assert.doesNotMatch(source, /from ["']@\/utils\/sapPatchExport["']/);
    assert.match(source, /await import\(["']@\/utils\/sapPatchExport["']\)/);
});
