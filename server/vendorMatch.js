import { VENDOR_CATALOG } from './vendorCatalog.js';

const escapeRe = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const aliasPattern = (alias) => alias.trim().split(/\s+/).map(escapeRe).join('\\s+');

// Unicode boundaries also reject brands inside Portuguese/Spanish words.
// Keep punctuation in aliases: Notepad++, B&R and Pepperl+Fuchs are names.
const compile = (aliases, flags) => aliases.length
    ? new RegExp('(?<![\\p{L}\\p{N}_])(?:' + [...aliases].sort((a, b) => b.length - a.length).map(aliasPattern).join('|') + ')(?![\\p{L}\\p{N}_])', flags)
    : null;
const RULES = VENDOR_CATALOG.map((vendor) => ({
    vendor,
    re: compile(vendor.aliases.filter((alias) => !vendor.caseSensitiveAliases.includes(alias)), 'iu'),
    caseSensitiveRe: compile(vendor.caseSensitiveAliases, 'u'),
}));

export function matchVendors(text) {
    const value = String(text || '').replace(/_/g, ' ');
    return RULES.flatMap(({ vendor, re, caseSensitiveRe }) => {
        const match = re?.exec(value) || caseSensitiveRe?.exec(value);
        return match ? [{ id: vendor.id, name: vendor.name, sector: vendor.sector, matched: match[0] }] : [];
    });
}
