import fs from 'node:fs';
import { auditSemanticCorrelation } from './semanticCorrelationAudit.js';
const [publicationsFile, vectorsFile] = process.argv.slice(2);
if (!publicationsFile || !vectorsFile) throw Error('Usage: node server/auditCrossLanguage.mjs reviewed-publications.json local-embeddings.json');
const data = JSON.parse(fs.readFileSync(publicationsFile, 'utf8'));
const vectors = JSON.parse(fs.readFileSync(vectorsFile, 'utf8'));
const report = auditSemanticCorrelation(Array.isArray(data) ? data : data.items, vectors.embeddings, {model: vectors.model, threshold: vectors.threshold ?? 0.9});
console.log(JSON.stringify(report, null, 2));
if (report.introducedFalseUnions) process.exitCode = 1;
