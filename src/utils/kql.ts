// Formatador de KQL. O modelo (e boa parte dos catálogos) devolve a consulta
// numa linha só; quem vai ler é o analista, então cada operador `|` ganha a sua
// linha e cada `;` fecha o statement. A quebra só acontece no nível zero: pipe
// dentro de string, parêntese ou comentário fica onde está.

const OPEN = "([{";
const CLOSE = ")]}";

export function formatKql(query: string): string {
  const src = (query || "").replace(/\r\n?/g, "\n").trim();
  if (!src) return "";

  const lines: string[] = [];
  let line = "";
  let depth = 0;
  let quote = "";
  let comment = false;

  const push = () => {
    const text = line.trimEnd();
    if (text) lines.push(text);
    line = "";
  };
  // Espaço em branco fora de string vira um espaço só — é o que transforma o
  // KQL despejado em linha única em algo alinhado.
  const space = () => { if (line && !line.endsWith(" ")) line += " "; };

  for (let i = 0; i < src.length; i += 1) {
    const char = src[i];

    if (comment) {
      if (char === "\n") { comment = false; push(); } else line += char;
      continue;
    }
    if (quote) {
      line += char;
      if (char === "\\") { line += src[i + 1] ?? ""; i += 1; }
      else if (char === quote) quote = "";
      continue;
    }
    if (char === '"' || char === "'") { quote = char; line += char; continue; }
    if (char === "/" && src[i + 1] === "/") { comment = true; line += "//"; i += 1; continue; }
    if (char === "\n") { push(); continue; }
    if (/\s/.test(char)) { space(); continue; }
    if (OPEN.includes(char)) { depth += 1; line += char; continue; }
    if (CLOSE.includes(char)) { depth = Math.max(0, depth - 1); line += char; continue; }
    if (char === "|" && depth === 0) { push(); line = "| "; continue; }
    if (char === ";" && depth === 0) { line += ";"; push(); continue; }
    line += char;
  }
  push();

  return lines.join("\n");
}
