// IOC extraction from free text (search input, uploaded logs). Helpers shared
// by the analyzer page and the search form.
//
// Não há cap de lote: o teto do que dá pra rodar de uma vez é a cota das bases,
// mostrada na faixa de créditos abaixo da barra de busca.

const IOC_FILE_EXTENSIONS = ["exe", "dll", "sys", "zip", "rar", "tar", "gz", "png", "jpg", "jpeg", "gif", "css", "js", "html", "htm", "txt", "log", "json", "xml", "pdf", "doc", "docx", "xls", "xlsx"];
const IPV4_GLOBAL_REGEX = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV4_QUERY_REGEX = /^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const DOMAIN_GLOBAL_REGEX = /\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const HASH_GLOBAL_REGEX = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
const URL_GLOBAL_REGEX = /https?:\/\/[^\s"'<>]+/gi;

const cleanUrlIoc = (url: string) => url.replace(/[),.;\]]+$/g, "");

export type AnalyzerQueryType = "ip" | "domain" | "hash" | "url" | "unknown";

export const isPublicIpv4 = (value: string): boolean => {
  if (!IPV4_QUERY_REGEX.test(value)) return false;

  const [first, second, third, fourth] = value.split(".").map(Number);
  if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
  if (first === 100 && second >= 64 && second <= 127) return false;
  if (first === 169 && second === 254) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && second === 168) return false;
  if (first === 192 && second === 0 && third === 0 && fourth !== 9 && fourth !== 10) return false;
  if (first === 192 && second === 0 && third === 2) return false;
  if (first === 192 && second === 88 && third === 99) return false;
  if (first === 198 && (second === 18 || second === 19)) return false;
  if (first === 198 && second === 51 && third === 100) return false;
  if (first === 203 && second === 0 && third === 113) return false;
  return true;
};

const parseIpv6 = (value: string): number[] | null => {
  if (!value || value.includes("%") || value.includes(".")) return null;

  const compressionIndex = value.indexOf("::");
  if (compressionIndex !== -1 && compressionIndex !== value.lastIndexOf("::")) return null;

  const parseSection = (section: string) => {
    if (!section) return [];
    const groups = section.split(":");
    if (groups.some((group) => !/^[a-fA-F0-9]{1,4}$/.test(group))) return null;
    return groups.map((group) => Number.parseInt(group, 16));
  };

  if (compressionIndex === -1) {
    const groups = parseSection(value);
    return groups?.length === 8 ? groups : null;
  }

  const left = parseSection(value.slice(0, compressionIndex));
  const right = parseSection(value.slice(compressionIndex + 2));
  if (!left || !right || left.length + right.length >= 8) return null;
  return [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
};

export const isPublicIpv6 = (value: string): boolean => {
  const groups = parseIpv6(value);
  if (!groups) return false;

  const [first, second, third] = groups;
  if (first === 0) return false;
  if ((first & 0xfe00) === 0xfc00) return false;
  if ((first & 0xffc0) === 0xfe80) return false;
  if ((first & 0xff00) === 0xff00) return false;
  if ((first & 0xe000) !== 0x2000) return false;
  if (first === 0x2001 && second === 0x0002 && third === 0) return false;
  if (first === 0x2001 && ((second & 0xfff0) === 0x0010 || (second & 0xfff0) === 0x0020)) return false;
  if (first === 0x2001 && second === 0x0db8) return false;
  if (first === 0x2002) return false;
  if ((first & 0xfff0) === 0x3ff0) return false;
  return true;
};

export const detectAnalyzerQueryType = (query: string): AnalyzerQueryType => {
  const value = query.trim();
  if (/^https?:\/\/[^ "<>]+$/i.test(value)) return "url";
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(value)) return "hash";
  if (isPublicIpv4(value) || isPublicIpv6(value)) return "ip";
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(value)) return "domain";
  return "unknown";
};

export const isSupportedAnalyzerQuery = (query: string) => detectAnalyzerQueryType(query) !== "unknown";

export const extractIocsFromText = (text: string) => {
  if (!text) return [];

  const urls = (text.match(URL_GLOBAL_REGEX) ?? []).map(cleanUrlIoc);
  const textWithoutUrls = text.replace(URL_GLOBAL_REGEX, " ");
  const ips = (text.match(IPV4_GLOBAL_REGEX) ?? []).filter(isPublicIpv4);
  const ipv6s = textWithoutUrls
    .split(/[\s,"'()\[\]{}|<>]+/)
    .map((candidate) => candidate.replace(/[),.;\]]+$/g, ""))
    .filter(isPublicIpv6);
  const hashes = text.match(HASH_GLOBAL_REGEX) ?? [];
  const domains = (textWithoutUrls.match(DOMAIN_GLOBAL_REGEX) ?? []).filter((domain) => {
    const ext = domain.split(".").pop()?.toLowerCase() || "";
    return !IOC_FILE_EXTENSIONS.includes(ext);
  });

  return Array.from(new Set([...ips, ...ipv6s, ...urls, ...domains, ...hashes]));
};
