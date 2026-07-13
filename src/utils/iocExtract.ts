// IOC extraction from free text (search input, uploaded logs). Batch cap and
// helpers shared by the analyzer page and the search form.

export const MAX_ANALYZER_TARGETS = 6;

const IOC_FILE_EXTENSIONS = ["exe", "dll", "sys", "zip", "rar", "tar", "gz", "png", "jpg", "jpeg", "gif", "css", "js", "html", "htm", "txt", "log", "json", "xml", "pdf", "doc", "docx", "xls", "xlsx"];
const IPV4_GLOBAL_REGEX = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV4_QUERY_REGEX = /^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const DOMAIN_GLOBAL_REGEX = /\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const HASH_GLOBAL_REGEX = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
const URL_GLOBAL_REGEX = /https?:\/\/[^\s"'<>]+/gi;

const cleanUrlIoc = (url: string) => url.replace(/[),.;\]]+$/g, "");

export type AnalyzerQueryType = "ip" | "domain" | "hash" | "url" | "unknown";

export const detectAnalyzerQueryType = (query: string): AnalyzerQueryType => {
  const value = query.trim();
  if (/^https?:\/\/[^ "<>]+$/i.test(value)) return "url";
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(value)) return "hash";
  if (IPV4_QUERY_REGEX.test(value)) return "ip";
  if (/^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(value)) return "domain";
  return "unknown";
};

export const isSupportedAnalyzerQuery = (query: string) => detectAnalyzerQueryType(query) !== "unknown";

export const extractIocsFromText = (text: string) => {
  if (!text) return [];

  const urls = (text.match(URL_GLOBAL_REGEX) ?? []).map(cleanUrlIoc);
  const textWithoutUrls = text.replace(URL_GLOBAL_REGEX, " ");
  const ips = text.match(IPV4_GLOBAL_REGEX) ?? [];
  const hashes = text.match(HASH_GLOBAL_REGEX) ?? [];
  const domains = (textWithoutUrls.match(DOMAIN_GLOBAL_REGEX) ?? []).filter((domain) => {
    const ext = domain.split(".").pop()?.toLowerCase() || "";
    return !IOC_FILE_EXTENSIONS.includes(ext);
  });

  return Array.from(new Set([...ips, ...urls, ...domains, ...hashes]));
};
