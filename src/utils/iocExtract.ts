// IOC extraction from free text (search input, uploaded logs). Batch cap and
// helpers shared by the analyzer page and the search form.

export const MAX_ANALYZER_TARGETS = 6;

const IOC_FILE_EXTENSIONS = ["exe", "dll", "sys", "zip", "rar", "tar", "gz", "png", "jpg", "jpeg", "gif", "css", "js", "html", "htm", "txt", "log", "json", "xml", "pdf", "doc", "docx", "xls", "xlsx"];
const IPV4_GLOBAL_REGEX = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const DOMAIN_GLOBAL_REGEX = /\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const HASH_GLOBAL_REGEX = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
const CVE_GLOBAL_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi;
const URL_GLOBAL_REGEX = /https?:\/\/[^\s"'<>]+/gi;

const cleanUrlIoc = (url: string) => url.replace(/[),.;\]]+$/g, "");

export const extractIocsFromText = (text: string) => {
  if (!text) return [];

  const urls = (text.match(URL_GLOBAL_REGEX) ?? []).map(cleanUrlIoc);
  const textWithoutUrls = text.replace(URL_GLOBAL_REGEX, " ");
  const ips = text.match(IPV4_GLOBAL_REGEX) ?? [];
  const hashes = text.match(HASH_GLOBAL_REGEX) ?? [];
  const cves = (text.match(CVE_GLOBAL_REGEX) ?? []).map((c) => c.toUpperCase());
  const domains = (textWithoutUrls.match(DOMAIN_GLOBAL_REGEX) ?? []).filter((domain) => {
    const ext = domain.split(".").pop()?.toLowerCase() || "";
    return !IOC_FILE_EXTENSIONS.includes(ext);
  });

  return Array.from(new Set([...ips, ...urls, ...domains, ...hashes, ...cves]));
};
