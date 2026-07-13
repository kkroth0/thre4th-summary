import net from 'node:net';

const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const HASH_REGEX = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;

export const isPublicIPv4 = (value) => {
  if (net.isIP(value) !== 4) return false;
  const [a, b, c, d] = value.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0 && d !== 9 && d !== 10) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
};

const ipv6Groups = (value) => {
  if (net.isIP(value) !== 6 || value.includes('%') || value.includes('.')) return null;
  const [left = '', right = ''] = value.split('::');
  const parse = (part) => part ? part.split(':').map((group) => Number.parseInt(group, 16)) : [];
  const leftGroups = parse(left);
  const rightGroups = parse(right);
  return [...leftGroups, ...Array(8 - leftGroups.length - rightGroups.length).fill(0), ...rightGroups];
};

export const isPublicIPv6 = (value) => {
  const groups = ipv6Groups(value);
  if (!groups) return false;
  const [first, second, third] = groups;
  if (first === 0 || (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80) return false;
  if ((first & 0xff00) === 0xff00 || (first & 0xe000) !== 0x2000) return false;
  if (first === 0x2001 && second === 0x0002 && third === 0) return false;
  if (first === 0x2001 && ((second & 0xfff0) === 0x0010 || (second & 0xfff0) === 0x0020)) return false;
  if (first === 0x2001 && second === 0x0db8) return false;
  if (first === 0x2002 || (first & 0xfff0) === 0x3ff0) return false;
  return true;
};

export const detectQueryType = (query) => {
  const value = query?.trim();
  if (!value || value.length > 2048) return 'unknown';
  if (/^https?:\/\/[^ "<>]+$/i.test(value)) return 'url';
  if (HASH_REGEX.test(value)) return 'hash';
  if (isPublicIPv4(value) || isPublicIPv6(value)) return 'ip';
  if (DOMAIN_REGEX.test(value)) return 'domain';
  return 'unknown';
};

export const sanitizeQuery = (query, expectedType) => {
  const value = query?.trim();
  if (!value) throw new Error('Empty query');
  if (value.length > 2048) throw new Error('Query too long');
  if (expectedType === 'ip') {
    if (!isPublicIPv4(value) && !isPublicIPv6(value)) throw new Error('Invalid or non-public IP');
    return value;
  }
  if (expectedType === 'domain') {
    if (!DOMAIN_REGEX.test(value) || value.length > 253) throw new Error('Invalid domain format');
    return value;
  }
  if (expectedType === 'hash') {
    if (!HASH_REGEX.test(value)) throw new Error('Invalid hash format');
    return value;
  }
  if (expectedType === 'url') {
    let parsed;
    try { parsed = new URL(value); } catch { throw new Error('Invalid URL'); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid URL protocol');
    const host = parsed.hostname.replace(/^\[|\]$/g, '');
    if ((net.isIP(host) === 4 && !isPublicIPv4(host)) || (net.isIP(host) === 6 && !isPublicIPv6(host))) {
      throw new Error('Invalid or non-public IP URL');
    }
    if (['localhost', 'localhost.localdomain'].includes(host.toLowerCase()) || host.endsWith('.local')) {
      throw new Error('Local domains not allowed');
    }
    return value;
  }
  if (expectedType === 'cidr') {
    const [ip, maskText] = value.split('/');
    const mask = Number(maskText);
    if (!isPublicIPv4(ip) || !Number.isInteger(mask) || mask < 0 || mask > 32) throw new Error('Invalid CIDR format');
    return value;
  }
  throw new Error('Unknown expected type');
};
