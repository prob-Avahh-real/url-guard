/** Domain helpers: eTLD+1-ish, public-suffix guard, allowlist validation. */

export const MULTI_PART_SUFFIXES = new Set([
  'com.cn', 'com.hk', 'co.uk', 'com.au', 'co.jp', 'com.tw',
  'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.br', 'com.sg', 'co.kr', 'com.mx', 'co.in', 'com.tr',
  'ac.uk', 'org.uk', 'gov.uk', 'ne.jp', 'or.jp',
]);

/** Bare public suffixes that must never be allowlisted. */
export const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
  'cn', 'uk', 'au', 'jp', 'kr', 'br', 'sg', 'in', 'mx', 'tr', 'tw', 'hk', 'io', 'co',
  'info', 'biz', 'name', 'pro', 'xyz', 'top', 'vip', 'app', 'dev', 'page',
  ...MULTI_PART_SUFFIXES,
]);

/** eTLD+1-ish: last two labels, or last three for known multi-part suffixes. */
export function registrableDomain(hostname) {
  const host = String(hostname || '')
    .replace(/[\u00ad\u200b-\u200d\ufeff]/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 1) return host;
  if (parts.length === 2) return host;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

export function isPublicSuffix(domain) {
  const d = String(domain || '')
    .toLowerCase()
    .replace(/\.$/, '');
  return PUBLIC_SUFFIXES.has(d);
}

/**
 * Allowlist entries must be a concrete registrable domain, never a public suffix.
 * @returns {{ ok: true, domain: string } | { ok: false, error: string }}
 */
export function normalizeAllowDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return { ok: false, error: '域名无效' };
  }
  const cleaned = domain
    .trim()
    .toLowerCase()
    .replace(/[\u00ad\u200b-\u200d\ufeff]/g, '')
    .replace(/^\.+|\.+$/g, '');
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(cleaned)) {
    return { ok: false, error: '域名格式非法' };
  }
  if (isPublicSuffix(cleaned)) {
    return { ok: false, error: '不能信任公共后缀（如 com / edu.cn）' };
  }
  const parts = cleaned.split('.');
  if (parts.length < 2) {
    return { ok: false, error: '域名层级不足' };
  }
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(last2) && parts.length < 3) {
    return { ok: false, error: '不能信任公共后缀' };
  }
  const reg = registrableDomain(cleaned);
  if (isPublicSuffix(reg)) {
    return { ok: false, error: '解析结果为公共后缀，已拒绝' };
  }
  // Only accept the registrable form (prevent trusting attacker-controlled deep labels as "domain")
  if (cleaned !== reg && !cleaned.endsWith('.' + reg)) {
    return { ok: false, error: '无法解析注册域' };
  }
  return { ok: true, domain: reg };
}

export function isValidAllowDomain(domain) {
  return normalizeAllowDomain(domain).ok;
}

/** Strip invisible / soft-hyphen confusables from hostnames. */
export function sanitizeHostname(hostname) {
  return String(hostname || '')
    .replace(/[\u00ad\u200b-\u200d\ufeff]/g, '')
    .replace(/\.$/, '');
}
