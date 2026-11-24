/**
 * Offline URL risk analyzer for phishing / fraud / gambling lookalikes.
 * Pure module — usable from service worker, popup, and Node tests.
 */

import {
  SUSPICIOUS_TLDS,
  BRANDS,
  TRUSTED_DOMAINS,
  GAMBLING_TOKENS,
  PHISHING_TOKENS,
  FRAUD_TOKENS,
  HOMOGLYPHS,
} from './rules.js';
import { registrableDomain, sanitizeHostname } from './domains.js';

const SEVERITY = { low: 1, medium: 2, high: 3, critical: 4 };

function reason(code, label, severity, category) {
  return { code, label, severity, category, score: SEVERITY[severity] || 1 };
}

function normalizeHomoglyphs(s) {
  let out = '';
  for (const ch of s.normalize('NFKC').toLowerCase()) {
    out += HOMOGLYPHS[ch] || ch;
  }
  return out;
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    let prev = i + 1;
    for (let j = 0; j < b.length; j++) {
      const cur = a[i] === b[j] ? row[j] : Math.min(row[j], row[j + 1], prev) + 1;
      row[j] = prev;
      prev = cur;
    }
    row[b.length] = prev;
  }
  return row[b.length];
}

function isIpHost(hostname) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  if (hostname.includes(':') && /^\[?[0-9a-f:]+\]?$/i.test(hostname)) return true;
  return false;
}

function domainMatchesList(host, list) {
  const h = host.toLowerCase();
  return list.some((d) => h === d || h.endsWith('.' + d));
}

function containsToken(haystack, tokens) {
  const h = haystack.toLowerCase();
  return tokens.filter((t) => h.includes(t.toLowerCase()));
}

/** Trusted seed domains that officially belong to a brand. */
function isOfficialBrandRegistrable(brand, reg) {
  return TRUSTED_DOMAINS.some((d) => {
    if (reg !== d && !reg.endsWith('.' + d) && d !== reg) return false;
    const labels = d.toLowerCase().split('.');
    return labels.some((l) => l === brand || normalizeHomoglyphs(l) === brand);
  });
}

function brandImpersonation(hostname) {
  const host = sanitizeHostname(hostname).toLowerCase();
  const reg = registrableDomain(host);
  const labels = host.split('.').filter(Boolean);
  const base = reg.split('.')[0] || '';
  const normBase = normalizeHomoglyphs(base);
  const hits = [];

  for (const brand of BRANDS) {
    if (brand.length < 2) continue;
    const official = isOfficialBrandRegistrable(brand, reg);

    // Exact / homoglyph brand as registrable base on a non-official domain → danger
    if ((base === brand || normBase === brand) && !official) {
      hits.push({ brand, label: base, dist: base === brand ? 0 : 0 });
      continue;
    }

    // Edit distance only for brands length >= 4 (avoid abc≈bbc)
    if (brand.length >= 4 && !official) {
      const dist = levenshtein(normBase, brand);
      const maxDist = brand.length <= 5 ? 1 : 2;
      if (dist > 0 && dist <= maxDist && normBase !== brand) {
        hits.push({ brand, label: base, dist });
        continue;
      }
    }

    for (const label of labels) {
      const n = normalizeHomoglyphs(label);
      // Brand as any label (paypal.evil.com / paypa1.cdn.net) outside official tree
      if ((label === brand || n === brand) && !official) {
        hits.push({ brand, label, dist: 0 });
        continue;
      }
      if (n.includes(brand) && n !== brand && /[-_]/.test(n) && !official) {
        hits.push({ brand, label, dist: 0 });
      } else if (
        brand.length >= 4 &&
        levenshtein(n, brand) === 1 &&
        n.length >= 4 &&
        !official
      ) {
        hits.push({ brand, label, dist: 1 });
      }
    }
  }
  return hits;
}

/**
 * @param {string} urlString
 * @param {{ allowlist?: string[], blocklist?: string[] }} [opts]
 */
export function analyzeUrl(urlString, opts = {}) {
  const allowlist = opts.allowlist || TRUSTED_DOMAINS;
  const blocklist = opts.blocklist || [];
  const reasons = [];
  let parsed;

  try {
    parsed = new URL(urlString);
  } catch {
    return {
      url: urlString,
      level: 'danger',
      score: 100,
      reasons: [reason('invalid_url', '网址无法解析，可能被故意混淆', 'critical', 'phishing')],
      host: '',
      registrable: '',
    };
  }

  const scheme = parsed.protocol.replace(':', '');
  const host = sanitizeHostname(parsed.hostname.replace(/^\[|\]$/g, ''));
  const reg = isIpHost(host) ? host : registrableDomain(host);
  const pathQ = (parsed.pathname + parsed.search).toLowerCase();
  const full = urlString.toLowerCase();

  if (['chrome:', 'chrome-extension:', 'about:', 'edge:', 'moz-extension:', 'devtools:'].includes(parsed.protocol)) {
    return {
      url: urlString,
      level: 'safe',
      score: 0,
      reasons: [],
      host,
      registrable: reg,
      scheme,
    };
  }

  if (domainMatchesList(host, allowlist) || domainMatchesList(reg, allowlist)) {
    return {
      url: urlString,
      level: 'safe',
      score: 0,
      reasons: [reason('allowlisted', '命中信任域名白名单', 'low', 'info')],
      host,
      registrable: reg,
      scheme,
    };
  }

  if (domainMatchesList(host, blocklist) || domainMatchesList(reg, blocklist)) {
    reasons.push(reason('blocklisted', '命中本地高风险黑名单', 'critical', 'phishing'));
  }

  if (scheme === 'javascript' || scheme === 'data') {
    reasons.push(reason('dangerous_scheme', `危险协议 ${scheme}:`, 'critical', 'phishing'));
  }

  // Only flag credential-style userinfo (@ before host), not query emails
  if (scheme.startsWith('http') && parsed.username) {
    reasons.push(reason('url_at_sign', '网址含 @ 用户信息，常见于伪装真实域名的钓鱼链接', 'high', 'phishing'));
  }

  if (isIpHost(host)) {
    reasons.push(reason('ip_host', '直接使用 IP 作为主机名，伪站点常见手法', 'high', 'phishing'));
  }

  if (host.startsWith('xn--') || host.includes('.xn--')) {
    reasons.push(reason('punycode', '国际域名（Punycode），请核对是否仿冒品牌字形', 'medium', 'phishing'));
  }

  const tld = host.includes('.') ? host.split('.').pop() : '';
  if (tld && SUSPICIOUS_TLDS.has(tld)) {
    reasons.push(reason('suspicious_tld', `高风险顶级域 .${tld}`, 'medium', 'fraud'));
  }

  const labels = host.split('.').filter(Boolean);
  if (labels.length >= 5) {
    reasons.push(reason('deep_subdomains', '子域名层级过深，常用于掩盖真实注册域', 'medium', 'phishing'));
  }
  if ((host.match(/-/g) || []).length >= 3) {
    reasons.push(reason('many_hyphens', '域名连字符过多，仿冒站点常见', 'low', 'phishing'));
  }

  const brandHits = brandImpersonation(host);
  if (brandHits.length) {
    const names = [...new Set(brandHits.map((h) => h.brand))].slice(0, 3).join(', ');
    reasons.push(
      reason('brand_lookalike', `疑似仿冒品牌域名（接近：${names}）`, 'critical', 'phishing'),
    );
  }

  const gamHost = containsToken(host + pathQ, GAMBLING_TOKENS);
  if (gamHost.length) {
    reasons.push(
      reason('gambling_tokens', `命中博彩相关关键词：${gamHost.slice(0, 4).join(', ')}`, 'high', 'gambling'),
    );
  }

  const phish = containsToken(host + ' ' + pathQ, PHISHING_TOKENS);
  const brandInPath = BRANDS.some((b) => pathQ.includes(b) && !domainMatchesList(host, allowlist));
  if (phish.length >= 2 || (phish.length >= 1 && brandInPath)) {
    reasons.push(
      reason('phishing_path', `路径/主机含钓鱼话术：${phish.slice(0, 4).join(', ')}`, 'high', 'phishing'),
    );
  } else if (phish.length === 1 && scheme === 'http') {
    reasons.push(reason('http_loginish', '明文 HTTP 且含登录/验证类词', 'medium', 'phishing'));
  }

  const fraud = containsToken(full, FRAUD_TOKENS);
  if (fraud.length) {
    reasons.push(
      reason('fraud_tokens', `命中欺诈营销话术：${fraud.slice(0, 4).join(', ')}`, 'high', 'fraud'),
    );
  }

  if (urlString.length > 200 && (urlString.match(/%[0-9a-f]{2}/gi) || []).length > 8) {
    reasons.push(reason('opaque_encoding', '超长且大量百分号编码，可能用于隐藏真实跳转', 'medium', 'fraud'));
  }

  const score = reasons.reduce((s, r) => s + r.score * 12, 0);
  let level = 'safe';
  if (score >= 48 || reasons.some((r) => r.severity === 'critical')) level = 'danger';
  else if (score >= 24 || reasons.some((r) => r.severity === 'high')) level = 'warn';
  else if (score > 0) level = 'caution';

  return {
    url: urlString,
    level,
    score: Math.min(100, score),
    reasons,
    host,
    registrable: reg,
    scheme,
  };
}

export function levelLabel(level) {
  return (
    {
      safe: '安全',
      caution: '留意',
      warn: '警告',
      danger: '高危',
    }[level] || level
  );
}

export function levelColor(level) {
  return (
    {
      safe: '#1f8a4c',
      caution: '#c49a00',
      warn: '#d97706',
      danger: '#c62828',
    }[level] || '#666'
  );
}

export { TRUSTED_DOMAINS, registrableDomain };
