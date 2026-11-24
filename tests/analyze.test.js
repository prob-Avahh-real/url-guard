import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, levelLabel, levelColor } from '../lib/analyze.js';

describe('allowlist / blocklist / parse', () => {
  test('trusted domain is safe', () => {
    const r = analyzeUrl('https://www.paypal.com/signin');
    assert.equal(r.level, 'safe');
  });

  test('allowlist overrides lookalike path noise', () => {
    const r = analyzeUrl('https://accounts.google.com/ServiceLogin');
    assert.equal(r.level, 'safe');
  });

  test('custom allowlist short-circuits', () => {
    const r = analyzeUrl('https://login.evil.test/verify', {
      allowlist: ['evil.test'],
    });
    assert.equal(r.level, 'safe');
  });

  test('blocklist forces danger', () => {
    const r = analyzeUrl('https://evil.example/ok', { blocklist: ['evil.example'] });
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some((x) => x.code === 'blocklisted'));
  });

  test('invalid url is danger', () => {
    const r = analyzeUrl('http://[bad');
    assert.equal(r.level, 'danger');
    assert.equal(r.score, 100);
    assert.ok(r.reasons.some((x) => x.code === 'invalid_url'));
  });

  test('browser internal protocol is safe', () => {
    const r = analyzeUrl('chrome://extensions');
    assert.equal(r.level, 'safe');
    assert.equal(r.score, 0);
  });

  test('about:blank is safe', () => {
    assert.equal(analyzeUrl('about:blank').level, 'safe');
  });
});

describe('structure signals', () => {
  test('javascript scheme is critical', () => {
    const r = analyzeUrl('javascript:alert(1)');
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some((x) => x.code === 'dangerous_scheme'));
  });

  test('data scheme is critical', () => {
    const r = analyzeUrl('data:text/html,hi');
    assert.ok(r.reasons.some((x) => x.code === 'dangerous_scheme'));
  });

  test('url with userinfo @ is flagged', () => {
    const r = analyzeUrl('https://paypal.com@evil.example/login');
    assert.ok(r.reasons.some((x) => x.code === 'url_at_sign' || x.code === 'brand_lookalike'));
  });

  test('ipv4 host is elevated risk', () => {
    const r = analyzeUrl('http://203.0.113.10/login');
    assert.ok(['warn', 'danger'].includes(r.level));
    assert.ok(r.reasons.some((x) => x.code === 'ip_host'));
  });

  test('ipv6 host is elevated risk', () => {
    const r = analyzeUrl('http://[2001:db8::1]/');
    assert.ok(r.reasons.some((x) => x.code === 'ip_host'));
  });

  test('punycode host is flagged', () => {
    const r = analyzeUrl('https://xn--pple-43d.com/');
    assert.ok(r.reasons.some((x) => x.code === 'punycode'));
  });

  test('suspicious tld is flagged', () => {
    const r = analyzeUrl('https://totally-random-site.xyz/');
    assert.ok(r.reasons.some((x) => x.code === 'suspicious_tld'));
  });

  test('deep subdomains are flagged', () => {
    const r = analyzeUrl('https://a.b.c.d.e.example.org/');
    assert.ok(r.reasons.some((x) => x.code === 'deep_subdomains'));
  });

  test('many hyphens are flagged', () => {
    const r = analyzeUrl('https://foo-bar-baz-qux.example.org/');
    assert.ok(r.reasons.some((x) => x.code === 'many_hyphens'));
  });

  test('opaque encoding on long urls', () => {
    const enc = Array.from({ length: 12 }, (_, i) => `%2${i % 10}`).join('');
    const url = `https://example.org/path?q=${enc}${'x'.repeat(180)}`;
    const r = analyzeUrl(url);
    assert.ok(r.reasons.some((x) => x.code === 'opaque_encoding'));
  });
});

describe('brand impersonation', () => {
  test('brand lookalike compound is danger', () => {
    const r = analyzeUrl('https://paypa1-secure-login.tk/verify');
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike' || x.code === 'suspicious_tld'));
  });

  test('edit-distance lookalike on registrable base', () => {
    const r = analyzeUrl('https://paypai.com/');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('homoglyph paypa1.com flags as brand lookalike', () => {
    const r = analyzeUrl('https://paypa1.com/');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('homoglyph-normalized brand compound still flags', () => {
    const r = analyzeUrl('https://paypa1-login.example.org/');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('compound brand label without tld noise', () => {
    const r = analyzeUrl('https://paypal-login.example.org/');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('label-level single edit distance', () => {
    const r = analyzeUrl('https://goggle.attacker.example/');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });
});

describe('keyword themes', () => {
  test('gambling tokens warn or higher', () => {
    const r = analyzeUrl('https://liuhecai-kaijiang.top/bocai');
    assert.ok(['warn', 'danger'].includes(r.level));
    assert.ok(r.reasons.some((x) => x.category === 'gambling' || x.code === 'suspicious_tld'));
  });

  test('phishing path with multiple tokens', () => {
    const r = analyzeUrl('https://random-corp.example/secure/verify-account');
    assert.ok(r.reasons.some((x) => x.code === 'phishing_path'));
  });

  test('phishing token plus brand in path', () => {
    const r = analyzeUrl('https://random-corp.example/paypal/login');
    assert.ok(r.reasons.some((x) => x.code === 'phishing_path'));
  });

  test('single phishing token on http is http_loginish', () => {
    const r = analyzeUrl('http://benign-example.org/login');
    assert.ok(r.reasons.some((x) => x.code === 'http_loginish' || x.code === 'phishing_path'));
  });

  test('fraud tokens are flagged', () => {
    const r = analyzeUrl('https://offer.example/get-rich-now');
    assert.ok(r.reasons.some((x) => x.code === 'fraud_tokens'));
  });

  test('chinese fraud token', () => {
    const r = analyzeUrl('https://scam.example/%E5%88%B7%E5%8D%95');
    // path may be encoded; also try decoded form in host+path via explicit chinese in path
    const r2 = analyzeUrl('https://scam.example/刷单返利');
    assert.ok(r2.reasons.some((x) => x.code === 'fraud_tokens'));
  });
});

describe('registrable domain helpers via analyze', () => {
  test('com.cn multi-part suffix allowlist', () => {
    const r = analyzeUrl('https://www.icbc.com.cn/');
    assert.equal(r.level, 'safe');
    assert.ok(r.registrable.endsWith('com.cn') || r.registrable.includes('icbc'));
  });

  test('trailing dot stripped in registrable domain', () => {
    const r = analyzeUrl('https://www.icbc.com.cn./');
    // allowlisted via com.cn multi-part; registrableDomain strips trailing dot
    assert.equal(r.level, 'safe');
    assert.ok(!r.registrable.endsWith('.'));
  });

  test('exact brand on non-allowlisted TLD is lookalike', () => {
    const r = analyzeUrl('https://paypal.example.org/');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
    assert.equal(r.level, 'danger');
  });
});

describe('level helpers', () => {
  test('levelLabel maps known levels', () => {
    assert.equal(levelLabel('safe'), '安全');
    assert.equal(levelLabel('caution'), '留意');
    assert.equal(levelLabel('warn'), '警告');
    assert.equal(levelLabel('danger'), '高危');
    assert.equal(levelLabel('other'), 'other');
  });

  test('levelColor maps known levels', () => {
    assert.equal(levelColor('safe'), '#1f8a4c');
    assert.equal(levelColor('caution'), '#c49a00');
    assert.equal(levelColor('warn'), '#d97706');
    assert.equal(levelColor('danger'), '#c62828');
    assert.equal(levelColor('other'), '#666');
  });
});

describe('scoring bands', () => {
  test('clean unknown https domain can be safe', () => {
    const r = analyzeUrl('https://completely-unique-blog-zz9.example/');
    assert.ok(['safe', 'caution'].includes(r.level));
  });

  test('score capped at 100', () => {
    const r = analyzeUrl('javascript:void(0)');
    assert.ok(r.score <= 100);
  });
});
