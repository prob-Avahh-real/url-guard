import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl } from '../lib/analyze.js';
import { normalizeAllowDomain } from '../lib/domains.js';
import {
  configureEvaluate,
  clearEvaluateCache,
  addAllowDomain,
  loadLists,
} from '../lib/evaluate.js';

describe('P0 adversarial: whitelist trees', () => {
  test('edu.cn phishing is NOT auto-allowlisted', () => {
    const r = analyzeUrl('https://paypal-secure-login.edu.cn/');
    assert.notEqual(r.level, 'safe');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('gov.cn phishing path is NOT auto-allowlisted', () => {
    const r = analyzeUrl('https://safe-verify.gov.cn/paypal/login');
    assert.notEqual(r.level, 'safe');
  });
});

describe('P0 adversarial: brand flip', () => {
  test('homoglyph paypa1.com is danger', () => {
    const r = analyzeUrl('https://paypa1.com/');
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('exact brand on non-official TLD is danger', () => {
    const r = analyzeUrl('https://paypal.io/');
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('brand subdomain on attacker domain is danger', () => {
    const r = analyzeUrl('https://paypal.customer-help.com/');
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some((x) => x.code === 'brand_lookalike'));
  });

  test('official paypal.com remains safe', () => {
    const r = analyzeUrl('https://www.paypal.com/signin');
    assert.equal(r.level, 'safe');
  });

  test('short-brand edit distance does not kill bbc.com', () => {
    const r = analyzeUrl('https://www.bbc.com/');
    assert.ok(!r.reasons.some((x) => x.code === 'brand_lookalike'));
  });
});

describe('P0 adversarial: allowlist hardening', () => {
  test('rejects bare com', () => {
    assert.equal(normalizeAllowDomain('com').ok, false);
  });

  test('rejects edu.cn public suffix', () => {
    assert.equal(normalizeAllowDomain('edu.cn').ok, false);
  });

  test('rejects com.br public suffix', () => {
    assert.equal(normalizeAllowDomain('com.br').ok, false);
  });

  test('accepts concrete registrable domain', () => {
    const r = normalizeAllowDomain('example.org');
    assert.equal(r.ok, true);
    assert.equal(r.domain, 'example.org');
  });

  test('addAllowDomain refuses public suffix', async () => {
    const store = { allowlist: [], blocklist: [], disabled: false };
    configureEvaluate({
      getStorage: async () => ({ ...store }),
      setStorage: async (data) => Object.assign(store, data),
      fetchSeedBlocklist: async () => [],
    });
    clearEvaluateCache();
    const res = await addAllowDomain('edu.cn');
    assert.equal(res.ok, false);
    clearEvaluateCache();
    configureEvaluate(null);
  });

  test('loadLists merges seed trust with user allowlist', async () => {
    const store = { allowlist: ['my-blog.example'], blocklist: [], disabled: false };
    configureEvaluate({
      getStorage: async () => ({ ...store }),
      setStorage: async (data) => Object.assign(store, data),
      fetchSeedBlocklist: async () => [],
    });
    clearEvaluateCache();
    const lists = await loadLists();
    assert.ok(lists.allowlist.includes('paypal.com'));
    assert.ok(lists.allowlist.includes('my-blog.example'));
    // poisoned public suffix in storage is dropped
    store.allowlist = ['com', 'ok.example'];
    const lists2 = await loadLists();
    assert.ok(!lists2.allowlist.includes('com'));
    assert.ok(lists2.allowlist.includes('ok.example'));
    configureEvaluate(null);
  });
});

describe('P0 adversarial: @ only userinfo', () => {
  test('query email does not trigger url_at_sign', () => {
    const r = analyzeUrl('https://example.org/path?email=a@b.com');
    assert.ok(!r.reasons.some((x) => x.code === 'url_at_sign'));
  });

  test('userinfo @ still flagged', () => {
    const r = analyzeUrl('https://paypal.com@evil.example/login');
    assert.ok(r.reasons.some((x) => x.code === 'url_at_sign' || x.code === 'brand_lookalike'));
  });
});
