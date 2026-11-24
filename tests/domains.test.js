import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  registrableDomain,
  normalizeAllowDomain,
  isValidAllowDomain,
  isPublicSuffix,
  sanitizeHostname,
} from '../lib/domains.js';

describe('domains helpers', () => {
  test('registrableDomain handles multi-part and com.br', () => {
    assert.equal(registrableDomain('a.b.icbc.com.cn'), 'icbc.com.cn');
    assert.equal(registrableDomain('evil-phish.com.br'), 'evil-phish.com.br');
    assert.equal(registrableDomain('example.org'), 'example.org');
  });

  test('sanitizeHostname strips soft hyphen', () => {
    assert.equal(sanitizeHostname('pay\u00adpal.com'), 'paypal.com');
  });

  test('isPublicSuffix', () => {
    assert.equal(isPublicSuffix('com'), true);
    assert.equal(isPublicSuffix('edu.cn'), true);
    assert.equal(isPublicSuffix('example.org'), false);
  });

  test('normalizeAllowDomain error paths', () => {
    assert.equal(normalizeAllowDomain('').ok, false);
    assert.equal(normalizeAllowDomain(null).ok, false);
    assert.equal(normalizeAllowDomain('not_a_domain!').ok, false);
    assert.equal(normalizeAllowDomain('localhost').ok, false);
    assert.equal(normalizeAllowDomain('edu.cn').ok, false);
    assert.equal(normalizeAllowDomain('com.br').ok, false);
    assert.equal(isValidAllowDomain('foo.example'), true);
  });
});
