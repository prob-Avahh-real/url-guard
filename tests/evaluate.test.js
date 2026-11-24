import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  configureEvaluate,
  clearEvaluateCache,
  evaluate,
  loadLists,
  addAllowDomain,
  addBlockDomain,
  setDisabled,
  CACHE_TTL_MS,
} from '../lib/evaluate.js';

let store;

function resetStore(initial = {}) {
  store = { allowlist: undefined, blocklist: undefined, disabled: false, ...initial };
}

beforeEach(() => {
  clearEvaluateCache();
  resetStore();
  configureEvaluate({
    getStorage: async () => ({ ...store }),
    setStorage: async (data) => {
      Object.assign(store, data);
    },
    fetchSeedBlocklist: async () => ['seed-bad.example'],
  });
});

afterEach(() => {
  configureEvaluate(null);
  clearEvaluateCache();
});

describe('loadLists', () => {
  test('merges seed blocklist and defaults allowlist', async () => {
    const lists = await loadLists();
    assert.ok(lists.allowlist.includes('paypal.com'));
    assert.ok(lists.blocklist.includes('seed-bad.example'));
    assert.equal(lists.disabled, false);
  });

  test('merges stored allowlist with seed trust', async () => {
    resetStore({ allowlist: ['my.test'] });
    configureEvaluate({
      getStorage: async () => ({ ...store }),
      setStorage: async (data) => Object.assign(store, data),
      fetchSeedBlocklist: async () => [],
    });
    const lists = await loadLists();
    assert.ok(lists.allowlist.includes('my.test'));
    assert.ok(lists.allowlist.includes('paypal.com'));
  });

  test('seed fetch failure yields empty seed', async () => {
    configureEvaluate({
      getStorage: async () => ({ ...store }),
      setStorage: async (data) => Object.assign(store, data),
      fetchSeedBlocklist: async () => {
        throw new Error('network');
      },
    });
    const lists = await loadLists();
    assert.deepEqual(lists.blocklist, []);
  });

  test('default chrome deps load seed blocklist', async () => {
    configureEvaluate(null);
    globalThis.chrome = {
      storage: {
        local: {
          get: async () => ({}),
          set: async () => {},
        },
      },
      runtime: {
        getURL: (p) => `https://ext.test/${p}`,
      },
    };
    const prevFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
      json: async () => ({ domains: ['from-chrome.example'] }),
    });
    try {
      const lists = await loadLists();
      assert.ok(lists.blocklist.includes('from-chrome.example'));
    } finally {
      globalThis.fetch = prevFetch;
      delete globalThis.chrome;
      configureEvaluate({
        getStorage: async () => ({ ...store }),
        setStorage: async (data) => Object.assign(store, data),
        fetchSeedBlocklist: async () => ['seed-bad.example'],
      });
    }
  });

  test('default fetchSeed catches bad responses', async () => {
    configureEvaluate(null);
    globalThis.chrome = {
      storage: {
        local: {
          get: async () => ({}),
          set: async () => {},
        },
      },
      runtime: { getURL: (p) => `https://ext.test/${p}` },
    };
    const prevFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      throw new Error('fail');
    };
    try {
      const lists = await loadLists();
      assert.deepEqual(lists.blocklist, []);
    } finally {
      globalThis.fetch = prevFetch;
      delete globalThis.chrome;
      configureEvaluate({
        getStorage: async () => ({ ...store }),
        setStorage: async (data) => Object.assign(store, data),
        fetchSeedBlocklist: async () => [],
      });
    }
  });
});

describe('evaluate', () => {
  test('disabled returns disabled result', async () => {
    resetStore({ disabled: true });
    configureEvaluate({
      getStorage: async () => ({ ...store }),
      setStorage: async (data) => Object.assign(store, data),
      fetchSeedBlocklist: async () => [],
    });
    const r = await evaluate('https://evil.example');
    assert.equal(r.disabled, true);
    assert.equal(r.level, 'safe');
  });

  test('analyzes url when enabled', async () => {
    const r = await evaluate('https://www.paypal.com/');
    assert.equal(r.level, 'safe');
    assert.equal(r.disabled, undefined);
  });

  test('uses cache within TTL', async () => {
    const url = 'https://paypai.com/cache-test';
    const r1 = await evaluate(url);
    store.blocklist = ['should-not-affect-cached'];
    const r2 = await evaluate(url);
    assert.equal(r1.level, r2.level);
    assert.equal(r1.score, r2.score);
  });

  test('cache expires after TTL', async () => {
    const url = 'https://example.org/ttl';
    const realNow = Date.now;
    let now = 1_000_000;
    Date.now = () => now;
    try {
      await evaluate(url);
      now += CACHE_TTL_MS + 1;
      const r = await evaluate(url);
      assert.ok(r);
    } finally {
      Date.now = realNow;
    }
  });

  test('cache can be cleared', async () => {
    await evaluate('https://example.org/cache-me');
    clearEvaluateCache();
    const r = await evaluate('https://example.org/cache-me');
    assert.ok(r);
  });
});

describe('list mutations', () => {
  test('addAllowDomain persists and clears cache', async () => {
    const res = await addAllowDomain('trusted.example');
    assert.equal(res.ok, true);
    assert.ok(store.allowlist.includes('trusted.example'));
  });

  test('addAllowDomain rejects public suffix', async () => {
    const res = await addAllowDomain('com');
    assert.equal(res.ok, false);
  });

  test('addBlockDomain persists', async () => {
    const res = await addBlockDomain('bad.example');
    assert.equal(res.ok, true);
    assert.ok(store.blocklist.includes('bad.example'));
  });

  test('setDisabled persists', async () => {
    await setDisabled(true);
    assert.equal(store.disabled, true);
    await setDisabled(false);
    assert.equal(store.disabled, false);
  });

  test('mutations via default chrome.storage', async () => {
    const mem = {};
    configureEvaluate(null);
    globalThis.chrome = {
      storage: {
        local: {
          get: async (keys) => {
            const out = {};
            for (const k of keys) out[k] = mem[k];
            return out;
          },
          set: async (data) => Object.assign(mem, data),
        },
      },
      runtime: { getURL: () => 'https://ext.test/data/blocklist.json' },
    };
    globalThis.fetch = async () => ({ json: async () => ({ domains: [] }) });
    try {
      const a = await addAllowDomain('a.test');
      const b = await addBlockDomain('b.test');
      assert.equal(a.ok, true);
      assert.equal(b.ok, true);
      await setDisabled(true);
      assert.ok(mem.allowlist.includes('a.test'));
      assert.ok(mem.blocklist.includes('b.test'));
      assert.equal(mem.disabled, true);
    } finally {
      delete globalThis.chrome;
      configureEvaluate({
        getStorage: async () => ({ ...store }),
        setStorage: async (data) => Object.assign(store, data),
        fetchSeedBlocklist: async () => [],
      });
    }
  });
});

describe('CACHE_TTL_MS', () => {
  test('exports positive ttl', () => {
    assert.ok(CACHE_TTL_MS >= 1000);
  });
});
