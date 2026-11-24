/**
 * List loading, caching, and URL evaluation — testable without chrome glue.
 */

import { analyzeUrl, TRUSTED_DOMAINS } from './analyze.js';
import { normalizeAllowDomain, isValidAllowDomain } from './domains.js';

const CACHE = new Map();
export const CACHE_TTL_MS = 60_000;

/** @type {{ getStorage: Function, fetchSeedBlocklist: Function, setStorage?: Function } | null} */
let deps = null;

export function configureEvaluate(next) {
  deps = next;
}

export function clearEvaluateCache() {
  CACHE.clear();
}

function defaultGetStorage() {
  return chrome.storage.local.get(['allowlist', 'blocklist', 'disabled']);
}

async function defaultFetchSeedBlocklist() {
  try {
    const url = chrome.runtime.getURL('data/blocklist.json');
    const res = await fetch(url);
    const json = await res.json();
    return json.domains || [];
  } catch {
    return [];
  }
}

function mergeAllowlist(storedAllow) {
  const user = (storedAllow || [])
    .map((d) => normalizeAllowDomain(d))
    .filter((r) => r.ok)
    .map((r) => r.domain);
  return [...new Set([...TRUSTED_DOMAINS, ...user])];
}

export async function loadLists() {
  const getStorage = deps?.getStorage || defaultGetStorage;
  const fetchSeed = deps?.fetchSeedBlocklist || defaultFetchSeedBlocklist;
  const stored = await getStorage();
  let seedBlock = [];
  try {
    seedBlock = (await fetchSeed()) || [];
  } catch {
    seedBlock = [];
  }
  return {
    allowlist: mergeAllowlist(stored.allowlist),
    blocklist: [...new Set([...(stored.blocklist || []), ...seedBlock])],
    disabled: Boolean(stored.disabled),
  };
}

export async function evaluate(url) {
  const lists = await loadLists();
  if (lists.disabled) {
    return {
      level: 'safe',
      score: 0,
      reasons: [],
      host: '',
      registrable: '',
      url,
      disabled: true,
    };
  }
  const hit = CACHE.get(url);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.result;
  const result = analyzeUrl(url, lists);
  CACHE.set(url, { at: Date.now(), result });
  return result;
}

/**
 * @returns {Promise<{ ok: true, domain: string } | { ok: false, error: string }>}
 */
export async function addAllowDomain(domain) {
  const normalized = normalizeAllowDomain(domain);
  if (!normalized.ok) return normalized;

  const getStorage = deps?.getStorage || defaultGetStorage;
  const setStorage =
    deps?.setStorage || ((data) => chrome.storage.local.set(data));
  const data = await getStorage();
  const list = new Set(
    (data.allowlist || []).filter(isValidAllowDomain).map((d) => normalizeAllowDomain(d).domain),
  );
  list.add(normalized.domain);
  await setStorage({ allowlist: [...list] });
  clearEvaluateCache();
  return { ok: true, domain: normalized.domain };
}

export async function addBlockDomain(domain) {
  const normalized = normalizeAllowDomain(domain);
  // blocklist can be stricter later; still reject public suffixes
  if (!normalized.ok) return normalized;

  const getStorage = deps?.getStorage || defaultGetStorage;
  const setStorage =
    deps?.setStorage || ((data) => chrome.storage.local.set(data));
  const data = await getStorage();
  const list = new Set(data.blocklist || []);
  list.add(normalized.domain);
  await setStorage({ blocklist: [...list] });
  clearEvaluateCache();
  return { ok: true, domain: normalized.domain };
}

export async function setDisabled(disabled) {
  const setStorage =
    deps?.setStorage || ((data) => chrome.storage.local.set(data));
  await setStorage({ disabled: Boolean(disabled) });
  clearEvaluateCache();
}
