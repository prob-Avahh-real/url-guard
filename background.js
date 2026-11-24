import { levelColor } from './lib/analyze.js';
import {
  evaluate,
  addAllowDomain,
  addBlockDomain,
  setDisabled,
} from './lib/evaluate.js';

function setBadge(tabId, result) {
  if (result.disabled) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  const map = { safe: '', caution: '!', warn: '!!', danger: '!' };
  const text = map[result.level] ?? '';
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: levelColor(result.level) });
  chrome.action.setTitle({
    tabId,
    title: result.level === 'safe' ? 'URL Guard · 安全' : `URL Guard · ${result.level.toUpperCase()}`,
  });
}

async function scanTab(tabId, url) {
  if (!url || !/^https?:/i.test(url)) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return null;
  }
  const result = await evaluate(url);
  setBadge(tabId, result);
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'URL_GUARD_RESULT', result });
  } catch {
    /* content script may be absent on restricted pages */
  }
  return result;
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'loading' || info.url) {
    if (tab.url) scanTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url) scanTab(tabId, tab.url);
  } catch {
    /* ignore */
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === 'ANALYZE_URL') {
      sendResponse(await evaluate(msg.url));
      return;
    }
    if (msg.type === 'GET_ACTIVE_RESULT') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        sendResponse(null);
        return;
      }
      sendResponse(await scanTab(tab.id, tab.url));
      return;
    }
    if (msg.type === 'ADD_ALLOW') {
      sendResponse(await addAllowDomain(msg.domain));
      return;
    }
    if (msg.type === 'ADD_BLOCK') {
      sendResponse(await addBlockDomain(msg.domain));
      return;
    }
    if (msg.type === 'SET_DISABLED') {
      await setDisabled(msg.disabled);
      sendResponse({ ok: true });
    }
  })();
  return true;
});
