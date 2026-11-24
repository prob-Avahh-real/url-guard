(() => {
  const ROOT_ID = 'url-guard-banner-root';
  let lastKey = '';

  function removeBanner() {
    document.getElementById(ROOT_ID)?.remove();
  }

  function ensureRoot() {
    let el = document.getElementById(ROOT_ID);
    if (el) return el;
    el = document.createElement('div');
    el.id = ROOT_ID;
    const mount = document.documentElement || document.body;
    if (!mount) return null;
    mount.prepend(el);
    return el;
  }

  function render(result) {
    if (!result || result.disabled || result.level === 'safe' || result.level === 'caution') {
      removeBanner();
      return;
    }
    const key = result.url + result.level + result.score;
    if (key === lastKey && document.getElementById(ROOT_ID)) return;
    lastKey = key;

    const root = ensureRoot();
    if (!root) return;

    const labels = { warn: '警告', danger: '高危' };
    const cats = [...new Set((result.reasons || []).map((r) => r.category).filter((c) => c && c !== 'info'))];
    const catText = cats.length ? cats.join(' / ') : '可疑';

    root.replaceChildren();
    root.className = `url-guard-banner url-guard-${result.level}`;
    root.setAttribute('role', 'alert');

    const title = document.createElement('div');
    title.className = 'url-guard-title';
    title.textContent = `URL Guard · ${labels[result.level] || '风险'}（${catText}）`;

    const desc = document.createElement('div');
    desc.className = 'url-guard-desc';
    const top = (result.reasons || []).slice(0, 3).map((r) => r.label);
    desc.textContent = top.join('；') || '该网址存在仿冒/欺诈特征，请勿输入账号或转账。';

    const hint = document.createElement('div');
    hint.className = 'url-guard-desc';
    hint.textContent = '若需信任此域名，请打开扩展弹窗操作（页面内无法写入白名单）。';

    const actions = document.createElement('div');
    actions.className = 'url-guard-actions';

    // Session-only dismiss — no allowlist mutation from page DOM (anti click-jacking).
    const dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.textContent = '暂时关闭提示';
    dismiss.addEventListener('click', () => removeBanner());

    actions.append(dismiss);
    root.append(title, desc, hint, actions);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'URL_GUARD_RESULT') render(msg.result);
  });

  try {
    chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url: location.href }, (result) => {
      if (chrome.runtime.lastError) return;
      render(result);
    });
  } catch {
    /* ignore */
  }
})();
