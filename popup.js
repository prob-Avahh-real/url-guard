import { levelLabel } from './lib/analyze.js';

const statusEl = document.getElementById('status');
const levelEl = document.getElementById('level');
const hostEl = document.getElementById('host');
const scoreEl = document.getElementById('score');
const reasonsEl = document.getElementById('reasons');
const enabledEl = document.getElementById('enabled');
const trustBtn = document.getElementById('trust');
const blockBtn = document.getElementById('block');

let current = null;

function paint(result) {
  current = result;
  if (!result) {
    levelEl.textContent = '无活动标签';
    hostEl.textContent = '';
    scoreEl.textContent = '';
    reasonsEl.innerHTML = '<li class="empty">打开网页后再查看</li>';
    return;
  }

  if (result.disabled) {
    statusEl.className = 'status caution';
    levelEl.textContent = '已暂停';
    hostEl.textContent = result.host || '';
    scoreEl.textContent = '';
    reasonsEl.innerHTML = '<li class="empty">扩展已关闭检测</li>';
    return;
  }

  statusEl.className = `status ${result.level}`;
  levelEl.textContent = levelLabel(result.level);
  hostEl.textContent = result.host || result.url || '';
  scoreEl.textContent = `风险分 ${result.score} · ${result.registrable || ''}`;

  const reasons = (result.reasons || []).filter((r) => r.code !== 'allowlisted');
  if (!reasons.length) {
    reasonsEl.innerHTML = '<li class="empty">未发现明显仿冒/欺诈信号</li>';
  } else {
    reasonsEl.innerHTML = reasons
      .map((r) => `<li><strong>${r.category}</strong> · ${r.label}</li>`)
      .join('');
  }
}

async function refresh() {
  const { disabled } = await chrome.storage.local.get(['disabled']);
  enabledEl.checked = !disabled;
  const result = await chrome.runtime.sendMessage({ type: 'GET_ACTIVE_RESULT' });
  paint(result);
}

enabledEl.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({ type: 'SET_DISABLED', disabled: !enabledEl.checked });
  refresh();
});

trustBtn.addEventListener('click', async () => {
  const domain = current?.registrable || current?.host;
  if (!domain) return;
  const res = await chrome.runtime.sendMessage({ type: 'ADD_ALLOW', domain });
  if (!res?.ok) {
    scoreEl.textContent = res?.error || '无法信任该域名';
    return;
  }
  refresh();
});

blockBtn.addEventListener('click', async () => {
  const domain = current?.registrable || current?.host;
  if (!domain) return;
  const res = await chrome.runtime.sendMessage({ type: 'ADD_BLOCK', domain });
  if (!res?.ok) {
    scoreEl.textContent = res?.error || '无法拉黑该域名';
    return;
  }
  refresh();
});

refresh();
