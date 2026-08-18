const CONFIG = document.body.dataset;
const ACTION_TOKEN = CONFIG.actionToken;
let pinger = null;
const copyTimers = new WeakMap();

function post(path, payload) {
  const body = Object.assign({action_token: ACTION_TOKEN}, payload || {});

  return fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(response => response.json().then(data => {
    if (!response.ok) { throw new Error(data.error || response.statusText); }
    return data;
  }));
}

function ping() {
  fetch(CONFIG.pingPath).then(
    response => { if (!response.ok) { markStopped(); } },
    () => markStopped());
}

function markStopped() {
  clearInterval(pinger);
  document.getElementById('bar-status').textContent = 'stopped';
  const dot = document.getElementById('status-dot');
  dot.classList.remove('live');
  dot.setAttribute('aria-label', 'CLI stopped');
  document.getElementById('page-title').disabled = true;
  ['btn-refresh', 'btn-end-session', 'btn-quit'].forEach(id => {
    const button = document.getElementById(id);
    if (button) {
      button.disabled = true;
      button.textContent = button.dataset.label;
    }
  });
}

function avatarFailed(img) {
  const fallback = document.createElement('div');
  fallback.className = 'avatar avatar-fallback';
  fallback.textContent = img.dataset.initials;
  img.replaceWith(fallback);
}

function quitCli(button) {
  button.disabled = true;
  post(CONFIG.quitPath).then(markStopped);
}

function endSession(button) {
  const question = 'Log out at the provider? This ends the single sign-on session '
    + 'for every application using it, not just this one.';

  if (window.confirm(question)) { window.open(button.dataset.url, '_blank', 'noopener'); }
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme
    || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';

  document.documentElement.dataset.theme = next;
  localStorage.setItem('theme', next);
}

function selectTab(name) {
  document.querySelectorAll('[data-tab]').forEach(node => {
    node.classList.toggle('active', node.dataset.tab === name);
  });
  history.replaceState(null, '', '#' + name);
}

function toggleToken(button) {
  const open = button.parentElement.classList.toggle('open');
  button.title = open ? 'Collapse' : 'Expand';
}

function copyValue(button) {
  copyText(button.parentElement.querySelector('.value').textContent, button);
}

function copyCurl(button) {
  copyText(button.dataset.curl, button);
}

function copyText(text, button) {
  const done = () => {
    button.classList.add('copied');
    clearTimeout(copyTimers.get(button));
    copyTimers.set(button, setTimeout(() => button.classList.remove('copied'), 1000));
  };

  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(done, () => copyBySelection(text, done));
  } else {
    copyBySelection(text, done);
  }
}

function copyBySelection(text, done) {
  const area = document.createElement('textarea');
  area.value = text;
  document.body.appendChild(area);
  area.select();
  const copied = document.execCommand('copy');
  area.remove();

  if (copied) { done(); }
}

function jsonSpan(className, text) {
  const span = document.createElement('span');
  span.className = className;
  span.textContent = text;

  return span;
}

function appendJsonValue(container, value, depth) {
  const indent = '  '.repeat(depth);
  const indentInner = '  '.repeat(depth + 1);

  if (Array.isArray(value)) {
    if (value.length === 0) { container.append('[]'); return; }

    container.append('[\n');
    value.forEach((item, index) => {
      container.append(indentInner);
      appendJsonValue(container, item, depth + 1);
      container.append(index < value.length - 1 ? ',\n' : '\n');
    });
    container.append(indent + ']');
    return;
  }

  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) { container.append('{}'); return; }

    container.append('{\n');
    keys.forEach((key, index) => {
      container.append(indentInner);
      container.appendChild(jsonSpan('json-key', JSON.stringify(key)));
      container.append(': ');
      appendJsonValue(container, value[key], depth + 1);
      container.append(index < keys.length - 1 ? ',\n' : '\n');
    });
    container.append(indent + '}');
    return;
  }

  if (typeof value === 'string') {
    container.appendChild(jsonSpan('json-string', JSON.stringify(value)));
  } else if (typeof value === 'number') {
    container.appendChild(jsonSpan('json-number', String(value)));
  } else {
    container.appendChild(jsonSpan('json-string', String(value)));
  }
}

function showResult(name, label, data, failed) {
  const panel = document.querySelector('section[data-tab="' + name + '"]');
  const heading = panel.querySelector('.result-label');
  const box = panel.querySelector('.result');

  heading.textContent = '— ' + label + ' —';
  heading.hidden = false;
  box.textContent = '';
  box.classList.toggle('failed', Boolean(failed));
  box.classList.toggle('json-rail', !failed && data !== null && typeof data === 'object');
  box.hidden = false;

  if (!failed && data !== null && typeof data === 'object') {
    appendJsonValue(box, data, 0);
  } else {
    box.textContent = data;
  }
}

function refreshTokens(button) {
  const restore = button.innerHTML;

  button.disabled = true;
  post(CONFIG.refreshPath).then(
    () => location.reload(),
    error => {
      button.disabled = false;
      button.textContent = 'failed';
      button.title = error.message;
      setTimeout(() => { button.innerHTML = restore; button.title = ''; }, 1500);
    });
}

function reloadUserinfo() {
  showResult('userinfo', 'USERINFO', 'fetching...');
  post(CONFIG.userinfoPath).then(
    data => showResult('userinfo', 'USERINFO', data),
    error => showResult('userinfo', 'USERINFO', error.message, true));
}

function introspect(name) {
  showResult(name, 'INTROSPECTION', 'introspecting...');
  post(CONFIG.introspectPath + '/' + encodeURIComponent(name)).then(
    data => showResult(name, 'INTROSPECTION', data),
    error => showResult(name, 'INTROSPECTION', error.message, true));
}

function revoke(name) {
  if (!window.confirm('Revoke the ' + name + '? This cannot be undone.')) { return; }

  showResult(name, 'REVOCATION', 'revoking...');
  post(CONFIG.revokePath + '/' + encodeURIComponent(name)).then(
    () => {
      showResult(name, 'REVOCATION', 'revoked');
      document.querySelector('section[data-tab="' + name + '"]').classList.add('revoked');
    },
    error => showResult(name, 'REVOCATION', error.message, true));
}

function tick() {
  const now = Date.now() / 1000;

  document.querySelectorAll('[data-time]').forEach(node => {
    const left = Number(node.dataset.time) - now;
    node.textContent = left >= 0 ? 'in ' + clock(left) : clock(-left) + ' ago';
  });
  document.querySelectorAll('.life-track').forEach(track => drawLifetime(track, now));
}

// Only the percentage and the zone class; every colour stays in the stylesheet.
function drawLifetime(track, now) {
  const start = Number(track.dataset.lifeStart);
  const span = Number(track.dataset.lifeEnd) - start;
  const elapsed = span > 0 ? Math.min(Math.max((now - start) / span, 0), 1) : 1;
  const percent = (elapsed * 100).toFixed(1) + '%';

  track.querySelector('.life-fill').style.width = percent;
  track.querySelector('.life-dot').style.left = percent;

  const row = track.closest('.life');
  row.classList.toggle('life-warn', elapsed >= 0.7 && elapsed < 0.9);
  row.classList.toggle('life-critical', elapsed >= 0.9);
}

function clock(seconds) {
  const total = Math.floor(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor(total / 60) % 60;
  const rest = String(total % 60).padStart(2, '0');

  return hours > 0 ? hours + 'h ' + minutes + 'm' : minutes + 'm ' + rest + 's';
}

const wanted = location.hash.slice(1);
if (wanted && document.querySelector('section[data-tab="' + wanted + '"]')) { selectTab(wanted); }

tick();
setInterval(tick, 1000);
ping();
pinger = setInterval(ping, Number(CONFIG.pingInterval) * 1000);
addEventListener('visibilitychange', () => { if (!document.hidden) { ping(); } });
