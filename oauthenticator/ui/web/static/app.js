const CONFIG = document.body.dataset;
const ACTION_TOKEN = CONFIG.actionToken;
let pinger = null;

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

function ping() { fetch(CONFIG.pingPath).catch(() => {}); }

function quitCli(button) {
  button.disabled = true;
  post(CONFIG.quitPath).then(() => {
    clearInterval(pinger);
    button.textContent = 'CLI stopped';
    document.querySelector('.bar .note').textContent = 'You can close this tab.';
  });
}

function endSession(button) {
  const question = 'Log out at the provider? This ends the single sign-on session '
    + 'for every application using it, not just this one.';

  if (window.confirm(question)) { window.open(button.dataset.url, '_blank', 'noopener'); }
}

function selectTab(name) {
  document.querySelectorAll('[data-tab]').forEach(node => {
    node.classList.toggle('active', node.dataset.tab === name);
  });
  history.replaceState(null, '', '#' + name);
}

function toggleToken(button) {
  const open = button.parentElement.classList.toggle('open');
  button.textContent = open ? '▾' : '▸';
  button.title = open ? 'Collapse' : 'Expand';
}

function copyValue(button) {
  copyText(button.parentElement.querySelector('.value').textContent, button, '📋');
}

function copyCurl(button) {
  copyText(button.dataset.curl, button, 'Copy as curl');
}

function copyText(text, button, restore) {
  const done = () => {
    button.textContent = '✅';
    setTimeout(() => { button.textContent = restore; }, 1000);
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
  document.execCommand('copy');
  area.remove();
  done();
}

function showResult(name, text, failed) {
  const box = document.querySelector('section[data-tab="' + name + '"] .result');
  box.textContent = text;
  box.classList.toggle('failed', Boolean(failed));
  box.hidden = false;
}

function refreshTokens(button) {
  const restore = button.textContent;
  const note = document.querySelector('.bar .note');

  button.disabled = true;
  button.textContent = 'Refreshing...';
  post(CONFIG.refreshPath).then(
    () => location.reload(),
    error => {
      button.disabled = false;
      button.textContent = restore;
      note.textContent = error.message;
      note.classList.add('failed');
    });
}

function reloadUserinfo() {
  showResult('userinfo', 'fetching...');
  post(CONFIG.userinfoPath).then(
    data => showResult('userinfo', JSON.stringify(data, null, 2)),
    error => showResult('userinfo', error.message, true));
}

function introspect(name) {
  showResult(name, 'introspecting...');
  post(CONFIG.introspectPath + '/' + encodeURIComponent(name)).then(
    data => showResult(name, JSON.stringify(data, null, 2)),
    error => showResult(name, error.message, true));
}

function revoke(name) {
  if (!window.confirm('Revoke the ' + name + '? This cannot be undone.')) { return; }

  showResult(name, 'revoking...');
  post(CONFIG.revokePath + '/' + encodeURIComponent(name)).then(
    () => {
      showResult(name, 'revoked');
      document.querySelector('section[data-tab="' + name + '"]').classList.add('revoked');
    },
    error => showResult(name, error.message, true));
}

function tick() {
  const now = Date.now() / 1000;

  document.querySelectorAll('[data-time]').forEach(node => {
    const left = Number(node.dataset.time) - now;
    node.textContent = left >= 0 ? 'in ' + clock(left) : clock(-left) + ' ago';
    node.classList.toggle('expired', left < 0 && 'deadline' in node.dataset);
  });
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
