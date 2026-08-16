"""The string.Template constants the result page and notice card are built from.

Route paths are never defined here: `web/` owns them and substitutes them in
as plain values, since this module only emits the `fetch()` calls that use
them.
"""

import string

PING_INTERVAL = 5

RESULT_PAGE = string.Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>oauthenticator</title>
<style>
:root {
  --bg: #fff; --fg: #1b1b1b; --muted: #666; --line: #ddd; --panel: #f4f4f4;
  --raised: #fafafa; --danger: #a00; --ok: #070;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16181c; --fg: #e4e4e4; --muted: #9aa1a9; --line: #333941; --panel: #1d2025;
    --raised: #1a1d21; --danger: #ff7b72; --ok: #7ee787;
  }
}
html { scrollbar-gutter: stable; }
body { font-family: sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem;
       background: var(--bg); color: var(--fg); }
h1 { font-size: 1.2rem; }
h3 { font-size: 0.85rem; text-transform: uppercase; color: var(--muted);
     margin: 1.2rem 0 0.3rem; }
pre { background: var(--panel); padding: 0.6rem; overflow-x: auto; font-size: 0.8rem;
      border-radius: 0.3rem; }
.note { color: var(--muted); font-size: 0.85rem; }
.mono { font-family: monospace; }
.failed { color: var(--danger); }
.expired { color: var(--danger); font-weight: 600; }

.bar { display: flex; align-items: center; gap: 0.8rem; }
.bar .note { flex: 1; margin: 0; }

button { font: inherit; font-size: 0.85rem; color: var(--fg); cursor: pointer;
         background: var(--raised); border: 1px solid var(--line); border-radius: 0.3rem;
         padding: 0.3rem 0.7rem; }
button:hover:not(:disabled) { border-color: var(--muted); }
button:disabled { color: var(--muted); cursor: default; }
button.danger { color: var(--danger); }

.identity { display: flex; align-items: center; gap: 0.9rem; margin-top: 1.5rem;
            border: 1px solid var(--line); border-radius: 0.5rem; padding: 0.8rem 1rem; }
.identity img { width: 3rem; height: 3rem; border-radius: 50%; object-fit: cover; }
.identity .who { flex: 1; min-width: 0; }
.identity .name { font-size: 1.05rem; font-weight: 600; }
.identity .line { color: var(--muted); font-size: 0.85rem; overflow-wrap: anywhere; }
.identity .badge { background: var(--panel); color: var(--muted); border-radius: 1rem;
                   padding: 0.15rem 0.6rem; font-size: 0.75rem; white-space: nowrap; }

.meta { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.6rem; }
.meta .chip { background: var(--panel); color: var(--muted); border-radius: 0.3rem;
              padding: 0.2rem 0.5rem; font-size: 0.8rem; }

.tabs { display: flex; gap: 0.3rem; border-bottom: 1px solid var(--line); margin-top: 1.5rem; }
.tabs button { background: none; border-color: transparent; border-bottom: none;
               border-radius: 0.4rem 0.4rem 0 0; padding: 0.5rem 0.9rem;
               font-size: 0.9rem; color: var(--muted); margin-bottom: -1px; }
.tabs button::after { content: attr(data-tab); display: block; height: 0; overflow: hidden;
                      font-weight: 600; visibility: hidden; }
.tabs button:hover:not(.active) { background: var(--panel); border-color: transparent;
                                  box-shadow: inset 0 -1px var(--line); }
.tabs button.active { border-color: var(--line); background: var(--bg); color: var(--fg);
                      font-weight: 600; }
.panel { display: none; }
.panel.active { display: block; }

.token { display: flex; align-items: flex-start; gap: 0.4rem; margin-top: 1rem;
         background: var(--raised); border: 1px solid var(--line); border-radius: 0.4rem;
         padding: 0.4rem 0.5rem; }
.token .value { flex: 1; min-width: 0; font-family: monospace; font-size: 0.8rem;
                line-height: 1.5; white-space: nowrap; overflow: hidden;
                text-overflow: ellipsis; }
.token.open .value { white-space: pre-wrap; word-break: break-all; }
.token button { background: none; border: none; padding: 0 0.2rem; font-size: 0.9rem;
                line-height: 1.5; }
.panel.revoked .token .value { text-decoration: line-through; opacity: 0.55; }

.times { margin-top: 0.4rem; }
.times .line { color: var(--muted); font-size: 0.8rem; }
.times b { font-family: monospace; color: var(--fg); font-weight: normal; }

.actions { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.6rem; }
.result { white-space: pre-wrap; word-break: break-word; margin-top: 0.6rem; }
</style>
</head>
<body>
<div class="bar">
<h1>$title</h1>
<p class="note">The CLI runs while this page is open.</p>
$session_actions
<button onclick="quitCli(this)">Finish and exit CLI</button>
</div>
$body
<script>
const ACTION_TOKEN = '$action_token';
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

function ping() { fetch('$ping_path').catch(() => {}); }

function quitCli(button) {
  button.disabled = true;
  post('$quit_path').then(() => {
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
  post('$refresh_path').then(
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
  post('$userinfo_path').then(
    data => showResult('userinfo', JSON.stringify(data, null, 2)),
    error => showResult('userinfo', error.message, true));
}

function introspect(name) {
  showResult(name, 'introspecting...');
  post('$introspect_path/' + encodeURIComponent(name)).then(
    data => showResult(name, JSON.stringify(data, null, 2)),
    error => showResult(name, error.message, true));
}

function revoke(name) {
  if (!window.confirm('Revoke the ' + name + '? This cannot be undone.')) { return; }

  showResult(name, 'revoking...');
  post('$revoke_path/' + encodeURIComponent(name)).then(
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
pinger = setInterval(ping, $ping_interval * 1000);
addEventListener('visibilitychange', () => { if (!document.hidden) { ping(); } });
</script>
</body>
</html>
""")

NOTICE = string.Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>oauthenticator</title>
<style>
body { font-family: sans-serif; margin: 4rem auto; max-width: 30rem; text-align: center;
       color: #444; }
@media (prefers-color-scheme: dark) { body { background: #16181c; color: #b8bec6; } }
</style>
</head>
<body>
<p>$message</p>
<p>You can close this tab.</p>
<script>window.close();</script>
</body>
</html>
""")
