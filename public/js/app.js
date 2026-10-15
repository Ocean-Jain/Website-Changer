'use strict';

const $ = (s, root = document) => root.querySelector(s);
const api = async (url, options = {}) => {
  const response = await fetch(url, { ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) {
    const next = location.pathname + location.search + location.hash;
    location.replace(`/login.html?next=${encodeURIComponent(next)}`);
  }
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
};
const esc = (value) => String(value || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const date = (value) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'Not checked yet';
const ago = (value) => {
  if (!value) return 'Not checked yet';
  const ms = Date.now() - new Date(value).getTime();
  if (ms < 60000) return 'Just now';
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`;
  if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`;
  return `${Math.floor(ms / 86400000)}d ago`;
};
function metricsMarkup(checks) {
  const data = checks.slice().reverse().map((check) => { try { return JSON.parse(check.metrics || '{}'); } catch { return {}; } });
  const names = [...new Set(data.flatMap((row) => Object.keys(row)))].slice(0, 8);
  if (!names.length) return '<p class="field-note">No labeled numbers found yet. Lines such as “Price: 12.50” are charted automatically.</p>';
  return `<div class="metrics-grid">${names.map((name) => {
    const points = data.map((row, index) => ({ index, value: row[name] })).filter((p) => Number.isFinite(p.value));
    const values = points.map((p) => p.value); const min = Math.min(...values); const max = Math.max(...values); const spread = max - min || 1;
    const path = points.map((p, i) => `${points.length < 2 ? 160 : 8 + i * 304 / (points.length - 1)},${46 - ((p.value - min) / spread) * 38}`).join(' ');
    return `<div class="metric-card"><strong>${esc(name)}</strong><span class="metric-value">${esc(values.at(-1))}</span><svg viewBox="0 0 320 52" role="img" aria-label="${esc(name)} over time"><polyline points="${path}"></polyline></svg></div>`;
  }).join('')}</div>`;
}
let pages = [];
let activePage = null;
let timer;

function toast(message) {
  const el = $('#toast'); el.textContent = message; el.classList.add('show');
  clearTimeout(timer); timer = setTimeout(() => el.classList.remove('show'), 2800);
}
async function refresh() {
  try {
    [pages] = await Promise.all([api('/api/pages'), api('/api/stats').then((stats) => {
      $('#stats').innerHTML = `<div class="stat"><b>${stats.pages}</b><span>pages tracked</span></div><div class="stat"><b>${stats.changes24h}</b><span>changes · 24h</span></div><div class="stat"><b>${stats.checks24h}</b><span>checks · 24h</span></div>`;
    })]);
    renderPages();
  } catch (error) { toast(error.message); }
}
function renderPages() {
  const term = $('#search').value.trim().toLowerCase();
  const visible = pages.filter((p) => `${p.name} ${p.url}`.toLowerCase().includes(term));
  $('#watch-count').textContent = pages.length ? `${pages.length} ${pages.length === 1 ? 'page' : 'pages'} monitored · checks scheduled automatically` : 'Your monitored pages and their history will appear here.';
  $('.search').hidden = pages.length === 0;
  $('#empty').hidden = pages.length > 0;
  $('#page-list').innerHTML = visible.map((p) => `<article class="page-card" data-id="${p.id}">
    <div class="page-main" data-detail="${p.id}"><div class="page-title-row"><span class="page-title">${esc(p.name)}</span><span class="badge ${esc(p.status)}">${esc(p.status || 'waiting')}</span>${p.last_changed_at ? '<span class="change-label">Changed</span>' : ''}</div>
      <div class="page-url">${esc(p.url)}</div><div class="page-meta"><span>Checked ${esc(ago(p.last_checked_at))}</span><span>${p.last_changed_at ? `Last changed ${esc(ago(p.last_changed_at))}` : 'No change detected yet'}</span><span>${Number(p.version_count || 0)} versions</span><span>Every ${Math.floor(p.interval_seconds / 60)} min</span></div>
      ${p.last_error ? `<p class="error">${esc(p.last_error)}</p>` : ''}</div>
    <div class="page-actions"><button class="button secondary" data-check="${p.id}">Check now</button><button class="icon-button" data-delete="${p.id}" aria-label="Delete ${esc(p.name)}">×</button></div>
  </article>`).join('');
  $('#page-list').hidden = pages.length === 0 || visible.length === 0;
  if (pages.length && !visible.length) $('#page-list').innerHTML = '<p class="empty-message">No pages match that search.</p>', $('#page-list').hidden = false;
}

function csv(value) { return value.split(',').map((x) => x.trim()).filter(Boolean); }
const addDialog = $('#add-dialog');
function openAdd(prefill = '') {
  $('#form-error').textContent = ''; $('#add-form').reset();
  if (prefill) {
    try { const url = new URL(prefill); if (!['http:', 'https:'].includes(url.protocol)) throw new Error(); $('#add-form').elements.url.value = url.href; $('#add-form').elements.name.value = url.hostname; }
    catch { toast('The extension provided an invalid public URL.'); }
  }
  addDialog.showModal();
}
$('#add-page').addEventListener('click', openAdd);
$('#empty-add').addEventListener('click', openAdd);
document.addEventListener('click', (event) => { if (event.target.closest('[data-close]')) event.target.closest('dialog').close(); });
$('#search').addEventListener('input', renderPages);
$('#add-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = Object.fromEntries(form.entries());
  data.intervalMinutes = Number(data.intervalMinutes);
  data.watchSelectors = csv(data.watchSelectors || ''); data.ignoreSelectors = csv(data.ignoreSelectors || ''); data.keywords = csv(data.keywords || ''); data.discordEnabled = form.has('discordEnabled'); data.dailyDigest = form.has('dailyDigest');
  try {
    const page = await api('/api/pages', { method: 'POST', body: JSON.stringify(data) });
    addDialog.close(); toast('Page added. First check is queued.'); await refresh(); openDetail(page.id);
  } catch (error) { $('#form-error').textContent = error.message; }
});

$('#page-list').addEventListener('click', async (event) => {
  const check = event.target.closest('[data-check]'); const del = event.target.closest('[data-delete]'); const card = event.target.closest('[data-detail]');
  if (check) {
    check.disabled = true; check.textContent = 'Checking…';
    try { const result = await api(`/api/pages/${check.dataset.check}/check`, { method: 'POST', body: '{}' }); toast(result.changed ? `Change found · version ${result.version}` : result.status === 'ok' ? 'No meaningful change found.' : result.error || 'Check finished.'); await refresh(); }
    catch (error) { toast(error.message); } finally { check.disabled = false; check.textContent = 'Check now'; }
  } else if (del) {
    if (!confirm('Remove this page and its saved history?')) return;
    try { await api(`/api/pages/${del.dataset.delete}`, { method: 'DELETE' }); toast('Page and history removed.'); await refresh(); } catch (error) { toast(error.message); }
  } else if (card) openDetail(Number(card.dataset.detail));
});

const detailDialog = $('#detail-dialog');
async function openDetail(id) {
  try {
    activePage = await api(`/api/pages/${id}`);
    const [versions, checks] = await Promise.all([api(`/api/pages/${id}/versions`), api(`/api/pages/${id}/checks`)]);
    const p = activePage;
    $('#detail-content').innerHTML = `<div class="detail-head"><div class="dialog-head"><div><p class="eyebrow">PAGE HISTORY</p><h2>${esc(p.name)} <span class="badge ${esc(p.status)}">${esc(p.status)}</span></h2><a class="detail-url" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.url)} ↗</a></div><button class="icon-button" data-close aria-label="Close">×</button></div><div class="detail-tools"><button class="button primary" id="detail-check">Check now</button><button class="button secondary" id="detail-picker">Pick region visually</button><button class="button secondary" id="detail-feed">Create RSS link</button><button class="button danger" id="detail-delete">Delete page</button></div></div>
      <div class="detail-body"><section class="detail-section"><h3>Saved versions (${versions.length})</h3><p class="field-note">New snapshots are stored when the normalized text changes.</p><div class="version-list">${versions.length ? versions.map((v, i) => `<label class="version"><input type="checkbox" data-version="${v.version}" ${i < 2 ? 'checked' : ''}><span><b>Version ${v.version}</b><br>${esc(date(v.created_at))}${v.summary ? `<br><strong>${esc(v.summary)}</strong>` : ''}<br>${esc(v.text.slice(0, 85))}${v.text.length > 85 ? '…' : ''}</span><img src="/api/pages/${p.id}/versions/${v.version}/screenshot" alt="Version ${v.version} screenshot"></label>`).join('') : '<p class="field-note">The first snapshot appears after the first successful check.</p>'}</div><div class="detail-tools"><button class="button secondary" id="compare-button" ${versions.length < 2 ? 'disabled' : ''}>Compare selected</button></div></section>
      <section class="detail-section"><h3>Check history</h3><div class="history-list">${checks.map((c) => `<div class="history-row"><span>${esc(date(c.checked_at))}</span><span class="badge ${esc(c.status)}">${esc(c.status)}</span></div>`).join('') || '<span>No checks yet.</span>'}</div></section>
      <section class="detail-metrics"><h3>Number tracking</h3>${metricsMarkup(checks)}</section>
      <section class="detail-config"><h3>Watch settings</h3><div class="config-grid"><label>Name<input id="cfg-name" value="${esc(p.name)}"></label><label>Interval<select id="cfg-interval">${[[15,'15 minutes'],[30,'30 minutes'],[60,'1 hour'],[360,'6 hours'],[720,'12 hours'],[1440,'24 hours']].map(([min,label]) => `<option value="${min}" ${Math.floor(p.interval_seconds/60)===min?'selected':''}>${label}</option>`).join('')}</select></label><label>Sensitivity<select id="cfg-sensitivity">${['low','medium','high'].map((x) => `<option ${p.sensitivity===x?'selected':''}>${x}</option>`).join('')}</select></label><label>Watch selectors<input id="cfg-watch" value="${esc(p.watchSelectors.join(', '))}"></label><label>Ignore selectors<input id="cfg-ignore" value="${esc(p.ignoreSelectors.join(', '))}"></label><label>Keyword alerts<input id="cfg-keywords" value="${esc(p.keywords.join(', '))}"></label><label>Email<input id="cfg-email" value="${esc(p.alert_email)}" placeholder="SMTP required"></label><label class="check-label"><input id="cfg-discord" type="checkbox" ${p.discord_enabled?'checked':''}> Send to configured Discord webhook</label><label>Telegram chat ID<input id="cfg-telegram" value="${esc(p.telegram_chat_id)}" placeholder="Bot token is a server setting"></label></div><div class="detail-tools"><label class="check-label"><input id="cfg-digest" type="checkbox" ${p.daily_digest?'checked':''}> Daily digest</label><button class="button primary" id="save-config">Save settings</button></div></section>
      <section id="compare-output" class="compare-output" hidden></section></div>`;
    detailDialog.showModal();
    $('#detail-feed').onclick = async () => { try { const feed = await api(`/api/pages/${id}/feed-token`, { method: 'POST', body: '{}' }); const url = new URL(feed.url, location.origin).href; if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(url); window.prompt('Private RSS feed URL (keep it private)', url); } catch (e) { toast(e.message); } };
    $('#detail-check').onclick = async () => { const button = $('#detail-check'); button.disabled = true; button.textContent = 'Checking…'; try { const r = await api(`/api/pages/${id}/check`, { method: 'POST', body: '{}' }); toast(r.changed ? `New version ${r.version}` : r.status === 'ok' ? 'No meaningful change found.' : r.error || r.status); await refresh(); await openDetail(id); } catch (e) { toast(e.message); } };
    $('#detail-picker').onclick = () => openPicker(id);
    $('#detail-delete').onclick = async () => { if (!confirm('Remove this page and all saved history?')) return; await api(`/api/pages/${id}`, { method: 'DELETE' }); detailDialog.close(); toast('Page and history removed.'); refresh(); };
    $('#save-config').onclick = async () => {
      try { await api(`/api/pages/${id}`, { method: 'PATCH', body: JSON.stringify({ name: $('#cfg-name').value, intervalMinutes: Number($('#cfg-interval').value), sensitivity: $('#cfg-sensitivity').value, watchSelectors: csv($('#cfg-watch').value), ignoreSelectors: csv($('#cfg-ignore').value), keywords: csv($('#cfg-keywords').value), alertEmail: $('#cfg-email').value, discordEnabled: $('#cfg-discord').checked, telegramChatId: $('#cfg-telegram').value, dailyDigest: $('#cfg-digest').checked }) }); toast('Settings saved.'); await refresh(); }
      catch (e) { toast(e.message); }
    };
    $('#compare-button').onclick = async () => {
      const selected = [...document.querySelectorAll('[data-version]:checked')].map((x) => Number(x.dataset.version));
      if (selected.length !== 2) return toast('Select exactly two versions.');
      try {
        const result = await api(`/api/pages/${id}/compare?a=${selected[1]}&b=${selected[0]}`);
        const out = $('#compare-output'); out.hidden = false;
        out.innerHTML = `<h3>Version ${result.a.version} → ${result.b.version} · ${result.diffRatio}% visual difference</h3>${result.b.summary ? `<p class="change-label">AI summary: ${esc(result.b.summary)}</p>` : ''}<div class="diff-text"><pre>${esc(result.textDiff.removed || 'No removed text')}</pre><pre>${esc(result.textDiff.added || 'No added text')}</pre></div><div class="compare-images"><p class="field-note">Highlighted pixel differences</p><img alt="Highlighted screenshot difference" src="data:image/png;base64,${result.highlightedPng}"><p class="field-note">Earlier screenshot on the left, newer on the right</p><img alt="Screenshots side by side" src="data:image/png;base64,${result.sideBySidePng}"></div>`;
        out.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } catch (e) { toast(e.message); }
    };
  } catch (error) { toast(error.message); }
}

const pickerDialog = $('#picker-dialog');
async function openPicker(id) {
  $('#picker-stage').innerHTML = '<p>Opening a safe preview…</p>'; pickerDialog.showModal();
  try {
    const result = await api(`/api/pages/${id}/picker`, { method: 'POST', body: '{}' });
    const image = new Image(); image.src = `data:image/png;base64,${result.screenshot}`; image.alt = 'Click a page element to track it';
    image.addEventListener('click', async (event) => {
      const rect = image.getBoundingClientRect();
      const x = Math.round((event.clientX - rect.left) / rect.width * result.width);
      const y = Math.round((event.clientY - rect.top) / rect.height * result.height);
      try { const mode = $('#picker-mode').value; const selected = await api(`/api/pages/${id}/picker/select`, { method: 'POST', body: JSON.stringify({ token: result.token, x, y, mode }) }); toast(`${mode === 'ignore' ? 'Ignoring' : 'Watching'} ${selected.selector}`); pickerDialog.close(); detailDialog.close(); await refresh(); openDetail(id); }
      catch (error) { toast(error.message); }
    });
    $('#picker-stage').replaceChildren(image);
  } catch (error) { $('#picker-stage').innerHTML = `<p>${esc(error.message)}</p>`; }
}
$('#picker-dialog').addEventListener('close', () => { if (activePage) api(`/api/pages/${activePage.id}/picker`, { method: 'DELETE' }).catch(() => {}); });
api('/api/auth/me').then((user) => {
  $('#account-email').textContent = user.email;
  $('#signout').addEventListener('click', async () => { await fetch('/api/auth/signout', { method: 'POST' }); location.assign('/login.html'); });
  return refresh();
}).then(async () => {
  const params = new URLSearchParams(location.search);
  const hashParams = new URLSearchParams(location.hash.slice(1));
  const addUrl = hashParams.get('add');
  if (addUrl) { openAdd(addUrl); history.replaceState(null, '', location.pathname); return; }
  const comparison = params.get('compare')?.match(/^(\d+):(\d+)$/);
  const pageId = Number(comparison?.[1] || params.get('page'));
  if (!Number.isSafeInteger(pageId) || pageId < 1) return;
  await openDetail(pageId);
  if (comparison) {
    const newest = Number(comparison[2]);
    const before = document.querySelector(`[data-version="${newest}"]`);
    const after = document.querySelector(`[data-version="${newest - 1}"]`);
    if (before && after) {
      document.querySelectorAll('[data-version]').forEach((x) => { x.checked = x === before || x === after; });
      $('#compare-button').click();
    }
  }
}).catch((error) => {
  if (error.message === 'Sign in required.') {
    const next = location.pathname + location.search + location.hash;
    location.replace(`/login.html?next=${encodeURIComponent(next)}`);
  } else toast(error.message);
});
setInterval(() => { if ($('#account-email').textContent) refresh(); }, 30000);
