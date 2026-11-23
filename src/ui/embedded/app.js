const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
let activeSvgBlobUrl = null;

function currentTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

function appendChatMessage(log, cls, prefix, text) {
  const row = document.createElement('div');
  row.className = `msg ${cls}`;
  const strong = document.createElement('b');
  strong.textContent = prefix;
  row.appendChild(strong);
  row.appendChild(document.createTextNode(text));
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
  return row;
}

// Navigation tabs
$$('nav button[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('nav button[data-tab]').forEach(b => b.classList.remove('active'));
    $$('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const panel = $(`#tab-${btn.dataset.tab}`);
    if (panel) panel.classList.add('active');
    if (btn.dataset.tab === 'viz') loadPureRustSvg();
    if (btn.dataset.tab === 'keys') refreshKeys();
  });
});

// Theme Toggle (Light & Dark)
(function initThemeToggle() {
  const root = document.documentElement;
  const saved = localStorage.getItem('nosih_theme') || 'dark';
  root.setAttribute('data-theme', saved);
  const btn = $('#theme-toggle');
  const syncLabel = () => {
    if (!btn) return;
    const isLight = root.getAttribute('data-theme') === 'light';
    btn.textContent = isLight ? 'Dark Mode' : 'Light Mode';
  };
  syncLabel();
  if (btn) {
    btn.addEventListener('click', () => {
      const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      localStorage.setItem('nosih_theme', next);
      syncLabel();
      if ($('#viz-container') && $('#viz-container').childElementCount > 0) {
        loadPureRustSvg();
      }
    });
  }
})();

// Health badges
async function refreshHealth() {
  try {
    const j = await window.NosihApi.getHealth();
    if (!j) return;
    if ($('#carbon-pill')) $('#carbon-pill').textContent = `Carbon: ${Number(j.carbon_gco2_kwh).toFixed(0)} gCO2/kWh`;
    if ($('#merkle-pill')) $('#merkle-pill').textContent = `MTLog: ${j.merkle_tree_size} leaves`;
  } catch (_) {}
}
refreshHealth();
setInterval(refreshHealth, 8000);

// Chat tab (XSS-safe DOM rendering + Enter key + Origin header)
async function sendChat() {
  const input = $('#chat-input');
  const prompt = input ? input.value.trim() : '';
  if (!prompt) return;
  const log = $('#chat-log');
  appendChatMessage(log, 'user', 'You: ', prompt);
  input.value = '';
  try {
    const res = await fetch('/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${window.NosihApi.localKey()}`,
        'X-NOSIH-Origin': $('#origin-select') ? $('#origin-select').value : 'user'
      },
      body: JSON.stringify({
        model: $('#model-select') ? $('#model-select').value : 'nosih-auto',
        messages: [{ role: 'user', content: prompt }],
        stream: false
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const errMsg = data.error?.message || `HTTP ${res.status} — check Local Key`;
      appendChatMessage(log, 'bot', 'Error: ', errMsg);
      return;
    }
    const txt = data.choices?.[0]?.message?.content || JSON.stringify(data);
    const co2 = res.headers.get('x-nosih-co2-g') || '0';
    const leaf = res.headers.get('x-nosih-merkle-leaf') || '-';
    appendChatMessage(log, 'bot', 'NOSIH: ', `${txt}  [CO2: ${co2}g · MTLog: #${leaf}]`);
    refreshOverviewCards();
    refreshHealth();
  } catch (err) {
    appendChatMessage(log, 'bot', 'Error: ', String(err));
  }
}

$('#chat-send').addEventListener('click', sendChat);
$('#chat-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendChat();
  }
});

// Keys tab (CSP-safe DOM event listeners, zero inline onclick)
async function refreshKeys() {
  const tbody = $('#keys-tbody');
  if (!tbody) return;
  const r = await fetch('/admin/keys', { headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() } });
  tbody.innerHTML = '';
  if (!r.ok) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.textContent = `Enter Admin Token to list keys (HTTP ${r.status}).`;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  const j = await r.json();
  const keys = j.keys || [];
  if (keys.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.textContent = 'No upstream provider keys uploaded yet.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  keys.forEach(k => {
    const tr = document.createElement('tr');
    const cells = [
      k.provider || '',
      k.label || '-',
      k.masked_key || '',
      k.max_usd_per_day != null ? `$${k.max_usd_per_day}` : 'unlimited'
    ];
    cells.forEach(val => {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    });
    const actTd = document.createElement('td');
    const testBtn = document.createElement('button');
    testBtn.className = 'secondary';
    testBtn.textContent = 'Test';
    testBtn.addEventListener('click', async () => {
      testBtn.textContent = '...';
      const trResp = await fetch(`/admin/keys/${encodeURIComponent(k.id)}/test`, {
        method: 'POST',
        headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() }
      });
      const tj = await trResp.json().catch(() => ({}));
      testBtn.textContent = tj.ok ? `OK (${tj.latency_ms}ms)` : `Fail (${tj.detail || trResp.status})`;
    });
    const delBtn = document.createElement('button');
    delBtn.className = 'secondary';
    delBtn.style.marginLeft = '6px';
    delBtn.textContent = 'Delete';
    delBtn.addEventListener('click', async () => {
      const dr = await fetch(`/admin/keys/${encodeURIComponent(k.id)}`, {
        method: 'DELETE',
        headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() }
      });
      if (dr.ok) refreshKeys();
    });
    actTd.appendChild(testBtn);
    actTd.appendChild(delBtn);
    tr.appendChild(actTd);
    tbody.appendChild(tr);
  });
}

$('#key-add').addEventListener('click', async () => {
  const payload = {
    provider: $('#key-provider').value,
    api_key: $('#key-secret').value.trim(),
    base_url: $('#key-base-url').value.trim() || null
  };
  if (!payload.api_key) return;
  const r = await fetch('/admin/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-NOSIH-Admin': window.NosihApi.adminToken() },
    body: JSON.stringify(payload)
  });
  if (r.ok) {
    $('#key-secret').value = '';
    $('#key-base-url').value = '';
    refreshKeys();
  }
});

$('#key-bulk-btn').addEventListener('click', async () => {
  const body = $('#key-bulk').value.trim();
  if (!body) return;
  const r = await fetch('/admin/keys', {
    method: 'POST',
    headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() },
    body
  });
  if (r.ok) {
    $('#key-bulk').value = '';
    refreshKeys();
  }
});

$('#key-refresh').addEventListener('click', refreshKeys);

// Config tab
$('#cfg-load').addEventListener('click', async () => {
  const r = await fetch('/admin/config', { headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() } });
  if (!r.ok) {
    $('#config-json').value = `Failed to load config (HTTP ${r.status}) — check Admin Token.`;
    return;
  }
  const j = await r.json();
  $('#config-json').value = JSON.stringify(j.settings, null, 2);
});

$('#cfg-save').addEventListener('click', async () => {
  const r = await fetch('/admin/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-NOSIH-Admin': window.NosihApi.adminToken() },
    body: $('#config-json').value
  });
  if (!r.ok) {
    $('#config-json').value = `Save failed (HTTP ${r.status}): ${await r.text()}`;
  }
});

// Live Logs SSE tab
let logAbort = null;
$('#log-connect').addEventListener('click', async () => {
  if (logAbort) logAbort.abort();
  logAbort = new AbortController();
  const out = $('#sse-log');
  const plane = $('#log-plane') ? $('#log-plane').value : '';
  const qs = plane ? `?plane=${encodeURIComponent(plane)}` : '';
  out.textContent = 'Connecting to live kernel SSE stream...\n';
  try {
    const r = await fetch(`/admin/logs/stream${qs}`, {
      headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() },
      signal: logAbort.signal
    });
    if (!r.ok || !r.body) {
      out.textContent = `SSE connection failed (HTTP ${r.status}) — verify Admin Token.\n`;
      return;
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      out.textContent += dec.decode(value, { stream: true });
      out.scrollTop = out.scrollHeight;
    }
  } catch (err) {
    if (err?.name !== 'AbortError') {
      out.textContent += `\nStream ended: ${err}\n`;
    }
  }
});

// Pure-Rust SVG Visualization loader (Light/Dark synced + blob cleanup)
async function loadPureRustSvg() {
  const chart = $('#viz-select') ? $('#viz-select').value : 'all';
  const box = $('#viz-container');
  if (!box) return;
  const svgText = await window.NosihApi.getSvg(chart, currentTheme());
  if (!svgText) {
    box.textContent = 'Enter Admin Token to render pure-Rust SVG graphs.';
    return;
  }
  if (activeSvgBlobUrl) URL.revokeObjectURL(activeSvgBlobUrl);
  activeSvgBlobUrl = URL.createObjectURL(new Blob([svgText], { type: 'image/svg+xml' }));
  box.innerHTML = '';
  const img = document.createElement('img');
  img.src = activeSvgBlobUrl;
  img.alt = 'NOSIH-CAZNSOS Pure-Rust SVG Graph';
  img.style.maxWidth = '100%';
  img.style.height = 'auto';
  box.appendChild(img);
}

$('#viz-refresh').addEventListener('click', loadPureRustSvg);
$('#viz-select').addEventListener('change', loadPureRustSvg);
$('#viz-download').addEventListener('click', async () => {
  const chart = $('#viz-select') ? $('#viz-select').value : 'all';
  const svgText = await window.NosihApi.getSvg(chart, currentTheme());
  if (!svgText) return;
  const url = URL.createObjectURL(new Blob([svgText], { type: 'image/svg+xml' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `nosih-caznsos-${chart}-${currentTheme()}.svg`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

// Universal Multi-Format Exporter (Save to ~/Downloads + Preview)
$('#export-btn').addEventListener('click', async () => {
  const fmt = $('#export-fmt').value;
  const r = await fetch(
    `/admin/export?format=${encodeURIComponent(fmt)}&save_to_disk=true&theme=${encodeURIComponent(currentTheme())}`,
    { method: 'POST', headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() } }
  );
  if (!r.ok) {
    $('#export-out').value = `Export failed (HTTP ${r.status}) — check Admin Token.`;
    return;
  }
  const j = await r.json();
  $('#export-out').value = `Saved (${j.format.toUpperCase()}, ${j.count} events) -> ${j.saved_path}\n\n${(j.content || '').slice(0, 8000)}`;
});

// Direct Browser Download (any format)
$('#export-dl-btn').addEventListener('click', async () => {
  const fmt = $('#export-fmt').value;
  const r = await fetch(
    `/admin/export?format=${encodeURIComponent(fmt)}&download=true&theme=${encodeURIComponent(currentTheme())}`,
    { method: 'GET', headers: { 'X-NOSIH-Admin': window.NosihApi.adminToken() } }
  );
  if (!r.ok) {
    $('#export-out').value = `Download failed (HTTP ${r.status}) — check Admin Token.`;
    return;
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `nosih-caznsos-export.${fmt === 'otel' ? 'otel.json' : fmt === 'merkle' ? 'merkle.json' : fmt}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  $('#export-out').value = `Downloaded ${a.download}`;
});

// 4-Card Telemetry Overview Dashboard (preserves carousel view across refreshes)
let cardsView = 'api';
async function refreshOverviewCards() {
  const container = $('#telemetry-grid');
  if (!container || !window.NosihApi || !window.NosihCharts) return;
  const win = $('#window-select') ? $('#window-select').value : '60';
  try {
    const payload = await window.NosihApi.getMetricCards(win, cardsView);
    if (payload) window.NosihCharts.renderCards(container, payload);
  } catch (_) {}
}

$('#window-select').addEventListener('change', refreshOverviewCards);
$('#overview-refresh').addEventListener('click', () => {
  refreshHealth();
  refreshOverviewCards();
});
$('#admin-token').addEventListener('change', () => {
  refreshOverviewCards();
  if ($('#viz-container') && $('#viz-container').childElementCount > 0) loadPureRustSvg();
});
$('#carousel-next').addEventListener('click', () => {
  cardsView = cardsView === 'api' ? 'planes' : 'api';
  refreshOverviewCards();
});

refreshOverviewCards();
setInterval(refreshOverviewCards, 8000);
