/* DiskFree WebUI ---------------------------------------------------------
   Vanilla JS, no build step, no CDN. Everything talks to the same origin.

   Security notes that shape this file:
   * File names and paths are attacker-controlled (a downloaded archive can name
     a folder anything). Every dynamic string goes through esc() before it
     reaches innerHTML.
   * The UI can never delete anything on its own: it builds a plan, shows it
     item by item, and only then sends the plan id plus the HMAC confirm token.
   ----------------------------------------------------------------------- */
(() => {
  'use strict';

  // ---------------------------------------------------------------- utils
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  function bytes(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return '?';
    let size = Math.abs(Number(value));
    const sign = Number(value) < 0 ? '-' : '';
    for (const unit of UNITS) {
      if (size < 1024 || unit === UNITS[UNITS.length - 1]) {
        return `${sign}${unit === 'B' ? Math.round(size) : size.toFixed(1)} ${unit}`;
      }
      size /= 1024;
    }
    return `${sign}${size.toFixed(1)} PB`;
  }
  const num = (value) => Number(value || 0).toLocaleString();
  function ago(seconds) {
    if (!seconds) return 'now';
    const s = Number(seconds);
    if (s < 60) return `${Math.round(s)}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  }
  function days(value) {
    const d = Number(value || 0);
    if (d < 1) return 'today';
    if (d < 60) return `${Math.round(d)} d`;
    if (d < 730) return `${Math.round(d / 30.4)} mo`;
    return `${(d / 365.25).toFixed(1)} y`;
  }
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const shortHome = (p) => String(p || '');

  // ------------------------------------------------------------------ api
  const TOKEN_KEY = 'diskfree.token';

  const API = {
    token: localStorage.getItem(TOKEN_KEY) || '',

    headers(extra = {}) {
      const head = { Accept: 'application/json', ...extra };
      if (this.token) head['X-DiskFree-Token'] = this.token;
      return head;
    },

    async req(method, path, body) {
      const init = { method, headers: this.headers() };
      if (body !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
      }
      const response = await fetch(path, init);
      if (response.status === 401) {
        promptToken();
        throw new ApiError('This DiskFree instance needs an access token.', 401);
      }
      const text = await response.text();
      let data = null;
      if (text) {
        try { data = JSON.parse(text); } catch { data = { error: text.slice(0, 300) }; }
      }
      if (!response.ok) {
        const detail = (data && (data.detail || data.error || data.message)) || `HTTP ${response.status}`;
        const hint = data && (data.hint || (data.detail && data.detail.hint));
        throw new ApiError(typeof detail === 'string' ? detail : JSON.stringify(detail), response.status, hint);
      }
      return data;
    },

    get(path) { return this.req('GET', path); },
    post(path, body) { return this.req('POST', path, body === undefined ? {} : body); },
    del(path) { return this.req('DELETE', path); },

    async sse(path, body, handlers) {
      const response = await fetch(path, {
        method: 'POST',
        headers: this.headers({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(body),
      });
      if (response.status === 401) { promptToken(); throw new ApiError('Token required.', 401); }
      if (!response.ok || !response.body) {
        const text = await response.text();
        throw new ApiError(`Chat failed (HTTP ${response.status}): ${text.slice(0, 200)}`, response.status);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let split;
        while ((split = buffer.indexOf('\n\n')) >= 0) {
          const chunk = buffer.slice(0, split);
          buffer = buffer.slice(split + 2);
          const event = parseSse(chunk);
          if (!event) continue;
          const fn = handlers[event.name];
          if (fn) fn(event.data);
        }
      }
    },
  };

  class ApiError extends Error {
    constructor(message, status, hint) {
      super(message);
      this.status = status;
      this.hint = hint;
    }
  }

  function parseSse(chunk) {
    let name = 'message';
    const dataLines = [];
    for (const line of chunk.split('\n')) {
      if (line.startsWith('event:')) name = line.slice(6).trim();
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    if (!dataLines.length) return null;
    let data;
    try { data = JSON.parse(dataLines.join('\n')); } catch { data = { raw: dataLines.join('\n') }; }
    return { name, data };
  }

  // ---------------------------------------------------------------- state
  const state = {
    view: 'overview',
    status: null,
    providers: [],
    presets: null,
    job: null,
    jobId: null,
    findings: [],
    findingIndex: new Map(),
    filters: { categories: new Set(), risks: new Set(), q: '', minBytes: 0, sort: 'bytes', onlySelectable: true },
    selection: new Set(),
    advice: null,
    adviceJobId: null,
    plan: null,
    lastReport: null,
    history: null,
    rules: null,
    safety: null,
    config: null,
    chat: [],
    chatBusy: false,
    scanTimer: null,
    acknowledged: false,
  };

  const VIEW_META = {
    overview: ['Overview', 'Your disk at a glance.'],
    scan: ['Scan', 'Read-only analysis. Nothing is modified while scanning.'],
    findings: ['Findings', 'Everything DiskFree thinks you could reclaim, grouped and risk-rated.'],
    advisor: ['AI Advisor', 'Local-model analysis of the scan, checked by DiskFree\'s guardrails.'],
    clean: ['Clean', 'Itemise, confirm, then move data to the trash. Reversible.'],
    history: ['History', 'Every move DiskFree made, with one-click undo.'],
    assistant: ['Assistant', 'Ask questions about your disk. Read-only by design.'],
    rules: ['Rules', 'The full cleaning knowledge base, expanded for this machine.'],
    safety: ['Safety', 'What is protected, where removed data goes, and why.'],
    settings: ['Settings', 'Configuration, providers and limits.'],
  };

  // --------------------------------------------------------------- toasts
  function toast(title, detail, kind = 'ok', timeout = 5200) {
    const stack = $('#toasts');
    if (!stack) return;
    const node = document.createElement('div');
    node.className = `toast ${kind === 'ok' ? '' : kind}`;
    node.innerHTML = `<div class="t">${esc(title)}</div>${detail ? `<div class="d">${esc(detail)}</div>` : ''}`;
    stack.appendChild(node);
    setTimeout(() => {
      node.style.opacity = '0';
      node.style.transform = 'translateY(6px)';
      node.style.transition = 'opacity .2s, transform .2s';
      setTimeout(() => node.remove(), 220);
    }, timeout);
  }

  function modal(title, bodyHtml, footHtml = '') {
    const dialog = $('#modal');
    $('#modal-title').textContent = title;
    $('#modal-body').innerHTML = bodyHtml;
    $('#modal-foot').innerHTML = footHtml || '<button class="btn btn-ghost" value="cancel">Close</button>';
    if (!dialog.open) dialog.showModal();
  }
  function closeModal() { const dialog = $('#modal'); if (dialog.open) dialog.close(); }

  function promptToken() {
    const tpl = $('#tpl-token').content.cloneNode(true);
    modal('Access token required', '');
    $('#modal-body').appendChild(tpl);
    $('#token-save').addEventListener('click', () => {
      const value = $('#token-input').value.trim();
      if (value) {
        API.token = value;
        localStorage.setItem(TOKEN_KEY, value);
        closeModal();
        toast('Token saved', 'Retrying…');
        boot(true);
      }
    });
  }

  // ------------------------------------------------------------ navigation
  function navigate(view, opts = {}) {
    if (!VIEW_META[view]) view = 'overview';
    state.view = view;
    $$('.nav-item').forEach((item) => item.classList.toggle('is-active', item.dataset.view === view));
    $$('.view').forEach((section) => section.classList.toggle('is-active', section.id === `view-${view}`));
    const [title, subtitle] = VIEW_META[view];
    $('#view-title').textContent = title;
    $('#view-subtitle').textContent = subtitle;
    document.body.classList.remove('nav-open');
    render(view, opts);
  }

  async function render(view, opts = {}) {
    const host = $(`#view-${view}`);
    if (!host) return;
    try {
      switch (view) {
        case 'overview': await renderOverview(host); break;
        case 'scan': await renderScan(host); break;
        case 'findings': await renderFindings(host); break;
        case 'advisor': await renderAdvisor(host); break;
        case 'clean': await renderClean(host); break;
        case 'history': await renderHistory(host); break;
        case 'assistant': renderAssistant(host); break;
        case 'rules': await renderRules(host); break;
        case 'safety': await renderSafety(host); break;
        case 'settings': await renderSettings(host); break;
        default: break;
      }
    } catch (error) {
      host.innerHTML = errorCard(error);
    }
  }

  function errorCard(error) {
    const hint = error && error.hint ? `<p class="hint">${esc(error.hint)}</p>` : '';
    return `<div class="notice danger"><strong>Something went wrong.</strong>
      <p>${esc((error && error.message) || String(error))}</p>${hint}</div>`;
  }

  function spinner(text = 'Working…') {
    return `<div class="row-gap dim"><span class="spinner"></span>${esc(text)}</div>`;
  }

  function empty(icon, title, text, actionHtml = '') {
    return `<div class="empty"><div class="big">${icon}</div><h3>${esc(title)}</h3>
      <p>${esc(text)}</p>${actionHtml ? `<div class="mt">${actionHtml}</div>` : ''}</div>`;
  }

  // -------------------------------------------------------------- overview
  async function renderOverview(host) {
    if (!state.status) host.innerHTML = spinner('Loading status…');
    const status = state.status || await refreshStatus();
    if (!status) return;

    const disk = status.disk || {};
    const pct = clamp(Number(disk.percent || 0), 0, 100);
    const job = state.job;
    const summary = job || {};
    const cats = summary.categories || [];
    const reclaim = summary.actionable_bytes || 0;
    const safeBytes = summary.safe_bytes || 0;

    host.innerHTML = `
      <div class="grid side">
        <div>
          <div class="card">
            <div class="card-head"><h2>Disk usage</h2>
              <span class="sub">${esc(status.home || '')}</span></div>
            <div class="card-body">
              <div class="row-gap" style="gap:22px;align-items:center">
                ${donut(pct, `${pct.toFixed(0)}%`, 'full')}
                <div class="stack" style="flex:1;min-width:190px">
                  ${usageLine('Used', disk.used, disk.total, '')}
                  ${usageLine('Free', disk.free, disk.total, 'accent')}
                  ${usageLine('Reclaimable', reclaim, disk.total, 'warn')}
                  <div class="hint">Reclaimable comes from the latest scan
                    ${job ? `(${esc(String(summary.findings || 0))} findings, ${esc(ago((Date.now() / 1000) - (summary.finished_at || summary.created_at || Date.now() / 1000)))})` : '— run one to see'}.</div>
                </div>
              </div>
            </div>
          </div>

          <div class="grid cols-4">
            ${statCard('Safe to clear', bytes(safeBytes), 'Regenerable caches, temp files', 'accent')}
            ${statCard('Total reclaimable', bytes(reclaim), `${num(summary.actionable_findings || 0)} actionable findings`)}
            ${statCard('Duplicates', bytes(summary.duplicate_bytes || 0), 'Byte-identical extras')}
            ${statCard('Findings', num(summary.findings || 0), `${num(cats.length)} categories`)}
          </div>

          ${cats.length ? categoryCard(cats, reclaim) : ''}
        </div>

        <div>
          ${quickStartCard(status, job)}
          ${folderCard(summary)}
          ${mountsCard(status)}
        </div>
      </div>`;

    wireOverview(host);
  }

  function donut(pct, value, label) {
    const r = 62;
    const c = 2 * Math.PI * r;
    const klass = pct > 90 ? 'var(--danger)' : pct > 75 ? 'var(--warn)' : 'var(--accent)';
    return `<div class="donut">
      <svg width="148" height="148" viewBox="0 0 148 148" aria-hidden="true">
        <circle cx="74" cy="74" r="${r}" fill="none" stroke="#1b2823" stroke-width="13"/>
        <circle cx="74" cy="74" r="${r}" fill="none" stroke="${klass}" stroke-width="13"
          stroke-linecap="round" stroke-dasharray="${(c * pct) / 100} ${c}"/>
      </svg>
      <div class="donut-center"><div class="v">${esc(value)}</div><div class="l">${esc(label)}</div></div>
    </div>`;
  }

  function usageLine(label, value, total, tone) {
    const pct = total ? clamp((Number(value || 0) / Number(total)) * 100, 0, 100) : 0;
    return `<div>
      <div class="spread" style="font-size:12.5px">
        <span class="dim">${esc(label)}</span>
        <span class="mono">${bytes(value)}</span>
      </div>
      <div class="meter-track" style="margin-top:4px">
        <div class="meter-fill ${tone === 'accent' ? '' : tone === 'warn' ? 'warn' : ''}" style="width:${pct}%"></div>
      </div>
    </div>`;
  }

  function statCard(label, value, note, tone = '') {
    return `<div class="stat ${tone}"><div class="label">${esc(label)}</div>
      <div class="value ${String(value).length > 9 ? 'small' : ''}">${esc(value)}</div>
      <div class="note">${esc(note)}</div></div>`;
  }

  function categoryCard(cats, total) {
    const rows = cats.map((cat) => {
      const pct = total ? clamp((cat.bytes / total) * 100, 0, 100) : 0;
      return `<div class="list-row">
        <span style="width:22px;text-align:center">${esc(cat.icon || '•')}</span>
        <div class="grow">
          <div class="spread"><span class="cell-title">${esc(cat.label)}</span>
            <span class="mono">${bytes(cat.bytes)}</span></div>
          <div class="bar" style="margin-top:5px"><i style="width:${pct}%"></i></div>
          <div class="cell-sub">${num(cat.items)} finding(s) · ${num(cat.files)} file(s)</div>
        </div>
      </div>`;
    }).join('');
    return `<div class="card"><div class="card-head"><h2>Where the space is</h2>
      <span class="sub">by category</span></div><div class="list">${rows}</div></div>`;
  }

  function quickStartCard(status, job) {
    const online = (status.providers || []).filter((p) => p.online);
    const providerText = online.length
      ? online.map((p) => esc(p.label)).join(', ')
      : 'no local model host detected';
    const running = job && job.status === 'running';
    return `<div class="card">
      <div class="card-head"><h2>Get started</h2></div>
      <div class="card-body stack">
        <button class="btn btn-primary btn-block" data-act="scan-balanced">
          ${running ? 'Scan in progress…' : '🔎 Scan home directory'}
        </button>
        <button class="btn btn-block" data-act="goto-advisor">✦ Analyse with local AI</button>
        <button class="btn btn-ghost btn-block" data-act="goto-findings">🧾 Review findings</button>
        <div class="hint">AI provider: ${providerText}. Without one, DiskFree falls back to its
          deterministic rule engine — every feature still works.</div>
      </div>
    </div>`;
  }

  function folderCard(job) {
    const dirs = (job && job.dir_totals) || [];
    if (!dirs.length) {
      return `<div class="card"><div class="card-head"><h2>Biggest folders</h2></div>
        ${empty('📁', 'No folder data yet', 'Run a scan to rank your directories by size.')}</div>`;
    }
    const max = Math.max(...dirs.map((d) => d.bytes), 1);
    const rows = dirs.slice(0, 10).map((dir) => `
      <div class="list-row">
        <div class="grow">
          <div class="spread"><span class="path" title="${esc(dir.path)}">${esc(dir.path)}</span>
            <span class="mono nowrap">${bytes(dir.bytes)}</span></div>
          <div class="bar" style="margin-top:5px"><i style="width:${clamp((dir.bytes / max) * 100, 2, 100)}%"></i></div>
        </div>
      </div>`).join('');
    return `<div class="card"><div class="card-head"><h2>Biggest folders</h2>
      <span class="sub">depth ≤ 4</span></div><div class="list">${rows}</div></div>`;
  }

  function mountsCard(status) {
    const disks = ((status.disks && status.disks.disks) || []).filter((d) => !d.pseudo).slice(0, 6);
    if (!disks.length) return '';
    const rows = disks.map((disk) => `
      <div class="list-row">
        <div class="grow">
          <div class="spread"><span class="path">${esc(disk.mountpoint)}</span>
            <span class="mono nowrap">${bytes(disk.free)} free / ${bytes(disk.total)}</span></div>
          <div class="meter-track" style="margin-top:5px">
            <div class="meter-fill ${disk.percent > 90 ? 'danger' : disk.percent > 75 ? 'warn' : ''}"
                 style="width:${clamp(disk.percent, 0, 100)}%"></div>
          </div>
        </div>
      </div>`).join('');
    return `<div class="card"><div class="card-head"><h2>Volumes</h2></div><div class="list">${rows}</div></div>`;
  }

  function wireOverview(host) {
    host.addEventListener('click', (event) => {
      const button = event.target.closest('[data-act]');
      if (!button) return;
      const action = button.dataset.act;
      if (action === 'scan-balanced') { startScan({ preset: 'balanced' }); }
      if (action === 'goto-advisor') navigate('advisor');
      if (action === 'goto-findings') navigate('findings');
      if (action === 'goto-rules') navigate('rules');
      if (action === 'goto-safety') navigate('safety');
    }, { once: true });
  }

  // ------------------------------------------------------------------ scan
  async function renderScan(host) {
    if (!state.presets) {
      try { state.presets = await API.get('/api/presets'); } catch { state.presets = { presets: [], home: '' }; }
    }
    const presets = state.presets.presets || [];
    const home = state.presets.home || '';
    const job = state.job;

    host.innerHTML = `
      <div class="card">
        <div class="card-head"><h2>Scan preset</h2><span class="sub">read-only · nothing is modified</span></div>
        <div class="card-body">
          <div class="grid cols-3">
            ${presets.map((preset) => `
              <label class="stat" style="cursor:pointer;display:block">
                <input type="radio" name="preset" value="${esc(preset.id)}"
                  ${preset.id === 'balanced' ? 'checked' : ''} style="accent-color:var(--accent)">
                <strong style="margin-left:6px">${esc(preset.label)}</strong>
                <div class="note">${esc(preset.blurb)}</div>
              </label>`).join('')}
          </div>

          <div class="grid cols-2 mt">
            <label class="field"><span>Scan roots (one per line, ~ allowed)</span>
              <textarea id="scan-roots" rows="3" placeholder="${esc(home)}">${esc(home)}</textarea>
            </label>
            <div class="stack">
              <label class="switch"><input type="checkbox" id="opt-duplicates" checked>
                <span>Find duplicate files (hashes large files)</span></label>
              <label class="switch"><input type="checkbox" id="opt-large" checked>
                <span>List the largest files (information only)</span></label>
              <label class="switch"><input type="checkbox" id="opt-advisories" checked>
                <span>Report system space DiskFree will not touch</span></label>
              <label class="field"><span>Ignore findings smaller than (MB)</span>
                <input type="number" id="opt-minbytes" value="1" min="0" step="1"></label>
            </div>
          </div>

          <div class="grid cols-3 mt">
            <label class="field"><span>Temp files older than (days)</span>
              <input type="number" id="opt-temp-age" value="2" min="0" step="1"></label>
            <label class="field"><span>Logs older than (days)</span>
              <input type="number" id="opt-log-age" value="7" min="0" step="1"></label>
            <label class="field"><span>Old downloads after (days)</span>
              <input type="number" id="opt-old-age" value="90" min="1" step="1"></label>
          </div>
        </div>
        <div class="card-foot">
          <span class="hint">Scans run in a background thread and can be cancelled at any time.</span>
          <div class="row-gap">
            <button class="btn btn-ghost" id="btn-scan-cancel" ${job && job.status === 'running' ? '' : 'disabled'}>Cancel</button>
            <button class="btn btn-primary" id="btn-scan-start">🔎 Start scan</button>
          </div>
        </div>
      </div>

      <div id="scan-progress"></div>
      <div id="scan-result"></div>`;

    $('#btn-scan-start').addEventListener('click', () => {
      const preset = ($('input[name=preset]:checked') || {}).value || 'balanced';
      const roots = $('#scan-roots').value.split('\n').map((line) => line.trim()).filter(Boolean);
      startScan({
        preset,
        roots,
        find_duplicates: $('#opt-duplicates').checked,
        find_large_files: $('#opt-large').checked,
        include_advisories: $('#opt-advisories').checked,
        min_finding_bytes: Math.max(0, Number($('#opt-minbytes').value || 0)) * 1048576,
        temp_min_age_days: Number($('#opt-temp-age').value || 0),
        log_min_age_days: Number($('#opt-log-age').value || 0),
        old_file_min_age_days: Number($('#opt-old-age').value || 1),
      });
    });
    $('#btn-scan-cancel').addEventListener('click', cancelScan);
    paintScanProgress();
    paintScanResult();
  }

  async function startScan(payload) {
    try {
      const response = await API.post('/api/scan', payload);
      state.jobId = response.job.id;
      state.job = response.job;
      state.selection.clear();
      state.advice = null;
      state.plan = null;
      toast('Scan started', `Job ${response.job.id}`);
      if (state.view !== 'scan') navigate('scan');
      else { paintScanProgress(); }
      pollScan();
    } catch (error) {
      toast('Scan failed', error.message, 'err');
    }
  }

  async function cancelScan() {
    if (!state.jobId) return;
    try {
      const response = await API.post(`/api/scans/${encodeURIComponent(state.jobId)}/cancel`);
      toast('Cancelling', response.message, 'warn');
    } catch (error) {
      toast('Cancel failed', error.message, 'err');
    }
  }

  function pollScan() {
    if (state.scanTimer) clearInterval(state.scanTimer);
    const tick = async () => {
      if (!state.jobId) return;
      try {
        const job = await API.get(`/api/scans/${encodeURIComponent(state.jobId)}`);
        state.job = job;
        updateBadges();
        paintScanProgress();
        if (job.status === 'running' || job.status === 'queued') {
          if (state.view === 'overview') renderOverview($('#view-overview'));
          return;
        }
        clearInterval(state.scanTimer);
        state.scanTimer = null;
        paintScanResult();
        await loadFindings();
        if (job.status === 'completed') {
          toast('Scan complete',
            `${num(job.findings || 0)} findings · ${bytes(job.actionable_bytes || 0)} reclaimable`);
          $('#pill-scan').hidden = true;
        } else if (job.status === 'cancelled') {
          toast('Scan cancelled', `${num(job.findings || 0)} findings collected so far`, 'warn');
        } else if (job.status === 'failed') {
          toast('Scan failed', job.error || 'Unknown error', 'err');
        }
        if (state.view === 'overview') renderOverview($('#view-overview'));
        if (state.view === 'findings') renderFindings($('#view-findings'));
      } catch (error) {
        clearInterval(state.scanTimer);
        state.scanTimer = null;
        toast('Lost track of the scan', error.message, 'err');
      }
    };
    tick();
    state.scanTimer = setInterval(tick, 900);
  }

  function paintScanProgress() {
    const host = $('#scan-progress');
    if (!host) return;
    const job = state.job;
    if (!job || (!job.progress && job.status === 'completed')) { host.innerHTML = ''; return; }
    const progress = job.progress || {};
    const running = job.status === 'running' || job.status === 'queued';
    const stats = job.stats || {};
    host.innerHTML = `
      <div class="card">
        <div class="card-head">
          <h2>${running ? 'Scanning…' : `Scan ${esc(job.status)}`}</h2>
          <span class="sub">${esc(progress.phase || job.status || '')} · ${esc(progress.message || '')}</span>
        </div>
        <div class="card-body">
          <div class="progress ${running ? 'indeterminate' : ''}"><i style="width:${running ? 0 : 100}%"></i></div>
          <div class="grid cols-4 mt">
            ${statCard('Directories', num(progress.dirs || 0), `${num(stats.pruned_dirs || 0)} pruned`)}
            ${statCard('Files', num(progress.files || 0), `${num(stats.symlinks_skipped || 0)} symlinks skipped`)}
            ${statCard('Seen so far', bytes(progress.bytes || 0), stats.entries_per_second ? `${num(stats.entries_per_second)} entries/s` : '')}
            ${statCard('Findings', num(job.findings || 0), bytes(job.actionable_bytes || 0) + ' reclaimable')}
          </div>
          ${progress.current ? `<div class="logbox mt">${esc(progress.current)}</div>` : ''}
          ${(job.errors || []).length ? `<div class="notice warn mt"><strong>Read errors</strong>
            <ul>${job.errors.slice(0, 5).map((e) => `<li class="mono">${esc(e)}</li>`).join('')}</ul></div>` : ''}
        </div>
      </div>`;
    $('#pill-scan').hidden = !running;
    $('#pill-scan').textContent = running ? `scanning · ${esc(progress.phase || '')}` : '';
    const cancel = $('#btn-scan-cancel');
    if (cancel) cancel.disabled = !running;
  }

  function paintScanResult() {
    const host = $('#scan-result');
    if (!host) return;
    const job = state.job;
    if (!job || job.status === 'running' || job.status === 'queued') { host.innerHTML = ''; return; }
    const warnings = job.warnings || [];
    host.innerHTML = `
      ${warnings.length ? `<div class="notice warn mb"><strong>Scan notes</strong>
        <ul>${warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul></div>` : ''}
      <div class="grid cols-2">
        ${folderCard(job)}
        ${mountsCard({ disks: { disks: job.mounts || [] } })}
      </div>
      <div class="row-gap mt">
        <button class="btn btn-primary" data-nav="findings">🧾 Review ${num(job.findings || 0)} findings</button>
        <button class="btn" data-nav="advisor">✦ Analyse with AI</button>
      </div>`;
    host.querySelectorAll('[data-nav]').forEach((button) => {
      button.addEventListener('click', () => navigate(button.dataset.nav));
    });
  }

  // -------------------------------------------------------------- findings
  async function loadFindings() {
    if (!state.jobId) return;
    const filters = state.filters;
    const params = new URLSearchParams({
      sort: filters.sort,
      limit: '1000',
      include_members: 'false',
    });
    if (filters.categories.size) params.set('category', [...filters.categories].join(','));
    if (filters.risks.size) params.set('risk', [...filters.risks].join(','));
    if (filters.q) params.set('q', filters.q);
    if (filters.minBytes) params.set('min_bytes', String(filters.minBytes));
    if (filters.onlySelectable) params.set('actionable', 'true');
    const data = await API.get(`/api/scans/${encodeURIComponent(state.jobId)}/findings?${params}`);
    state.findings = data.findings || [];
    state.findingMeta = data;
    state.findingIndex = new Map(state.findings.map((item) => [item.id, item]));
    // Drop selections that no longer exist (new scan, filter change).
    for (const id of [...state.selection]) {
      if (!state.findingIndex.has(id)) state.selection.delete(id);
    }
    updateBadges();
  }

  async function renderFindings(host) {
    if (!state.jobId) {
      host.innerHTML = empty('🧾', 'No scan yet',
        'Findings appear after a scan. DiskFree only reads your disk during a scan.',
        '<button class="btn btn-primary" data-nav="scan">Start a scan</button>');
      host.querySelector('[data-nav]').addEventListener('click', () => navigate('scan'));
      return;
    }
    host.innerHTML = spinner('Loading findings…');
    await loadFindings();
    paintFindings(host);
  }

  function paintFindings(host) {
    const meta = state.findingMeta || {};
    const categories = meta.categories || [];
    const findings = state.findings;
    const selected = [...state.selection];
    const selectedBytes = selected.reduce((sum, id) => sum + (state.findingIndex.get(id)?.bytes || 0), 0);
    const adviceMap = state.advice ? new Map((state.advice.items || []).map((i) => [i.finding_id, i])) : null;

    host.innerHTML = `
      <div class="card">
        <div class="card-head">
          <h2>${num(meta.total || 0)} findings</h2>
          <span class="sub">${bytes(meta.total_bytes || 0)} shown · risk summary
            ${meta.risk_summary ? `· ${bytes(meta.risk_summary.safe || 0)} safe` : ''}</span>
        </div>
        <div class="card-body tight">
          <div class="row-gap mb">
            <span class="faint" style="font-size:11.5px">CATEGORY</span>
            ${categories.map((cat) => `<button class="chip ${state.filters.categories.has(cat.category) ? 'is-on' : ''}"
              data-cat="${esc(cat.category)}" title="${esc(cat.blurb)}">${esc(cat.icon)} ${esc(cat.label)}</button>`).join('')}
          </div>
          <div class="row-gap mb">
            <span class="faint" style="font-size:11.5px">RISK</span>
            ${['safe', 'low', 'medium', 'high', 'forbidden'].map((risk) => `
              <button class="chip ${state.filters.risks.has(risk) ? 'is-on' : ''}" data-risk="${risk}">
                <span class="risk risk-${risk}">${risk}</span></button>`).join('')}
            <label class="switch" style="margin-left:8px"><input type="checkbox" id="filter-actionable"
              ${state.filters.onlySelectable ? 'checked' : ''}><span>Actionable only</span></label>
          </div>
          <div class="row-gap">
            <input type="text" id="filter-q" placeholder="Filter by path, title or rule…" value="${esc(state.filters.q)}" style="min-width:230px;flex:1">
            <select id="filter-sort">
              ${[['bytes', 'Largest first'], ['risk', 'Riskiest first'], ['age', 'Oldest first'],
                 ['category', 'By category'], ['path', 'By path']]
                .map(([value, label]) => `<option value="${value}" ${state.filters.sort === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
            </select>
            <select id="filter-min">
              ${[[0, 'Any size'], [1048576, '≥ 1 MB'], [104857600, '≥ 100 MB'], [1073741824, '≥ 1 GB']]
                .map(([value, label]) => `<option value="${value}" ${String(state.filters.minBytes) === String(value) ? 'selected' : ''}>${esc(label)}</option>`).join('')}
            </select>
            <span style="flex:1"></span>
            <button class="btn btn-sm" id="btn-select-safe">Select all safe</button>
            <button class="btn btn-sm" id="btn-select-advice" ${adviceMap ? '' : 'disabled'}>Apply AI selection</button>
            <button class="btn btn-sm btn-ghost" id="btn-clear-selection">Clear</button>
          </div>
        </div>
      </div>

      ${findings.length ? findingsTable(findings, adviceMap) : empty('🔍', 'Nothing matches those filters',
        'Loosen the filters, or run a deeper scan from the Scan view.')}

      <div class="sticky-foot">
        <div>
          <strong>${num(selected.length)}</strong> <span class="dim">item(s) selected</span>
          <span class="mono" style="margin-left:10px">${bytes(selectedBytes)}</span>
          <span class="dim">to reclaim</span>
        </div>
        <div class="row-gap">
          <button class="btn btn-ghost" id="btn-dry-run" ${selected.length ? '' : 'disabled'}>Dry run</button>
          <button class="btn btn-primary" id="btn-make-plan" ${selected.length ? '' : 'disabled'}>
            🧹 Create clean plan</button>
        </div>
      </div>`;

    wireFindings(host);
  }

  function findingsTable(findings, adviceMap) {
    const maxBytes = Math.max(...findings.map((f) => f.bytes), 1);
    const rows = findings.map((finding) => {
      const advice = adviceMap ? adviceMap.get(finding.id) : null;
      const checked = state.selection.has(finding.id);
      const pct = clamp((finding.bytes / maxBytes) * 100, 1.5, 100);
      const selectable = finding.selectable;
      return `<tr class="${checked ? 'is-selected' : ''}" data-id="${esc(finding.id)}">
        <td style="width:34px">
          <input type="checkbox" data-check="${esc(finding.id)}" ${checked ? 'checked' : ''}
            ${selectable ? '' : 'disabled title="DiskFree will not remove this"'}>
        </td>
        <td style="width:88px"><span class="risk risk-${esc(finding.risk)}">${esc(finding.risk)}</span></td>
        <td>
          <div class="cell-title">${esc(finding.title)}</div>
          <div class="path" title="${esc(finding.path)}">${esc(finding.path)}</div>
          <div class="cell-sub">
            ${esc(finding.category.replace('_', ' '))} · rule <span class="mono">${esc(finding.rule_id)}</span>
            ${finding.files ? `· ${num(finding.files)} file(s)` : ''}
            ${finding.age_days ? `· ${esc(days(finding.age_days))} old` : ''}
            ${advice ? `· <span class="act act-${esc(advice.action)}">${esc(advice.action)}</span>` : ''}
            ${finding.advisory ? `· <span class="act act-manual">manual</span>` : ''}
          </div>
        </td>
        <td class="num" style="width:110px">
          <div class="mono">${bytes(finding.bytes)}</div>
          <div class="bar" style="margin-top:4px"><i style="width:${pct}%"></i></div>
        </td>
        <td style="width:64px" class="right">
          <button class="icon-btn" data-info="${esc(finding.id)}" title="Details">ⓘ</button>
        </td>
      </tr>`;
    }).join('');
    return `<div class="card"><div class="table-wrap"><table class="table">
      <thead><tr><th></th><th>Risk</th><th>Finding</th><th class="num">Size</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table></div></div>`;
  }

  function wireFindings(host) {
    host.querySelectorAll('[data-cat]').forEach((chip) => chip.addEventListener('click', () => {
      toggleSet(state.filters.categories, chip.dataset.cat);
      renderFindings($('#view-findings'));
    }));
    host.querySelectorAll('[data-risk]').forEach((chip) => chip.addEventListener('click', () => {
      toggleSet(state.filters.risks, chip.dataset.risk);
      renderFindings($('#view-findings'));
    }));
    const actionable = $('#filter-actionable');
    if (actionable) actionable.addEventListener('change', () => {
      state.filters.onlySelectable = actionable.checked;
      renderFindings($('#view-findings'));
    });
    const sortSelect = $('#filter-sort');
    if (sortSelect) sortSelect.addEventListener('change', () => {
      state.filters.sort = sortSelect.value;
      renderFindings($('#view-findings'));
    });
    const minSelect = $('#filter-min');
    if (minSelect) minSelect.addEventListener('change', () => {
      state.filters.minBytes = Number(minSelect.value);
      renderFindings($('#view-findings'));
    });
    const search = $('#filter-q');
    if (search) {
      let timer = null;
      search.addEventListener('input', () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          state.filters.q = search.value.trim();
          renderFindings($('#view-findings'));
          const again = $('#filter-q');
          if (again) { again.focus(); again.setSelectionRange(again.value.length, again.value.length); }
        }, 320);
      });
    }

    host.querySelectorAll('[data-check]').forEach((box) => box.addEventListener('change', () => {
      const id = box.dataset.check;
      if (box.checked) state.selection.add(id); else state.selection.delete(id);
      const row = box.closest('tr');
      if (row) row.classList.toggle('is-selected', box.checked);
      updateSelectionFooter();
    }));

    host.querySelectorAll('[data-info]').forEach((button) => button.addEventListener('click', () => {
      showFinding(button.dataset.info);
    }));

    const selectSafe = $('#btn-select-safe');
    if (selectSafe) selectSafe.addEventListener('click', () => {
      state.findings.forEach((finding) => {
        if (finding.selectable && finding.default_selected) state.selection.add(finding.id);
      });
      paintFindings($('#view-findings'));
      toast('Selected safe items', `${state.selection.size} item(s) ticked`);
    });

    const selectAdvice = $('#btn-select-advice');
    if (selectAdvice) selectAdvice.addEventListener('click', () => {
      const ids = (state.advice && state.advice.clean_ids) || [];
      ids.forEach((id) => { if (state.findingIndex.has(id)) state.selection.add(id); });
      paintFindings($('#view-findings'));
      toast('AI selection applied', `${ids.length} recommendation(s) ticked — medium and high risk items are never auto-selected`);
    });

    const clear = $('#btn-clear-selection');
    if (clear) clear.addEventListener('click', () => {
      state.selection.clear();
      paintFindings($('#view-findings'));
    });

    const planButton = $('#btn-make-plan');
    if (planButton) planButton.addEventListener('click', () => createPlan('trash'));
    const dryButton = $('#btn-dry-run');
    if (dryButton) dryButton.addEventListener('click', () => createPlan('dry_run'));
  }

  function toggleSet(set, value) {
    if (set.has(value)) set.delete(value); else set.add(value);
  }

  function updateSelectionFooter() {
    const selectedBytes = [...state.selection]
      .reduce((sum, id) => sum + (state.findingIndex.get(id)?.bytes || 0), 0);
    const foot = $('.sticky-foot');
    if (!foot) return;
    foot.querySelector('strong').textContent = num(state.selection.size);
    const mono = foot.querySelector('.mono');
    if (mono) mono.textContent = bytes(selectedBytes);
    ['#btn-make-plan', '#btn-dry-run'].forEach((selector) => {
      const button = $(selector);
      if (button) button.disabled = state.selection.size === 0;
    });
    updateBadges();
  }

  function showFinding(id) {
    const finding = state.findingIndex.get(id);
    if (!finding) return;
    const advice = state.advice && (state.advice.items || []).find((item) => item.finding_id === id);
    modal(finding.title, `
      <dl class="kv">
        <dt>Path</dt><dd>${esc(finding.path)}</dd>
        <dt>Size</dt><dd>${bytes(finding.bytes)} (${num(finding.bytes)} bytes)</dd>
        <dt>Files</dt><dd>${num(finding.files)}</dd>
        <dt>Category</dt><dd>${esc(finding.category)}</dd>
        <dt>Rule</dt><dd>${esc(finding.rule_id)}</dd>
        <dt>Risk</dt><dd><span class="risk risk-${esc(finding.risk)}">${esc(finding.risk)}</span>
          ${finding.default_selected ? '· pre-selectable' : '· never pre-selected'}</dd>
        <dt>Age</dt><dd>${esc(days(finding.age_days))}</dd>
        <dt>Actionable</dt><dd>${finding.actionable ? 'yes' : 'no — advisory only'}</dd>
      </dl>
      <div class="notice mt">${esc(finding.description)}</div>
      ${finding.extra && finding.extra.tier_reason ? `<div class="notice warn mt">
        <strong>Safety policy:</strong> ${esc(finding.extra.tier_reason)}</div>` : ''}
      ${finding.advisory ? `<div class="mt"><div class="hint">DiskFree will not run this. Copy it and run it yourself:</div>
        <div class="cmd mt"><span>${esc(finding.advisory)}</span>
        <button class="btn btn-sm" data-copy="${esc(finding.advisory)}">Copy</button></div></div>` : ''}
      ${advice ? `<div class="notice ok mt"><strong>Advisor:</strong>
        <span class="act act-${esc(advice.action)}">${esc(advice.action)}</span>
        ${esc(advice.reason)}<br><span class="hint">confidence
        ${(Number(advice.confidence) * 100).toFixed(0)}%${advice.escalated ? ' · risk raised from ' + esc(advice.risk_original) : ''}${advice.action_downgraded ? ' · action downgraded by guardrails' : ''}</span></div>` : ''}
      ${(finding.members || []).length ? `<div class="mt"><div class="hint">Largest contents</div>
        <div class="logbox mt">${finding.members.slice(0, 20).map((m) => `${bytes(m.bytes).padStart(9)}  ${esc(m.path)}`).join('\n')}</div></div>` : ''}
    `, '<button class="btn btn-ghost" value="cancel">Close</button>');
    const copy = $('#modal-body [data-copy]');
    if (copy) copy.addEventListener('click', () => copyText(copy.dataset.copy, copy));
  }

  function copyText(text, button) {
    const done = () => {
      if (!button) return;
      const original = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = original; }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, done) {
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); done(); } catch { toast('Copy failed', 'Select the text manually', 'warn'); }
    area.remove();
  }

  // --------------------------------------------------------------- advisor
  async function renderAdvisor(host) {
    if (!state.providers.length) {
      try {
        const data = await API.get('/api/providers');
        state.providers = data.providers || [];
        state.providerMeta = data;
      } catch (error) {
        host.innerHTML = errorCard(error);
        return;
      }
    }
    const providers = state.providers;
    const advice = state.advice;
    const hasJob = Boolean(state.jobId);

    host.innerHTML = `
      <div class="card">
        <div class="card-head"><h2>Local model hosts</h2>
          <button class="btn btn-sm btn-ghost" id="btn-refresh-providers">↻ Re-check</button></div>
        <div class="card-body">
          <div class="grid cols-3">
            ${providers.map((provider) => providerCard(provider)).join('')}
            ${offlineCard()}
          </div>
          <div class="notice mt">Advice never leaves this machine. DiskFree sends
            <strong>metadata only</strong> — paths, sizes, ages and categories — never file contents,
            and never your username (the home directory is written as <span class="mono">~</span>).</div>
        </div>
        <div class="card-foot">
          <div class="row-gap">
            <label class="field" style="min-width:220px"><span>Model (optional override)</span>
              <input type="text" id="advise-model" placeholder="auto" value="${esc(state.adviceModel || '')}"></label>
            <label class="switch" style="margin-top:18px"><input type="checkbox" id="advise-use-model" checked>
              <span>Use a model (otherwise the offline rule engine answers)</span></label>
          </div>
          <button class="btn btn-primary" id="btn-run-advice" ${hasJob ? '' : 'disabled'}>
            ✦ ${advice ? 'Re-analyse' : 'Analyse scan'}</button>
        </div>
      </div>
      <div id="advice-out">${advice ? adviceHtml(advice) : (hasJob
        ? empty('✦', 'No advice yet', 'Ask a local model — or the offline rule engine — to interpret this scan.',
            '<button class="btn btn-primary" id="btn-run-advice-2">Analyse now</button>')
        : empty('🔎', 'Scan first', 'Advice is generated from a scan. Run one from the Scan view.',
            '<button class="btn" data-nav="scan">Go to Scan</button>'))}</div>`;

    const run = () => runAdvice();
    const b1 = $('#btn-run-advice'); if (b1) b1.addEventListener('click', run);
    const b2 = $('#btn-run-advice-2'); if (b2) b2.addEventListener('click', run);
    const refresh = $('#btn-refresh-providers');
    if (refresh) refresh.addEventListener('click', async () => {
      state.providers = [];
      await renderAdvisor($('#view-advisor'));
      toast('Providers re-checked');
    });
    host.querySelectorAll('[data-provider]').forEach((card) => {
      card.addEventListener('click', () => {
        state.providerChoice = card.dataset.provider;
        host.querySelectorAll('[data-provider]').forEach((other) => other.classList.remove('is-chosen'));
        card.classList.add('is-chosen');
      });
    });
    const nav = host.querySelector('[data-nav]');
    if (nav) nav.addEventListener('click', () => navigate(nav.dataset.nav));
    if (state.providerChoice) {
      const chosen = host.querySelector(`[data-provider="${state.providerChoice}"]`);
      if (chosen) chosen.classList.add('is-chosen');
    }
  }

  function providerCard(provider) {
    const tone = provider.status === 'online' ? 'ok' : provider.status === 'degraded' ? 'warn' : 'err';
    return `<div class="stat" data-provider="${esc(provider.name)}" style="cursor:pointer">
      <div class="spread">
        <div class="label">${esc(provider.label)}</div>
        <span class="pill ${tone}"><span class="dot"></span>${esc(provider.status)}</span>
      </div>
      <div class="value small" style="margin-top:6px">${esc(provider.base_url)}</div>
      <div class="note">${esc(provider.detail || '')}</div>
      <div class="note faint">${provider.models && provider.models.length
        ? `${provider.models.length} model(s): ${esc(provider.models.slice(0, 3).join(', '))}`
        : 'no models listed'}</div>
      ${provider.latency_ms ? `<div class="note faint">${provider.latency_ms.toFixed(0)} ms · key ${provider.api_key_set ? 'set' : 'not set'}</div>` : ''}
      ${provider.hint && provider.status !== 'online' ? `<div class="hint mt">${esc(provider.hint)}</div>` : ''}
    </div>`;
  }

  function offlineCard() {
    return `<div class="stat" data-provider="heuristic" style="cursor:pointer">
      <div class="spread"><div class="label">Rule engine (offline)</div>
        <span class="pill ok"><span class="dot"></span>always on</span></div>
      <div class="value small" style="margin-top:6px">deterministic</div>
      <div class="note">DiskFree's own scoring of every finding. No model required, fully
        reproducible, and it is also the fallback when a model host is down.</div>
    </div>`;
  }

  async function runAdvice() {
    if (!state.jobId) { toast('Scan first', 'Advice needs a completed scan', 'warn'); return; }
    const out = $('#advice-out');
    if (out) out.innerHTML = `<div class="card"><div class="card-body">${spinner('Asking the local model…')}</div></div>`;
    const button = $('#btn-run-advice');
    if (button) button.disabled = true;
    const useModel = ($('#advise-use-model') || {}).checked !== false;
    const model = ($('#advise-model') || {}).value || '';
    state.adviceModel = model;
    const provider = state.providerChoice || 'auto';
    try {
      const advice = await API.post('/api/advise', {
        job_id: state.jobId,
        provider: provider === 'heuristic' ? 'heuristic' : provider,
        model: model || null,
        use_model: useModel && provider !== 'heuristic',
      });
      state.advice = advice;
      state.adviceJobId = state.jobId;
      paintAdvice(advice);
      const engine = advice.engine === 'heuristic' ? 'offline rule engine' : `${advice.engine}${advice.model ? ' · ' + advice.model : ''}`;
      toast('Advice ready', `${engine} · ${num((advice.items || []).length)} recommendations`,
        advice.fallback_used ? 'warn' : 'ok');
    } catch (error) {
      if (out) out.innerHTML = errorCard(error);
      toast('Advice failed', error.message, 'err');
    } finally {
      if (button) button.disabled = false;
    }
  }

  function paintAdvice(advice) {
    const out = $('#advice-out');
    if (out) out.innerHTML = adviceHtml(advice);
    wireAdvice(out || document);
  }

  function adviceHtml(advice) {
    const items = advice.items || [];
    const totals = advice.totals || {};
    const guardrails = advice.guardrails || [];
    const cleanBytes = items.filter((i) => i.action === 'clean').reduce((s, i) => s + i.bytes, 0);
    const reviewBytes = items.filter((i) => i.action === 'review').reduce((s, i) => s + i.bytes, 0);
    const grouped = {};
    items.forEach((item) => { (grouped[item.action] = grouped[item.action] || []).push(item); });
    const order = ['clean', 'review', 'manual', 'keep'];

    return `
      ${advice.error ? `<div class="notice ${advice.fallback_used ? 'warn' : 'danger'} mb">
        <strong>${advice.fallback_used ? 'Model unavailable — offline rule engine answered' : 'Advice error'}.</strong>
        <p>${esc(advice.error)}</p>${advice.error_hint ? `<p class="hint">${esc(advice.error_hint)}</p>` : ''}</div>` : ''}

      <div class="card">
        <div class="card-head">
          <h2>${esc(advice.headline || 'Analysis')}</h2>
          <span class="sub">${esc(advice.engine)}${advice.model ? ' · ' + esc(advice.model) : ''}
            ${advice.latency_ms ? `· ${advice.latency_ms.toFixed(0)} ms` : ''}
            ${advice.est_tokens ? `· ~${num(advice.est_tokens)} tokens` : ''}</span>
        </div>
        <div class="card-body">
          <p style="margin:0 0 12px">${esc(advice.summary || '')}</p>
          <div class="grid cols-4">
            ${statCard('Recommended', bytes(cleanBytes), `${num((totals.clean || {}).items || 0)} item(s)`, 'accent')}
            ${statCard('For your review', bytes(reviewBytes), `${num((totals.review || {}).items || 0)} item(s)`)}
            ${statCard('Manual steps', num((advice.manual_steps || []).length), 'commands DiskFree will not run')}
            ${statCard('Guardrails', num(guardrails.length), 'model corrections applied')}
          </div>
          ${(advice.quick_wins || []).length ? `<div class="notice ok mt"><strong>Quick wins</strong>
            <ul>${advice.quick_wins.map((w) => `<li>${esc(w)}</li>`).join('')}</ul></div>` : ''}
          ${(advice.warnings || []).length ? `<div class="notice warn mt"><strong>Before you clean</strong>
            <ul>${advice.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul></div>` : ''}
        </div>
        <div class="card-foot">
          <span class="hint">Only safe and low risk items are ever pre-selected, whatever the model said.</span>
          <div class="row-gap">
            <button class="btn btn-ghost" id="btn-advice-goto">🧾 See in findings</button>
            <button class="btn btn-primary" id="btn-advice-apply">Apply selection & plan</button>
          </div>
        </div>
      </div>

      ${(advice.manual_steps || []).length ? `<div class="card">
        <div class="card-head"><h2>Do these yourself</h2>
          <span class="sub">DiskFree never runs shell commands</span></div>
        <div class="card-body stack">
          ${advice.manual_steps.map((step) => `<div class="cmd"><span>${esc(step)}</span>
            <button class="btn btn-sm" data-copy="${esc(step)}">Copy</button></div>`).join('')}
        </div></div>` : ''}

      ${guardrails.length ? `<div class="card">
        <div class="card-head"><h2>Guardrail log</h2>
          <span class="sub">where DiskFree overruled the model</span></div>
        <div class="card-body tight">
          <div class="list">${guardrails.map((event) => `
            <div class="list-row">
              <span class="act ${guardTone(event.kind)}">${esc(event.kind.replace(/_/g, ' '))}</span>
              <div class="grow"><div>${esc(event.message)}</div>
                ${event.detail ? `<div class="cell-sub mono">${esc(event.detail)}</div>` : ''}</div>
            </div>`).join('')}</div>
        </div></div>` : ''}

      ${order.filter((action) => grouped[action] && grouped[action].length).map((action) => `
        <div class="card">
          <div class="card-head"><h2><span class="act act-${action}">${action}</span>
            <span class="sub" style="margin-left:8px">${num(grouped[action].length)} item(s)</span></h2></div>
          <div class="table-wrap"><table class="table">
            <thead><tr><th>Risk</th><th>Item</th><th>Why</th><th class="num">Size</th><th class="num">Conf.</th></tr></thead>
            <tbody>${grouped[action].sort((a, b) => b.bytes - a.bytes).slice(0, 120).map((item) => `
              <tr>
                <td><span class="risk risk-${esc(item.risk)}">${esc(item.risk)}</span>
                  ${item.escalated ? `<div class="cell-sub">was ${esc(item.risk_original)}</div>` : ''}</td>
                <td><div class="cell-title">${esc(item.title)}</div>
                  <div class="path" title="${esc(item.path)}">${esc(item.path)}</div></td>
                <td class="dim" style="max-width:38ch">${esc(item.reason)}
                  ${item.action_downgraded ? '<div class="cell-sub">↓ downgraded by guardrails</div>' : ''}</td>
                <td class="num mono">${bytes(item.bytes)}</td>
                <td class="num mono">${(Number(item.confidence) * 100).toFixed(0)}%</td>
              </tr>`).join('')}</tbody>
          </table></div>
        </div>`).join('')}`;
  }

  function guardTone(kind) {
    if (kind === 'dangerous_command' || kind === 'unknown_id' || kind === 'not_actionable') return 'act-keep';
    if (kind === 'high_risk_needs_review' || kind === 'risk_clamped') return 'act-review';
    return 'act-manual';
  }

  function wireAdvice(root) {
    root.querySelectorAll('[data-copy]').forEach((button) => {
      button.addEventListener('click', () => copyText(button.dataset.copy, button));
    });
    const goto = $('#btn-advice-goto');
    if (goto) goto.addEventListener('click', () => navigate('findings'));
    const apply = $('#btn-advice-apply');
    if (apply) apply.addEventListener('click', async () => {
      const ids = (state.advice && state.advice.clean_ids) || [];
      if (!ids.length) { toast('Nothing to apply', 'The advisor did not mark anything as safe to clean', 'warn'); return; }
      state.selection = new Set(ids);
      await createPlan('trash', { finding_ids: ids });
    });
  }

  // ----------------------------------------------------------------- clean
  async function createPlan(mode, override = {}) {
    if (!state.jobId) { toast('Scan first', 'A plan needs scan findings', 'warn'); return; }
    const ids = override.finding_ids || [...state.selection];
    if (!ids.length) { toast('Nothing selected', 'Tick items in Findings first', 'warn'); return; }
    navigate('clean');
    const host = $('#view-clean');
    host.innerHTML = `<div class="card"><div class="card-body">${spinner('Validating every path against the safety policy…')}</div></div>`;
    try {
      const plan = await API.post('/api/clean/plan', { job_id: state.jobId, finding_ids: ids, mode });
      state.plan = plan;
      state.acknowledged = false;
      paintPlan(host);
      if (plan.refused_count) {
        toast('Some items refused', `${plan.refused_count} item(s) are protected and will not be touched`, 'warn');
      }
    } catch (error) {
      host.innerHTML = errorCard(error);
      toast('Plan failed', error.message, 'err');
    }
  }

  function paintPlan(host) {
    const plan = state.plan;
    if (!plan) { renderClean(host); return; }
    const items = plan.items || [];
    const refused = plan.refused || [];
    const maxBytes = Math.max(...items.map((i) => i.bytes), 1);
    const isDry = plan.mode === 'dry_run';
    const isPermanent = plan.mode === 'permanent';

    host.innerHTML = `
      <div class="card">
        <div class="card-head">
          <h2>${isDry ? 'Dry run' : isPermanent ? 'Permanent deletion plan' : 'Clean plan'}</h2>
          <span class="sub">plan ${esc(plan.id)} · expires in ${num(plan.expires_in_seconds)}s</span>
        </div>
        <div class="card-body">
          <div class="grid cols-4">
            ${statCard('Items', num(plan.item_count), `${num(plan.total_files)} file(s)`)}
            ${statCard('Reclaiming', bytes(plan.total_bytes), plan.mode, 'accent')}
            ${statCard('Refused', num(plan.refused_count), 'protected by policy', refused.length ? '' : '')}
            ${statCard('By risk', Object.keys(plan.by_risk || {}).length ? Object.entries(plan.by_risk)
              .map(([risk, value]) => `${risk}: ${value.items}`).join(' · ') : '—', 'risk mix')}
          </div>
          <div class="notice ${isPermanent ? 'danger' : 'ok'} mt">
            <strong>${esc(plan.note)}</strong>
            ${isPermanent ? '<p>Permanent deletion cannot be undone. This mode is only available when the server was started with DISKFREE_ALLOW_PERMANENT_DELETE=1.</p>' : ''}
          </div>
          ${refused.length ? `<div class="notice warn mt"><strong>Refused by the safety policy</strong>
            <ul>${refused.slice(0, 12).map((item) => `<li><span class="mono">${esc(item.path || item.finding_id)}</span>
              — ${esc(item.reason || 'blocked')}</li>`).join('')}</ul></div>` : ''}
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Every item in this plan</h2>
          <span class="sub">nothing here was chosen by a model alone</span></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Risk</th><th>Path</th><th>Title</th><th class="num">Files</th><th class="num">Size</th></tr></thead>
          <tbody>${items.sort((a, b) => b.bytes - a.bytes).slice(0, 800).map((item) => `
            <tr>
              <td><span class="risk risk-${esc(item.risk)}">${esc(item.risk)}</span></td>
              <td><div class="path" title="${esc(item.path)}">${esc(item.path)}</div>
                <div class="bar" style="margin-top:4px;width:110px"><i style="width:${clamp((item.bytes / maxBytes) * 100, 2, 100)}%"></i></div></td>
              <td class="dim">${esc(item.title)}</td>
              <td class="num mono">${num(item.files)}</td>
              <td class="num mono">${bytes(item.bytes)}</td>
            </tr>`).join('')}
          </tbody></table></div>
        ${items.length > 800 ? `<div class="card-foot"><span class="hint">Showing the 800 largest of ${num(items.length)} items.</span></div>` : ''}
      </div>

      ${isDry ? `<div class="card"><div class="card-body spread">
          <span class="dim">Dry run: nothing was modified.</span>
          <div class="row-gap">
            <button class="btn btn-ghost" data-nav="findings">Back to findings</button>
            <button class="btn btn-primary" id="btn-plan-real">Plan a real clean</button>
          </div></div></div>`
        : `<div class="card">
          <div class="card-head"><h2>Confirm</h2></div>
          <div class="card-body stack">
            <label class="switch"><input type="checkbox" id="ack">
              <span>I have reviewed all ${num(plan.item_count)} item(s).
                ${bytes(plan.total_bytes)} will be moved to the ${isPermanent ? 'permanent delete queue' : 'trash'} and can be restored from History.</span></label>
            <div class="row-gap">
              <button class="btn btn-ghost" data-nav="findings">Cancel</button>
              <button class="btn ${isPermanent ? 'btn-danger' : 'btn-primary'}" id="btn-execute" disabled>
                ${isPermanent ? 'Permanently delete' : '🧹 Move to trash'}</button>
            </div>
            <div class="hint">The confirm token is bound to this exact item list, mode and expiry.
              Change anything and it becomes invalid.</div>
          </div></div>`}
      <div id="clean-result">${state.lastReport ? reportHtml(state.lastReport) : ''}</div>`;

    host.querySelectorAll('[data-nav]').forEach((button) => {
      button.addEventListener('click', () => navigate(button.dataset.nav));
    });
    const real = $('#btn-plan-real');
    if (real) real.addEventListener('click', () => createPlan('trash'));
    const ack = $('#ack');
    const execute = $('#btn-execute');
    if (ack && execute) {
      ack.addEventListener('change', () => { execute.disabled = !ack.checked; state.acknowledged = ack.checked; });
      execute.addEventListener('click', executePlan);
    }
  }

  async function executePlan() {
    const plan = state.plan;
    if (!plan) return;
    const button = $('#btn-execute');
    if (button) { button.disabled = true; button.innerHTML = '<span class="spinner"></span> Moving…'; }
    try {
      const report = await API.post('/api/clean/execute', {
        plan_id: plan.id,
        confirm_token: plan.confirm_token,
        expected_bytes: plan.total_bytes,
      });
      state.lastReport = report;
      state.plan = null;
      report.skipped.forEach((item) => state.selection.delete(item.finding_id));
      toast(report.ok_count ? 'Cleaned' : 'Nothing removed',
        `${num(report.ok_count)} item(s) · ${bytes(report.bytes)} reclaimed${report.failed_count ? ` · ${num(report.failed_count)} skipped` : ''}`,
        report.failed_count ? 'warn' : 'ok', 8000);
      const host = $('#view-clean');
      if (host) {
        const result = $('#clean-result');
        if (result) result.innerHTML = reportHtml(report);
        else renderClean(host);
        wireReport(host);
      }
      await Promise.all([refreshStatus(), loadFindings().catch(() => {})]);
      updateBadges();
    } catch (error) {
      toast('Clean failed', error.message + (error.hint ? ` — ${error.hint}` : ''), 'err', 9000);
      if (button) { button.disabled = false; button.textContent = '🧹 Move to trash'; }
    }
  }

  function reportHtml(report) {
    const skipped = report.skipped || [];
    const moved = (report.moved || []).filter((item) => item.ok);
    return `<div class="card">
      <div class="card-head"><h2>${report.mode === 'restore' ? 'Restore result' : 'Operation result'}</h2>
        <span class="sub">${esc(report.op_id)} · ${esc(report.mode)}</span></div>
      <div class="card-body">
        <div class="grid cols-3">
          ${statCard('Completed', num(report.ok_count), bytes(report.bytes), 'accent')}
          ${statCard('Skipped', num(report.failed_count), 'see below for reasons')}
          ${statCard('Bytes freed', bytes(report.bytes), report.mode === 'restore' ? 'returned to disk' : 'reclaimed')}
        </div>
        ${skipped.length ? `<div class="notice warn mt"><strong>Skipped</strong>
          <ul>${skipped.slice(0, 15).map((item) => `<li><span class="mono">${esc(item.path)}</span> — ${esc(item.reason)}</li>`).join('')}</ul>
          ${skipped.length > 15 ? `<div class="hint">…and ${skipped.length - 15} more.</div>` : ''}</div>` : ''}
        ${moved.length ? `<div class="mt"><div class="hint">Moved to ${esc((moved[0].backend) || 'trash')}</div>
          <div class="logbox mt">${moved.slice(0, 40).map((item) => `${bytes(item.bytes).padStart(9)}  ${esc(item.path)}`).join('\n')}</div></div>` : ''}
      </div>
      <div class="card-foot">
        <span class="hint">Changed your mind? Undo it in one click.</span>
        <div class="row-gap">
          <button class="btn btn-ghost" data-nav="history">Open history</button>
          <button class="btn btn-primary" data-undo="${esc(report.op_id)}">↩ Undo this operation</button>
        </div>
      </div>
    </div>`;
  }

  function wireReport(root) {
    root.querySelectorAll('[data-nav]').forEach((button) => {
      button.onclick = () => navigate(button.dataset.nav);
    });
    root.querySelectorAll('[data-undo]').forEach((button) => {
      button.onclick = () => undoOperation(button.dataset.undo);
    });
  }

  async function undoOperation(opId) {
    try {
      const report = await API.post('/api/history/restore', { op_id: opId });
      state.lastReport = report;
      toast('Restored', report.message, 'ok');
      if (state.view === 'clean') {
        const host = $('#view-clean');
        host.innerHTML = reportHtml(report);
        wireReport(host);
      } else if (state.view === 'history') {
        renderHistory($('#view-history'));
      }
    } catch (error) {
      toast('Undo failed', error.message, 'err');
    }
  }

  async function renderClean(host) {
    if (state.lastReport) {
      host.innerHTML = `<div id="clean-result">${reportHtml(state.lastReport)}</div>` +
        (state.plan ? '' : planEmpty());
      wireReport(host);
      return;
    }
    if (state.plan) { paintPlan(host); return; }
    host.innerHTML = planEmpty();
    host.querySelectorAll('[data-nav]').forEach((button) => {
      button.addEventListener('click', () => navigate(button.dataset.nav));
    });
    const dry = $('#btn-clean-dry');
    if (dry) dry.addEventListener('click', () => createPlan('dry_run'));
    const real = $('#btn-clean-real');
    if (real) real.addEventListener('click', () => createPlan('trash'));
  }

  function planEmpty() {
    const count = state.selection.size;
    return `<div class="card"><div class="card-body">
      ${empty('🧹', count ? `${count} item(s) selected` : 'Nothing selected yet',
        count
          ? 'Create a plan to see every path itemised, priced and re-validated against the safety policy before anything moves.'
          : 'Pick items in the Findings view, or apply the AI advisor’s selection. DiskFree will show you an itemised plan first and nothing is deleted permanently.',
        `<div class="row-gap" style="justify-content:center">
          <button class="btn" data-nav="findings">🧾 Go to findings</button>
          ${count ? '<button class="btn btn-ghost" id="btn-clean-dry">Dry run</button><button class="btn btn-primary" id="btn-clean-real">Create clean plan</button>' : ''}
        </div>`)}
    </div></div>`;
  }

  // --------------------------------------------------------------- history
  async function renderHistory(host) {
    host.innerHTML = spinner('Loading journal…');
    try {
      const data = await API.get('/api/history?limit=300');
      state.history = data;
    } catch (error) {
      host.innerHTML = errorCard(error);
      return;
    }
    const data = state.history;
    const operations = data.operations || [];
    const entries = data.entries || [];
    const status = state.actionsStatus || (state.actionsStatus = await API.get('/api/actions/status').catch(() => null));

    host.innerHTML = `
      ${status ? `<div class="card">
        <div class="card-head"><h2>Where removed data goes</h2>
          <span class="pill ${status.allow_writes ? 'ok' : 'warn'}">${status.allow_writes ? 'writes enabled' : 'read-only'}</span></div>
        <div class="card-body">
          <dl class="kv">
            <dt>Backend</dt><dd>${esc(status.backend)}</dd>
            <dt>Trash folder</dt><dd>${esc(status.trash_dir || '')}</dd>
            <dt>Quarantine</dt><dd>${esc(status.quarantine_dir || '')}</dd>
            <dt>Journal</dt><dd>${esc(status.journal_path || '')}</dd>
            <dt>In trash now</dt><dd>${num(status.items_in_trash)} item(s) · ${bytes(status.bytes_in_trash)}
              of ${bytes(status.max_trash_bytes)} ceiling</dd>
            <dt>Permanent delete</dt><dd>${status.allow_permanent_delete ? 'ENABLED' : 'disabled (default)'}</dd>
          </dl>
        </div></div>` : ''}

      <div class="card">
        <div class="card-head"><h2>Operations</h2><span class="sub">${num(operations.length)} recorded</span></div>
        ${operations.length ? `<div class="list">${operations.map((operation) => `
          <div class="list-row">
            <span class="act ${operation.mode === 'restore' ? 'act-review' : 'act-clean'}">${esc(operation.mode)}</span>
            <div class="grow">
              <div class="mono">${esc(operation.op_id)}</div>
              <div class="cell-sub">${esc(operation.timestamp)} · ${num(operation.items)} item(s) ·
                ${bytes(operation.bytes)} · ${num(operation.restorable)} restorable</div>
            </div>
            ${operation.restorable ? `<button class="btn btn-sm" data-undo="${esc(operation.op_id)}">↩ Undo</button>` : ''}
          </div>`).join('')}</div>`
        : empty('↩', 'Nothing removed yet', 'DiskFree has not moved any of your data. Every operation will be listed here with a one-click undo.')}
      </div>

      <div class="card">
        <div class="card-head"><h2>Journal</h2>
          <div class="row-gap">
            <select id="history-status">
              <option value="">all statuses</option>
              <option value="trashed">in trash</option>
              <option value="restored">restored</option>
              <option value="purged">purged</option>
            </select>
            <button class="btn btn-sm" id="btn-restore-selected">Restore selected</button>
            ${data.allow_permanent_delete ? '<button class="btn btn-sm btn-danger" id="btn-purge-selected">Purge selected</button>' : ''}
          </div>
        </div>
        ${entries.length ? `<div class="table-wrap"><table class="table">
          <thead><tr><th></th><th>Status</th><th>Original path</th><th>Category</th><th class="num">Size</th><th>When</th></tr></thead>
          <tbody>${entries.map((entry) => `
            <tr class="${entry.status === 'trashed' ? '' : 'is-refused'}">
              <td><input type="checkbox" data-entry="${esc(entry.id)}" ${entry.status === 'trashed' ? '' : 'disabled'}></td>
              <td><span class="act ${entry.status === 'trashed' ? 'act-clean' : entry.status === 'restored' ? 'act-review' : 'act-keep'}">${esc(entry.status)}</span></td>
              <td><div class="path" title="${esc(entry.path)}">${esc(entry.path)}</div>
                <div class="cell-sub mono">${esc(entry.backend)} → ${esc(entry.stored_path || 'gone')}</div></td>
              <td class="dim">${esc(entry.category || '')}</td>
              <td class="num mono">${bytes(entry.bytes)}</td>
              <td class="dim nowrap">${esc(entry.timestamp)}</td>
            </tr>`).join('')}</tbody></table></div>`
        : empty('📔', 'Journal is empty', 'Nothing has been moved, so there is nothing to undo.')}
      </div>`;

    host.querySelectorAll('[data-undo]').forEach((button) => {
      button.addEventListener('click', () => undoOperation(button.dataset.undo));
    });
    const statusFilter = $('#history-status');
    if (statusFilter) statusFilter.addEventListener('change', async () => {
      state.history = await API.get(`/api/history?limit=300${statusFilter.value ? `&status=${statusFilter.value}` : ''}`);
      renderHistory($('#view-history'));
    });
    const restoreButton = $('#btn-restore-selected');
    if (restoreButton) restoreButton.addEventListener('click', () => batchJournal('restore'));
    const purgeButton = $('#btn-purge-selected');
    if (purgeButton) purgeButton.addEventListener('click', () => batchJournal('purge'));
  }

  async function batchJournal(kind) {
    const ids = $$('[data-entry]').filter((box) => box.checked).map((box) => box.dataset.entry);
    if (!ids.length) { toast('Nothing selected', 'Tick journal entries first', 'warn'); return; }
    if (kind === 'purge') {
      const sure = window.confirm(`Permanently delete ${ids.length} quarantined item(s)? This cannot be undone.`);
      if (!sure) return;
    }
    try {
      const report = await API.post(`/api/history/${kind}`, { entry_ids: ids });
      toast(kind === 'restore' ? 'Restored' : 'Purged', report.message, 'ok');
      state.actionsStatus = null;
      renderHistory($('#view-history'));
      refreshStatus();
    } catch (error) {
      toast('Failed', error.message, 'err');
    }
  }

  // ------------------------------------------------------------- assistant
  function renderAssistant(host) {
    const online = (state.providers || []).filter((p) => p.online);
    host.innerHTML = `
      <div class="card">
        <div class="card-head"><h2>Assistant</h2>
          <span class="pill info">read-only · it cannot delete anything</span></div>
        <div class="card-body">
          <div class="chat">
            <div class="chat-log" id="chat-log"></div>
            <div class="chat-input">
              <textarea id="chat-text" rows="1"
                placeholder="Ask about your disk… e.g. “Why is ~/.cache so big?” or “What is safest to clear first?”"></textarea>
              <button class="btn btn-primary" id="chat-send">Send</button>
            </div>
          </div>
          <div class="hint mt">The assistant sees the same metadata the advisor sees — never file
            contents. ${online.length ? `Answering via ${esc(online.map((p) => p.label).join(' or '))}.`
            : 'No local model host is online, so start Cortex LLMHoster or Ollama to chat.'}</div>
        </div>
      </div>`;
    paintChat();
    const text = $('#chat-text');
    const send = $('#chat-send');
    const submit = () => sendChat();
    send.addEventListener('click', submit);
    text.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submit(); }
    });
    text.focus();
  }

  function paintChat() {
    const log = $('#chat-log');
    if (!log) return;
    log.innerHTML = state.chat.map((message) => `
      <div class="bubble ${message.role === 'user' ? 'user' : 'bot'}">
        <div class="who">${esc(message.role === 'user' ? 'You' : (message.who || 'DiskFree'))}</div>
        <div class="text">${esc(message.text)}${message.streaming ? ' ▌' : ''}</div>
      </div>`).join('') || `<div class="empty"><div class="big">💬</div>
        <h3>Ask anything about your disk</h3>
        <p>“What is using the most space?”, “Is it safe to clear the pip cache?”,
        “Why can’t DiskFree clean /var/lib/docker?”</p></div>`;
    log.scrollTop = log.scrollHeight;
  }

  async function sendChat() {
    const input = $('#chat-text');
    const text = (input.value || '').trim();
    if (!text || state.chatBusy) return;
    input.value = '';
    state.chat.push({ role: 'user', text });
    const bot = { role: 'assistant', text: '', streaming: true, who: state.providerChoice || 'auto' };
    state.chat.push(bot);
    state.chatBusy = true;
    paintChat();
    try {
      await API.sse('/api/chat', {
        message: text,
        history: state.chat.slice(0, -2).slice(-12).map((m) => ({ role: m.role, content: m.text })),
        job_id: state.jobId,
        provider: state.providerChoice || 'auto',
        stream: true,
      }, {
        meta: (data) => { bot.who = `${data.engine || ''}${data.model ? ' · ' + data.model : ''}`; },
        delta: (data) => { bot.text += data.text || ''; paintChat(); },
        error: (data) => { bot.text += `\n[error: ${data.error || 'unknown'}]`; },
        done: () => { bot.streaming = false; },
      });
    } catch (error) {
      bot.text = bot.text || `The assistant could not answer: ${error.message}`;
      bot.streaming = false;
      toast('Chat failed', error.message, 'err');
    } finally {
      state.chatBusy = false;
      bot.streaming = false;
      paintChat();
    }
  }

  // ----------------------------------------------------------------- rules
  async function renderRules(host) {
    if (!state.rules) {
      host.innerHTML = spinner('Loading the rule catalogue…');
      state.rules = await API.get('/api/rules');
    }
    const data = state.rules;
    const rules = data.rules || [];
    const byCategory = {};
    rules.forEach((rule) => { (byCategory[rule.category] = byCategory[rule.category] || []).push(rule); });

    host.innerHTML = `
      <div class="notice mb">DiskFree publishes its whole knowledge base. Every finding in the UI names
        the rule that produced it, so you can always check <em>why</em> something was proposed.</div>
      <div class="card">
        <div class="card-head"><h2>${num(rules.length)} rules</h2>
          <input type="text" id="rule-q" placeholder="Filter rules…" style="min-width:200px"></div>
        <div class="table-wrap"><table class="table" id="rules-table">
          <thead><tr><th>Rule</th><th>Category</th><th>Risk</th><th>Pre-select</th><th>How it matches</th></tr></thead>
          <tbody>${rules.map(ruleRow).join('')}</tbody>
        </table></div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Risk ladder</h2></div>
        <div class="card-body tight"><div class="list">
          ${(data.risk_ladder || []).map((item) => `
            <div class="list-row">
              <span class="risk risk-${esc(item.risk)}">${esc(item.risk)}</span>
              <div class="grow">${esc(item.meaning)}</div>
              <span class="pill ${item.auto_selectable ? 'ok' : ''}">${item.auto_selectable ? 'may be pre-selected' : 'never pre-selected'}</span>
            </div>`).join('')}
        </div></div>
      </div>`;

    const search = $('#rule-q');
    search.addEventListener('input', () => {
      const needle = search.value.trim().toLowerCase();
      $$('#rules-table tbody tr').forEach((row) => {
        row.style.display = !needle || row.textContent.toLowerCase().includes(needle) ? '' : 'none';
      });
    });
  }

  function ruleRow(rule) {
    const matcher = rule.matcher || {};
    const bits = [];
    if ((matcher.paths || []).length) bits.push(`paths: ${matcher.paths.slice(0, 3).join(', ')}${matcher.paths.length > 3 ? ' …' : ''}`);
    if ((matcher.names || []).length) bits.push(`names: ${matcher.names.slice(0, 6).join(', ')}${matcher.names.length > 6 ? ' …' : ''}`);
    if ((matcher.globs || []).length) bits.push(`globs: ${matcher.globs.slice(0, 4).join(', ')}`);
    if ((matcher.parent_is || []).length) bits.push(`direct child of: ${matcher.parent_is.join(', ')}`);
    if ((matcher.parents_contain || []).length) bits.push(`inside: ${matcher.parents_contain.slice(0, 5).join(', ')}`);
    if ((matcher.require_sibling || []).length) bits.push(`needs sibling: ${matcher.require_sibling.join(', ')}`);
    if ((matcher.under || []).length) bits.push(`under: ${matcher.under.join(', ')}`);
    if (matcher.min_age_days !== null && matcher.min_age_days !== undefined) bits.push(`older than ${matcher.min_age_days} d`);
    if (matcher.require_own_file) bits.push('only your own files');
    if (rule.probe) bits.push('probe: reported as a command, never removed');
    if (rule.computed) bits.push('computed pass');
    return `<tr ${rule.applies_here ? '' : 'class="is-refused"'}>
      <td><div class="cell-title">${esc(rule.title)}</div>
        <div class="mono cell-sub">${esc(rule.id)} · priority ${esc(rule.priority)}</div>
        <div class="cell-sub" style="max-width:46ch">${esc(rule.description)}</div></td>
      <td class="dim nowrap">${esc(rule.category_label)}</td>
      <td><span class="risk risk-${esc(rule.risk)}">${esc(rule.risk)}</span></td>
      <td>${rule.auto_selectable ? '<span class="pill ok">yes</span>'
        : rule.default_selected ? '<span class="pill warn">rule says yes, risk says no</span>'
        : '<span class="pill">no</span>'}</td>
      <td class="cell-sub mono" style="max-width:40ch">${esc(bits.join(' · ') || '—')}
        ${rule.advisory ? `<div class="cmd" style="margin-top:5px"><span>${esc(rule.advisory)}</span></div>` : ''}
        ${rule.applies_here ? '' : '<div class="cell-sub">not applicable on this platform</div>'}</td>
    </tr>`;
  }

  // ---------------------------------------------------------------- safety
  async function renderSafety(host) {
    if (!state.safety) {
      host.innerHTML = spinner('Loading the safety policy…');
      state.safety = await API.get('/api/safety');
    }
    const data = state.safety;
    const policy = data.policy || {};
    host.innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <div class="card-head"><h2>Guarantees</h2></div>
          <div class="card-body"><ul class="stack" style="padding-left:18px;margin:0">
            ${(data.guarantees || []).map((g) => `<li>${esc(g)}</li>`).join('')}
          </ul></div>
        </div>
        <div class="card">
          <div class="card-head"><h2>Trash &amp; limits</h2></div>
          <div class="card-body">
            <dl class="kv">
              <dt>Backend</dt><dd>${esc((data.trash || {}).backend || '')}</dd>
              <dt>Trash folder</dt><dd>${esc((data.trash || {}).trash_dir || '')}</dd>
              <dt>Quarantine</dt><dd>${esc((data.trash || {}).quarantine_dir || '')}</dd>
              <dt>Journal</dt><dd>${esc((data.trash || {}).journal_path || '')}</dd>
              <dt>Ceiling</dt><dd>${bytes((data.trash || {}).max_trash_bytes || 0)}</dd>
              <dt>Confirmation</dt><dd>${(data.trash || {}).require_confirmation ? 'token required' : 'disabled'}</dd>
              <dt>Plan lifetime</dt><dd>${num((data.trash || {}).plan_ttl_seconds || 0)}s</dd>
              <dt>Max items / op</dt><dd>${num((data.limits || {}).max_items_per_operation || 0)}</dd>
              <dt>Permanent delete</dt><dd>${(data.trash || {}).allow_permanent_delete ? 'ENABLED' : 'disabled'}</dd>
            </dl>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Worked examples</h2>
          <span class="sub">live policy decisions on this machine</span></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Path</th><th>Tier</th><th>Removable</th><th>Why</th></tr></thead>
          <tbody>${(data.examples || []).map((example) => `
            <tr>
              <td class="path">${esc(example.path)}</td>
              <td><span class="risk risk-${example.tier === 'blocked' ? 'forbidden' : example.tier === 'sensitive' ? 'high' : 'safe'}">${esc(example.tier)}</span></td>
              <td>${example.decision && example.decision.allowed ? '<span class="pill ok">yes</span>' : '<span class="pill err">no</span>'}</td>
              <td class="dim">${esc(example.reason || (example.decision && example.decision.reason) || '')}
                ${example.zone_escape ? '<div class="cell-sub">cache-name escape applied</div>' : ''}</td>
            </tr>`).join('')}</tbody>
        </table></div>
      </div>

      <div class="grid cols-2">
        <div class="card">
          <div class="card-head"><h2>Protected system locations</h2></div>
          <div class="card-body"><div class="logbox">${(policy.blocked_system_roots || []).map(esc).join('\n')}</div>
            <div class="hint mt">Anything under these trees is refused, whatever the model or the user asks.</div>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><h2>Protected by name</h2></div>
          <div class="card-body">
            <div class="hint">Folders protected wherever they appear:</div>
            <div class="logbox mt">${['.git', '.svn', '.hg', '.ssh', '.gnupg', '.aws', '.azure', '.kube', '.docker', 'System Volume Information', '$Recycle.Bin'].map(esc).join('\n')}</div>
            <div class="hint mt">Personal folders treated as sensitive (never pre-selected):</div>
            <div class="logbox mt">${(policy.sensitive_folder_names || []).map(esc).join('\n')}</div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Home zones</h2>
          <span class="sub">protected areas and their cache allow-lists</span></div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Zone</th><th>Default tier</th><th>Allowed inside</th><th>Reason</th></tr></thead>
          <tbody>${(policy.zones || []).map((zone) => `
            <tr><td class="mono">${esc(zone.root)}</td>
              <td><span class="risk risk-${zone.tier === 'blocked' ? 'forbidden' : zone.tier === 'sensitive' ? 'high' : 'safe'}">${esc(zone.tier)}</span></td>
              <td class="mono cell-sub">${(zone.allowed_prefixes || []).map(esc).join(', ') || '—'}</td>
              <td class="dim">${esc(zone.reason || '')}</td></tr>`).join('')}</tbody>
        </table></div>
      </div>`;
  }

  // -------------------------------------------------------------- settings
  async function renderSettings(host) {
    if (!state.config) state.config = await API.get('/api/config').catch(() => null);
    const config = state.config || {};
    const ai = config.ai || {};
    host.innerHTML = `
      <div class="grid cols-2">
        <div class="card">
          <div class="card-head"><h2>Server</h2></div>
          <div class="card-body"><dl class="kv">
            <dt>Version</dt><dd>${esc(config.version || '')}</dd>
            <dt>Bind</dt><dd>${esc((config.server || {}).host || '')}:${esc((config.server || {}).port || '')}</dd>
            <dt>Data dir</dt><dd>${esc((config.server || {}).data_dir || '')}</dd>
            <dt>Config file</dt><dd>${esc((config.server || {}).config_path || 'none (defaults + env)')}</dd>
            <dt>Log level</dt><dd>${esc((config.server || {}).log_level || '')}</dd>
            <dt>Token auth</dt><dd>${(config.server || {}).ui_token_required ? 'required' : 'off (loopback only)'}</dd>
          </dl></div>
        </div>
        <div class="card">
          <div class="card-head"><h2>Safety</h2></div>
          <div class="card-body"><dl class="kv">
            <dt>Writes</dt><dd>${(config.safety || {}).allow_writes ? 'enabled' : 'DISABLED (read-only)'}</dd>
            <dt>Permanent delete</dt><dd>${(config.safety || {}).allow_permanent_delete ? 'ENABLED' : 'disabled'}</dd>
            <dt>Trash backend</dt><dd>${esc((config.safety || {}).effective_trash_backend || '')}
              (configured: ${esc((config.safety || {}).trash_backend || 'auto')})</dd>
            <dt>Quarantine</dt><dd>${esc((config.safety || {}).quarantine_dir || '')}</dd>
            <dt>Journal</dt><dd>${esc((config.safety || {}).journal_path || '')}</dd>
            <dt>Confirmation</dt><dd>${(config.safety || {}).require_confirmation ? 'token required' : 'off'}</dd>
            <dt>Extra protected</dt><dd>${(config.safety || {}).extra_protected_paths?.length
              ? (config.safety || {}).extra_protected_paths.map(esc).join('<br>') : 'none'}</dd>
          </dl></div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Local model hosts</h2>
          <span class="sub">preferred: ${esc(ai.preferred_provider || 'auto')}</span></div>
        <div class="card-body">
          <div class="grid cols-2">
            ${(ai.providers || []).map((provider) => `
              <div class="stat">
                <div class="spread"><div class="label">${esc(provider.name)}</div>
                  <span class="pill ${provider.enabled ? 'ok' : ''}">${provider.enabled ? 'enabled' : 'disabled'}</span></div>
                <dl class="kv mt">
                  <dt>Base URL</dt><dd>${esc(provider.base_url)}</dd>
                  <dt>API key</dt><dd>${provider.api_key_set ? 'set (hidden)' : 'not set'}</dd>
                  <dt>Model</dt><dd>${esc(provider.model || 'auto')}</dd>
                  <dt>Timeout</dt><dd>${esc(provider.timeout)}s</dd>
                </dl>
              </div>`).join('')}
          </div>
          <div class="notice mt"><strong>Connect a host</strong>
            <p>Set environment variables before starting DiskFree:</p>
            <div class="cmd mt"><span>DISKFREE_CORTEX_URL=http://127.0.0.1:8624
DISKFREE_CORTEX_API_KEY=your-local-secret
DISKFREE_OLLAMA_URL=http://127.0.0.1:11434
DISKFREE_OLLAMA_MODEL=llama3.2
DISKFREE_PROVIDER=auto</span>
              <button class="btn btn-sm" data-copy="DISKFREE_CORTEX_URL=http://127.0.0.1:8624&#10;DISKFREE_CORTEX_API_KEY=your-local-secret&#10;DISKFREE_OLLAMA_URL=http://127.0.0.1:11434&#10;DISKFREE_OLLAMA_MODEL=llama3.2&#10;DISKFREE_PROVIDER=auto">Copy</button></div>
            <p class="hint mt">Both hosts stay on your machine. DiskFree sends metadata only.</p>
          </div>
          <div class="row-gap mt">
            <button class="btn btn-sm" id="btn-test-cortex">Test Cortex connection</button>
            <button class="btn btn-sm" id="btn-test-ollama">Test Ollama connection</button>
            <span class="hint" id="provider-test-out"></span>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Scan defaults</h2></div>
        <div class="card-body"><dl class="kv">
          ${Object.entries(config.scan || {}).map(([key, value]) =>
            `<dt>${esc(key.replace(/_/g, ' '))}</dt><dd>${esc(typeof value === 'number' && key.endsWith('_bytes') ? `${num(value)} (${bytes(value)})` : value)}</dd>`).join('')}
        </dl></div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Access token</h2></div>
        <div class="card-body stack">
          <div class="hint">Stored only in this browser. Needed when the server was started with
            <span class="mono">DISKFREE_UI_TOKEN</span>.</div>
          <div class="row-gap">
            <input type="password" id="token-value" placeholder="token" value="${esc(API.token)}" style="min-width:260px">
            <button class="btn btn-sm" id="btn-token-save">Save</button>
            <button class="btn btn-sm btn-ghost" id="btn-token-clear">Clear</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Environment</h2></div>
        <div class="card-body"><div class="logbox">${Object.entries(config.environment || {})
          .map(([key, value]) => `${esc(key)}=${esc(value)}`).join('\n') || '(no DISKFREE_* variables set)'}</div></div>
      </div>`;

    host.querySelectorAll('[data-copy]').forEach((button) => {
      button.addEventListener('click', () => copyText(button.dataset.copy, button));
    });
    $('#btn-token-save').addEventListener('click', () => {
      API.token = $('#token-value').value.trim();
      if (API.token) localStorage.setItem(TOKEN_KEY, API.token);
      else localStorage.removeItem(TOKEN_KEY);
      toast('Token saved', 'Requests now include it');
    });
    $('#btn-token-clear').addEventListener('click', () => {
      API.token = '';
      localStorage.removeItem(TOKEN_KEY);
      $('#token-value').value = '';
      toast('Token cleared');
    });
    $('#btn-test-cortex').addEventListener('click', () => testProvider('cortex'));
    $('#btn-test-ollama').addEventListener('click', () => testProvider('ollama'));
  }

  async function testProvider(name) {
    const out = $('#provider-test-out');
    out.textContent = 'testing…';
    try {
      const data = await API.post(`/api/providers/${encodeURIComponent(name)}/check`, {});
      const provider = data.provider || {};
      out.textContent = `${provider.status}: ${provider.detail || ''}`;
      state.providers = [];
      toast(`${name} → ${provider.status}`, provider.detail || '', provider.online ? 'ok' : 'warn');
    } catch (error) {
      out.textContent = `failed: ${error.message}`;
      toast('Provider test failed', error.message, 'err');
    }
  }

  // ------------------------------------------------------------ shell/boot
  function updateBadges() {
    const badge = $('#badge-findings');
    const count = state.findings.length || (state.job && state.job.findings) || 0;
    if (badge) {
      badge.hidden = !count;
      badge.textContent = count > 999 ? '999+' : String(count);
    }
    const selection = state.selection.size;
    const cleanButton = $('#btn-make-plan');
    if (cleanButton) cleanButton.disabled = !selection;
    const pill = $('#pill-scan');
    if (pill && state.job && state.job.status === 'running') {
      pill.hidden = false;
      pill.textContent = `scanning · ${esc(state.job.progress?.phase || '')}`;
    } else if (pill) {
      pill.hidden = true;
    }
  }

  async function refreshStatus() {
    try {
      state.status = await API.get('/api/status');
    } catch (error) {
      if (error.status !== 401) toast('Status failed', error.message, 'err');
      return null;
    }
    const status = state.status;
    $('#brand-version').textContent = `v${status.version} · ${status.read_only ? 'read-only' : 'local'}`;
    $('#pill-readonly').hidden = !status.read_only;
    const disk = status.disk || {};
    const pct = clamp(Number(disk.percent || 0), 0, 100);
    const fill = $('#sidebar-meter-fill');
    fill.style.width = `${pct}%`;
    fill.className = `meter-fill ${pct > 90 ? 'danger' : pct > 75 ? 'warn' : ''}`;
    $('#sidebar-meter-text').textContent =
      `${pct.toFixed(0)}% used · ${bytes(disk.free)} free of ${bytes(disk.total)}`;

    const strip = $('#provider-strip');
    strip.innerHTML = (status.providers || []).map((provider) => {
      const tone = provider.status === 'online' ? 'ok' : provider.status === 'degraded' ? 'warn' : 'err';
      return `<span class="pill ${tone}" title="${esc(provider.detail || '')}">
        <span class="dot"></span>${esc(provider.name)}</span>`;
    }).join('') + `<span class="pill ok" title="Deterministic offline advisor"><span class="dot"></span>rules</span>`;

    if (status.scans && status.scans.latest_id && !state.jobId) {
      state.jobId = status.scans.latest_id;
    }
    if (state.jobId && (!state.job || state.job.status === 'running')) {
      try { state.job = await API.get(`/api/scans/${encodeURIComponent(state.jobId)}`); } catch { /* ignore */ }
    }
    updateBadges();
    return status;
  }

  function wireShell() {
    $('#nav').addEventListener('click', (event) => {
      const item = event.target.closest('.nav-item');
      if (item) navigate(item.dataset.view);
    });
    $('#btn-quick-scan').addEventListener('click', () => startScan({ preset: 'quick' }));
    $('#btn-advise').addEventListener('click', () => navigate('advisor'));
    $('#modal').addEventListener('close', closeModal);
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeModal();
      if ((event.key === 'k' || event.key === 'K') && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        navigate('findings');
        setTimeout(() => { const q = $('#filter-q'); if (q) q.focus(); }, 60);
      }
    });
  }

  async function boot(silent = false) {
    wireShell();
    const status = await refreshStatus();
    if (!status && !silent) return;
    if (status && status.scans && status.scans.latest_id) {
      state.jobId = status.scans.latest_id;
      try {
        state.job = await API.get(`/api/scans/${encodeURIComponent(state.jobId)}`);
        if (state.job.status === 'running') pollScan();
        else await loadFindings().catch(() => {});
      } catch { /* a stale job id is fine */ }
    }
    try {
      const disks = await API.get('/api/disks');
      if (state.status) state.status.disks = disks;
    } catch { /* optional */ }
    navigate(state.view);
    setInterval(() => {
      if (!state.scanTimer) refreshStatus().then(() => {
        if (state.view === 'overview') renderOverview($('#view-overview'));
      }).catch(() => {});
    }, 20000);
    updateBadges();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => boot());
  else boot();
})();
