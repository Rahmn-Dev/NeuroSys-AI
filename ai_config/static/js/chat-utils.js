// Chat utilities (escapeHtml, bulk edit). Extracted from templates/chat3.html.
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Pure display helpers shared by the chat bundles. They live here (instead
  // of chat-app.js) so the frontend smoke tests can load this small bundle
  // alone, without booting the whole app. No DOM writes, no network.
  function chatTimeLabel(ts) {
    try {
      const d = ts ? new Date(ts) : new Date();
      // new Date('garbage') does not throw - it yields an Invalid Date whose
      // toLocaleTimeString() is the literal string "Invalid Date".
      if (isNaN(d.getTime())) return '';
      return d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return '';
    }
  }

  // Date label for the floating pill and the turn-rail tooltip. Pure: no DOM,
  // no network. Today / Yesterday keep it glanceable, older dates read like
  // "Oct 10" (year appended across New Year).
  window.sreDateLabel = function (ts) {
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return '';
      const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const diffDays = Math.round((today - day) / 86400000);
      if (diffDays === 0) return 'Today';
      if (diffDays === 1) return 'Yesterday';
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const sameYear = d.getFullYear() === today.getFullYear();
      return months[d.getMonth()] + ' ' + d.getDate() + (sameYear ? '' : ', ' + d.getFullYear());
    } catch (e) {
      return '';
    }
  };
  // One turn-rail row worth of data for a user question bubble: the question
  // with attachment footers stripped, the following answer's excerpt, and the
  // display timestamp + date. Reads the live DOM but never mutates it.
  window.turnRailEntry = function (userEl) {
    const raw = userEl.dataset.originalText || userEl.textContent || '';
    const q = raw.replace(/\n\n\[Context Attached: [^\]]+\]/g, '').trim();
    let sib = userEl.nextElementSibling;
    while (sib && !(sib.classList && sib.classList.contains('agent-msg'))) sib = sib.nextElementSibling;
    const ansEl = sib && sib.querySelector('.ai-content');
    const a = ansEl ? ansEl.textContent.trim().slice(0, 220) : '';
    let t = '';
    try { t = userEl.dataset.created ? chatTimeLabel(userEl.dataset.created) : ''; } catch (e) { /* best-effort */ }
    let d = '';
    try { d = userEl.dataset.created ? window.sreDateLabel(userEl.dataset.created) : ''; } catch (e) { /* best-effort */ }
    return { el: userEl, q: q || '(empty question)', a: a, t: t, d: d };
  };
  // ============================================
  // 1. FUNGSI BULK EDIT (Global)
  // ============================================
  let isBulkEditMode = false;

  function updateBulkSelectedCount() {
    const totalCheckboxes = document.querySelectorAll('.history-checkbox');
    const checkedCheckboxes = document.querySelectorAll('.history-checkbox:checked');
    const countSpan = document.getElementById('bulk-selected-count');
    const selectAllCb = document.getElementById('bulk-select-all');

    if (countSpan) {
      countSpan.textContent = `${checkedCheckboxes.length} selected`;
    }

    if (selectAllCb && totalCheckboxes.length > 0) {
      selectAllCb.checked = checkedCheckboxes.length === totalCheckboxes.length;
    }

    // Update row highlighting for all items
    totalCheckboxes.forEach(cb => {
      const parentItem = cb.closest('.sre-history-item');
      if (parentItem) {
        if (cb.checked) {
          parentItem.classList.add('bulk-selected');
        } else {
          parentItem.classList.remove('bulk-selected');
        }
      }
    });
  }

  function toggleBulkEditMode() {
    isBulkEditMode = !isBulkEditMode;
    const bulkBar = document.getElementById('bulk-action-bar');
    if (bulkBar) bulkBar.style.display = isBulkEditMode ? 'flex' : 'none';

    const deleteSingleBtns = document.querySelectorAll('.delete-single-history-btn');
    deleteSingleBtns.forEach(btn => {
      btn.style.display = isBulkEditMode ? 'none' : '';
    });

    const checkboxes = document.querySelectorAll('.history-checkbox');
    checkboxes.forEach(cb => {
      cb.style.display = isBulkEditMode ? 'inline-block' : 'none';
      cb.checked = false;
    });

    const selectAllBtn = document.getElementById('bulk-select-all');
    if (selectAllBtn) selectAllBtn.checked = false;

    updateBulkSelectedCount();
  }

  function selectAllHistory(checked) {
    const checkboxes = document.querySelectorAll('.history-checkbox');
    checkboxes.forEach(cb => {
      cb.checked = checked;
    });
    updateBulkSelectedCount();
  }

  function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.substring(0, name.length + 1) === (name + '=')) {
          // Keep the LAST match: rotated secrets append, stale copies first
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        }
      }
    }
    return cookieValue;
  }

  // Turns an opaque 403 into something the operator can act on. The usual
  // cause is a stale tab: the page was loaded before the service restarted, so
  // it has no csrfmiddlewaretoken input and no matching csrftoken cookie.
  async function explainMutationFailure(res, what) {
    let detail = '';
    try {
      detail = (await res.text()).slice(0, 300);
    } catch (e) { }
    console.error(`${what} failed: ${res.status}`, detail);
    if (res.status === 403) {
      // A fresh token was already tried automatically, so this is not staleness.
      let reason = '';
      try {
        const text = detail.trim();
        if (text.startsWith('{')) reason = (JSON.parse(text).detail || '').slice(0, 120);
      } catch (e) { }
      return `${what}: the server rejected the request (403). `
        + (reason || 'The session may no longer be valid - reload the page and try again.');
    }
    if (res.status === 404) {
      return `${what}: the record no longer exists (404).`;
    }
    return `${what} failed (${res.status}). ${detail || ''}`;
  }

  function getCSRFToken() {
    // The cookie is what the server compares against, so it wins. The token
    // rendered into this page can be stale (a restarted service rotates the
    // secret) and preferring it is exactly what made every mutation fail with
    // a 403 until the operator hard refreshed.
    const cookie = getCookie('csrftoken');
    if (cookie) return cookie;
    const dom = document.querySelector('input[name="csrfmiddlewaretoken"]');
    return dom && dom.value ? dom.value : '';
  }

  // Ask Django for a current token by re-fetching the page shell. Cheap, and it
  // removes the operator's hard-refresh reflex entirely.
  async function refreshCSRFToken() {
    try {
      await fetch(window.location.pathname + (window.location.search || ''), {
        credentials: 'same-origin', cache: 'no-store'
      });
    } catch (e) { }
    return getCSRFToken();
  }

  // Every state-changing request goes through here: credentials always sent,
  // a live CSRF token attached, and one automatic retry with a refreshed token
  // if the first attempt is rejected.
  async function sreFetch(url, options) {
    const opts = Object.assign({}, options || {});
    opts.credentials = opts.credentials || 'same-origin';
    const method = String(opts.method || 'GET').toUpperCase();
    const safe = (method === 'GET' || method === 'HEAD' || method === 'OPTIONS');
    if (!safe) {
      opts.headers = Object.assign({}, opts.headers || {}, {
        'X-CSRFToken': getCSRFToken() || '', 'X-Requested-With': 'XMLHttpRequest'
      });
      // A JSON body without a content type arrives as application/octet-stream
      // and the server answers 415 before reading it, which the UI could only
      // report as "rejected". Set it unless the caller chose one.
      if (opts.body != null && typeof opts.body === 'string'
          && !Object.keys(opts.headers).some((k) => k.toLowerCase() === 'content-type')) {
        opts.headers['Content-Type'] = 'application/json';
      }
    }
    let res = await fetch(url, opts);
    if (res.status === 403 && !safe) {
      const token = await refreshCSRFToken();
      opts.headers = Object.assign({}, opts.headers || {}, { 'X-CSRFToken': token || '' });
      res = await fetch(url, opts);
    }
    return res;
  }
  window.sreFetch = sreFetch;
  window.getCSRFToken = getCSRFToken;
  window.refreshCSRFToken = refreshCSRFToken;

  // Permission state has three writers: the initial GET, the PUTs triggered by
  // the composer picker, and rapid clicks from the operator. They used to race:
  // a slow GET could land after a click and silently reset the pill, and two
  // PUTs could resolve out of order so the label showed one mode while the
  // hidden select (and the server) held the other.
  let permissionLoadSeq = 0;
  let permissionSaveSeq = 0;
  let permissionSaving = false;
  let permissionUserPicked = false;
  let permissionQueuedMode = null;

  function applyPermissionValue(mode) {
    const selector = document.getElementById('permission-selector');
    if (!selector) return;
    selector.value = mode === 'full_access' ? 'full_access' : 'need_approval';
    // Label and hidden value must never disagree.
    if (typeof updatePermissionPickerLabel === 'function') updatePermissionPickerLabel();
  }

  // Never let UI feedback throw inside the save path.
  function notifyPermission(message) {
    try {
      if (typeof window.addSystemMsg === 'function') {
        window.addSystemMsg(message, 'shield');
      } else {
        console.info('[permission] ' + message);
      }
    } catch (error) {
      console.info('[permission] ' + message);
    }
  }

  async function loadAgentPermission() {
    const selector = document.getElementById('permission-selector');
    if (!selector) return;
    const seq = ++permissionLoadSeq;
    try {
      const response = await fetch('/api/v1/agent-permission/', {credentials: 'same-origin'});
      if (!response.ok) throw new Error(`permission load failed (${response.status})`);
      const payload = await response.json();
      // Drop stale loads: a newer load started, or the operator already chose.
      if (seq !== permissionLoadSeq || permissionUserPicked) return;
      applyPermissionValue(payload.mode);
    } catch (error) {
      if (seq !== permissionLoadSeq) return;
      applyPermissionValue('need_approval');
      selector.disabled = true;
      updatePermissionPickerLabel();
      console.warn('Agent permission is fail-closed until the server preference is available.', error);
    }
  }

  async function saveAgentPermission(mode) {
    const selector = document.getElementById('permission-selector');
    if (!selector) return;
    const seq = ++permissionSaveSeq;
    permissionSaving = true;
    updatePermissionPickerLabel();
    try {
      const payload = await window.wsCall('agent_permission.set', { mode });
      // A newer PUT already went out; its response owns the final state.
      if (seq !== permissionSaveSeq) return;
      applyPermissionValue(payload.mode);
      notifyPermission(
        payload.mode === 'full_access'
          ? 'Full Access enabled for in-goal actions. Hard security boundaries remain enforced.'
          : 'Need Approval enabled. Mutating actions require Allow Once.');
    } catch (error) {
      if (seq !== permissionSaveSeq) return;
      // Fail closed, and make the UI say so instead of keeping a stale label.
      applyPermissionValue('need_approval');
      console.warn('Permission update rejected; using Need Approval.', error);
      notifyPermission('Permission update rejected; falling back to Need Approval.');
    } finally {
      if (seq === permissionSaveSeq) {
        permissionSaving = false;
        updatePermissionPickerLabel();
        // Last click wins: flush a click that arrived while this PUT was in flight.
        const queued = permissionQueuedMode;
        permissionQueuedMode = null;
        if (queued && queued !== selector.value) {
          applyPermissionValue(queued);
          saveAgentPermission(queued);
        }
      }
    }
  }

  const permissionSelector = document.getElementById('permission-selector');
  if (permissionSelector) {
    permissionSelector.addEventListener('change', event => {
      permissionUserPicked = true;
      saveAgentPermission(event.target.value);
    });
    permissionSelector.addEventListener('change', updatePermissionPickerLabel);
  }

  const PERMISSION_MODES = [
    { value: 'need_approval', label: 'Need Approval', icon: 'fa-shield-halved',
      hint: 'Risky or mutating actions wait for your approval' },
    { value: 'full_access', label: 'Full Access', icon: 'fa-unlock-keyhole',
      hint: 'Auto-approve inside the goal; hard blocks still apply' }
  ];

  function closePermissionPicker() {
    const panel = document.getElementById('permission-picker-panel');
    if (panel) panel.classList.remove('open');
  }

  function togglePermissionPicker(ev) {
    if (ev) ev.stopPropagation();
    const panel = document.getElementById('permission-picker-panel');
    if (!panel) return;
    const willOpen = !panel.classList.contains('open');
    if (willOpen) {
      closeModelPicker();
      closeModePicker();
      renderPermissionPickerPanel();
      panel.classList.add('open');
    } else {
      panel.classList.remove('open');
    }
  }

  function renderPermissionPickerPanel() {
    const panel = document.getElementById('permission-picker-panel');
    const hidden = document.getElementById('permission-selector');
    if (!panel) return;
    const current = hidden ? hidden.value : 'need_approval';
    panel.innerHTML = PERMISSION_MODES.map(p => `
      <button type="button" class="model-picker-item ${p.value === current ? 'selected' : ''}"
        onclick="selectPermissionFromPicker('${p.value}')">
        <i class="fa-solid ${p.icon}" style="font-size: 12px; width: 16px; color: var(--accent);"></i>
        <span style="flex: 1; min-width: 0;">
          <span class="mp-name">${p.label}</span>
          <span class="mp-sub" style="font-family: inherit;">${p.hint}</span>
        </span>
        ${p.value === current ? '<i class="fa-solid fa-check" style="color: var(--success-text); font-size: 11px;"></i>' : ''}
      </button>`).join('');
  }

  // Explicit choice, identical interaction to the agent-mode picker: the row
  // you click is the mode you get, no blind toggling.
  function selectPermissionFromPicker(value) {
    const hidden = document.getElementById('permission-selector');
    if (!hidden) return;
    if (hidden.disabled) {
      alert('Agent authorization cannot be changed: the server preference could not be read. Reload the page.');
      return;
    }
    console.info('[permission] requested=' + value + ' (was ' + hidden.value + ')');
    closePermissionPicker();
    permissionUserPicked = true;
    if (hidden.value === value && !permissionSaving) {
      updatePermissionPickerLabel();
      return;
    }
    hidden.value = value;
    updatePermissionPickerLabel();
    if (permissionSaving) {
      permissionQueuedMode = value;
      return;
    }
    saveAgentPermission(value);
  }

  function updatePermissionPickerLabel() {
    const hidden = document.getElementById('permission-selector');
    const label = document.getElementById('permission-picker-label');
    const icon = document.getElementById('permission-picker-icon');
    const btn = document.getElementById('permission-picker-btn');
    if (!hidden) return;
    const mode = PERMISSION_MODES.find(p => p.value === hidden.value) || PERMISSION_MODES[0];
    if (label) label.textContent = mode.label;
    if (icon) icon.className = 'fa-solid ' + mode.icon;
    if (btn) {
      btn.style.color = mode.value === 'full_access' ? 'var(--warning)' : 'var(--text-secondary)';
      btn.style.opacity = hidden.disabled ? '0.5' : '1';
      btn.setAttribute('aria-pressed', mode.value === 'full_access' ? 'true' : 'false');
      btn.title = permissionSaving
        ? 'Saving authorization preference...'
        : `Agent authorization: ${mode.label} (click to switch)`;
    }
  }

  updatePermissionPickerLabel();
  loadAgentPermission();

  // Slide a chat row out to the right, then let the rows below it close the
  // gap, so deleting reads as one card being pulled off the stack.
  window.animateHistoryRowOut = function (id) {
    const row = document.getElementById('history-item-' + id);
    const list = document.getElementById('history-list');
    if (!row || !list || typeof row.animate !== 'function') return false;
    row.style.pointerEvents = 'none';
    row.style.overflow = 'hidden';
    const height = row.offsetHeight || 48;
    const gap = parseFloat(getComputedStyle(list).rowGap || getComputedStyle(list).gap || '0') || 0;
    row.animate([
      { transform: 'translateX(0)', opacity: 1, maxHeight: height + 'px', marginBottom: gap + 'px' },
      { transform: 'translateX(30px)', opacity: 0.8, maxHeight: height + 'px', marginBottom: gap + 'px', offset: 0.3 },
      { transform: 'translateX(110%)', opacity: 0, maxHeight: height + 'px', marginBottom: gap + 'px', offset: 0.68 },
      { transform: 'translateX(110%)', opacity: 0, maxHeight: '0px', marginBottom: '0px' },
    ], { duration: 420, easing: 'cubic-bezier(.4,0,.2,1)', fill: 'forwards' });

    Array.from(list.children).filter((el) => el !== row).forEach((el, index) => {
      setTimeout(() => {
        el.animate([
          { transform: 'translateY(-7px)', opacity: 0.55 },
          { transform: 'translateY(0)', opacity: 1 },
        ], { duration: 230, delay: Math.min(index * 20, 170), easing: 'ease-out' });
      }, 250);
    });
    return true;
  };

  // Danger confirm modal (pengganti confirm() bawaan browser).
  // Pakai: const ok = await window.sreConfirm({title, message, confirmText});
  window.sreConfirm = function (opts) {
    opts = opts || {};
    return new Promise((resolve) => {
      let overlay = document.getElementById('sre-confirm-modal');
      if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'sre-confirm-modal';
        overlay.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);backdrop-filter:blur(4px);z-index:10001;align-items:center;justify-content:center;padding:1rem;';
        overlay.innerHTML = `
          <div style="background:var(--bg-panel);border:1px solid var(--border-color);border-radius:18px;width:440px;max-width:94vw;padding:28px 30px;display:flex;flex-direction:column;gap:16px;box-shadow:0 25px 60px rgba(0,0,0,0.45);font-family:'Poppins',sans-serif;">
            <div style="display:flex;align-items:center;gap:14px;">
              <div style="width:48px;height:48px;border-radius:50%;background:rgba(248,81,73,0.12);border:1px solid rgba(248,81,73,0.3);display:flex;align-items:center;justify-content:center;color:var(--error);font-size:20px;flex-shrink:0;">
                <i class="fa-solid fa-trash"></i>
              </div>
              <h3 id="sre-confirm-title" style="margin:0;font-size:19px;font-weight:700;color:var(--text-strong);"></h3>
            </div>
            <p id="sre-confirm-message" style="margin:0;font-size:14px;line-height:1.6;color:var(--text-secondary);"></p>
            <div style="display:flex;gap:10px;justify-content:flex-end;">
              <button id="sre-confirm-cancel" onmouseover="this.style.background='var(--border-color)';this.style.color='var(--text-strong)';" onmouseout="this.style.background='var(--bg-main)';this.style.color='var(--text-primary)';" style="border:1px solid var(--border-color);background:var(--bg-main);color:var(--text-primary);border-radius:12px;padding:10px 22px;font-size:13px;font-weight:500;font-family:'Poppins',sans-serif;cursor:pointer;transition:all .15s;">Cancel</button>
              <button id="sre-confirm-ok" onmouseover="this.style.filter='brightness(1.08)';this.style.boxShadow='0 10px 30px rgba(248,81,73,0.5)';" onmouseout="this.style.filter='none';this.style.boxShadow='0 8px 24px rgba(248,81,73,0.35)';" style="border:none;border-radius:12px;padding:10px 22px;font-size:13px;font-weight:600;font-family:'Poppins',sans-serif;cursor:pointer;color:#fff;background:linear-gradient(135deg,#f85149 0%,#da3633 100%);box-shadow:0 8px 24px rgba(248,81,73,0.35);transition:all .15s;">Hapus</button>
            </div>
          </div>`;
        document.body.appendChild(overlay);
      }
      overlay.querySelector('#sre-confirm-title').textContent = opts.title || 'Delete?';
      overlay.querySelector('#sre-confirm-message').textContent = opts.message || 'This action cannot be undone.';
      const okBtn = overlay.querySelector('#sre-confirm-ok');
      okBtn.textContent = opts.confirmText || 'Delete';
      overlay.style.display = 'flex';
      const done = (val) => {
        overlay.style.display = 'none';
        okBtn.onclick = null;
        overlay.querySelector('#sre-confirm-cancel').onclick = null;
        overlay.onclick = null;
        resolve(val);
      };
      okBtn.onclick = () => done(true);
      overlay.querySelector('#sre-confirm-cancel').onclick = () => done(false);
      overlay.onclick = (e) => { if (e.target === overlay) done(false); };
    });
  };

  async function deleteSingleHistory(id) {
    const ok = await window.sreConfirm({
      title: 'Delete chat session?',
      message: 'This session and its entire conversation history will be permanently deleted and cannot be recovered.',
      confirmText: 'Delete',
    });
    if (!ok) return;
    const animated = window.animateHistoryRowOut(id);
    if (animated) await new Promise((resolve) => setTimeout(resolve, 250));
    try {
      await window.wsCall('chat.delete', { id });
      if (typeof window.onSessionDeleted === 'function') {
        window.onSessionDeleted(id);
      } else {
        window.location.reload();
      }
    } catch (e) {
      console.error(e);
      alert('Error deleting chat session.');
    }
  }

  async function deleteSelectedHistory() {
    const checkboxes = document.querySelectorAll('.history-checkbox:checked');
    const sessionIds = Array.from(checkboxes).map(cb => cb.value);

    if (sessionIds.length === 0) {
      alert('No chat sessions selected.');
      return;
    }

    const okBulk = await window.sreConfirm({
      title: `Delete ${sessionIds.length} sessions?`,
      message: `${sessionIds.length} selected chat sessions and their entire histories will be permanently deleted and cannot be recovered.`,
      confirmText: 'Delete All',
    });
    if (!okBulk) return;

    try {
      await window.wsCall('chat.bulk_delete', { session_ids: sessionIds });
      toggleBulkEditMode();
      if (typeof window.loadHistoryGlobal === 'function') {
        window.loadHistoryGlobal();
      } else {
        window.location.reload();
      }
    } catch (e) {
      console.error(e);
      alert('An error occurred while contacting the server.');
    }
  }

