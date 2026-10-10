// AI model manager UI. Extracted from templates/chat3.html.
  let currentLoadedAIModels = [];

  function compatibleAutoModels() {
    return currentLoadedAIModels.filter(model => model.is_active);
  }

  function updateAutoModelsButton() {
    const button = document.getElementById('auto-model-btn');
    const selector = document.getElementById('model-selector');
    if (!button || !selector) return;
    const active = localStorage.getItem('sre_auto_models') === 'true';
    const count = compatibleAutoModels().length;
    button.setAttribute('aria-pressed', active ? 'true' : 'false');
    button.style.color = active ? 'var(--success)' : 'var(--text-secondary)';
    button.style.borderColor = active ? 'var(--success)' : 'var(--border-color)';
    button.innerHTML = `<i class="fa-solid fa-rotate"></i> Auto Models: ${active ? `On (${count})` : 'Off'}`;
    button.title = active
      ? `Automatic failover is active across ${count} active models and providers`
      : 'Try active models across providers automatically when one is unavailable';
    selector.style.opacity = active ? '0.72' : '1';
  }

  function toggleAutoModels() {
    const next = localStorage.getItem('sre_auto_models') !== 'true';
    const compatible = compatibleAutoModels();
    if (next && compatible.length < 2) {
      alert('Auto Models needs at least 2 active models. Activate another model in Model Settings first.');
      return;
    }
    localStorage.setItem('sre_auto_models', next ? 'true' : 'false');
    updateAutoModelsButton();
  }

  function purgeBootstrapSelect() {
    if (window.jQuery && $.fn.selectpicker) {
      try {
        $('#permission-selector, #model-selector, #mode-selector, #arch-model-selector').selectpicker('destroy');
      } catch (e) { }
    }
    ['permission-selector', 'model-selector', 'mode-selector', 'arch-model-selector'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        const parent = el.closest('.bootstrap-select');
        if (parent) {
          parent.parentNode.insertBefore(el, parent);
          parent.remove();
        }
      }
    });
  }

  async function loadAIModels() {
    try {
      const res = await fetch('/api/v1/ai-models/');
      const data = await res.json();
      if (data.status === 'success' && Array.isArray(data.models)) {
        currentLoadedAIModels = data.models;
        const selector = document.getElementById('model-selector');
        if (!selector) return;

        const savedVal = localStorage.getItem('sre_selected_model');
        const currentVal = selector.value;
        const targetVal = savedVal || currentVal;

        selector.innerHTML = '';

        data.models.filter(m => m.is_active).forEach(m => {
          const opt = document.createElement('option');
          opt.value = m.model_id;
          opt.textContent = m.name;
          selector.appendChild(opt);
        });

        if (targetVal && Array.from(selector.options).some(o => o.value === targetVal)) {
          selector.value = targetVal;
        } else if (selector.options.length > 0) {
          localStorage.setItem('sre_selected_model', selector.options[0].value);
        }
        // Only now is the select authoritative - refresh the visible label.
        updateModelPickerLabel();
        updateAutoModelsButton();
      }
    } catch (err) {
      console.error('Failed to load AI models:', err);
    }
    purgeBootstrapSelect();
  }

  function openModelManagerModal() {
    document.getElementById('ai-model-modal').style.display = 'flex';
    setModelStatusFilter(window.modelStatusFilter || 'all');
    renderModelManagerTable();
    closeAIModelForm();
  }

  function closeModelManagerModal() {
    document.getElementById('ai-model-modal').style.display = 'none';
    closeAIModelForm();
  }

  function openAddAIModelForm() {
    resetAIModelForm();
    const card = document.getElementById('ai-model-form-card');
    card.style.display = 'flex';
    document.getElementById('ai-model-form-title').innerText = 'Add Model';
    setTimeout(() => {
      const input = document.getElementById('model-name-input');
      if (input) input.focus();
    }, 50);
  }

  function closeAIModelForm() {
    const card = document.getElementById('ai-model-form-card');
    if (card) card.style.display = 'none';
    resetAIModelForm();
  }

  function setModelStatusFilter(val) {
    window.modelStatusFilter = (val === 'active' || val === 'inactive') ? val : 'all';
    const bar = document.getElementById('model-status-filter');
    if (bar) {
      Array.from(bar.querySelectorAll('button')).forEach(b => {
        const active = b.dataset.statusfilter === window.modelStatusFilter;
        b.style.background = active ? 'var(--bg-panel)' : 'transparent';
        b.style.color = active ? 'var(--text-primary)' : 'var(--text-secondary)';
        b.style.boxShadow = active ? '0 1px 2px rgba(0,0,0,0.1)' : 'none';
      });
    }
    if (typeof renderModelManagerTable === 'function') renderModelManagerTable();
  }

  function setModelTableSearch(val) {
    window.modelTableSearch = (val || '').toLowerCase().trim();
    if (typeof renderModelManagerTable === 'function') renderModelManagerTable();
  }

  function modelRowMatches(m, filt, q) {
    if (filt === 'active' && !m.is_active) return false;
    if (filt === 'inactive' && m.is_active) return false;
    if (!q) return true;
    const meta = providerMeta(m.provider);
    return [m.name, m.model_id, m.provider, meta.label, m.base_url]
      .filter(Boolean).join(' ').toLowerCase().includes(q);
  }

  async function persistModelOrder(idsInOrder) {
    // Tulis ulang order 1..N sesuai urutan drag. API hanya punya save per-row,
    // jadi kirim berurutan; yang gagal tidak menghentikan sisanya.
    for (let i = 0; i < idsInOrder.length; i++) {
      const m = currentLoadedAIModels.find(x => String(x.id) === String(idsInOrder[i]));
      if (!m || m.order === i + 1) continue;
      try {
        await window.wsCall('aimodel.save', {
          id: m.id, name: m.name, model_id: m.model_id, provider: m.provider,
          endpoint_type: m.endpoint_type || 'openai', base_url: m.base_url || '',
          order: i + 1, is_active: m.is_active, tool_choice: m.tool_choice || 'any',
        });
        m.order = i + 1;
      } catch (e) { console.error('Failed to persist order for', m.id, e); }
    }
    await loadAIModels();
    renderModelManagerTable();
  }

  function moveModelRow(id, dir) {
    const sorted = [...(currentLoadedAIModels || [])].sort((a, b) => (a.order - b.order) || (a.id - b.id));
    const idx = sorted.findIndex(x => String(x.id) === String(id));
    const j = idx + dir;
    if (idx < 0 || j < 0 || j >= sorted.length) return;
    const tmp = sorted[idx]; sorted[idx] = sorted[j]; sorted[j] = tmp;
    persistModelOrder(sorted.map(x => x.id));
  }

  function renderModelManagerTable() {
    const tbody = document.getElementById('ai-models-table-body');
    const filt = window.modelStatusFilter || 'all';
    const q = window.modelTableSearch || '';
    const visibleModels = (currentLoadedAIModels || []).filter(m => modelRowMatches(m, filt, q));
    const dragLocked = filt !== 'all' || !!q;

    if (!tbody) return;
    if (visibleModels.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="padding: 3rem; text-align: center; color: var(--text-secondary); font-size: 1.1rem;">No models found.</td></tr>`;
      return;
    }
    tbody.innerHTML = visibleModels.map(m => `
      <tr data-model-id="${m.id}"
        ondragover="event.preventDefault(); this.style.background='var(--bg-main)';"
        ondragleave="this.style.background='';"
        ondrop="event.preventDefault(); this.style.background=''; const src=event.dataTransfer.getData('text/plain'); if(src && String(src)!=='${m.id}'){ const sorted=[...(currentLoadedAIModels||[])].sort((a,b)=>(a.order-b.order)||(a.id-b.id)).map(x=>String(x.id)); const from=sorted.indexOf(String(src)); const to=sorted.indexOf('${m.id}'); if(from>-1&&to>-1){ sorted.splice(to,0,sorted.splice(from,1)[0]); persistModelOrder(sorted); } }"
        style="border-bottom: 1px solid var(--border-color);">
        <td style="padding: 1rem 0.5rem; width: 40px; text-align: center;">
          <span draggable="${dragLocked ? 'false' : 'true'}"
            ondragstart="event.dataTransfer.setData('text/plain', '${m.id}'); event.dataTransfer.effectAllowed='move';"
            title="${dragLocked ? 'Drag aktif saat filter All + tanpa search' : 'Drag untuk ubah urutan'}"
            style="cursor: ${dragLocked ? 'default' : 'grab'}; display: inline-block; padding: 4px;">
            <i class="fa-solid fa-grip-vertical" style="color: var(--text-secondary); opacity: ${dragLocked ? '0.2' : '0.5'}; font-size: 1rem;"></i>
          </span>
        </td>
        <td style="padding: 1rem; white-space: normal;">
          <div style="display: flex; align-items: center; gap: 0.75rem;">
            ${providerLogoHtml(m.provider, 28)}
            <div style="display: flex; flex-direction: column;">
              <span style="font-size: 1.1rem; font-weight: 500; color: var(--text-primary); line-height: 1.2;">${escapeHtml(providerMeta(m.provider).label)}</span>
              <span style="font-size: 0.95rem; color: var(--text-secondary);">${(m.endpoint_type || 'openai') === 'anthropic' ? 'Anthropic' : 'OpenAI'} API</span>
            </div>
          </div>
        </td>
        <td style="padding: 1rem; font-size: 1.1rem; font-weight: 600; color: var(--text-strong);">
          ${escapeHtml(m.name)}
        </td>
        <td style="padding: 1rem;">
          <span style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 1rem; padding: 0.35rem 0.65rem; background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); display: inline-block; word-break: break-word; max-width: 100%;">
            ${escapeHtml(m.model_id)}
          </span>
        </td>
        <td style="padding: 1rem; text-align: center; width: 1%; white-space: nowrap;">
          ${m.is_active
        ? `<div style="display: inline-flex; align-items: center; gap: 6px; padding: 0.35rem 0.75rem; background: rgba(16, 185, 129, 0.1); color: rgb(16, 185, 129); border-radius: 9999px; font-size: 1rem; font-weight: 500;"><div style="width: 8px; height: 8px; border-radius: 50%; background: rgb(16, 185, 129);"></div>Active</div>`
        : `<div style="display: inline-flex; align-items: center; gap: 6px; padding: 0.35rem 0.75rem; background: var(--bg-main); color: var(--text-secondary); border-radius: 9999px; font-size: 1rem; font-weight: 500;"><div style="width: 8px; height: 8px; border-radius: 50%; background: var(--text-secondary);"></div>Inactive</div>`
      }
        </td>
        <td style="padding: 1rem; text-align: right; width: 1%; white-space: nowrap;">
          <div style="display: inline-flex; gap: 0.5rem; justify-content: flex-end;">
            <button onclick="editAIModel(${m.id})" style="display: inline-flex; align-items: center; gap: 6px; background: var(--bg-main); border: 1px solid var(--border-color); color: var(--text-primary); padding: 0.5rem 1rem; border-radius: 6px; font-size: 1.05rem; font-weight: 500; cursor: pointer; transition: all 0.15s;" onmouseover="this.style.background='var(--bg-panel)'; this.style.borderColor='var(--accent)';" title="Edit">
              <i class="fa-solid fa-pen"></i> Edit
            </button>
            <button onclick="deleteAIModel(${m.id})" style="display: inline-flex; align-items: center; gap: 6px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: rgb(239, 68, 68); padding: 0.5rem 1rem; border-radius: 6px; font-size: 1.05rem; font-weight: 500; cursor: pointer; transition: all 0.15s;" onmouseover="this.style.background='rgb(239, 68, 68)'; this.style.color='#fff';" title="Delete">
              <i class="fa-solid fa-trash"></i> Hapus
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  }





  /* ---------- Provider catalog: selectable + searchable, with logo ---------- */
  const AI_PROVIDER_CATALOG = [
    { id: '9router', label: '9Router', domain: 'router.com', fallback: '9', color: '#1f6feb', baseUrl: 'http://localhost:20128/v1', models: ['OPENCODE', '9router:auto'] },
    { id: 'openai', label: 'OpenAI', domain: 'openai.com', fallback: 'O', color: '#10a37f', baseUrl: '', models: ['gpt-4o', 'gpt-4o-mini', 'o3-mini'] },
    { id: 'anthropic', label: 'Anthropic', domain: 'anthropic.com', fallback: 'A', color: '#d97757', baseUrl: '', endpoint: 'anthropic', models: ['claude-sonnet-4-20250514', 'claude-3-5-sonnet-20241022'] },
    { id: 'deepseek', label: 'DeepSeek', domain: 'deepseek.com', fallback: 'D', color: '#4d6bfe', baseUrl: 'https://api.deepseek.com/v1', models: ['deepseek-chat', 'deepseek-reasoner'] },
    { id: 'minimax', label: 'MiniMax', domain: 'minimax.io', fallback: 'M', color: '#e5484d', baseUrl: 'https://api.minimax.chat/v1', models: ['MiniMax-Text-01'] },
    { id: 'mistral', label: 'Mistral AI', domain: 'mistral.ai', fallback: 'M', color: '#ff7000', baseUrl: '', models: ['mistral-large-latest'] },
    { id: 'groq', label: 'Groq', domain: 'groq.com', fallback: 'G', color: '#f55036', baseUrl: '', models: ['llama-3.3-70b-versatile'] },
    { id: 'nvidia', label: 'NVIDIA', domain: 'nvidia.com', fallback: 'N', color: '#76b900', baseUrl: 'https://integrate.api.nvidia.com/v1', models: ['nvidia/llama-3.1-nemotron-70b-instruct'] },
    { id: 'ollama', label: 'Ollama', domain: 'ollama.com', fallback: 'O', color: '#a3a3a3', baseUrl: 'http://127.0.0.1:11434', models: ['qwen2.5-coder:latest'] },
    { id: 'gemini', label: 'Google Gemini', domain: 'google.com', fallback: 'G', color: '#1a73e8', baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/', models: ['gemini-2.0-flash'] },
    { id: 'xai', label: 'xAI Grok', domain: 'x.ai', fallback: 'X', color: '#cccccc', baseUrl: 'https://api.x.ai/v1', models: ['grok-2-latest'] },
    { id: 'cohere', label: 'Cohere', domain: 'cohere.com', fallback: 'C', color: '#39594d', baseUrl: 'https://api.cohere.ai/compatibility/v1', models: ['command-r-plus'] },
    { id: 'together', label: 'Together AI', domain: 'together.ai', fallback: 'T', color: '#7c3aed', baseUrl: 'https://api.together.xyz/v1', models: ['meta-llama/Llama-3.3-70B-Instruct-Turbo'] },
    { id: 'fireworks', label: 'Fireworks', domain: 'fireworks.ai', fallback: 'F', color: '#f97316', baseUrl: 'https://api.fireworks.ai/inference/v1', models: ['accounts/fireworks/models/llama-v3p1-70b-instruct'] },
    { id: 'openrouter', label: 'OpenRouter', domain: 'openrouter.ai', fallback: 'O', color: '#8b5cf6', baseUrl: 'https://openrouter.ai/api/v1', models: ['anthropic/claude-3.5-sonnet'] },
    { id: 'perplexity', label: 'Perplexity', domain: 'perplexity.ai', fallback: 'P', color: '#20b8cd', baseUrl: 'https://api.perplexity.ai', models: ['llama-3.1-sonar-large-128k-online'] },
    { id: 'qwen', label: 'Qwen', domain: 'qwen.ai', fallback: 'Q', color: '#6c5ce7', baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1', models: ['qwen-max'] },
    { id: 'moonshot', label: 'Moonshot', domain: 'moonshot.ai', fallback: 'M', color: '#fbbf24', baseUrl: 'https://api.moonshot.ai/v1', models: ['moonshot-v1-8k'] },
    { id: 'zhipu', label: 'Zhipu', domain: 'zhipuai.cn', fallback: 'Z', color: '#0ea5e9', baseUrl: 'https://open.bigmodel.cn/api/paas/v4/', models: ['glm-4-plus'] },
    { id: 'azure', label: 'Azure OpenAI', domain: 'azure.microsoft.com', fallback: 'A', color: '#0078d4', baseUrl: '', models: ['gpt-4o'] },
    { id: 'bedrock', label: 'AWS Bedrock', domain: 'aws.amazon.com', fallback: 'B', color: '#ff9900', baseUrl: '', models: ['anthropic.claude-3-5-sonnet-20241022-v2:0'] },
    { id: 'huggingface', label: 'Hugging Face', domain: 'huggingface.co', fallback: 'H', color: '#ff9d0a', baseUrl: 'https://api-inference.huggingface.co/v1', models: ['meta-llama/Llama-3.3-70B-Instruct'] },
    { id: 'xiaomi', label: 'Xiaomi MiMo', domain: 'mimo.mi.com', fallback: 'X', color: '#ff6900', baseUrl: '', models: [] },
    { id: 'cerebras', label: 'Cerebras', domain: 'cerebras.ai', fallback: 'C', color: '#ff4c00', baseUrl: 'https://api.cerebras.ai/v1', models: ['llama3.1-8b'] },
    { id: 'other', label: 'Other / Custom', domain: '', fallback: 'O', color: '#6b7280', baseUrl: '', models: [] },
  ];

  function providerMeta(pid) {
    const key = String(pid || '').toLowerCase();
    return AI_PROVIDER_CATALOG.find(p => p.id === key)
      || AI_PROVIDER_CATALOG.find(p => p.label.toLowerCase() === key)
      || { id: key || 'other', label: pid || 'Other', domain: '', fallback: pid.charAt(0).toUpperCase() || 'O', color: '#6b7280', baseUrl: '', models: [] };
  }

  function providerLogoHtml(pid, size) {
    const meta = providerMeta(pid);
    const s = size || 24;
    if (meta.domain) {
      return `<img src="https://www.google.com/s2/favicons?sz=64&domain=${meta.domain}" alt="${escapeHtml(meta.label)}" style="width: ${s}px; height: ${s}px; border-radius: 14px; object-fit: contain; flex-shrink: 0; background: transparent; padding: 0;" onerror="this.onerror=null; this.outerHTML='<span style=\'display:inline-flex; align-items:center; justify-content:center; width:${s}px; height:${s}px; border-radius:14px; font-size:${Math.round(s*0.6)}px; background:${meta.color}22; border:1px solid ${meta.color}66; color:${meta.color}; font-weight:bold;\'>${escapeHtml(meta.fallback)}</span>'"/>`;
    }
    return `<span title="${escapeHtml(meta.label)}" style="display: inline-flex; align-items: center; justify-content: center; width: ${s}px; height: ${s}px; border-radius: 14px; font-size: ${Math.round(s * 0.6)}px; background: ${meta.color}22; border: 1px solid ${meta.color}66; color: ${meta.color}; font-weight: bold; flex-shrink: 0;">${escapeHtml(meta.fallback)}</span>`;
  }

  function getModelProviderValue() {
    const el = document.getElementById('model-provider-input');
    return (el && el.value ? el.value : '9router').toLowerCase();
  }

  function setModelProviderValue(pid, opts) {
    const meta = providerMeta(pid);
    const input = document.getElementById('model-provider-input');
    const label = document.getElementById('model-provider-label');
    const logo = document.getElementById('model-provider-logo');
    if (input) input.value = meta.id;
    if (label) label.textContent = meta.label;
    if (logo) logo.innerHTML = providerLogoHtml(meta.id, 20);
    renderModelIdSuggestions();
    if (!(opts && opts.keepOpen)) closeProviderDropdown();
    const base = document.getElementById('model-baseurl-input');
    if (base && !base.value && meta.baseUrl && !(opts && opts.noPrefill)) base.placeholder = meta.baseUrl;
    if (meta.endpoint && !(opts && opts.noEndpoint)) setModelEndpointType(meta.endpoint);
  }

  function toggleProviderDropdown(e) {
    if (e) e.stopPropagation();
    const dd = document.getElementById('model-provider-dropdown');
    if (!dd) return;
    const open = dd.style.display !== 'none';
    if (open) { dd.style.display = 'none'; return; }
    dd.style.display = 'block';
    const s = document.getElementById('model-provider-search');
    if (s) { s.value = ''; s.focus(); }
    renderProviderDropdown();
  }

  function closeProviderDropdown() {
    const dd = document.getElementById('model-provider-dropdown');
    if (dd) dd.style.display = 'none';
  }

  function renderProviderDropdown() {
    const box = document.getElementById('model-provider-options');
    const q = ((document.getElementById('model-provider-search') || {}).value || '').toLowerCase().trim();
    if (!box) return;
    const list = AI_PROVIDER_CATALOG.filter(p =>
      !q || p.label.toLowerCase().includes(q) || p.id.includes(q));
    box.innerHTML = list.length ? list.map(p => `
      <div onclick="setModelProviderValue('${p.id}')"
        style="display: flex; align-items: center; gap: 1rem; padding: 0.5rem; border-radius: 6px; cursor: pointer; font-size: 1.1rem; transition: background 0.15s;"
        onmouseover="this.style.background='var(--bg-main)'" onmouseout="this.style.background='transparent'">
        ${providerLogoHtml(p.id, 20)}
        <span style="flex: 1; font-weight: 500; color: var(--text-primary);">${escapeHtml(p.label)}</span>
      </div>`).join('')
      : `<div style="padding: 1rem; font-size: 1.1rem; color: var(--text-secondary); text-align: center;">Not found.<br><button type="button" onclick="setModelProviderValue(document.getElementById('model-provider-search').value.trim() || 'other')" style="margin-top: 0.5rem; background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 4px; padding: 0.25rem 0.5rem; font-size: 1rem; cursor: pointer; color: var(--text-primary);">Use Custom</button></div>`;
  }

  function renderModelIdSuggestions() {
    const dl = document.getElementById('model-id-suggestions');
    const hint = document.getElementById('model-id-hint');
    if (!dl) return;
    const meta = providerMeta(getModelProviderValue());
    dl.innerHTML = (meta.models || []).map(m => `<option value="${escapeHtml(m)}">`).join('');
    if (hint) hint.textContent = (meta.models || []).length
      ? `${meta.models.length} Model ID populer ${meta.label} — klik kolom Model ID untuk pilih, atau Test Connection untuk ID valid dari endpoint.`
      : 'Ketik Model ID lalu Test Connection untuk melihat ID valid dari endpoint.';
  }

  function toggleModelApiKeyVisibility() {
    const inp = document.getElementById('model-apikey-input');
    const eye = document.getElementById('model-apikey-eye');
    if (!inp) return;
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    if (eye) eye.className = show ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
  }

  document.addEventListener('click', function (e) {
    const combo = document.getElementById('model-provider-combo');
    const dd = document.getElementById('model-provider-dropdown');
    if (dd && dd.style.display !== 'none' && combo && !combo.contains(e.target)) closeProviderDropdown();
  });

  const MODEL_ENDPOINT_INFO = {
    'openai': { hint: 'Chat-completions transport (OpenAI, 9Router, proxy apapun). Default untuk semua provider.', placeholder: 'http://localhost:20128/v1' },
    'anthropic': { hint: 'Anthropic NATIVE Messages API (api.anthropic.com). Kosongkan Base URL. Wajib API key sk-ant-... Isi Base URL hanya bila pakai proxy OpenAI-compatible.', placeholder: '(kosongkan untuk native)' }
  };

  // Per-model tool calling: thinking models (DeepSeek thinking mode) answer the
  // tool-forcing headers with a 400, so they need the model to decide instead.
  const MODEL_TOOLCHOICE_HINTS = {
    any: 'Force a tool call every ReAct turn. Default; works for Anthropic and most OpenAI-compatible endpoints.',
    auto: 'Let the model decide. Required for thinking/reasoning models that reject forced calls (DeepSeek thinking mode).',
  };

  function getModelToolChoice() {
    const toggle = document.getElementById('model-toolchoice-toggle');
    if (!toggle) return 'any';
    const active = toggle.querySelector('[data-toolchoice].active-choice');
    return active ? active.dataset.toolchoice : 'any';
  }

  function setModelToolChoice(val) {
    const toggle = document.getElementById('model-toolchoice-toggle');
    if (!toggle) return;
    toggle.querySelectorAll('[data-toolchoice]').forEach(b => {
      const on = b.dataset.toolchoice === val;
      b.classList.toggle('active-choice', on);
      b.style.background = on ? 'var(--bg-panel)' : 'transparent';
      b.style.color = on ? 'var(--text-primary)' : 'var(--text-secondary)';
      b.style.boxShadow = on ? '0 1px 2px rgba(0,0,0,0.1)' : 'none';
    });
  }

  function setModelEndpointType(val) {
    const toggle = document.getElementById('model-endpoint-toggle');
    const v = (val === 'anthropic') ? 'anthropic' : 'openai';
    if (toggle) {
      toggle.dataset.value = v;
      Array.from(toggle.querySelectorAll('button')).forEach(b => {
        const active = b.dataset.endpoint === v;
        b.style.background = active ? 'var(--bg-panel)' : 'transparent';
        b.style.color = active ? 'var(--text-primary)' : 'var(--text-secondary)';
        b.style.boxShadow = active ? '0 1px 2px rgba(0,0,0,0.1)' : 'none';
      });
    }
    const base = document.getElementById('model-baseurl-input');
    const info = MODEL_ENDPOINT_INFO[v];
    if (base && !base.value && info) base.placeholder = info.placeholder;
    const hint = document.getElementById('model-endpoint-hint');
    if (hint && info) hint.textContent = info.hint;
  }

  function getModelEndpointType() {
    const toggle = document.getElementById('model-endpoint-toggle');
    const v = toggle && toggle.dataset.value;
    return (v === 'anthropic') ? 'anthropic' : 'openai';
  }

  function resetAIModelForm() {
    const editId = document.getElementById('model-edit-id');
    if (editId) editId.value = '';
    const nameInput = document.getElementById('model-name-input');
    if (nameInput) nameInput.value = '';
    const idInput = document.getElementById('model-id-input');
    if (idInput) idInput.value = '';
    setModelProviderValue('9router', { keepOpen: true, noPrefill: true });
    setModelEndpointType('openai');
    setModelToolChoice('any');
    const baseUrlInput = document.getElementById('model-baseurl-input');
    if (baseUrlInput) baseUrlInput.value = '';
    const apiKeyInput = document.getElementById('model-apikey-input');
    if (apiKeyInput) apiKeyInput.value = '';
    const orderInput = document.getElementById('model-order-input');
    if (orderInput) orderInput.value = '0';
    const activeInput = document.getElementById('model-active-input');
    if (activeInput) activeInput.checked = true;
    const resDiv = document.getElementById('ai-model-test-result');
    if (resDiv) { resDiv.style.display = 'none'; resDiv.innerHTML = ''; }
  }

  function editAIModel(id) {
    const m = currentLoadedAIModels.find(x => x.id == id);
    if (!m) return;
    document.getElementById('model-edit-id').value = m.id;
    document.getElementById('model-name-input').value = m.name;
    document.getElementById('model-id-input').value = m.model_id;
    setModelProviderValue(m.provider || '9router', { keepOpen: true });
    setModelEndpointType(m.endpoint_type || 'openai');
    setModelToolChoice(m.tool_choice || 'any');
    document.getElementById('model-baseurl-input').value = m.base_url || '';
    // The secret is write-only: the field stays empty and only a freshly
    // typed value is ever sent. Untouched means keep the stored key.
    document.getElementById('model-apikey-input').value = '';
    document.getElementById('model-apikey-input').placeholder =
      m.has_key ? '•••••••• (saved — leave blank to keep)' : 'sk-… (paste a key to set one)';
    document.getElementById('model-order-input').value = m.order;
    document.getElementById('model-active-input').checked = m.is_active;
    document.getElementById('ai-model-form-title').innerText = 'Edit Model: ' + m.name;

    const card = document.getElementById('ai-model-form-card');
    card.style.display = 'block';
    setTimeout(() => {
      const input = document.getElementById('model-name-input');
      if (input) input.focus();
    }, 50);
  }

  async function saveAIModelForm(e) {
    e.preventDefault();
    const id = document.getElementById('model-edit-id').value;
    const payload = {
      name: document.getElementById('model-name-input').value,
      model_id: document.getElementById('model-id-input').value,
      provider: document.getElementById('model-provider-input').value,
      endpoint_type: getModelEndpointType(),
      base_url: document.getElementById('model-baseurl-input').value,
      order: parseInt(document.getElementById('model-order-input').value) || 0,
      is_active: document.getElementById('model-active-input').checked,
      tool_choice: getModelToolChoice()
    };

    const _typedKey = document.getElementById('model-apikey-input').value.trim();
    if (_typedKey) payload.api_key = _typedKey;

    try {
      const data = await window.wsCall('aimodel.save', Object.assign({}, payload, id ? { id } : {}));
      if (data.status === 'success') {
        const savedModelId = payload.model_id;
        localStorage.setItem('sre_selected_model', savedModelId);
        await loadAIModels();
        const mainSel = document.getElementById('model-selector');
        if (mainSel && Array.from(mainSel.options).some(o => o.value === savedModelId)) {
          mainSel.value = savedModelId;
        }
        renderModelManagerTable();
        closeAIModelForm();
      } else {
        alert('Error saving model: ' + (data.message || 'Unknown error'));
      }
    } catch (err) {
      alert('Failed to save model: ' + err.toString());
    }
  }

  async function deleteAIModel(id) {
    if (!confirm('Are you sure you want to delete this model configuration?')) return;
    try {
      const data = await window.wsCall('aimodel.delete', { id });
      if (data.status === 'success') {
        await loadAIModels();
        renderModelManagerTable();
        closeAIModelForm();
      } else {
        alert('Error deleting model: ' + (data.message || 'Unknown error'));
      }
    } catch (err) {
      alert('Failed to delete model: ' + err.toString());
    }
  }

  async function testAIModelForm() {
    const testBtn = document.getElementById('model-test-btn');
    const resultDiv = document.getElementById('ai-model-test-result');
    if (!testBtn || !resultDiv) return;

    const payload = {
      id: document.getElementById('model-edit-id').value || '',
      model_id: document.getElementById('model-id-input').value,
      provider: document.getElementById('model-provider-input').value,
      endpoint_type: getModelEndpointType(),
      base_url: document.getElementById('model-baseurl-input').value,
      api_key: document.getElementById('model-apikey-input').value.trim(),
    };

    if (!payload.model_id) {
      alert('Please enter a Model ID first.');
      return;
    }

    testBtn.disabled = true;
    testBtn.innerHTML = `<i class="fa-solid fa-spinner spin-anim me-1"></i> Testing...`;
    resultDiv.style.display = 'none';

    try {
      const data = await window.wsCall('aimodel.test', payload, 60000);
      resultDiv.style.display = 'block';

      if (data.status === 'success') {
        let text = `<b><i class="fa-solid fa-circle-check me-1"></i> ${data.message}</b>`;
        if (data.reply) text += `<br><span style="opacity: 0.8;">Response preview: "${escapeHtml(data.reply)}"</span>`;
        if (data.available_models && data.available_models.length > 0) {
          text += `<br><span style="font-size: 11px;">Available Models from Endpoint: <code>${data.available_models.join(', ')}</code></span>`;
        }
        resultDiv.style.background = 'rgba(45, 164, 78, 0.15)';
        resultDiv.style.border = '1px solid var(--success)';
        resultDiv.style.color = 'var(--success-text)';
        resultDiv.innerHTML = text;
      } else {
        let text = `<b><i class="fa-solid fa-circle-xmark me-1"></i> Connection / Model Failed:</b> ${escapeHtml(data.message)}`;
        if (data.available_models && data.available_models.length > 0) {
          text += `<br><span style="font-weight: 600;">Valid Model IDs returned by Endpoint:</span> <code style="user-select: all;">${data.available_models.join(', ')}</code>`;
        }
        resultDiv.style.background = 'rgba(248, 81, 73, 0.15)';
        resultDiv.style.border = '1px solid var(--error)';
        resultDiv.style.color = 'var(--error)';
        resultDiv.innerHTML = text;
      }
    } catch (err) {
      resultDiv.style.display = 'block';
      resultDiv.style.background = 'rgba(248, 81, 73, 0.15)';
      resultDiv.style.border = '1px solid var(--error)';
      resultDiv.style.color = 'var(--error)';
      resultDiv.innerHTML = `<b><i class="fa-solid fa-circle-xmark me-1"></i> Error:</b> ${escapeHtml(err.toString())}`;
    } finally {
      testBtn.disabled = false;
      testBtn.innerHTML = `<i class="fa-solid fa-vial me-1"></i> Test Connection`;
    }
  }

  // --- Architecture Feature Logic ---
  let archSocket = null;
  let cachedServices = [];
  let archPollingInterval = null;

  function initArchitectureSocket() {
    if (!archSocket || archSocket.readyState === WebSocket.CLOSED) {
      const wsScheme = window.location.protocol === "https:" ? "wss" : "ws";
      archSocket = new WebSocket(`${wsScheme}://${window.location.host}/ws/architecture/`);

      archSocket.onopen = function () {
        archSocket.send(JSON.stringify({ type: 'load_cache' }));
      };

      archSocket.onmessage = function (e) {
        const data = JSON.parse(e.data);
        console.log('📩 Architecture WS received:', data.type, data);
        if (data.type === 'arch_sudo_key_exchange') {
          window.archServerRsaPublicKey = data.public_key;
        } else if (data.type === 'arch_not_found') {
          // No cache in DB, show setup view for new generation
          showArchSetup();
        } else if (data.type === 'arch_progress') {
          document.getElementById('arch-progress-container').style.display = 'flex';
          document.getElementById('arch-content-container').style.display = 'none';
          document.getElementById('arch-progress-text').innerText = data.step;
        } else if (data.type === 'arch_result') {
          renderArchitecture(data.data, data.cached);
        } else if (data.type === 'arch_error') {
          alert("Architecture Generation Failed: " + data.message);
          showArchSetup();
        } else if (data.type === 'status_result') {
          updateServicesStatus(data.services);
        }
      };
    } else if (archSocket.readyState === WebSocket.OPEN) {
      archSocket.send(JSON.stringify({ type: 'get_cached_arch' }));
    }
  }

  function openArchitectureModal() {
    document.getElementById('architecture-modal').style.display = 'flex';
    initArchitectureSocket();
  }



  function closeArchitectureModal() {
    document.getElementById('architecture-modal').style.display = 'none';
    stopArchPolling();
  }

  function regenerateArchitecture() {
    showArchSetup();
  }

  async function refreshArchModels(spinIcon = false) {
    const archSelector = document.getElementById('arch-model-selector');
    if (!archSelector) return;

    const icon = document.getElementById('arch-refresh-icon');
    if (spinIcon && icon) icon.classList.add('fa-spin');

    // Destroy bootstrap-select on this element if it exists to ensure standard rendering
    if (window.jQuery && $.fn.selectpicker) {
      try {
        $(archSelector).selectpicker('destroy');
      } catch (e) { }
    }

    archSelector.innerHTML = '';

    try {
      const res = await fetch('/api/v1/ai-models/');
      const data = await res.json();
      const modelsList = Array.isArray(data) ? data : (data.models || []);

      if (modelsList.length > 0) {
        modelsList.filter(m => m.is_active).forEach(m => {
          const opt = document.createElement('option');
          opt.value = m.model_id;
          opt.textContent = m.name;
          archSelector.appendChild(opt);
        });
      }
    } catch (err) {
      console.error("Failed to fetch models for architecture modal:", err);
    }

    // Fallback if fetch produced no options
    if (archSelector.options.length === 0) {
      const mainSelector = document.getElementById('model-selector');
      if (mainSelector) {
        Array.from(mainSelector.options).forEach(mOpt => {
          const opt = document.createElement('option');
          opt.value = mOpt.value;
          opt.textContent = mOpt.textContent;
          archSelector.appendChild(opt);
        });
      }
    }

    const mainSelector = document.getElementById('model-selector');
    if (mainSelector && mainSelector.value) {
      archSelector.value = mainSelector.value;
    }

    purgeBootstrapSelect();

    if (spinIcon && icon) {
      setTimeout(() => icon.classList.remove('fa-spin'), 400);
    }
  }

  async function showArchSetup() {
    document.getElementById('arch-progress-container').style.display = 'none';
    document.getElementById('arch-content-container').style.display = 'none';
    document.getElementById('arch-setup-container').style.display = 'flex';

    await refreshArchModels();
  }

  async function startArchGeneration(e) {
    if (e && e.preventDefault) e.preventDefault();
    const pwdInput = document.getElementById('arch-sudo-pwd-input');
    const pwd = pwdInput ? pwdInput.value : '';
    if (!pwd) {
      alert("Sudo password is required to perform deep system scans.");
      return;
    }

    if (!window.archServerRsaPublicKey) {
      alert("RSA Public Key not received from server yet. Please wait.");
      return;
    }

    if (!window.crypto || !window.crypto.subtle) {
      alert("Cryptography API not available. This feature requires a secure context (HTTPS or localhost).");
      return;
    }

    let encryptedBase64 = "";
    try {
      const keyBuffer = pemToArrayBuffer(window.archServerRsaPublicKey);
      const importedKey = await window.crypto.subtle.importKey(
        "spki",
        keyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );
      const encodedPwd = new TextEncoder().encode(pwd);
      const encryptedBuf = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        importedKey,
        encodedPwd
      );
      encryptedBase64 = window.btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedBuf)));
    } catch (err) {
      console.error("Encryption failed:", err);
      alert("Failed to encrypt sudo password: " + (err.message || err.toString()));
      return;
    }

    document.getElementById('arch-setup-container').style.display = 'none';
    document.getElementById('arch-progress-container').style.display = 'flex';
    document.getElementById('arch-content-container').style.display = 'none';
    document.getElementById('arch-progress-text').innerText = 'Starting dynamic scan...';

    const archSelector = document.getElementById('arch-model-selector');
    const modelId = archSelector ? archSelector.value : "mistral:latest";

    if (!archSocket || archSocket.readyState !== WebSocket.OPEN) {
      alert("WebSocket is not connected to the server yet. Please wait a moment or refresh the page.");
      showArchSetup();
      return;
    }

    try {
      archSocket.send(JSON.stringify({ type: 'generate', model_id: modelId, encrypted_password: encryptedBase64 }));
    } catch (sendErr) {
      alert("Failed to send generate request: " + sendErr.message);
      showArchSetup();
    }
  }

  function renderArchitecture(data, isCached) {
    document.getElementById('arch-setup-container').style.display = 'none';
    document.getElementById('arch-progress-container').style.display = 'none';
    document.getElementById('arch-content-container').style.display = 'flex';

    const cachedBadge = document.getElementById('arch-cached-badge');
    if (isCached) {
      cachedBadge.style.display = 'inline-block';
    } else {
      cachedBadge.style.display = 'none';
    }

    // 1. Render Mermaid
    const mermaidContainer = document.getElementById('mermaid-container');
    mermaidContainer.innerHTML = ''; // clear previous
    if (data.mermaid_diagram) {
      try {
        const id = 'mermaid-graph-' + Date.now();
        mermaid.render(id, data.mermaid_diagram).then(result => {
          mermaidContainer.innerHTML = result.svg;
          // Make interactive using svg-pan-zoom
          const svgEl = mermaidContainer.querySelector('svg');
          if (svgEl) {
            svgEl.style.width = '100%';
            svgEl.style.height = '100%';
            svgEl.style.maxWidth = '100%';
            svgPanZoom(svgEl, {
              zoomEnabled: true,
              controlIconsEnabled: true,
              fit: true,
              center: true,
              minZoom: 0.1,
              maxZoom: 10
            });
          }
        }).catch(err => {
          mermaidContainer.innerHTML = `<div style="color:var(--error);">Failed to render diagram: ${err.message}</div><pre style="color:var(--text-secondary);font-size:11px;">${escapeHtml(data.mermaid_diagram)}</pre>`;
        });
      } catch (err) {
        mermaidContainer.innerHTML = `<div style="color:var(--error);">Error parsing diagram: ${err.message}</div><pre style="color:var(--text-secondary);font-size:11px;">${escapeHtml(data.mermaid_diagram)}</pre>`;
      }
    }

    const infraContainer = document.getElementById('arch-infrastructure-container');
    if (data.infrastructure || data.network) {
      infraContainer.style.display = 'grid';

      let sysHtml = '';
      if (data.infrastructure) {
        const inf = data.infrastructure;
        if (inf.hostname) sysHtml += `<div><strong>Hostname:</strong> ${escapeHtml(inf.hostname)}</div>`;
        if (inf.os) sysHtml += `<div><strong>OS:</strong> ${escapeHtml(inf.os)} (${escapeHtml(inf.kernel || '')})</div>`;
        if (inf.cpu && inf.cpu.cores) sysHtml += `<div><strong>CPU:</strong> ${inf.cpu.cores} Cores - ${escapeHtml(inf.cpu.model || '')}</div>`;
        if (inf.ram && inf.ram.total) sysHtml += `<div><strong>RAM:</strong> ${escapeHtml(inf.ram.total)} (Used: ${escapeHtml(inf.ram.used || '')})</div>`;
      }
      document.getElementById('arch-sys-info').innerHTML = sysHtml || '<em>No system data</em>';

      let netHtml = '';
      if (data.network) {
        const net = data.network;
        if (net.gateway) netHtml += `<div><strong>Gateway:</strong> ${escapeHtml(net.gateway)}</div>`;
        if (net.dns && net.dns.length) netHtml += `<div><strong>DNS:</strong> ${escapeHtml(net.dns.join(', '))}</div>`;
        if (net.interfaces && net.interfaces.length) {
          netHtml += `<div><strong>Interfaces:</strong></div><ul style="margin:2px 0 0 20px; padding:0;">`;
          net.interfaces.forEach(i => {
            netHtml += `<li>${escapeHtml(i.name)}: ${escapeHtml(i.ip)}</li>`;
          });
          netHtml += `</ul>`;
        }
      }
      document.getElementById('arch-net-info').innerHTML = netHtml || '<em>No network data</em>';
    } else {
      infraContainer.style.display = 'none';
    }

    // 3. Render Services List
    cachedServices = data.services || [];
    renderServicesList(cachedServices);

    // Immediately poll status after render
    pollArchStatus();
  }

  function renderServicesList(services) {
    console.log('🔧 renderServicesList called with:', services?.length, 'services');
    const container = document.getElementById('arch-services-container');
    console.log('📦 Container found:', !!container);
    console.log('📦 Container display:', container?.style.display);
    console.log('📦 Container parent visible:', container?.offsetParent !== null);

    if (!services || !Array.isArray(services) || services.length === 0) {
      container.innerHTML = '<div style="color:var(--text-secondary);font-size:13px;">No services detected.</div>';
      return;
    }

    // Group by type dynamically
    const groups = {};
    services.forEach(s => {
      if (!s) return;
      const name = String(s.name || s.service_name || s.service || s.raw_name || 'Unknown Service');
      const t = String(s.type || s.category || 'System Service');
      if (!groups[t]) groups[t] = [];

      const safeService = {
        name: name,
        type: t,
        status: String(s.status || 'running'),
        ports: Array.isArray(s.ports) ? s.ports : (s.port ? [s.port] : [])
      };
      groups[t].push(safeService);
    });

    let html = '';
    for (const [type, list] of Object.entries(groups)) {
      html += `
        <div style="background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; margin-bottom: 12px;">
          <div style="background: rgba(255,255,255,0.05); padding: 8px 12px; font-size: 12px; font-weight: 600; color: var(--text-primary); border-bottom: 1px solid var(--border-color);">
            ${escapeHtml(type.toUpperCase())}
          </div>
          <div style="padding: 12px; display: flex; flex-direction: column; gap: 8px;">
            ${list.map(s => {
        const isRunning = s.status.toLowerCase() === 'running' || s.status.toLowerCase() === 'active';
        const statusColor = isRunning ? 'var(--success-text)' : 'var(--error)';
        const statusIcon = isRunning ? 'fa-circle-check' : 'fa-circle-xmark';
        const sId = 'srv-status-' + s.name.replace(/[^a-zA-Z0-9]/g, '-');
        const portsDisplay = s.ports.length > 0 ? s.ports.join(', ') : '-';
        return `
              <div style="display: flex; justify-content: space-between; align-items: center; font-size: 13px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <i id="${sId}-icon" class="fa-solid ${statusIcon}" style="color: ${statusColor}; font-size: 14px;"></i>
                  <span style="color: var(--text-strong); font-weight: 500;">${escapeHtml(s.name)}</span>
                </div>
                <div style="text-align: right;">
                  <div id="${sId}-text" style="color: ${statusColor}; font-size: 11px; font-weight: 600; text-transform: uppercase;">${escapeHtml(s.status)}</div>
                  <div style="color: var(--text-secondary); font-size: 11px;">Port: ${escapeHtml(portsDisplay)}</div>
                </div>
              </div>
              `;
      }).join('<div style="height:1px; background:var(--border-color); margin: 4px 0;"></div>')}
          </div>
        </div>
      `;
    }
    console.log('✅ HTML generated:', html.substring(0, 200));

    container.innerHTML = html || '<div style="color:var(--text-secondary);font-size:13px;">No services detected.</div>';
    console.log('✅ Container innerHTML set!');
    console.log('✅ Container children count:', container.children.length);
  }

  function updateServicesStatus(updatedServices) {
    document.getElementById('arch-status-spinner').style.display = 'none';
    updatedServices.forEach(s => {
      const sId = 'srv-status-' + s.name.replace(/[^a-zA-Z0-9]/g, '-');
      const iconEl = document.getElementById(`${sId}-icon`);
      const textEl = document.getElementById(`${sId}-text`);
      if (iconEl && textEl) {
        const statusColor = s.status === 'running' ? 'var(--success-text)' : 'var(--error)';
        const statusIcon = s.status === 'running' ? 'fa-circle-check' : 'fa-circle-xmark';
        iconEl.className = `fa-solid ${statusIcon}`;
        iconEl.style.color = statusColor;
        textEl.innerText = s.status.toUpperCase();
        textEl.style.color = statusColor;
      }
    });
  }

  function pollArchStatus() {
    if (!cachedServices || cachedServices.length === 0) return;
    if (archSocket && archSocket.readyState === WebSocket.OPEN) {
      document.getElementById('arch-status-spinner').style.display = 'inline-block';
      archSocket.send(JSON.stringify({ type: 'status_update', services: cachedServices }));
    }
  }

  function startArchPolling() {
    if (archPollingInterval) clearInterval(archPollingInterval);
    archPollingInterval = setInterval(() => {
      pollArchStatus();
    }, 5000); // Poll every 5 seconds
  }

  function stopArchPolling() {
    if (archPollingInterval) {
      clearInterval(archPollingInterval);
      archPollingInterval = null;
    }
  }

  // ============================================
  // IN-COMPOSER MODEL PICKER + MODE SYNC + BEAM STATE
  // ============================================

  // The real <select id="model-selector"> stays hidden; this picker is the
  // visible control and writes back into it so all existing code paths
  // (submit payload, architecture modal, failover) keep working.
  function closeModelPicker() {
    const panel = document.getElementById('model-picker-panel');
    if (panel) panel.classList.remove('open');
  }

  function toggleModelPicker(ev) {
    if (ev) ev.stopPropagation();
    const panel = document.getElementById('model-picker-panel');
    if (!panel) return;
    const willOpen = !panel.classList.contains('open');
    if (willOpen) {
      renderModelPickerPanel();
      panel.classList.add('open');
    } else {
      panel.classList.remove('open');
    }
  }

  function renderModelPickerPanel() {
    const panel = document.getElementById('model-picker-panel');
    const selector = document.getElementById('model-selector');
    if (!panel || !selector) return;

    const models = (currentLoadedAIModels || []).filter(m => m.is_active);
    if (!models.length) {
      panel.innerHTML = `<div style="padding: 14px; text-align: center; font-size: 12px; color: var(--text-secondary);">
        No active model configured.<br>Open <b>Models</b> to add one.
      </div>`;
      return;
    }

    panel.innerHTML = models.map(m => {
      // The tick means "this is the model in use". is_active only decides
      // whether the row is offered at all, otherwise every enabled model
      // looked selected at once.
      const isSelected = selector.value === m.model_id;
      const selected = isSelected ? 'selected' : '';
      const isAnthropic = (m.endpoint_type || 'openai') === 'anthropic';
      const missingKey = m.has_key === false;
      const logo = (typeof providerLogoHtml === 'function') ? providerLogoHtml(m.provider, 26) : '🌐';
      const provLabel = (typeof providerMeta === 'function') ? providerMeta(m.provider).label : (m.provider || '?');
      return `
        <button type="button" class="model-picker-item ${selected}" onclick="selectModelFromPicker('${escapeHtml(m.model_id)}')">
          <i class="fa-solid ${isSelected ? 'fa-circle-check' : 'fa-circle'}" style="color: ${isSelected ? 'var(--success-text)' : 'var(--text-secondary)'}; font-size: 12px;"></i>
          ${logo}
          <span style="flex: 1; min-width: 0;">
            <span class="mp-name">${escapeHtml(m.name)}</span>
            <span class="mp-sub">${escapeHtml(m.model_id)}</span>
          </span>
          <span class="mp-badge" title="${escapeHtml(provLabel)}" style="display: inline-flex; align-items: center; gap: 4px;">${escapeHtml(provLabel)}</span>
          <span class="mp-badge ${isAnthropic ? 'anthropic' : 'openai'}">${isAnthropic ? 'anthropic' : 'openai'}</span>
          ${missingKey ? '<span class="mp-badge" title="No API key saved for this model" style="color:#f85149; border-color:rgba(248,81,73,0.4);">no key</span>' : ''}
        </button>`;
    }).join('');
  }

  function selectModelFromPicker(modelId) {
    const selector = document.getElementById('model-selector');
    if (!selector) return;
    if (!Array.from(selector.options).some(o => o.value === modelId)) {
      // Not in the list yet (stale cache) - inject then select.
      const opt = document.createElement('option');
      opt.value = modelId;
      opt.textContent = modelId;
      selector.appendChild(opt);
    }
    selector.value = modelId;
    localStorage.setItem('sre_selected_model', modelId);
    updateModelPickerLabel();
    closeModelPicker();
    selector.dispatchEvent(new Event('change'));
  }

  function updateModelPickerLabel() {
    const selector = document.getElementById('model-selector');
    const label = document.getElementById('model-picker-label');
    const logoEl = document.getElementById('model-picker-logo');
    const hint = document.getElementById('composer-model-hint');
    if (!selector) return;
    const value = selector.value;
    const match = (currentLoadedAIModels || []).find(m => m.model_id === value);
    if (label) label.textContent = (match && match.name) ? match.name : (value || 'Model');
    if (logoEl) {
      if (match && typeof providerLogoHtml === 'function') {
        const meta = providerMeta(match.provider);
        logoEl.innerHTML = providerLogoHtml(meta.id, 14);
        logoEl.title = meta.label;
        logoEl.style.background = 'transparent';
        logoEl.style.borderColor = 'var(--border-color)';
      } else {
        logoEl.textContent = '🌐';
        logoEl.title = '';
      }
    }
    if (!hint) return;
    if (!match) {
      hint.textContent = '';
      return;
    }
    const isAnthropic = (match.endpoint_type || 'openai') === 'anthropic';
    if (match.has_key === false) {
      hint.textContent = (match.provider || match.name) + ' · no API key saved';
      hint.style.color = 'var(--error)';
      return;
    }
    const bits = [match.provider || '?', isAnthropic ? 'native' : 'openai'];
    if (!match.is_active) bits.push('inactive');
    hint.textContent = bits.join(' \u00b7 ');
  }

  // Agent modes shown in the composer popover. The hidden #mode-selector stays
  // the single source of truth for the submit payload.
  const AGENT_MODES = [
    { value: 'autonomous_single', label: 'Single Agent', icon: 'fa-user-tie', hint: 'One agent runs the whole loop' },
    { value: 'guided', label: 'Guided Investigation', icon: 'fa-compass', hint: 'Senior planner + workers, human checkpoints' },
    { value: 'autonomous_multi', label: 'Multi Agent', icon: 'fa-users', hint: 'Parallel workers split by service domain' }
  ];

  function closeModePicker() {
    const panel = document.getElementById('mode-picker-panel');
    if (panel) panel.classList.remove('open');
  }

  function toggleModePicker(ev) {
    if (ev) ev.stopPropagation();
    const panel = document.getElementById('mode-picker-panel');
    if (!panel) return;
    const willOpen = !panel.classList.contains('open');
    if (willOpen) {
      closeModelPicker();
      closePermissionPicker();
      renderModePickerPanel();
      panel.classList.add('open');
    } else {
      panel.classList.remove('open');
    }
  }

  function renderModePickerPanel() {
    const panel = document.getElementById('mode-picker-panel');
    const hidden = document.getElementById('mode-selector');
    if (!panel) return;
    const current = hidden ? hidden.value : 'autonomous_single';
    panel.innerHTML = AGENT_MODES.map(m => `
      <button type="button" class="model-picker-item ${m.value === current ? 'selected' : ''}"
        onclick="selectModeFromPicker('${m.value}')">
        <i class="fa-solid ${m.icon}" style="font-size: 12px; width: 16px; color: var(--accent);"></i>
        <span style="flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px;">
          <span class="mp-name">${m.label}</span>
          <span class="mp-sub" style="font-family: inherit;">${m.hint}</span>
        </span>
        ${m.value === current ? '<i class="fa-solid fa-check" style="color: var(--success-text); font-size: 11px;"></i>' : ''}
      </button>`).join('');
  }

  function selectModeFromPicker(value) {
    const hidden = document.getElementById('mode-selector');
    if (!hidden) return;
    if (!Array.from(hidden.options).some(o => o.value === value)) {
      const opt = document.createElement('option');
      opt.value = value;
      opt.textContent = value;
      hidden.appendChild(opt);
    }
    hidden.value = value;
    try { localStorage.setItem('sre_selected_mode', value); } catch (e) { }
    updateModePickerLabel();
    closeModePicker();
    hidden.dispatchEvent(new Event('change'));
  }

  function updateModePickerLabel() {
    const hidden = document.getElementById('mode-selector');
    const label = document.getElementById('mode-picker-label');
    const icon = document.getElementById('mode-picker-icon');
    if (!hidden) return;
    const mode = AGENT_MODES.find(m => m.value === hidden.value) || AGENT_MODES[0];
    if (label) label.textContent = mode.label;
    if (icon) icon.className = 'fa-solid ' + mode.icon;
  }

  // Keep the hidden select authoritative and mirror changes back to the label.
  function syncComposerModeFromHidden() {
    updateModePickerLabel();
  }

  document.addEventListener('click', function (ev) {
    const modelPanel = document.getElementById('model-picker-panel');
    if (modelPanel && modelPanel.classList.contains('open')) {
      const modelBtn = document.getElementById('model-picker-btn');
      if (!modelPanel.contains(ev.target) && !(modelBtn && modelBtn.contains(ev.target))) {
        modelPanel.classList.remove('open');
      }
    }
    const modePanel = document.getElementById('mode-picker-panel');
    if (modePanel && modePanel.classList.contains('open')) {
      const modeBtn = document.getElementById('mode-picker-btn');
      if (!modePanel.contains(ev.target) && !(modeBtn && modeBtn.contains(ev.target))) {
        modePanel.classList.remove('open');
      }
    }
    const permPanel = document.getElementById('permission-picker-panel');
    if (permPanel && permPanel.classList.contains('open')) {
      const permBtn = document.getElementById('permission-picker-btn');
      if (!permPanel.contains(ev.target) && !(permBtn && permBtn.contains(ev.target))) {
        permPanel.classList.remove('open');
      }
    }
  });

  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') {
      closeModelPicker();
      closeModePicker();
      closePermissionPicker();
    }
  });

  // --- Beam palettes: curated, low-saturation color-picker sets ---
  const BEAM_PALETTES = {
    aurora: { label: 'Aurora', colors: ['#7c8cf8', '#a996ef', '#8fb6f0', '#74cfc4'] },
    sakura: { label: 'Sakura', colors: ['#e2a2c2', '#c6a4ea', '#efc3a4', '#b6a6ea'] },
    tide: { label: 'Tide', colors: ['#5fb6c9', '#7f9ff0', '#68cfb2', '#8aa6d6'] },
    dusk: { label: 'Dusk', colors: ['#6d7bd9', '#8f7ad0', '#5f9fb8', '#9a86c8'] }
  };
  const BEAM_PALETTE_ORDER = ['aurora', 'sakura', 'tide', 'dusk'];

  // Symmetric sweep: colors 0..n-1 across 0-50%, then mirrored back to 100%,
  // so the ring blends seamlessly and never shows hard hue bands.
  function beamGradient(colors) {
    const n = colors.length;
    if (n < 2) return colors[0] || 'transparent';
    const stops = [];
    for (let i = 0; i < n; i++) {
      stops.push(`${colors[i]} ${Math.round((i / (n - 1)) * 50)}%`);
    }
    for (let i = n - 2; i >= 0; i--) {
      stops.push(`${colors[i]} ${Math.round(50 + ((n - 1 - i) / (n - 1)) * 50)}%`);
    }
    return `conic-gradient(from var(--beam-angle), ${stops.join(', ')})`;
  }

  function applyBeamPalette(name) {
    const palette = BEAM_PALETTES[name] || BEAM_PALETTES.aurora;
    document.querySelectorAll('.beam-layer').forEach(layer => {
      layer.style.background = beamGradient(palette.colors);
    });
    const swatch = document.getElementById('beam-palette-swatch');
    if (swatch) swatch.style.background = `linear-gradient(135deg, ${palette.colors.join(', ')})`;
    const btn = document.getElementById('beam-palette-btn');
    if (btn) btn.title = `Beam color: ${palette.label} - click to change`;
    const spark = document.getElementById('composer-ai-spark');
    if (spark) {
      spark.style.color = palette.colors[0];
      spark.title = `Beam color: ${palette.label} - click to change`;
    }
    try { localStorage.setItem('sre_beam_palette', name); } catch (e) { }
  }

  function cycleBeamPalette() {
    const current = localStorage.getItem('sre_beam_palette') || 'aurora';
    const idx = BEAM_PALETTE_ORDER.indexOf(current);
    const next = BEAM_PALETTE_ORDER[(idx + 1) % BEAM_PALETTE_ORDER.length];
    applyBeamPalette(next);
  }

  // Sparkle: ketik saran SRE bergantian ke input seolah hasil generate.
  // Beam ikut ganti mengikuti index biar fitur palet tetap hidup.
  const SRE_SPARK_SUGGESTIONS = [
    'cek status nginx, lagi active atau down?',
    'cek kesehatan server: cpu, memory, disk, dan service yang failed',
    'cari 3 pemakan disk terbesar di root filesystem',
    'cek 50 baris terakhir error log nginx',
    'bandingkan kondisi nginx vs ollama, mana yang sehat?',
    'cek port 80 dan 443 lagi kepake siapa?',
    'validasi config nginx sebelum reload',
  ];
  window.sreSparkIdx = window.sreSparkIdx || 0;
  window.sreSparkTimers = window.sreSparkTimers || [];
  function sparkSuggest() {
    const input = document.getElementById('chat-input');
    if (!input) return;
    (window.sreSparkTimers || []).forEach(clearTimeout);
    window.sreSparkTimers = [];
    const text = SRE_SPARK_SUGGESTIONS[window.sreSparkIdx % SRE_SPARK_SUGGESTIONS.length];
    window.sreSparkIdx += 1;
    try {
      const pal = BEAM_PALETTE_ORDER[(window.sreSparkIdx - 1) % BEAM_PALETTE_ORDER.length];
      if (pal) applyBeamPalette(pal);
    } catch (e) { /* best-effort */ }
    // Shimmer sweep: teks lama fade-out, tukar di tengah, teks baru shimmer-in.
    input.classList.remove('sre-shimmer');
    void input.offsetWidth;
    input.classList.add('sre-shimmer');
    window.sreSparkTimers.push(setTimeout(() => {
      input.value = text;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }, 160));
    window.sreSparkTimers.push(setTimeout(() => {
      input.classList.remove('sre-shimmer');
    }, 680));
  }

  // --- Beam state: fast + glowing while the agent works ---
  let beamRunTimer = null;
  function setBeamRunning(running) {
    const wrap = document.getElementById('chat-beam');
    if (!wrap) return;
    clearTimeout(beamRunTimer);
    if (running) {
      wrap.classList.remove('beam-idle', 'beam-done');
      wrap.classList.add('beam-running');
      // Safety net: never leave the beam spinning forever.
      beamRunTimer = setTimeout(() => setBeamRunning(false), 60000);
    } else {
      wrap.classList.remove('beam-running');
      wrap.classList.add('beam-done');
      beamRunTimer = setTimeout(() => {
        wrap.classList.remove('beam-done');
        wrap.classList.add('beam-idle');
      }, 1200);
    }
  }
  window.setBeamRunning = setBeamRunning;

  // Load models on page load and bind change listener

  document.addEventListener('DOMContentLoaded', function () {
    const selector = document.getElementById('model-selector');
    if (selector) {
      const savedVal = localStorage.getItem('sre_selected_model');
      if (savedVal && Array.from(selector.options).some(o => o.value === savedVal)) {
        selector.value = savedVal;
      }
      selector.addEventListener('change', function () {
        updateModelPickerLabel();
        localStorage.setItem('sre_selected_model', this.value);
        if (localStorage.getItem('sre_auto_models') === 'true' && compatibleAutoModels().length < 2) {
          localStorage.setItem('sre_auto_models', 'false');
        }
        updateAutoModelsButton();
      });
    }
    const hiddenMode = document.getElementById('mode-selector');
    if (hiddenMode) {
      const savedMode = localStorage.getItem('sre_selected_mode');
      if (savedMode && Array.from(hiddenMode.options).some(o => o.value === savedMode)) {
        hiddenMode.value = savedMode;
      }
      hiddenMode.addEventListener('change', syncComposerModeFromHidden);
    }
    updateModePickerLabel();
    {
      const lbl = document.getElementById('model-picker-label');
      const saved = localStorage.getItem('sre_selected_model');
      if (lbl) lbl.textContent = saved || 'Model';
    }
    applyBeamPalette(localStorage.getItem('sre_beam_palette') || 'aurora');
    purgeBootstrapSelect();
    loadAIModels();
    updateAutoModelsButton();
    setTimeout(purgeBootstrapSelect, 300);
    setTimeout(purgeBootstrapSelect, 1000);
    setTimeout(updateModelPickerLabel, 500);
  });


