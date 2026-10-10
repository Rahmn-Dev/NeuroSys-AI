// Main chat app. Extracted from templates/chat3.html.

  (function () {
    function formatTime(ts) {
      const d = new Date(ts * 1000); // Convert Unix timestamp ke Date
      return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    function formatRelativeTime(ts, startTs) {
      if (!ts || !startTs) return '';
      const diff = ts - startTs;
      if (diff < 0) return '0.0s';
      return '✓ ' + diff.toFixed(1) + 's';  // ← SELALU pake centang!
    }


    // Cytoscape initialized dynamically on render
    const messagesDiv = document.getElementById('chat-messages');
    const form = document.getElementById('chat-form');
    const input = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-btn');
    const badge = document.getElementById('connection-badge');
    const dot = document.getElementById('status-dot');

    let ws = null;
    let sessionId = null;
    let currentAIMsg = null;
    let currentTurnWasDirect = false;
    let currentDirectAnswerSaved = false;
    let currentDirectRunId = '';
    let isProcessing = false;
    let pendingApproval = null;
    let approvalTimer = null;
    let snapshotInFlight = false;
    let lastSnapshotCheckpoint = 0;
    let rehydratedSessionId = null;
    let snapshotPollTimer = null;
    let agentHeartbeatTimer = null;
    let agentLastActivity = 0;
    let agentRetryAttempt = 0;

    // --- IDE Context State ---
    window.currentTerminalCwd = localStorage.getItem('sre_terminal_cwd') || null;
    window.selectedFile = localStorage.getItem('sre_selected_file') || null;

    function updateContextAttachments() {
      const container = document.getElementById('context-attachments');
      if (!container) return;

      container.innerHTML = '';
      if (window.selectedFile) {
        const fileName = window.selectedFile.split('/').pop();
        const chip = document.createElement('div');
        chip.style.cssText = 'background: rgb(30 41 59 / 3%); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 8px 12px; font-size: 13px; color: var(--text-primary); display: flex; align-items: flex-start; gap: 12px; cursor: default; box-shadow: 0 4px 12px rgba(0,0,0,0.2);';

        chip.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 2px;">
                    <div style="font-weight: 600; display: flex; align-items: center; gap: 6px;">
                        <i class="fas fa-file-alt" style="color: var(--accent);"></i> ${fileName}
                    </div>
                    <div style="font-size: 11px; opacity: 0.6; font-family: monospace;">${window.selectedFile}</div>
                </div>
                <span style="cursor: pointer; opacity: 0.7; font-size: 16px; margin-top: -2px;" onclick="window.clearSelectedFile()" title="Remove file context">&times;</span>
            `;
        container.appendChild(chip);
      }
    }

    window.clearSelectedFile = function () {
      window.selectedFile = null;
      localStorage.removeItem('sre_selected_file');
      updateContextAttachments();
    };
    let reconnectTimer = null;

    // --- WebSocket ---
    function connect() {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }

      // Don't reconnect if already connected
      if (ws && ws.readyState === WebSocket.OPEN) {
        return;
      }

      // Don't reconnect if currently connecting
      if (ws && ws.readyState === WebSocket.CONNECTING) {
        return;
      }
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${protocol}//${location.host}/ws/sre-agent/`);
      window.sreAgentWs = ws;

      ws.onopen = () => {
        try { window.refreshRunPresence(); } catch (err) { /* best-effort */ }
        badge.textContent = 'Live';
        badge.style.background = '#23863633';
        badge.style.color = '#3fb950';
        dot.style.background = '#3fb950';
        ensureConnectionCard();
        agentRetryAttempt = 0;
        agentLastActivity = Date.now();
        clearInterval(agentHeartbeatTimer);
        agentHeartbeatTimer = setInterval(() => {
          if (!ws || ws.readyState !== WebSocket.OPEN) return;
          if (Date.now() - agentLastActivity > 45000) { ws.close(4000, 'heartbeat timeout'); return; }
          ws.send(JSON.stringify({type: 'ping'}));
        }, 15000);
        if (sessionId) ws.send(JSON.stringify({type: 'subscribe', session_id: sessionId}));
        // Reconcile after every reconnect, not only the first page load. A
        // WebSocket subscription carries new events, while the snapshot fills
        // the gap from the time this tab was disconnected.
        bootstrapActiveRun();
      };

      ws.onclose = (event) => {
        clearInterval(agentHeartbeatTimer);
        document.querySelector('[data-agent-connection-card="true"]')?.remove();
        const permanent = [4401, 4403].includes(event.code);
        badge.textContent = permanent ? 'Offline' : 'Reconnecting';
        badge.style.background = '#da363333';
        badge.style.color = '#f85149';
        dot.style.background = permanent ? '#d29922' : '#f85149';
        if (permanent) return;
        startSnapshotPolling();
        const base = Math.min(30000, 1000 * (2 ** agentRetryAttempt++));
        const delay = Math.round(base * (0.75 + Math.random() * 0.5));
        clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(connect, delay);
      };

      // Run-scoped events render only with positive proof they belong to the
      // open chat. Anything else is either presence for the sidebar or dropped.
      window.RUN_CONTENT_EVENTS = new Set(['exploring', 'discovering_tools', 'planning',
        'thinking', 'hypothesis', 'resolution_plan', 'tool_start', 'tool_end',
        'message_chunk', 'task_plan', 'task_updated', 'findings', 'worker_activity',
        'executing', 'observing', 'analyzing', 'approval_required',
        'creating_artifact', 'restoring_artifact', 'security_scan']);

      window.eventBelongsHere = function (payload) {
        if (!window.RUN_CONTENT_EVENTS.has(String(payload.type || ''))) return true;
        // Positive proof first: an event stamped with the open chat's own
        // session belongs here even if liveRunSessionId was never set (fresh
        // new chat whose id only arrived via the session_id event).
        const claimed = payload && payload.session_id ? String(payload.session_id) : '';
        if (claimed && sessionId && claimed === String(sessionId)) return true;
        return !!(window.liveRunSessionId && sessionId &&
          window.liveRunSessionId === String(sessionId));
      };

    // Mutations go over this authenticated socket with request/response
    // correlation, not over cookie-based HTTP: there is no ambient credential
    // for a foreign page to ride, so the CSRF class is gone structurally.
    window.wsSeq = window.wsSeq || 0;
    window.wsPending = window.wsPending || {};
    window.wsCall = function (type, payload, timeoutMs) {
      return new Promise((resolve, reject) => {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          reject(new Error('The live connection is not open. Reconnect and try again.'));
          return;
        }
        const request_id = 'rpc-' + Date.now().toString(36) + '-' + (++window.wsSeq);
        const timer = setTimeout(() => {
          if (window.wsPending[request_id]) {
            delete window.wsPending[request_id];
            reject(new Error('The server took too long to answer.'));
          }
        }, timeoutMs || 20000);
        window.wsPending[request_id] = { resolve, reject, timer };
        ws.send(JSON.stringify(Object.assign({ type, request_id }, payload || {})));
      });
    };
    window.resolveRpcResult = function (payload) {
      const pending = payload && payload.request_id && window.wsPending[payload.request_id];
      if (!pending) return false;
      delete window.wsPending[payload.request_id];
      clearTimeout(pending.timer);
      if (payload.ok) pending.resolve(payload.data || {});
      else pending.reject(new Error(payload.error || 'Request failed.'));
      return true;
    };

      ws.onmessage = (e) => {
        agentLastActivity = Date.now();
        try {
          const payload = JSON.parse(e.data);
          if (payload && payload.type === 'rpc_result') {
            window.resolveRpcResult(payload);
            return;
          }
          if (payload && payload.type === 'presence') {
            window.applyPresence(payload);
            return;
          }
          if (payload.type === 'session_id') {
            window.liveRunSessionId = String(payload.content || '');
          } else {
            // Strongest signal first: the authoritative session stamped by the
            // server on every event. It does not depend on event ordering, so
            // it also covers reloads, reconnects and late stragglers.
            const claimed = payload.session_id ? String(payload.session_id) : '';
            if (claimed && sessionId && claimed !== String(sessionId)) {
              window.noteForeignRunEvent(payload, claimed);
              window.updateForeignRunBadge && window.updateForeignRunBadge(payload);
              return;
            }
            if (!window.eventBelongsHere(payload)) {
              if (window.liveRunSessionId) {
                window.noteForeignRunEvent(payload);
                window.updateForeignRunBadge && window.updateForeignRunBadge(payload);
              }
              return;
            }
          }
          // Events timestamped before this chat's cancel are stragglers from
          // the killed run, not news: drop them instead of rendering ghosts.
          const cancelHorizon = (window.cancelledAt || {})[String(sessionId || '')];
          const eventMs = payload.timestamp ? Number(payload.timestamp) * 1000 : 0;
          if (cancelHorizon && eventMs && eventMs < cancelHorizon - 5000 &&
              window.RUN_CONTENT_EVENTS.has(String(payload.type || ''))) {
            return;
          }
          handleEvent(payload);
        }
        catch (error) { badge.textContent = 'Message error'; console.warn('Invalid Agent event', error); }
      };
    }

    // --- Event handler ---
    function lifecycleNarration(status) {
      const messages = {
        queued: 'Preparing the investigation...',
        running: 'Checking the requested system...',
        planning: 'Planning the next diagnostic steps...',
        executing: 'Running the authorized action...',
        awaiting_approval: 'This action needs your approval.',
        verifying: 'Verifying the results...',
        completed: 'The investigation is complete based on the available evidence.',
        failed: 'The investigation stopped and needs review.',
        blocked: 'The action was blocked by a security boundary.',
        security_blocked: 'The action was blocked by a security boundary.',
        cancelled: 'The investigation was cancelled.'
      };
      return messages[String(status || '').toLowerCase()] || 'Updating investigation status...';
    }

    function handleEvent(data) {
      window.agentSeenEvents = window.agentSeenEvents || new Set();
      if (data.event_id) {
        if (window.agentSeenEvents.has(data.event_id)) return;
        window.agentSeenEvents.add(data.event_id);
        if (window.agentSeenEvents.size > 2000) window.agentSeenEvents.delete(window.agentSeenEvents.values().next().value);
      }
      if (data.run_id) window.activeAgentRunId = data.run_id;
      const type = data.type;

      switch (type) {
        case 'sudo_key_exchange':
          window.serverRsaPublicKey = data.public_key;
          break;

        case 'message_saved': {
          const _sid = (data.content || data.session_id || sessionId || '');
          const _mid = String(data.msg_id || '');
          if (_mid) {
            let _el = null;
            if (String(data.sender).toLowerCase() === 'user') {
              const _list = messagesDiv.querySelectorAll('.sre-msg-user');
              _el = _list[_list.length - 1];
            } else {
              _el = (window.liveBubbleCurrent && window.liveBubbleCurrent.bubble)
                || messagesDiv.querySelector('.agent-msg.sre-msg-ai:last-of-type');
            }
            if (_el) _el.dataset.msgId = _mid;
          }
          // Direct Chat saves its complete assistant answer only after model
          // streaming has ended. This acknowledgement is already reliable
          // success evidence, so settle the live status here instead of
          // leaving "Thinking" up while waiting for the separate completed
          // event (which can be delayed or missed during a socket hiccup).
          if (currentTurnWasDirect && String(data.sender || '').toLowerCase() === 'ai'
              && window.turnIsOpen()) {
            currentDirectAnswerSaved = true;
            const _directDuration = window.sessionStartTime
              ? (Date.now() - window.sessionStartTime.getTime()) / 1000 : null;
            window.markStreaming(false, currentAIMsg && currentAIMsg.querySelector('.ai-content'));
            window.stopAllStreaming();
            window.setRunPhase('done');
            window.markRunFinished(window.liveRunSessionId || sessionId, true);
            updateRunStateCard(currentDirectRunId, 'completed', _directDuration);
            if (window.activeRunWrap) {
              paintRunWrap(window.activeRunWrap.dataset.wrapId, 'completed', _directDuration);
            }
            finalizeRunWrap('completed', _directDuration);
            window.closeTurn();
            isProcessing = false;
            window.setSendButtonState('idle');
          }
          break;
        }
        case 'session_id':
          const oldSessionId = sessionId;
          const sessionBelongsToSubmittedTurn = !!window.expectingSession;
          // Adopt the id only when this chat asked for a run and is still
          // waiting for its session. A straggler from another chat must never
          // repoint the open chat at itself.
          if (window.expectingSession && data.content) {
            window.expectingSession = false;
            sessionId = data.content;
            // New chat: the submitter stored '' because no id existed yet.
            // Adopt it now or every content event gets dropped as foreign.
            if (!window.liveRunSessionId) window.liveRunSessionId = String(data.content);
          } else if (!sessionId && data.content) {
            sessionId = data.content;
            if (!window.liveRunSessionId) window.liveRunSessionId = String(data.content);
          }
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type: 'subscribe', session_id: sessionId}));
          // A locally submitted turn has already opened its own run card. The
          // snapshot endpoint returns the latest durable run for the session,
          // which may be the *previous* completed turn (Direct Chat does not
          // create an AgentRun row). Hydrating it here races the new live
          // events and can paint "completed" above a fresh Thinking step.
          if (!isProcessing && !sessionBelongsToSubmittedTurn) bootstrapActiveRun();
          startSnapshotPolling();

          // If this is a new session (not from loading history), refresh the history sidebar
          if (!window.isLoadingHistory && oldSessionId !== sessionId && sessionId) {
            setTimeout(async () => {
              await loadHistory();
              // After loading, ensure the new session is highlighted
              document.querySelectorAll('.sre-history-item').forEach(i => i.classList.remove('active'));
              const newItem = document.getElementById('history-item-' + sessionId);
              if (newItem) {
                newItem.classList.add('active');
              }
              // Update URL without reloading
              window.history.pushState({}, '', window.location.pathname + '?session=' + sessionId);
            }, 800);
          }
          break;

        case 'resuming':
        case 'lifecycle':
          if (!window.SRE_TERMINAL.includes(data.status)) {
            updateRunStateCard(data.run_id, data.status || 'running');
            addAgentStep('Progress', lifecycleNarration(data.status), '#79c0ff', 'activity');
          } else {
            stopAllAgentStepTimers();
            updateRunStateCard(data.run_id, data.status);
            window.sessionStartTime = null;
          }
          if (data.status === 'awaiting_approval') isProcessing = true;
          if (window.SRE_TERMINAL.includes(data.status)) {
            isProcessing = false;
            window.setSendButtonState('idle');
            window.markRunFinished(window.liveRunSessionId || sessionId, data.status === 'completed');
            // The final event must pin the bubble pill and the plan right away;
            // relying on a later canvas is how the turn got stuck on "working".
            try {
              const _w = window.activeRunWrap
                || (window.lastRunBody && document.contains(window.lastRunBody) ? window.lastRunBody : null);
              if (_w && _w.dataset && _w.dataset.wrapId) {
                window.paintRunWrap(_w.dataset.wrapId, data.status, data.duration || null);
              }
            } catch (err) { /* best-effort */ }
            try { window.refreshInvestigations(); } catch (err) { /* best-effort */ }
            if (activeInvestigationId && investigations[activeInvestigationId]) {
              const _inv = investigations[activeInvestigationId];
              (_inv.plan || []).forEach((p) => {
                const _st = String(p.status || '').toLowerCase();
                if (['pending', 'running', 'in_progress', 'executing'].includes(_st)) {
                  p.status = window.SRE_TERMINAL.includes(String(data.status).toLowerCase()) ? data.status : 'stopped';
                }
              });
              _inv.status = data.status === 'error' ? 'failed' : data.status;
              renderInvestigationTimeline();
            }
            window.setRunPhase('done');
          } else if (!window.isLoadingHistory) {
            var phase = {
              starting: ['exploring', 'starting'],
              resuming: ['exploring', 'resuming'],
              exploring: ['exploring', 'observing'],
              discovering_tools: ['search', 'discovering tools'],
              planning: ['planning', 'planning'],
              thinking: ['thinking', 'thinking'],
              verifying: ['thinking', 'verifying'],
              executing: ['working', 'executing'],
              running: ['working', 'executing'],
              awaiting_approval: ['listening', 'awaiting approval'],
            }[data.status] || ['working', data.status || 'executing'];
            window.setRunPhase(phase[0], phase[1]);
          }
          break;

        case 'verifying':
          addAgentStep('Verifying', data.content || 'Checking postconditions...', '#79c0ff', 'shield-check');
          window.setRunPhase('thinking', 'verifying');
          break;

        case 'provider_fallback':
          addAgentStep('Provider Fallback', data.content || `Switched to ${data.to || 'fallback provider'}`, '#d29922', 'refresh-cw');
          break;

        case 'session_title':
          const titleContent = data.content;
          document.title = titleContent;
          const historyItem = document.getElementById('history-item-' + sessionId);
          if (historyItem) {
            const titleEl = historyItem.querySelector('.sre-history-title');
            if (titleEl) titleEl.textContent = titleContent;
          }
          break;

        case 'status':
          addSystemMsg(data.content, /slice complete/i.test(String(data.content || '')) ? 'rotate' : 'check');
          // A slice rotation is real progress: keep it inside the run card.
          if (/slice complete/i.test(String(data.content || '')) && window.activeRunWrap) {
            addAgentStep('Slice complete', escapeHtml(String(data.content)), 'var(--accent)', 'rotate');
          }
          break;

        case 'sudo_password_required':
          addSystemMsg(data.content, 'lock');
          {
            const modal = document.getElementById('sudo-modal');
            if (modal) modal.style.display = 'flex';
            const pwd = document.getElementById('sudo-password-input');
            if (pwd) { pwd.value = ''; setTimeout(() => pwd.focus(), 80); }
          }
          break;

        case 'sudo_pwd_saved':
          addSystemMsg(data.content, 'shield-check');
          {
            const sudoBtn = document.getElementById('sudo-auth-btn');
            if (sudoBtn) {
              sudoBtn.style.color = '#3fb950';
              sudoBtn.innerHTML = '<i class="fa-solid fa-shield-check"></i> Sudo Active';
            }
            document.getElementById('sudo-modal').style.display = 'none';
            const saveBtn = document.getElementById('sudo-save-btn');
            if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = 'Encrypt & Save'; }
          }
          break;

        case 'sudo_pwd_error':
          addSystemMsg(data.content, 'alert-triangle');
          alert(data.content);
          {
            const saveBtn = document.getElementById('sudo-save-btn');
            if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = 'Encrypt & Save'; }
          }
          break;

        case 'direct_chat':
          // Direct chat has a lightweight run trace (Thinking only), but no
          // tool-discovery or planning phases. The following thinking event
          // creates the card before the answer starts streaming.
          currentTurnWasDirect = true;
          if (!currentDirectRunId) {
            currentDirectRunId = 'direct-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
          }
          break;

        case 'exploring':
          // Safety net: if no run container is active (e.g. stream resumed
          // without a fresh submit), open one so steps stay grouped.
          if (!window.isLoadingHistory && !window.activeRunWrap) startRunWrap();
          addAgentStep('Exploring', data.content, 'var(--accent)', 'search');
          window.setRunPhase('exploring');
          break;

        case 'discovering_tools':
          window.ensureRunWrap();
          let toolsHtml = data.content;
          if (data.tools && data.tools.length) {
            toolsHtml += '<div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px;">';
            data.tools.forEach(t => {
              toolsHtml += `<span style="font-size: 11px; background: #21262d; padding: 2px 8px; border-radius: 4px; color: #79c0ff;">${t}</span>`;
            });
            toolsHtml += '</div>';
          }
          addAgentStep('Discovering Tools', toolsHtml, 'var(--purple)', 'wrench');
          window.setRunPhase('search');
          break;

        case 'planning':
          window.ensureRunWrap();
          addAgentStep('Planning', data.content, '#dac654', 'list-todo');
          window.setRunPhase('planning');
          break;

        case 'thinking':
          if (!window.turnIsOpen()) break;
          if (currentAIMsg) {
            const _hasAnswer = currentAIMsg.querySelector('.ai-content')
              && currentAIMsg.querySelector('.ai-content').textContent.trim();
            if (!_hasAnswer) {
              currentAIMsg.remove();
              currentAIMsg = null;
            }
          }
          window.ensureRunWrap();
          if (currentTurnWasDirect) updateRunStateCard(currentDirectRunId, 'thinking');
          addAgentStep('Thinking', data.content, '#ff69b4', 'brain');
          window.setRunPhase('thinking');
          break;

        case 'hypothesis':
          addAgentStep('Hypothesis', data.content, '#a371f7', 'lightbulb');
          break;

        case 'resolution_plan': {
          const steps = data.steps || (data.metadata && data.metadata.steps) || [];
          const stepsHtml = Array.isArray(steps) && steps.length > 0
            ? '<ol style="margin: 6px 0 0 18px; padding: 0;">' + steps.map(s => `<li>${escapeHtml(String(s))}</li>`).join('') + '</ol>'
            : escapeHtml(data.content || '');
          addAgentStep('Resolution Plan', stepsHtml, '#39c5cf', 'list-checks');
          break;
        }

        case 'tool_start':
          window.ensureRunWrap();
          addAgentStep('Executing', window.sreToolChip(escapeHtml(data.tool || 'tool'), data.command ? escapeHtml(data.command) : ''), 'var(--warning)', 'zap', data.step_id, false);
          window.setRunPhase('working');
          break;

        case 'tool_end':
          const resultTxt = (data.result || data.content || '').trim();
          addAgentStep('Result', window.sreResultHtml(resultTxt), 'var(--success)', 'check-circle', data.step_id, true);
          break;

        case 'approval_required':
          addAgentStep('Approval Required', data.content, 'var(--warning)', 'lock');
          window.setRunPhase('listening');
          showApprovalCard(data);
          break;

        case 'approval_approved':
          hideApprovalCard();
          pendingApproval = null;
          addSystemMsg('Approved once; resuming the pending action.', 'check');
          break;

        case 'denied':
        case 'denied_timeout':
        case 'security_blocked':
          hideApprovalCard();
          pendingApproval = null;
          stopAllAgentStepTimers();
          updateRunStateCard(data.run_id, data.type === 'security_blocked' ? 'failed' : data.type);
          // Each way of stopping says what it was. Calling a denial a failure
          // told the operator the agent broke when they simply said no.
          const _stopLabel = data.type === 'security_blocked' ? 'Blocked by Security Policy'
            : data.type === 'denied_timeout' ? 'Denied — no decision before the deadline'
            : 'Denied by you';
          const _stopStatus = data.type === 'security_blocked' ? 'security_blocked'
            : data.type === 'denied_timeout' ? 'denied_timeout' : 'denied';
          const _blockedCaseId = data.investigation_id || (data.metadata && data.metadata.investigation_id) || '';
          const _canUpdateInvestigation = activeInvestigationId
            && investigations[activeInvestigationId]
            && (data.type !== 'security_blocked' || _blockedCaseId === activeInvestigationId);
          finalizeRunWrap(_stopStatus);
          addAgentStep(_stopLabel, escapeHtml(data.content || ''), 'var(--warning)', 'ban', null, true);
          window.refreshInvestigations();
          // The pill and the plan must say what happened right now, even if the
          // run container was already cleared: otherwise the pill keeps spinning
          // on the last live phase and the plan keeps reading running/pending.
          try {
            const _body = window.activeRunWrap
              || (window.lastRunBody && document.contains(window.lastRunBody) ? window.lastRunBody : null);
            if (_body && _body.dataset.wrapId) {
              paintRunWrap(_body.dataset.wrapId, _stopStatus);
            }
          } catch (err) { /* best-effort */ }
          if (_canUpdateInvestigation) {
            const _inv = investigations[activeInvestigationId];
            _inv.status = data.type === 'security_blocked' ? 'blocked'
              : data.type === 'denied_timeout' ? 'denied_timeout' : 'denied';
            (_inv.plan || []).forEach((p) => {
              const _st = String(p.status || '').toLowerCase();
              if (['pending', 'running', 'in_progress', 'executing', 'verifying'].includes(_st)) {
                p.status = data.type === 'security_blocked' ? 'blocked' : 'denied';
              }
            });
            renderInvestigationTimeline();
          }
          if (data.type === 'security_blocked') {
            const _blockedBubble = addAIMessage(data.content || '', new Date());
            window.paintBlockedBubble(_blockedBubble);
            currentAIMsg = null;
          }
          window.sessionStartTime = null;
          // The prompt that triggered the block is quarantined in place.
          try {
            const users = messagesDiv.querySelectorAll('.sre-msg-user');
            if (users.length) window.quarantineUserBubble(users[users.length - 1]);
          } catch (err) { /* best-effort */ }
          // A blocked prompt never ran this investigation. Repainting the case
          // red overwrote work that had genuinely completed earlier, which is
          // how a finished case ended up labelled "security blocked".
          if (_canUpdateInvestigation) {
            investigations[activeInvestigationId].status = data.type === 'security_blocked' ? 'blocked' : data.type;
            renderInvestigationTimeline();
          }
          isProcessing = false;
          window.closeTurn();
          // A stopped run leaves the registry, or the submit guard keeps
          // insisting a run is going when there is nothing left to stop.
          window.markRunFinished(window.liveRunSessionId || sessionId, false);
          window.setSendButtonState('idle');
          break;

        case 'safety_blocked':
          addAgentStep('Blocked', data.content, 'var(--error)', 'shield-alert');
          break;

        case 'safety_warn':
          addAgentStep('Warning', data.content, 'var(--warning)', 'alert-triangle');
          break;


        case 'security_scan':
          addAgentStep('Security Scan', data.content, 'var(--purple)', 'shield-check');
          break;

        case 'parallel_start':
          addAgentStep('Parallel Execution', `⚡ ${data.content || 'Executing tasks in parallel...'}`, '#00d4ff', 'layers');
          break;

        case 'parallel_progress':
          addAgentStep('Progress', data.content || 'Tasks progressing...', '#00d4ff', 'loader');
          break;

        case 'parallel_complete':
          addAgentStep('Parallel Complete', `✅ ${data.content || 'All tasks completed.'}`, 'var(--success)', 'check-circle');
          break;
        case 'creating_artifact':
          addAgentStep('Creating Artifact', data.content, 'var(--success)', 'file-code-2');
          loadArtifacts();  // Always call - it works even if tab is hidden
          break;

        case 'restoring_artifact':
          addAgentStep('Restoring Artifact', data.content, 'var(--warning)', 'history');
          loadArtifacts();  // Always call
          break;

        case 'investigation_started':
          if (data.investigation_id && window.activeRunWrap) {
            const slot = document.getElementById(window.activeRunWrap.dataset.wrapId + '-case');
            if (slot) slot.textContent = data.investigation_id;
          }
          if (!window.isLoadingHistory && activeInvestigationId && investigations[activeInvestigationId]) {
            investigations[activeInvestigationId].status = 'completed';
            window.setRunPhase('done');
          }
          const invId = data.investigation_id || (data.metadata && data.metadata.investigation_id);
          if (invId) {
            if (!investigations[invId]) {
              investigations[invId] = {
                id: invId,
                title: data.content || 'Investigation',
                status: 'active',
                createdAt: Date.now(),
                plan: [],
                findings: []
              };
            } else if (!window.isLoadingHistory) {
              investigations[invId].status = 'active';
            }
            activeInvestigationId = invId;
            renderInvestigationTimeline();

            addAgentStep('Investigation Started', data.content || 'Starting new investigation...', 'var(--accent)', 'search');
          }
          break;

        case 'worker_activity':
          const workers = data.workers || (data.metadata && data.metadata.workers);
          if (workers) {
            updateInvestigationWorkerActivity(
              workers,
              data.investigation_id || (data.metadata && data.metadata.investigation_id)
                || data.case_id || (data.metadata && data.metadata.case_id)
            );
          }
          break;

        case 'task_plan':
          const planData = data.plan || (data.metadata && data.metadata.plan);
          if (planData && planData.investigation_id) {
            if (!investigations[planData.investigation_id]) {
              investigations[planData.investigation_id] = {
                id: planData.investigation_id,
                title: planData.title || 'Investigation',
                status: 'active',
                createdAt: Date.now(),
                plan: [],
                findings: []
              };
            }
            investigations[planData.investigation_id].plan = Array.isArray(planData) ? planData : (planData.tasks || []);
            renderInvestigationTimeline();
            addAgentStep('Task Plan Updated', 'A new task plan has been generated for the investigation.', '#dac654', 'list-todo');
          }
          break;

        case 'task_updated':
          const taskData = data.task || (data.metadata && data.metadata.task);
          if (taskData) {
            if (taskData.new_status === 'completed') {
              addAgentStep('Task Completed', window.sreMarkdownHtml(taskData.task), 'var(--success)', 'check-circle');
            }
            renderInvestigationTimeline();
          }
          break;

        case 'findings':
          const findingsData = data.findings || (data.metadata && data.metadata.findings);
          if (findingsData && findingsData.investigation_id) {
            if (!investigations[findingsData.investigation_id]) {
              investigations[findingsData.investigation_id] = {
                id: findingsData.investigation_id,
                title: findingsData.title || 'Investigation',
                status: 'active',
                createdAt: Date.now(),
                plan: [],
                findings: []
              };
            }
            investigations[findingsData.investigation_id].findings = Array.isArray(findingsData) ? findingsData : (findingsData.findings || []);
            renderInvestigationTimeline();
            addAgentStep('Findings Recorded', 'New findings have been added to the investigation timeline.', 'var(--success)', 'check-square');
          }
          break;

        case 'message_chunk':
          if (currentAIMsg && currentAIMsg.dataset.sessionId !== String(sessionId || '')) {
            // New-chat bubble was created before the server issued the
            // session id. Adopt it onto the live run instead of dropping the
            // turn's chunks (which froze the bubble at its first piece).
            // A bubble stamped for a *different* chat still breaks here.
            if (!currentAIMsg.dataset.sessionId && window.liveRunSessionId
                && String(window.liveRunSessionId) === String(sessionId || '')) {
              currentAIMsg.dataset.sessionId = String(sessionId || '');
            } else break;
          }
          if (!window.turnIsOpen() && !(currentTurnWasDirect && currentDirectAnswerSaved)) break;
          if (!currentAIMsg) {
            currentAIMsg = addAIMessage('');
          }
          // Reply is streaming; keep the phase label in sync.
          if (!currentDirectAnswerSaved) window.setRunPhase('composing');

          let rawData = data.content;
          if (typeof rawData !== 'string') {
            try { rawData = JSON.stringify(rawData); } catch (e) { rawData = String(rawData); }
          }
          const fullText = rawData || '';

          const contentDiv = currentAIMsg.querySelector('.ai-content');
          // The server accumulates every chunk into the stored reply, but an
          // individual chunk is not always accumulated itself: the React path
          // emits one piece of narration per turn. Replacing here is what left
          // the live bubble showing only the last piece while the replay -
          // built from the stored accumulation - showed everything. So the
          // bubble accumulates exactly like the server does.
          let nextText = String(fullText || '');
          try {
            const prevText = String(contentDiv.dataset.fullText || '');
            if (prevText && nextText.startsWith(prevText)) {
              // Already accumulated: take it as is.
            } else if (prevText && prevText.startsWith(nextText) && nextText) {
              nextText = prevText;
            } else if (prevText && nextText) {
              nextText = prevText + '\n\n' + nextText;
            }
            contentDiv.dataset.fullText = nextText;
          } catch (err) { /* best-effort */ }
          contentDiv.innerHTML = window.renderAnswerContent(nextText);
          // The reveal replays on every chunk, so each arrival settles in
          // instead of the whole block blinking at once.
          window.markStreaming(!currentDirectAnswerSaved, contentDiv);
          if (window.runHeaderPinned && window.activeRunWrap && window.activeRunWrap.dataset.wrapId) {
            window.centerRunTurn(window.activeRunWrap.dataset.wrapId);
          }
          scrollToBottom();
          break;


        case 'completed':
          const directTurn = currentTurnWasDirect;
          const completedRunId = data.run_id || (directTurn ? currentDirectRunId : '');
          window.agentCompletedRuns = window.agentCompletedRuns || new Set();
          if (completedRunId && window.agentCompletedRuns.has(completedRunId)) {
            window.stopAllStreaming();
            window.closeTurn();
            window.setSendButtonState('idle');
            break;
          }
          if (completedRunId) window.agentCompletedRuns.add(completedRunId);
          window.markRunFinished(window.liveRunSessionId || sessionId, true);
          window.markStreaming(false);
          window.stopAllStreaming();
          // The last chunk carries the final answer and the split marker. If it
          // landed anywhere else, the bubble would keep showing narration, so
          // settle the current bubble onto its newest text one final time.
          try {
            const _box = currentAIMsg && currentAIMsg.querySelector('.ai-content');
            if (_box && _box.dataset.fullText) {
              _box.innerHTML = window.renderAnswerContent(_box.dataset.fullText);
            }
          } catch (err) { /* best-effort */ }
          window.setAgentDotState('done');
          window.closeTurn();
          if (window.activeRunWrap) {
            paintRunWrap(window.activeRunWrap.dataset.wrapId, 'completed',
              (data.duration != null) ? data.duration
                : ((new Date() - (window.sessionStartTime || new Date())) / 1000));
          }
          updateRunStateCard(completedRunId, 'completed', data.duration);
          finalizeRunWrap('completed', data.duration);
          if (!directTurn && activeInvestigationId && investigations[activeInvestigationId]) {
            investigations[activeInvestigationId].status = 'completed';
            if (sessionId) {
              loadHistory();
            }

            // Refresh if visible
            renderInvestigationTimeline();  // Always refresh
            loadArtifacts();
          }
          // Direct Chat has no investigation object, but its answer is still a
          // terminal run. Keep its live dot/phase in sync with the completed
          // pill rather than leaving the bubble in Thinking until a replay.
          window.setRunPhase('done');
          stopAllAgentStepTimers();
          const activeDash = document.getElementById('active-dashboard');
          if (activeDash) { activeDash.removeAttribute('id'); }

          const endTime = new Date();
          const startTime = window.sessionStartTime || new Date(Date.now() - (data.duration || 0) * 1000);
          const dur = data.duration ? data.duration.toFixed(1) : ((endTime - startTime) / 1000).toFixed(1);

          const auditHtml = window.buildAuditHtml({
            summary: data.content || '',
            started: startTime.toLocaleTimeString(),
            finished: endTime.toLocaleTimeString(),
            total: dur + ' seconds',
          });
          if (!window.attachRunAudit(currentAIMsg, auditHtml)) {
            messagesDiv.insertAdjacentHTML('beforeend', auditHtml);
          }
          window.normalizeRunCards();

          currentAIMsg = null;
          currentTurnWasDirect = false;
          currentDirectAnswerSaved = false;
          currentDirectRunId = '';
          window.sessionStartTime = null;
          isProcessing = false;
          window.setSendButtonState('idle');
          break;

        case 'error':
          const failedRunId = data.run_id || (currentTurnWasDirect ? currentDirectRunId : '');
          window.markRunFinished(window.liveRunSessionId || sessionId, false);
          window.markStreaming(false);
          window.setAgentDotState('idle');
          stopAllAgentStepTimers();
          updateRunStateCard(failedRunId, 'failed');
          finalizeRunWrap('failed');
          addAgentStep('Error', data.content, 'var(--error)', 'x-circle', null, true);
          {
            window.continueSessionId = sessionId;
            window.continueCaseId = data.case_id || '';
            messagesDiv.appendChild(window.renderRunFailureActions(sessionId, data.case_id));
            window.renderActiveRuns && window.renderActiveRuns();
            scrollToBottom();
          }
          window.sessionStartTime = null;
          isProcessing = false;
          window.closeTurn();
          window.setSendButtonState('idle');
          currentAIMsg = null;
          currentTurnWasDirect = false;
          currentDirectAnswerSaved = false;
          currentDirectRunId = '';
          break;
      }

      scrollToBottom();
    }

    // --- UI helpers ---
    function getIcon(name) {
      if (window.lucide && window.lucide.icons[name]) {
        return window.lucide.icons[name].toSvg({ width: 14, height: 14 });
      }
      return '';
    }



    function chatTimeLabel(ts) {
      try {
        const d = ts ? new Date(ts) : new Date();
        return d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
      } catch (e) {
        return '';
      }
    }

    // Paints (or repaints) a prompt bubble. Reused when a prompt is revised so
    // the edited bubble looks exactly like a freshly sent one.
    window.paintUserBubble = function (div, text, options) {
      const opts = options || {};
      const contextRegex = /\n\n\[Context Attached: (file:\/\/[^\]]+)\]/g;
      const body = escapeHtml(text.replace(contextRegex, '').trim()).replace(/\n/g, '<br>');
      div.innerHTML = body;
      div.dataset.rawText = text;
      div.style.width = '';
      div.style.minWidth = '';
      div.style.maxWidth = '70%';

      if (opts.edited) {
        const tag = document.createElement('div');
        tag.style.cssText = 'font-size:10px; opacity:0.75; margin-top:4px; text-align:right;';
        tag.textContent = 'edited';
        div.appendChild(tag);
      }

      if (opts.animate) {
        div.classList.add('sre-sending');
        div.addEventListener('animationend', () => div.classList.remove('sre-sending'), { once: true });
      }

      const actions = document.createElement('div');
      actions.style.cssText = 'display:flex; justify-content:flex-end; gap:6px; margin-top:6px; opacity:0;' +
        ' transition:opacity 0.15s ease;';
      actions.innerHTML =
        `<button title="Edit this message" class="sre-msg-edit-btn" onclick="window.editUserMessage(this)"` +
        ` style="background:rgba(0, 0, 0, 0.18); border:1px solid rgba(255,255,255,0.35);` +
        ` color:#ffffff; border-radius:6px; padding:3px 8px; font-size:10px; cursor:pointer;` +
        ` font-weight:600; display:inline-flex; align-items:center; gap:4px; transition:background 0.15s ease;">` +
        `<i class="fa-solid fa-pen" style="font-size:9px;"></i> Edit</button>` +
        `<button title="Delete this message" class="sre-msg-delete-btn" onclick="window.deleteChatMessage(event,this)"` +
        ` data-delete-msg="1"` +
        ` style="background:rgba(0, 0, 0, 0.18); border:1px solid rgba(255,255,255,0.35);` +
        ` color:#ffffff; border-radius:6px; padding:3px 8px; font-size:10px; cursor:pointer;` +
        ` font-weight:600; display:inline-flex; align-items:center; gap:4px; transition:background 0.15s ease;">` +
        `<i class="fa-solid fa-trash-can" style="font-size:9px;"></i> Delete</button>`;
      div.appendChild(actions);
      div.onmouseenter = () => { actions.style.opacity = '1'; };
      div.onmouseleave = () => { actions.style.opacity = '0'; };
      return div;
    };

    function addUserMessage(text, ts, msgId) {
      const div = document.createElement('div');
      div.className = 'sre-msg-user';
      div.dataset.originalText = String(text || '');
      // Messages remember their timestamp so an artifact can point back at the
      // exact turn that produced it.
      if (ts) div.dataset.created = String(ts);
      if (msgId) div.dataset.msgId = String(msgId);
      div.style.cssText = 'align-self: flex-end; border-radius: 16px; padding: 12px 16px; max-width: 70%; font-size: 14px; line-height: 1.5; margin-bottom: 2px;';

      const contextRegex = /\n\n\[Context Attached: (file:\/\/[^\]]+)\]/g;
      const matches = [...text.matchAll(contextRegex)];

      const html = escapeHtml(text.replace(contextRegex, '').trim()).replace(/\n/g, '<br>');

      // Attachments render as their own card ABOVE the chat bubble (chat stays text-only)
      if (matches.length > 0) {
        const attachCard = document.createElement('div');
        attachCard.style.cssText = 'align-self: flex-end; max-width: 70%; margin-bottom: 6px; display: flex; flex-direction: column; gap: 6px;';
        matches.forEach(match => {
          const fileUrl = match[1];
          const fileName = fileUrl.split('/').pop();
          const item = document.createElement('div');
          item.style.cssText = 'display: flex; align-items: center; gap: 8px; background: var(--bg-panel); padding: 8px 12px; border-radius: 12px; font-size: 12px; border: 1px solid var(--border-color);';
          item.title = fileUrl;
          item.innerHTML = `<i class="fas fa-file-alt" style="color: var(--accent);"></i>
            <span style="flex: 1; min-width: 0; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(fileName)}</span>`;
          attachCard.appendChild(item);
        });
        messagesDiv.appendChild(attachCard);
      }

      if (html) {
        window.paintUserBubble(div, text, { animate: !window.isLoadingHistory });
        messagesDiv.appendChild(div);
      }
      const timeDiv = document.createElement('div');
      timeDiv.className = 'sre-msg-time';
      timeDiv.style.cssText = 'align-self: flex-end; font-size: 10px; color: var(--text-secondary); opacity: 0.7; margin-bottom: 8px; padding-right: 4px;';
      timeDiv.textContent = chatTimeLabel(ts);
      if (!window.isLoadingHistory && div.classList.contains('sre-sending')) {
        timeDiv.classList.add('sre-sending');
      }
      messagesDiv.appendChild(timeDiv);
      // Older prompts keep their text, but only the latest is currency: the
      // delete affordance lives on the newest bubble alone.
      try {
        const _allUser = messagesDiv.querySelectorAll('.sre-msg-user');
        _allUser.forEach((_el, _idx) => {
          const _del = _el.querySelector('[data-delete-msg="1"]');
          if (_del) _del.style.display = _idx === _allUser.length - 1 ? '' : 'none';
        });
      } catch (err) { /* best-effort */ }
      scrollToBottom();
    }

    // --- Delete a message (user messages cascade to their AI reply) -------
    window.deleteChatMessage = async function (event, btn) {
      event.preventDefault();
      event.stopPropagation();
      const el = btn.closest('[data-msg-id], .sre-msg-user, .agent-msg.sre-msg-ai');
      if (!el) return;
      // Only the newest user message can be deleted, which keeps the
      // cascade to its direct AI reply predictable.
      if (el.classList.contains('sre-msg-user')) {
        const all = Array.from(messagesDiv.querySelectorAll('.sre-msg-user'));
        if (el !== all[all.length - 1]) {
          addSystemMsg('Only the latest message can be deleted.', 'circle-info');
          return;
        }
      }
      const msgId = el.dataset.msgId;
      if (!msgId) {
        addSystemMsg('Message still loading, try again in a moment.', 'circle-info');
        return;
      }
      if (!confirm('Delete this message?')) return;
      try {
        const data = await window.wsCall('message.delete', { id: msgId });
        if (data && data.deleted) {
          // Remove the bubble and its paired reply from the DOM.
          el.remove();
          const isUser = el.classList.contains('sre-msg-user');
          if (isUser) {
            // The AI response that immediately followed this user message
            // belongs to the same turn and goes away too. Skip the timestamp
            // div that sits between the two bubbles.
            let sib = el.nextElementSibling;
            while (sib) {
              if (sib.classList.contains('sre-msg-time')) { sib = sib.nextElementSibling; continue; }
              if (sib.classList.contains('agent-msg')) { sib.remove(); }
              else if (sib.classList.contains('sre-msg-user')) { break; }
              sib = sib.nextElementSibling;
            }
            // Also remove the timestamp of the deleted user bubble.
            const prevTime = el.previousElementSibling;
            if (prevTime && prevTime.classList.contains('sre-msg-time')) prevTime.remove();
          }
          addSystemMsg('Message deleted.', 'check');
        }
      } catch (e) {
        addSystemMsg('Delete failed: ' + (e.message || e), 'circle-alert');
      }
    };

    // --- Revise a prompt before it is sent on -------------------------------
    window.editUserMessage = function (btn) {
      const bubble = btn && btn.closest('.sre-msg-user');
      if (!bubble) return;
      if (isProcessing) {
        addSystemMsg('Stop the current run first, then edit the message.', 'circle-info');
        return;
      }
      // Only the newest prompt can be revised; older turns are history.
      const bubbles = Array.from(messagesDiv.querySelectorAll('.sre-msg-user'));
      if (bubble !== bubbles[bubbles.length - 1]) {
        addSystemMsg('Only the latest message can be edited. Start a new chat to ask something else.', 'circle-info');
        return;
      }
      const original = (bubble.dataset.rawText || bubble.textContent || '').trim();
      // Hold the bubble's rendered width, otherwise it collapses to the
      // textarea's intrinsic width and the card shrinks to a thin strip.
      const renderedWidth = Math.round(bubble.getBoundingClientRect().width);
      bubble.innerHTML = '';
      bubble.style.maxWidth = 'none';
      bubble.style.width = Math.max(renderedWidth, 280) + 'px';
      bubble.style.minWidth = '280px';
      const ta = document.createElement('textarea');
      ta.value = original.replace(/\n\n\[Context Attached:[\s\S]*\]$/, '').trim();
      ta.rows = Math.min(8, Math.max(2, ta.value.split('\n').length + 1));
      ta.style.cssText = 'width:100%; box-sizing:border-box; background:rgba(0,0,0,0.14); color:#ffffff;' +
        ' border:1px solid rgba(255,255,255,0.22); border-radius:10px; outline:none; padding:8px 10px;' +
        ' resize:vertical; font-size:14px; line-height:1.5; font-family:inherit;';
      const row = document.createElement('div');
      row.style.cssText = 'display:flex; gap:6px; justify-content:flex-end; margin-top:8px;';
      const save = document.createElement('button');
      save.textContent = 'Save & send';
      save.style.cssText = 'background:#0b6fc4; color:#fff; border:1px solid rgba(255,255,255,0.3); border-radius:8px;' +
        ' padding:5px 12px; font-size:12px; font-weight:600; cursor:pointer;';
      const drop = document.createElement('button');
      drop.textContent = 'Cancel';
      drop.style.cssText = 'background:rgba(0,0,0,0.2); color:#fff; border:1px solid rgba(255,255,255,0.3);' +
        ' border-radius:8px; padding:5px 12px; font-size:12px; cursor:pointer;';
      const err = document.createElement('div');
      err.style.cssText = 'font-size:11px; color:var(--error); margin-top:6px; display:none;';
      row.appendChild(drop); row.appendChild(save);
      bubble.appendChild(ta); bubble.appendChild(row); bubble.appendChild(err);
      ta.focus();
      ta.setSelectionRange(ta.value.length, ta.value.length);

      drop.onclick = () => {
        window.paintUserBubble(bubble, original, {});
      };
      save.onclick = () => {
        const text = ta.value.trim();
        if (!text) { err.textContent = 'Message cannot be empty.'; err.style.display = 'block'; return; }
        drop.onclick = null;
        // Editing is non-destructive: the bubble is repainted in place and the
        // earlier answer, run card and error cards stay exactly where they are.
        // The revised request is simply sent again below them.
        window.paintUserBubble(bubble, text, { edited: true, animate: true });
        addSystemMsg('Sent again with the revised request. The earlier answer is kept above for reference.', 'pen');
        const inputEl = document.getElementById('chat-input');
        if (inputEl) { inputEl.value = text; inputEl.dispatchEvent(new Event('input')); }
        const formEl = document.getElementById('chat-form') || (inputEl && inputEl.form);
        if (formEl) {
          if (formEl.requestSubmit) formEl.requestSubmit();
          else formEl.dispatchEvent(new Event('submit', { cancelable: true }));
        } else {
          addSystemMsg('Could not resend the message. Copy it to the composer and send again.', 'alert-triangle');
        }
      };
      ta.addEventListener('input', () => {
        ta.style.height = 'auto';
        ta.style.height = Math.min(220, ta.scrollHeight) + 'px';
        bubble.style.width = 'auto';
        bubble.style.minWidth = Math.max(renderedWidth, 280) + 'px';
      });
      ta.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); save.click(); }
        if (e.key === 'Escape') { e.preventDefault(); drop.click(); }
      });
    };

    // --- Bot avatar: no external deps, pure inline SVG + SMIL animation.
    window.neuroBotAvatar = window.neuroBotAvatar || function (size, working) {
      var h = size || 28;
      var bob = working
        ? '<animateTransform attributeName="transform" type="translate" values="0 0; 0 -2; 0 0" dur="1.1s" repeatCount="indefinite"/>'
        : '<animateTransform attributeName="transform" type="translate" values="0 0; 0 -1.5; 0 0" dur="2.4s" repeatCount="indefinite"/>';
      return `<svg width="${h}" height="${h}" viewBox="0 0 64 64" aria-hidden="true">
        <defs>
          <linearGradient id="nb-g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#7c8cf8"/><stop offset="1" stop-color="#7bd6c2"/>
          </linearGradient>
        </defs>
        <g>${bob}
          <rect x="11" y="15" width="42" height="34" rx="17" fill="url(#nb-g)" stroke="rgba(255,255,255,.55)" stroke-width="1.4"/>
          <rect x="14" y="17" width="20" height="8" rx="4" fill="rgba(255,255,255,.55)"/>
          <g>
            <animateTransform attributeName="transform" type="translate" values="0 0; 1.1 0; 0 0; -1 0; 0 0" dur="9.4s" repeatCount="indefinite"/>
            <g fill="#0f172a">
              <g transform="translate(27,31)">
                <g>
                  <animateTransform attributeName="transform" type="scale" values="1 1;1 1;1 0.07;1 1;1 1;1 1;1 0.07;1 0.07;1 1;1 1;1 1;1 0.07;1 1;1 1"
                    keyTimes="0;0.18;0.196;0.215;0.42;0.445;0.461;0.479;0.5;0.7;0.722;0.74;0.766;1"
                    dur="13.2s" repeatCount="indefinite"/>
                  <circle r="2.8"/>
                  <circle cx="-0.9" cy="-0.9" r="0.9" fill="rgba(255,255,255,.85)"/>
                </g>
              </g>
              <g transform="translate(39,31)">
                <g>
                  <animateTransform attributeName="transform" type="scale" values="1 1;1 1;1 0.07;1 1;1 1;1 1;1 0.07;1 0.07;1 1;1 1;1 1;1 0.07;1 1;1 1"
                    keyTimes="0;0.18;0.196;0.215;0.42;0.445;0.461;0.479;0.5;0.7;0.722;0.74;0.766;1"
                    dur="13.2s" begin="-0.12s" repeatCount="indefinite"/>
                  <circle r="2.8"/>
                  <circle cx="-0.9" cy="-0.9" r="0.9" fill="rgba(255,255,255,.85)"/>
                </g>
              </g>
            </g>
          </g>
          <path d="M25 40 q7 5 14 0" fill="none" stroke="#0f172a" stroke-width="2" stroke-linecap="round"/>
          <line x1="33" y1="15" x2="38" y2="8" stroke="#7c8cf8" stroke-width="2.4" stroke-linecap="round"/>
          <circle cx="39" cy="7" r="2.4" fill="#7bd6c2"/>
        </g>
      </svg>`;
    };

    // A phase event must never be dropped because the run wrap is missing
    // (resumed socket, run started before the wrap existed, ...).
    // Where does a step of the current turn belong? Answered in one place so a
    // step can never escape the Agent Run card: the live card, else the card
    // this turn just finished, else the packaged card of the live turn, else a
    // freshly opened one. The bare timeline is only acceptable while replaying
    // history that predates run grouping.
    window.resolveStepParent = function () {
      const sid = String(sessionId || '');
      const wrap = window.activeRunWrap;
      if (wrap && document.contains(wrap)) {
        const owner = String(wrap.dataset.sessionId || '');
        if (!owner || owner === sid) return wrap;
      }
      const last = window.lastRunBody;
      if (last && document.contains(last) && !window.replayActive) {
        const owner = String(last.dataset.sessionId || '');
        if (!owner || owner === sid) return last;
      }
      const skel = window.liveBubbleCurrent;
      const skelBody = skel && skel.wrap && document.contains(skel.wrap)
        ? (skel.wrap.querySelector('[data-wrap-id]') || null) : null;
      if (skelBody && document.contains(skelBody)) return skelBody;
      // While replaying, steps belong to the card currently being rebuilt.
      const replayWrap = window.historyReplayWrap;
      if (replayWrap && document.contains(replayWrap)) return replayWrap;
      // Replay of a turn whose card is not open yet must never fall through to
      // the bare timeline: that is how steps escaped their card entirely.
      // A live call landing here takes the live path below instead.
      if (window.replayActive) return null;
      if (window.ensureRunWrap) {
        const fresh = window.ensureRunWrap();
        if (fresh && document.contains(fresh)) return fresh;
      }
      return null;
    };

    // A turn is open from submit until its terminal event. Anything arriving
    // after it closed is a straggler: adopting it is what left a second empty
    // bubble with a spinner, a stuck caret, and a run that could never send
    // again. Closed turns ignore run content and never open new containers.
    // Every status that means "this will never run again", in one place. The
    // thirteenth entry matters: superseded and expired cases kept falling
    // through every check written before they existed, so dead cases rendered
    // as alive.
    window.SRE_TERMINAL = ['completed', 'failed', 'cancelled', 'stopped', 'blocked', 'denied',
      'denied_timeout', 'security_blocked', 'error', 'finalized', 'expired', 'superseded'];
    window.turnState = window.turnState || 'idle';
    window.openTurn = function () { window.turnState = 'running'; };
    window.closeTurn = function () {
      window.turnState = 'idle';
      // The live flag is what pins the bubble header; drop it the moment the
      // turn ends so archived answers scroll like ordinary history again.
      document.querySelectorAll('.agent-msg.sre-msg-ai[data-live="1"]').forEach(b => {
        b.removeAttribute('data-live');
      });
    };
    window.turnIsOpen = function () { return window.turnState !== 'idle'; };

    window.ensureRunWrap = function () {
      if (window.replayActive) return null;
      if (!window.turnIsOpen()) return window.activeRunWrap;
      if (!window.activeRunWrap) startRunWrap();
      else if (window.revealRunWrap) window.revealRunWrap();
      return window.activeRunWrap;
    };

    // The send action creates the bubble and starting pill immediately, while
    // the empty workflow card stays tucked away until the first real step.
    window.revealRunWrap = function () {
      const body = window.activeRunWrap;
      if (!body || !body.dataset || body.dataset.deferOpen !== '1') return body;
      body.dataset.deferOpen = '0';
      const wrapId = body.dataset.wrapId;
      if (wrapId) window.toggleRunWrap(wrapId, true);
      return body;
    };

    window.runPhaseLabels = {
      starting: 'starting',
      resuming: 'resuming',
      exploring: 'observing',
      search: 'discovering tools',
      planning: 'planning',
      thinking: 'thinking',
      verifying: 'verifying',
      executing: 'executing',
      working: 'executing',
      running: 'executing',
      listening: 'awaiting approval',
      awaiting_approval: 'awaiting approval',
      composing: 'composing',
    };

    window.setRunPhaseLabel = function (state, label) {
      var wrapId = window.activeRunWrap ? window.activeRunWrap.dataset.wrapId : null;
      if (!wrapId) return;
      var text = label || window.runPhaseLabels[state];
      if (!text) return;
      window.paintBubblePill(wrapId, text, { spinner: true, working: true });
    };

    // The dot mirrors the run state: informative, and it never washes out text.
    window.setAgentDotState = function (state) {
      document.querySelectorAll('.sre-agent-dot').forEach((dot) => {
        dot.dataset.state = state;
        dot.title = state === 'running' ? 'Agent working' : (state === 'done' ? 'Run finished' : 'Agent idle');
      });
    };

    // Streaming presentation for the reply itself: newly arrived text settles
    // in with a soft reveal, while a restrained shimmer marks the live answer.
    // A turn's text is two things: the narrated reasoning that arrived while
    // the agent worked, and the answer it concluded with. The server marks
    // where the second one starts, so a live turn and the same turn replayed
    // from history split in exactly the same place. Narration folds away once
    // the answer exists, and stays one click away.
    window.SRE_FINAL_MARKER = '<!--sre-final-->';
    // The completion summary belongs to the reply it explains, so it lives
    // inside that bubble's column directly under the panel instead of floating
    // in the transcript as a separate block.
    // One audit card for live and replay alike: a green check, the title, a
    // one-line summary of what was achieved, and the trail underneath.
    window.buildAuditHtml = function (opts) {
      const o = opts || {};
      // Audit time only: the answer already lives above, repeating it here
      // doubled the bubble for no reason.
      const check = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      const row = (icon, k, v) => '<div style="display:flex; align-items:center; gap:10px; padding:8px 0; border-top:1px solid var(--border-color); font-size:12px;">'
        + '<i class="fa-solid ' + icon + '" style="flex:none; width:16px; text-align:center; color:var(--success-text); font-size:11px;"></i>'
        + '<span style="flex:none; width:96px; color:var(--text-secondary);">' + k + '</span>'
        + '<span style="flex:1; min-width:0; color:var(--text-primary); font-family:monospace; font-size:11.5px; word-break:break-word;">' + v + '</span></div>';
      return '<details class="sre-run-audit">'
        + '<summary style="cursor:pointer; list-style:none; display:flex; align-items:center; gap:12px; padding:12px 14px; user-select:none;">'
        + '<span style="flex:none; width:24px; height:24px; border-radius:50%; background:var(--success); display:flex; align-items:center; justify-content:center;">'
        + check + '</span>'
        + '<span style="flex:1; min-width:0; font-size:14px; font-weight:700; color:var(--success-text);">Task Execution Completed</span>'
        + '<i class="fa-solid fa-chevron-down" style="flex:none; color:var(--success-text); font-size:12px; transition:transform .2s;"></i>'
        + '</summary>'
        + '<div style="padding:2px 14px 12px 48px; font-size:12.5px;">'
        + row('fa-circle-check', 'Status', '<strong style="color:var(--success-text); font-family:inherit;">COMPLETED</strong>')
        + row('fa-play', 'Started', escapeHtml(o.started || '-'))
        + row('fa-flag-checkered', 'Finished', escapeHtml(o.finished || '-'))
        + row('fa-clock', 'Total time', escapeHtml(o.total || '-'))
        + '</div></details>';
    };

    window.attachRunAudit = function (bubble, html) {
      try {
        if (!bubble || !html) return false;
        let column = null;
        for (const child of bubble.children) {
          if (child.classList && child.classList.contains('agent-msg-body')) { column = child; break; }
        }
        if (!column) {
          const panel = bubble.querySelector('.sre-panel');
          if (!panel) return false;
          column = document.createElement('div');
          column.className = 'agent-msg-body';
          column.style.cssText = 'flex:1; min-width:0; display:flex; flex-direction:column;';
          bubble.insertBefore(column, panel);
          column.appendChild(panel);
        }
        const panel = bubble.querySelector(':scope .agent-msg-body .sre-panel')
          || bubble.querySelector('.sre-panel');
        if (!panel) return false;
        const stale = panel.querySelector(':scope > .sre-run-audit');
        if (stale) stale.remove();
        const holder = document.createElement('div');
        holder.innerHTML = html;
        const audit = holder.querySelector('.sre-run-audit');
        if (!audit) return false;
        const answer = panel.querySelector(':scope > .ai-content');
        if (answer) panel.insertBefore(audit, answer.nextSibling);
        else panel.appendChild(audit);
        return true;
      } catch (err) { return false; }
    };

    // Status emoji -> ikon/badge monokrom biru aksen (senada bg header
    // tabel). Emoji native beda-beda render per OS/browser; yang diganti
    // cuma emoji status, bukan semua emoji.
    window.SRE_EMOJI_MAP = [
      ['✅', 'circle-check'], ['❎', 'circle-xmark:red'], ['❌', 'circle-xmark:red'],
      ['✖️', 'xmark:red'], ['✖', 'xmark:red'], ['✔️', 'check'], ['✔', 'check'],
      ['⚠️', 'triangle-exclamation:warn'], ['⚠', 'triangle-exclamation:warn'],
      ['❗', 'circle-exclamation'], ['ℹ️', 'circle-info'], ['ℹ', 'circle-info'],
      ['🔧', 'screwdriver-wrench'], ['🔨', 'hammer'], ['⚙️', 'gear'], ['⚙', 'gear'],
      ['🛠️', 'screwdriver-wrench'], ['🛠', 'screwdriver-wrench'], ['🧰', 'toolbox'],
      ['🌐', 'globe'], ['🔍', 'magnifying-glass'], ['📡', 'tower-broadcast'],
      ['🖥️', 'desktop'], ['🖥', 'desktop'], ['💻', 'laptop'],
      ['🗄️', 'database'], ['🗄', 'database'], ['💾', 'floppy-disk'], ['💿', 'compact-disc'],
      ['📁', 'folder'], ['📂', 'folder-open'], ['📄', 'file-lines'], ['📝', 'pen'],
      ['📦', 'box'], ['🔗', 'link'], ['🔌', 'plug'], ['🔋', 'battery-full'],
      ['📊', 'chart-column'], ['📈', 'chart-line'], ['📉', 'arrow-trend-down'],
      ['⚡', 'bolt'], ['🔥', 'fire'], ['💥', 'bolt'], ['🚨', 'bell'],
      ['🔔', 'bell'], ['🔕', 'bell-slash'], ['📢', 'bullhorn'], ['🎯', 'crosshairs'],
      ['🏁', 'flag-checkered'],
      ['⏱️', 'stopwatch'], ['⏱', 'stopwatch'], ['⏳', 'hourglass-half'], ['⌛', 'hourglass'],
      ['🕐', 'clock'], ['📅', 'calendar'],
      ['🔒', 'lock'], ['🔓', 'lock-open'], ['🔑', 'key'], ['🛡️', 'shield-halved'], ['🛡', 'shield-halved'],
      ['🚀', 'rocket'], ['💡', 'lightbulb'], ['📌', 'thumbtack'], ['📍', 'location-dot'],
      ['🧠', 'brain'], ['🤖', 'robot'], ['💬', 'comment'], ['👀', 'eye'],
      ['👍', 'thumbs-up'], ['👎', 'thumbs-down'], ['⭐', 'star'], ['🌙', 'moon'],
      ['☀️', 'sun'], ['☀', 'sun'], ['🌡️', 'temperature-half'],
      ['🧹', 'broom'], ['🗑️', 'trash-can'], ['🗑', 'trash-can'], ['🧪', 'flask'],
      ['🧭', 'compass'], ['🗺️', 'map'], ['🏠', 'house'], ['🖧', 'network-wired'],
      ['🔹', null], ['🔸', null],
    ].map(([emo, icon]) => {
      if (!icon) return [emo, '<span style="display:inline-block;width:.5em;height:.5em;border-radius:2px;background:var(--accent);margin-right:.2em;"></span>'];
      const [name, tone] = String(icon).split(':');
      const color = tone === 'red' ? 'var(--error)' : tone === 'warn' ? '#eab308' : 'var(--accent)';
      return [emo, `<i class="fa-solid fa-${name}" style="color:${color};"></i>`];
    });
    // Ganti emoji status di HTML jawaban. Output terminal/code (<pre>)
    // dilewat supaya log tetap apa adanya.
    window.sreEmojifyHtml = function (html) {
      const parts = String(html == null ? '' : html).split(/(<pre[\s>][\s\S]*?<\/pre>)/gi);
      for (let i = 0; i < parts.length; i += 2) {
        let s = parts[i];
        window.SRE_EMOJI_MAP.forEach(([emo, rep]) => { s = s.split(emo).join(rep); });
        parts[i] = s;
      }
      return parts.join('');
    };

    // Markdown mentah (task, findings) -> HTML bubble. Pisahin separator
    // tabel yang nempel (lihat fixTables di renderAnswerContent), parse,
    // terus emojify. Aman dipanggil di step mana pun.
    window.sreMarkdownHtml = function (rawText) {
      let src = String(rawText == null ? '' : rawText);
      const parts = src.split(/(```[\s\S]*?(?:```|$))/g);
      for (let i = 0; i < parts.length; i += 2) {
        parts[i] = parts[i].split('\n').map((line) =>
          line.replace(/\|\|(?=\s*:?-{2,})/, '|\n|')
        ).join('\n');
      }
      src = parts.join('');
      try { return window.sreEmojifyHtml(marked.parse(src)); } catch (e) { return escapeHtml(src); }
    };

    window.renderAnswerContent = function (rawText) {      const text = String(rawText == null ? '' : rawText);
      const at = text.indexOf(window.SRE_FINAL_MARKER);
      // Model kadang nempelin garis separator ke baris header:
      // "| Cek | Hasil ||-----|" -> pecah jadi header + delimiter agar
      // marked mau render tabel. Blok kode (```) dilewat.
      const fixTables = (src) => {
        const parts = String(src == null ? '' : src).split(/(```[\s\S]*?(?:```|$))/g);
        for (let i = 0; i < parts.length; i += 2) {
          parts[i] = parts[i].split('\n').map((line) =>
            line.replace(/\|\|(?=\s*:?-{2,})/, '|\n|')
          ).join('\n');
        }
        return parts.join('');
      };
      const md = (chunk) => {
        try { return window.sreEmojifyHtml(marked.parse(fixTables(chunk))); } catch (e) { return escapeHtml(chunk); }
      };
      if (at < 0) {
        return '<div class="sre-answer-body">' + md(text) + '</div>';
      }
      const narration = text.slice(0, at).trim();
      const answer = text.slice(at + window.SRE_FINAL_MARKER.length).trim();
      const paragraphs = narration ? narration.split(/\n{2,}/).filter((p) => p.trim()).length : 0;
      const narrationHtml = narration
        ? '<details class="sre-reasoning" open style="margin-bottom: 10px; border: 0; background: transparent;">' +
          '<summary style="cursor: pointer; padding: 8px 0; font-size: 12px; font-weight: 600; color: var(--text-secondary); list-style: none; display: flex; align-items: center; gap: 8px;">' +
          '<i class="fa-solid fa-chevron-right sre-reasoning-chev" style="font-size: 10px; transition: transform .2s;"></i>' +
          'Reasoning <span style="font-weight: 400; opacity: .8;">· ' + paragraphs + ' note' + (paragraphs === 1 ? '' : 's') + ' while it worked</span>' +
          '</summary>' +
          '<div class="sre-reasoning-body sre-md" style="padding: 0 0 10px 18px; font-size: 12.5px; line-height: 1.65; color: var(--text-secondary); opacity: .92;">' +
          md(narration) + '</div></details>'
        : '';
      return narrationHtml + '<div class="sre-answer-body">' + md(answer) + '</div>';
    };

    // Reasoning stays open while streaming and after completion, in both live
    // rendering and history replay.
    // A finished turn leaves no trace of motion behind: every highlight settles,
    // in every bubble, not just the one the
    // pointer happens to reference. A duplicate terminal event used to skip
    // all of this and leave the blue caret blinking forever.
    window.stopAllStreaming = function () {
      try {
        document.querySelectorAll('#chat-messages .ai-content.sre-streaming').forEach((box) => {
          box.classList.remove('sre-streaming');
          const live = box.querySelector('.sre-live-text');
          if (live) live.outerHTML = live.innerHTML;
          box.style.animation = 'none';
          void box.offsetWidth;
          box.style.animation = '';
        });
      } catch (err) { /* best-effort */ }
    };

    window.markStreaming = function (on, contentDiv) {
      const box = contentDiv || (window.currentAIMsg && window.currentAIMsg.querySelector('.ai-content'));
      if (!box) return;
      if (on) {
        box.classList.add('sre-streaming');
        const fresh = box.querySelector('.sre-live-text');
        if (!fresh) {
          // Wrap the last block of text so only the new part is highlighted.
          const blocks = Array.from(box.children);
          const target = blocks.length ? blocks[blocks.length - 1] : null;
          if (target && !target.querySelector('.sre-live-text')) {
            const inner = target.innerHTML;
            target.innerHTML = '<span class="sre-live-text">' + inner + '</span>';
          }
        }
      } else {
        box.classList.remove('sre-streaming');
        const live = box.querySelector('.sre-live-text');
        if (live) {
          const span = live;
          span.outerHTML = span.innerHTML;
        }
        box.style.animation = 'none';
        void box.offsetWidth;
        box.style.animation = '';
      }
    };

    window.setRunPhase = function (state, label) {
      if (state === 'done') {
        window.setAgentDotState('done');
        return;
      }
      if (window.isLoadingHistory) return;
      window.setAgentDotState('running');
      window.setRunPhaseLabel(state, label);
    };

    // The run card is the trace of the work that produced this answer, so it
    // always reads directly above the response panel, beside the bot avatar.
    // Appending in arrival order is not enough: a resumed run can open its
    // card after the bubble already exists, so the position is enforced here.
    window.seatRunCardAbove = function (card) {
      if (!card) return;
      const body = window.activeRunWrap;
      if (!body) return;
      window.seatWrapAbove(body.parentElement, card);
    };

    // One bubble, one column: avatar on the left, and on the right a single
    // column with the run card on top and the response panel below it. The
    // card is seated inside the bubble's column so the turn reads as one unit
    // and the header keeps its full clickable width.
    // A chat runs one turn at a time, so the packaged skeleton is a single
    // slot rather than a map keyed by session id: on a brand new chat the id
    // is still unknown when the skeleton is born, and a keyed lookup simply
    // missed it and built a second bubble with a second avatar.
    window.liveBubbles = window.liveBubbles || {};
    // Exactly one turn is live at a time, so exactly one bubble carries the
    // flag that pins its header. Anything else still flagged is stale.
    window.markLiveBubble = function (bubble) {
      try {
        if (!bubble) return;
        document.querySelectorAll('.agent-msg.sre-msg-ai[data-live="1"]').forEach(b => {
          if (b !== bubble) b.removeAttribute('data-live');
        });
        bubble.setAttribute('data-live', '1');
      } catch (err) { /* best-effort */ }
    };

    // --- Turn rail: chat outline navigation ---
    // One strip per question turn down the left edge of the chat column.
    // Hover previews the question and its answer, click jumps straight to the
    // turn, and the strip for the turn on screen stretches long.
    window.turnRail = window.turnRail || { marks: [] };

    window.turnRailRoot = function () {
      const host = messagesDiv && messagesDiv.parentElement;
      if (!host) return null;
      if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
      let rail = document.getElementById('sre-turn-rail');
      if (!rail) {
        rail = document.createElement('div');
        rail.id = 'sre-turn-rail';
        host.appendChild(rail);
      }
      let tip = document.getElementById('sre-turn-tip');
      if (!tip) {
        tip = document.createElement('div');
        tip.id = 'sre-turn-tip';
        host.appendChild(tip);
      }
      return { rail: rail, tip: tip };
    };

    window.turnRailEntry = function (userEl) {
      const raw = userEl.dataset.originalText || userEl.textContent || '';
      const q = raw.replace(/\n\n\[Context Attached: [^\]]+\]/g, '').trim();
      let sib = userEl.nextElementSibling;
      while (sib && !(sib.classList && sib.classList.contains('agent-msg'))) sib = sib.nextElementSibling;
      const ansEl = sib && sib.querySelector('.ai-content');
      const a = ansEl ? ansEl.textContent.trim().slice(0, 220) : '';
      let t = '';
      try { t = userEl.dataset.created ? chatTimeLabel(userEl.dataset.created) : ''; } catch (e) { /* best-effort */ }
      return { el: userEl, q: q || '(empty question)', a: a, t: t };
    };

    // A turn is a user question bubble; every direct .sre-msg-user child of the
    // scroll column is one, in document order.
    window.refreshTurnRail = function () {
      try {
        const root = window.turnRailRoot();
        if (!root || !messagesDiv) return;
        const users = Array.from(messagesDiv.children)
          .filter(el => el.classList && el.classList.contains('sre-msg-user'));
        root.rail.innerHTML = '';
        window.turnRailHide();
        window.turnRail.marks = users.map((u) => {
          const entry = window.turnRailEntry(u);
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'sre-turn-mark';
          b.setAttribute('aria-label', entry.q.slice(0, 80));
          b.innerHTML = '<span class="sre-turn-bar"></span>';
          b.addEventListener('click', () => window.turnRailJump(entry.el));
          b.addEventListener('mouseenter', () => window.turnRailTip(entry, b));
          b.addEventListener('mouseleave', () => window.turnRailHide());
          root.rail.appendChild(b);
          return { mark: b, el: u };
        });
        root.rail.style.display = users.length ? '' : 'none';
        window.turnRailActive();
      } catch (err) { /* best-effort */ }
    };

    window.turnRailJump = function (el) {
      try {
        if (!el || !document.contains(el) || !messagesDiv) return;
        const r = el.getBoundingClientRect();
        const host = messagesDiv.getBoundingClientRect();
        messagesDiv.scrollTo({ top: messagesDiv.scrollTop + r.top - host.top - 56, behavior: 'smooth' });
      } catch (err) { /* best-effort */ }
    };

    window.turnRailTip = function (entry, mark) {
      try {
        const root = window.turnRailRoot();
        if (!root || !messagesDiv) return;
        const tip = root.tip;
        tip.innerHTML =
          '<p class="sre-tip-q">' + escapeHtml(entry.q) + '</p>' +
          (entry.t ? '<div class="sre-tip-t">' + escapeHtml(entry.t) + '</div>' : '') +
          '<p class="sre-tip-a">' + escapeHtml(entry.a || 'Agent is working on this…') + '</p>';
        tip.classList.add('sre-show');
        // Center the card on the strip, clamped inside the column above the
        // floating composer so it never slides under the input bar.
        const host = messagesDiv.parentElement.getBoundingClientRect();
        const mr = mark.getBoundingClientRect();
        let top = mr.top - host.top + (mr.height / 2) - (tip.offsetHeight / 2);
        top = Math.max(8, Math.min(top, host.height - tip.offsetHeight - 190));
        tip.style.top = Math.round(top) + 'px';
      } catch (err) { /* best-effort */ }
    };

    window.turnRailHide = function () {
      const tip = document.getElementById('sre-turn-tip');
      if (tip) tip.classList.remove('sre-show');
    };

    // The deepest turn that has crossed into view owns the long strip.
    window.turnRailActive = function () {
      try {
        if (!messagesDiv) return;
        const host = messagesDiv.getBoundingClientRect();
        let pick = null;
        (window.turnRail.marks || []).forEach(m => {
          if (!document.contains(m.el)) return;
          if (m.el.getBoundingClientRect().top <= host.top + 140) pick = m;
        });
        (window.turnRail.marks || []).forEach(m => m.mark.classList.toggle('sre-active', m === pick));
      } catch (err) { /* best-effort */ }
    };

    window.turnRailActiveSchedule = function () {
      if (window.turnRailQueued) return;
      window.turnRailQueued = true;
      requestAnimationFrame(() => {
        window.turnRailQueued = false;
        try { window.turnRailActive(); window.turnRailHide(); } catch (e) { /* best-effort */ }
      });
    };

    // Rebuild on every turn-level change: history load, older-page prepend,
    // new question, new answer. Step rows land inside the run body, not as
    // direct children, so streaming never triggers a rebuild by itself.
    window.turnRailObserve = function () {
      if (window.turnRailInit || !messagesDiv) return;
      window.turnRailInit = true;
      let t = null;
      new MutationObserver(() => {
        if (t) clearTimeout(t);
        t = setTimeout(() => { try { window.refreshTurnRail(); } catch (e) { /* best-effort */ } }, 400);
      }).observe(messagesDiv, { childList: true });
      window.refreshTurnRail();
    };
    // A packaged turn skeleton: bot avatar on the left, one column on the
    // right holding the run card now and the answer panel later.
    // On send, the answer bubble is born first and the run seats its chain
    // into it: avatar, header with the live pill, the chain of thought, then
    // the answer as it streams.
    window.ensureLiveBubble = function (sid, wrap) {
      try {
        if (!wrap) return null;
        const prev = window.liveBubbleCurrent;
        const prevPanel = prev && document.contains(prev.bubble)
          ? prev.bubble.querySelector('.sre-panel .ai-content') : null;
        if (prev && prevPanel && !prevPanel.textContent.trim()) {
          prev.wrap = wrap;
          window.seatChain(prev.bubble, wrap);
          window.markLiveBubble(prev.bubble);
          if (typeof currentAIMsg !== 'undefined' && !currentAIMsg) currentAIMsg = prev.bubble;
          return prev;
        }
        const bubble = buildAnswerBubble('', null, null);
        bubble.dataset.sessionId = sid;
        messagesDiv.appendChild(bubble);
        window.seatChain(bubble, wrap);
        window.markLiveBubble(bubble);
        const column = bubble.querySelector(':scope > .agent-msg-body');
        const entry = { bubble: bubble, column: column, wrap: wrap, claimed: false, sid: sid };
        window.liveBubbles[sid] = entry;
        window.liveBubbleCurrent = entry;
        if (typeof currentAIMsg !== 'undefined' && !currentAIMsg) currentAIMsg = bubble;
        scrollToBottom();
        return entry;
      } catch (err) { return null; }
    };

    window.discardLiveBubble = function (sid) {
      try {
        const skel = window.liveBubbleCurrent;
        const answer = skel && skel.bubble.querySelector('.sre-panel .ai-content');
        if (skel && document.contains(skel.bubble)
            && (!sid || !skel.sid || String(skel.sid) === String(sid))
            && answer && !answer.textContent.trim()) {
          skel.bubble.remove();
        }
        window.liveBubbleCurrent = null;
        if (window.liveBubbles && sid) delete window.liveBubbles[sid];
      } catch (err) { /* best-effort */ }
    };

    // The chain of thought seats inside the bubble's own slot, under the
    // header and above the answer. The bubble owns the status pill; the run
    // card's own header steps aside (its hooks keep working, they are just not
    // painted anymore).
    // The chain is its own card standing directly above its bubble, and the
    // bubble pill opens it. Nesting it inside the bubble kept breaking in ways
    // that all looked the same from the outside - an empty slot, a card that
    // never arrived, steps in someone else's card - because every render moved
    // nodes across containers and each move could orphan something. Placement
    // is now a single insertBefore in the transcript order, so ownership is
    // visible in the DOM itself and there is nothing to leak.
    window.seatChain = function (bubble, wrap) {
      if (!bubble || !wrap) return false;
      try {
        if (String(wrap.dataset.sessionId || '') && String(bubble.dataset.sessionId || '')
            && String(wrap.dataset.sessionId) !== String(bubble.dataset.sessionId)) return false;
        const slot = bubble.querySelector(':scope .agent-msg-body .sre-panel .sre-cot');
        if (!slot) return false;
        const body = wrap.querySelector('[data-wrap-id]') || wrap.firstElementChild;
        const wrapId = (body && body.dataset.wrapId) || wrap.id;
        // A card painted before it met its bubble (replay) hands its latest
        // state to the pill the moment they join.
        if (wrapId) {
          const _w = document.getElementById(wrapId);
          const _last = _w && _w.dataset.lastStatus;
          if (_last) {
            const _dur = _w.dataset.lastDuration !== '' ? Number(_w.dataset.lastDuration) : null;
            const _low = _last.toLowerCase();
            const _terminal = window.SRE_TERMINAL.includes(_low);
            const _status = _terminal ? _last : 'working';
            window.paintBubblePill(wrapId, _status,
              _terminal
                ? { done: _low === 'completed', failed: _low !== 'completed', duration: _dur }
                : { spinner: true, working: true });
          }
        }
        if (wrap.parentElement === messagesDiv && wrap.nextElementSibling === bubble) {
          if (wrapId) bubble.dataset.wrapId = wrapId;
          bubble.dataset.chainOpen = document.getElementById(wrapId + '-body')
            && document.getElementById(wrapId + '-body').dataset.open === '1' ? '1' : '0';
          return true;
        }
        messagesDiv.insertBefore(wrap, bubble);
        wrap.dataset.bubbleId = bubble.id;
        if (wrapId) bubble.dataset.wrapId = wrapId;
        window.syncBubblePill(bubble);
        const _shown = wrap.style.display !== 'none';
        bubble.dataset.chainOpen = _shown ? '1' : '0';
        const chev = bubble.querySelector('.sre-run-chev');
        if (chev) chev.style.transform = _shown ? 'rotate(0deg)' : 'rotate(-90deg)';
        return true;
      } catch (err) { return false; }
    };

    window.seatWrapAbove = function (wrap, card) {
      if (!wrap || !card || wrap === card || wrap.contains(card)) return;
      window.seatChain(card, wrap);
    };

    // A run card always lives inside its answer's column, above the response
    // panel. Anything left elsewhere (stale-tree artifact) is pulled in.
    window.normalizeRunCards = function () {
      try {
        document.querySelectorAll('[id^="runwrap-"]').forEach((wrap) => {
          const linked = wrap.dataset.bubbleId && document.getElementById(wrap.dataset.bubbleId);
          if (linked && document.contains(linked)) { window.seatChain(linked, wrap); return; }
          const bubble = wrap.closest('.agent-msg.sre-msg-ai');
          if (bubble && document.contains(bubble)) window.seatChain(bubble, wrap);
        });
      } catch (err) { /* best-effort */ }
    };

    function buildAnswerBubble(content, ts, msgId) {
      const div = document.createElement('div');
      const bubbleId = 'bubble-' + Math.random().toString(36).substr(2, 9);
      div.id = bubbleId;
      div.className = 'agent-msg sre-msg-ai';
      div.dataset.sessionId = String(sessionId || '');
      if (ts) div.dataset.created = String(ts);
      if (msgId) div.dataset.msgId = String(msgId);
      div.style.cssText = 'display:flex; align-items:flex-start; gap:12px; max-width: 92%; margin-bottom: 2px;';
      // One card per turn: header with the status pill, the chain of thought,
      // then the answer. The pill opens the chain.
      div.innerHTML = `
            <div data-avatar="agent" style="flex-shrink:0; width:56px; height:56px; border-radius:50%; background:rgba(31, 111, 235, 0.12); border:1px solid var(--border-color); display:flex; align-items:center; justify-content:center; box-shadow: 0 4px 12px rgba(0,0,0,0.08); flex-wrap: nowrap; overflow: hidden;">
                ${window.neuroBotAvatar(42)}
            </div>
            <div class="agent-msg-body" style="flex:1; min-width: 0; display:flex; flex-direction:column;">
            <div class="sre-panel p-3 my-2" style="background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 14px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); min-width: 0;">
                <div class="sre-bubble-head">
                    <strong style="font-size: 13px;"><span class="theme-gradient">NeuroSysAI</span><i class="sre-agent-dot" data-state="idle" title="Agent idle"></i></strong>
                    <button type="button" class="sre-run-toggle sre-hidden" id="${bubbleId}-toggle" title="Show the agent's work" onclick="window.toggleBubbleChain('${bubbleId}')">
                        <span class="sre-run-glyph"></span><span class="sre-run-title"></span><span class="sre-run-dur"></span><span class="sre-run-chev">${window.sreChevSvg(12)}</span>
                    </button>
                </div>
                <div class="sre-cot" style="display:none;"></div>
                <div class="ai-content sre-text-primary" style="font-size: 13px; color: var(--text-primary); line-height: 1.6;">${window.renderAnswerContent(content || '')}</div>
            </div>
            </div>
        `;
      return div;
    }

    function addAIMessage(content, ts, msgId) {
      // The live turn already owns a bubble: the empty answer region inside it
      // is filled instead of stacking a second bubble with a second avatar.
      const _skel = window.liveBubbleCurrent;
      if (_skel && !window.replayingOlder && document.contains(_skel.bubble)) {
        const _empty = _skel.bubble.querySelector('.sre-panel .ai-content');
        if (_empty && !_empty.textContent.trim()) {
          _empty.innerHTML = window.renderAnswerContent(content || '');
          const _sid = String(sessionId || '');
          if (_skel.sid !== _sid) { _skel.sid = _sid; window.liveBubbles[_sid] = _skel; }
          if (ts && !_skel.bubble.dataset.created) _skel.bubble.dataset.created = String(ts);
          if (msgId && !_skel.bubble.dataset.msgId) _skel.bubble.dataset.msgId = String(msgId);
          window.seatRunCardAbove(_skel.bubble);
          const _aiTime = document.createElement('div');
          _aiTime.style.cssText = 'font-size: 10px; color: var(--text-secondary); opacity: 0.7; margin-bottom: 8px; padding-left: 4px; margin-left: 68px;';
          _aiTime.textContent = chatTimeLabel(ts);
          _skel.bubble.after(_aiTime);
          window.liveBubbleCurrent = null;
          scrollToBottom();
          return _skel.bubble;
        }
      }
      const div = buildAnswerBubble(content, ts, msgId);
      window.markStreaming(false, div.querySelector('.ai-content'));
      messagesDiv.appendChild(div);
      window.seatRunCardAbove(div);
      const aiTime = document.createElement('div');
      aiTime.style.cssText = 'font-size: 10px; color: var(--text-secondary); opacity: 0.7; margin-bottom: 8px; padding-left: 4px; margin-left: 68px;';
      aiTime.textContent = chatTimeLabel(ts);
      messagesDiv.appendChild(aiTime);
      scrollToBottom();
      return div;
    }

    // --- Timers and UI ---
    let stepTimers = {};
    let lastGenericStepId = null;

    function stopStep(stepId, forceSuccess = true) {
      if (!stepTimers[stepId]) return;
      clearInterval(stepTimers[stepId].interval);

      const el = document.getElementById('timer-' + stepId);
      if (el) {
        const elapsed = ((Date.now() - stepTimers[stepId].startTime) / 1000).toFixed(1);
        el.textContent = `✓ ${elapsed}s`;
        el.style.color = 'var(--success-text)';
      }

      const iconContainer = document.getElementById('icon-' + stepId);
      if (iconContainer && forceSuccess) {
        iconContainer.innerHTML = window.sreCheckSvg(14);
        iconContainer.style.color = 'var(--success-text)';
        const svg = iconContainer.querySelector('svg');
        if (svg) svg.classList.remove('fa-spin');
      }

      delete stepTimers[stepId];
      if (window.paintTimelineStep) window.paintTimelineStep(stepId, 'success');
    }

    // Chain-of-thought status rings: blue while a step is working, emerald
    // once it lands, rose when it fails. Translated from the AgentPlanning
    // reference into CSS variables so both themes keep working.
    window.__sreUiBuild = 'cardown-10';
    console.log('[NeuroSysAI UI] build cardown-10');

    // Icons below never depend on the lucide name table: an unknown name used
    // to render an empty dot. These inline SVGs always paint.
    window.sreCheckSvg = function (size) {
      const px = size || 13;
      return `<svg width="${px}" height="${px}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    };
    window.sreXSvg = function (size) {
      const px = size || 13;
      return `<svg width="${px}" height="${px}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
    };
    window.sreChevSvg = function (size) {
      const px = size || 14;
      return `<svg width="${px}" height="${px}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>`;
    };
    // Tool chip + result card. Arguments arrive already escaped.
    window.sreToolChip = function (toolHtml, cmdHtml) {
      return `<div style="font-family: monospace; font-size: 11px; color: var(--text-secondary);">`
        + `<div style="display: flex; align-items: center; gap: 8px;">Executing tool: `
        + `<span style="display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 8px; background: rgba(129,140,248,.12); color: #818cf8; border: 1px solid rgba(129,140,248,.3); font-weight: 600;">${toolHtml}</span></div>`
        + (cmdHtml ? `<div style="margin-top: 6px; opacity: .8; word-break: break-all;">${cmdHtml}</div>` : '')
        + `</div>`;
    };
    window.sreResultCard = function (resultHtml) {
      return `<div style="border: 1px solid var(--border-color); border-radius: 8px; background: var(--bg-main); box-shadow: 0 1px 2px rgba(0,0,0,.05); overflow: hidden;">`
        + `<div style="padding: 6px 12px; font-size: 11px; font-weight: 700; color: var(--text-strong); border-bottom: 1px solid var(--border-color);">Output</div>`
        + `<pre class="sre-layout" style="padding: 10px 12px; margin: 0; overflow-x: auto; font-size: 12px; max-height: 220px; overflow-y: auto;">${resultHtml}</pre></div>`;
    };
    // Terminal-style rendering for terminal_execute JSON payloads
    // ({command, stdout, stderr, exit_code}). Anything else falls back to
    // plain escaped text, so this is safe to call on any tool result.
    window.sreTerminalHtml = function (rawText, maxLen) {
      const txt = String(rawText || '');
      let parsed = null;
      try { parsed = JSON.parse(txt); } catch (e) { parsed = null; }
      if (!parsed || typeof parsed !== 'object' || typeof parsed.stdout === 'undefined' || typeof parsed.command === 'undefined') {
        const lim = maxLen || 1200;
        const cut = txt.length > lim ? txt.slice(0, lim) + '\n… (truncated)' : txt;
        return `<div style="font-family: monospace; font-size: 11px; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--text-secondary);">${escapeHtml(cut)}</div>`;
      }
      const cmd = String(parsed.command || '');
      const out = String(parsed.stdout || '');
      const err = String(parsed.stderr || '');
      const code = String(parsed.exit_code);
      const codeColor = code === '0' ? 'var(--success-text)' : 'var(--error)';
      const body = (out + (err ? '\n' + err : '')).slice(0, maxLen || 1500) || '(no output)';
      return `<div style="font-family: monospace; font-size: 11px; background: #0d1117; border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; margin: 4px 0;">`
        + `<div style="padding: 6px 10px; border-bottom: 1px solid var(--border-color); color: #79c0ff; white-space: pre-wrap; overflow-wrap: anywhere;"><span style="color: var(--success-text);">$ </span>${escapeHtml(cmd.slice(0, 500))}</div>`
        + `<div style="padding: 6px 10px; color: #e6edf3; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 200px; overflow-y: auto;">${escapeHtml(body)}</div>`
        + `<div style="padding: 3px 10px; border-top: 1px solid var(--border-color); font-size: 10px; color: ${codeColor};">exit ${escapeHtml(code)}</div></div>`;
    };
    // Result card that auto-detects terminal JSON: terminal card for shell
    // output, classic Output card otherwise.
    window.sreResultHtml = function (rawText) {
      let parsed = null;
      try { parsed = JSON.parse(String(rawText || '')); } catch (e) { parsed = null; }
      if (parsed && typeof parsed === 'object' && typeof parsed.stdout !== 'undefined' && typeof parsed.command !== 'undefined') {
        return window.sreTerminalHtml(rawText, 1500);
      }
      const t = String(rawText || '').trim();
      return window.sreResultCard(t ? escapeHtml(t.substring(0, 1000)) : '(no output)');
    };

    // One neutral look for every phase. The phase itself is carried by its
    // icon, not by a rainbow of hues, so a replayed run reads exactly like the
    // live one.
    window.sreTlPalette = function (status) {
      if (status === 'error') {
        return ['rgba(248,81,73,.14)', 'var(--error)', 'rgba(248,81,73,.28)'];
      }
      if (status === 'active') {
        return ['rgba(88,166,255,.14)', 'var(--accent)', 'rgba(88,166,255,.3)'];
      }
      return ['rgba(63,185,80,.16)', 'var(--success-text)', 'rgba(63,185,80,.3)'];
    };

    // Inline phase glyphs. lucide lookups silently returned an empty string for
    // names it does not know, which is how a finished step ended up with an
    // empty ring; these always paint.
    window.sreIconSvg = function (name, size) {
      const px = size || 13;
      const wrap = (inner, w) => `<svg width="${px}" height="${px}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
      switch (String(name || '')) {
        case 'search': return wrap('<circle cx="11" cy="11" r="7"></circle><line x1="20" y1="20" x2="16.5" y2="16.5"></line>');
        case 'brain': return wrap('<path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-1 5.8V16a3 3 0 0 0 4 2.8V4z"></path><path d="M15 4a3 3 0 0 1 3 3 3 3 0 0 1 1 5.8V16a3 3 0 0 1-4 2.8V4z"></path>');
        case 'list-todo': return wrap('<line x1="4" y1="7" x2="4" y2="7"></line><line x1="9" y1="7" x2="20" y2="7"></line><line x1="4" y1="12" x2="4" y2="12"></line><line x1="9" y1="12" x2="20" y2="12"></line><line x1="4" y1="17" x2="4" y2="17"></line><line x1="9" y1="17" x2="20" y2="17"></line>');
        case 'zap': return wrap('<polygon points="13 2 4 14 11 14 10 22 20 10 13 10 13 2"></polygon>');
        case 'terminal': return wrap('<polyline points="5 7 10 12 5 17"></polyline><line x1="13" y1="17" x2="19" y2="17"></line>');
        case 'wrench': return wrap('<path d="M14 6a4 4 0 1 0 5 5l-9 9-4-4 9-9z"></path>');
        case 'x-circle': return window.sreXSvg(px);
        case 'check-circle': return window.sreCheckSvg(px);
        default: return window.sreChevSvg(px);
      }
    };

    // Phase identity comes from an icon, so no step is coloured by mood.
    window.srePhaseIcon = function (label, iconName) {
      const text = String(label || '').toLowerCase();
      if (/^(error|cancelled|failed)/.test(text) || iconName === 'x-circle') return 'x-circle';
      if (/execut|tool|command|terminal/.test(text) || iconName === 'zap') return 'zap';
      if (/plan|task/.test(text) || iconName === 'list-todo') return 'list-todo';
      if (/think|reason|evaluat|hypothes/.test(text) || iconName === 'brain') return 'brain';
      if (/discover|tool set/.test(text) || iconName === 'wrench') return 'wrench';
      if (/result|output|finding|success/.test(text) || iconName === 'check-circle') return 'check-circle';
      if (/investigat|start/.test(text) || iconName === 'search') return 'search';
      return iconName || 'terminal';
    };

    window.paintTimelineStep = function (stepId, status) {
      const step = document.getElementById('step-' + stepId);
      if (!step) return;
      step.dataset.status = status;
      const pal = window.sreTlPalette(status);
      const dot = step.querySelector(':scope > .sre-tl-dot');
      if (dot) {
        dot.style.background = pal[0];
        dot.style.color = pal[1];
        dot.style.boxShadow = '0 0 0 3px ' + pal[2];
      }
      const icon = document.getElementById('icon-' + stepId);
      if (icon) {
        if (status === 'success') icon.innerHTML = window.sreCheckSvg(13);
        else if (status === 'error') icon.innerHTML = window.sreXSvg(13);
        else if (status === 'active') {
          const phaseIcon = window.sreIconSvg(step.dataset.phaseIcon || 'terminal', 13);
          icon.innerHTML = phaseIcon
            ? `<span class="sre-tl-pulse" style="display:flex">${phaseIcon}</span>`
            : '<div class="spinner-border spinner-border-sm" role="status" style="width: 12px; height: 12px; border-width: 2px;"></div>';
        }
        icon.style.color = pal[1];
      }
    };

    window.toggleStep = function (stepId, ev) {
      if (ev) ev.stopPropagation();
      const step = document.getElementById('step-' + stepId);
      const wrap = document.getElementById('collapse-' + stepId);
      if (!step || !wrap) return;
      const open = step.dataset.open !== '1';
      step.dataset.open = open ? '1' : '0';
      wrap.style.gridTemplateRows = open ? '1fr' : '0fr';
      wrap.style.opacity = open ? '1' : '0';
      const chev = step.querySelector(':scope .sre-tl-chev');
      if (chev) chev.style.transform = open ? 'rotate(0deg)' : 'rotate(-90deg)';
    };

    function stopAllAgentStepTimers() {
      Object.keys(stepTimers).forEach(stepId => stopStep(stepId));
      lastGenericStepId = null;
    }

    function startAgentStepTimer(stepId, startedAt = null) {
      if (window.isLoadingHistory) return;
      const startTime = Number(startedAt) || Date.now();
      if (stepTimers[stepId]) {
        if (startedAt) {
          clearInterval(stepTimers[stepId].interval);
          stepTimers[stepId].startTime = startTime;
          const current = document.getElementById(`timer-${stepId}`);
          if (current) current.textContent = `${Math.max(0, (Date.now() - startTime) / 1000).toFixed(1)}s...`;
          stepTimers[stepId].interval = setInterval(() => {
            const el = document.getElementById(`timer-${stepId}`);
            if (el) el.textContent = `${Math.max(0, (Date.now() - stepTimers[stepId].startTime) / 1000).toFixed(1)}s...`;
          }, 100);
        }
        return;
      }
      const timer = document.getElementById(`timer-${stepId}`);
      if (timer) {
        timer.textContent = `${Math.max(0, (Date.now() - startTime) / 1000).toFixed(1)}s...`;
        timer.style.color = '';
      }
      stepTimers[stepId] = {
        startTime,
        interval: setInterval(() => {
          const el = document.getElementById(`timer-${stepId}`);
          if (el) el.textContent = `${Math.max(0, (Date.now() - stepTimers[stepId].startTime) / 1000).toFixed(1)}s...`;
        }, 100)
      };
    }

    // --- Run grouping: one collapsible roadmap container per agent run ---
    // Steps stream into the active container (with a left timeline rail);
    // history replays group per run_id the same way (collapsed by default).
    window.activeRunWrap = null;
    window.historyRunWraps = {};

    function startRunWrap(options = {}) {
      const deferOpen = !!options.deferOpen;
      window.runHeaderPinned = false;
      // Collapse any previous still-open run first
      if (window.activeRunWrap && window.activeRunWrap.dataset.open === '1') {
        toggleRunWrap(window.activeRunWrap.dataset.wrapId, false);
      }
      if (window.lastRunBody && window.lastRunBody.dataset.open === '1') {
        toggleRunWrap(window.lastRunBody.dataset.wrapId, false);
      }
      window.lastRunBody = null;
      const wrapId = 'runwrap-' + Math.random().toString(36).substr(2, 9);
      // The bot avatar belongs to the answer card alone, so there is exactly
      // one avatar per turn. The run card is seated directly above that card
      // when the answer arrives (see seatRunCardAbove).
      const wrap = document.createElement('div');
      wrap.id = wrapId;
      wrap.dataset.sessionId = String(sessionId || '');
      wrap.className = 'sre-run-card';
      wrap.style.cssText = 'margin-bottom: 10px;';
      wrap.innerHTML = `
        <div id="${wrapId}-body" class="sre-run-body" style="padding: 14px 16px 16px; display: flex; flex-direction: column; align-items: stretch; max-height: 280px; overflow-y: auto; background: transparent; border: 1px solid var(--border-color); border-radius: 20px; margin: 8px;">
          <div id="${wrapId}-case" style="display:none; font-size: 10px; font-family: monospace; color: var(--text-secondary); opacity: .7; margin-bottom: 6px;"></div>
        </div>
      `;
      messagesDiv.appendChild(wrap);
      window.agentAutoScroll = window.isPinnedToBottom();
      safeBeamRunning(true);
      const body = document.getElementById(wrapId + '-body');
      body.dataset.wrapId = wrapId;
      // The ownership tag must live on the body itself: activeRunWrap points
      // here, not at the outer wrap, and the render sites compare against it.
      body.dataset.sessionId = String(sessionId || '');
      // A live run shows its work as it happens; a replayed one stays hidden
      // until its pill is pressed.
      const _live = !window.isLoadingHistory;
      const _showLive = _live && !deferOpen;
      body.dataset.deferOpen = _live && deferOpen ? '1' : '0';
      body.dataset.open = _showLive ? '1' : '0';
      body.style.display = _showLive ? 'flex' : 'none';
      wrap.style.display = _showLive ? '' : 'none';
      wrap.dataset.open = _showLive ? '1' : '0';
      window.activeRunWrap = body;
      body.dataset.follow = '1';
      body.addEventListener('scroll', () => {
        try {
          const nearBottom = body.scrollHeight - body.scrollTop - body.clientHeight <= 60;
          body.dataset.follow = nearBottom ? '1' : '0';
        } catch (err) { /* best-effort */ }
      }, { passive: true });
      // Only a run that is actually executing gets a spinner. A card built
      // while replaying history is finished by definition, and a spinning glyph
      // on a stored run made it look like the agent was still working.
      const liveStat = document.getElementById(wrapId + '-stat');
      const livePill = document.getElementById(wrapId + '-pill');
      if (!window.isLoadingHistory) {
        if (liveStat) {
          liveStat.style.color = 'var(--accent)';
          liveStat.innerHTML = '<div class="spinner-border spinner-border-sm" role="status" style="width:13px; height:13px; border-width:2px;"></div>';
        }
        if (livePill) livePill.style.color = '';
      } else {
        if (liveStat) { liveStat.style.color = ''; liveStat.innerHTML = ''; }
        if (livePill) {
          livePill.classList.remove('sre-run-phase');
          livePill.textContent = 'archived run';
          livePill.style.color = 'var(--text-secondary)';
        }
      }
      // Every submitted turn starts with the same packaged card and avatar;
      // subsequent events add Thinking or the full tool workflow as needed.
      if (!window.isLoadingHistory) {
        window.ensureLiveBubble(String(sessionId || ''), wrap);
        window.paintBubblePill(wrapId, 'starting', { spinner: true, working: true });
      }
      const startPill = document.getElementById(wrapId + '-pill');
      if (startPill) {
        startPill.textContent = 'starting';
        startPill.classList.add('sre-run-phase');
      }
      scrollToBottom();
    }

    window.toggleQuarantine = function (btn) {
      const box = btn && btn.closest('.sre-quarantine');
      if (!box) return;
      const open = !box.classList.contains('sre-open');
      box.classList.toggle('sre-open', open);
      const label = btn.querySelector('span');
      if (label) label.textContent = open
        ? 'Hide the blocked prompt'
        : 'Blocked prompt — hidden. Click to reveal for audit.';
    };

    // A blocked prompt is evidence: it stays in history, blurred, until the
    // operator explicitly reveals it. Called for the turn that precedes a
    // security block, live and on replay alike.
    window.quarantineUserBubble = function (bubble) {
      try {
        if (!bubble || !bubble.classList || !bubble.classList.contains('sre-msg-user')) return false;
        if (bubble.dataset.quarantined === '1') return true;
        bubble.dataset.quarantined = '1';
        bubble.classList.add('sre-quarantined');
        const original = bubble.innerHTML;
        bubble.innerHTML =
          '<div class="sre-quarantine">'
          + '<div class="sre-quarantine-body">' + original + '</div>'
          + '<button type="button" class="sre-quarantine-veil" onclick="window.toggleQuarantine(this)">'
          + '<i class="fa-solid fa-triangle-exclamation"></i>'
          + '<span>Blocked prompt — hidden. Click to reveal for audit.</span>'
          + '</button></div>';
        return true;
      } catch (err) { return false; }
    };

    window.paintBlockedBubble = function (bubble) {
      if (!bubble || !bubble.classList) return false;
      bubble.classList.add('sre-blocked-turn');
      const toggle = bubble.querySelector('.sre-run-toggle');
      if (toggle) toggle.classList.remove('sre-hidden');
      return true;
    };

    window.toggleBubbleChain = function (bubbleId, force) {
      const bubble = document.getElementById(bubbleId);
      if (!bubble) return;
      const wrapId = bubble.dataset.wrapId;
      const body = wrapId && document.getElementById(wrapId + '-body');
      if (!body || !document.contains(body)) return;
      window.toggleRunWrap(wrapId, force);
    };

    window.toggleRunWrap = function (wrapId, force) {
      const card = document.getElementById(wrapId);
      const body = document.getElementById(wrapId + '-body');
      const chev = document.getElementById(wrapId + '-chev');
      if (!card || !body) return;
      const open = (typeof force === 'boolean') ? force : card.style.display === 'none';
      card.style.display = open ? '' : 'none';
      body.dataset.open = open ? '1' : '0';
      body.style.display = open ? 'flex' : 'none';
      if (chev) chev.style.transform = open ? 'rotate(0deg)' : 'rotate(-90deg)';
      const head = document.getElementById(wrapId + '-head');
      if (head) head.dataset.open = open ? '1' : '0';
      card.dataset.open = open ? '1' : '0';
      const bubble = card.dataset.bubbleId && document.getElementById(card.dataset.bubbleId);
      if (bubble) {
        bubble.dataset.chainOpen = open ? '1' : '0';
        const bchev = bubble.querySelector('.sre-run-chev');
        if (bchev) bchev.style.transform = open ? 'rotate(0deg)' : 'rotate(-90deg)';
      }
    };

    // The bubble owns the visible status pill, so whatever the run card
    // learns is mirrored onto it: live phase while it works, the outcome with
    // its duration once it lands.
    window.paintBubblePill = function (wrapId, title, opts) {
      try {
        opts = opts || {};
        const wrap = document.getElementById(wrapId);
        if (!wrap) return;
        let bubble = wrap.dataset.bubbleId && document.getElementById(wrap.dataset.bubbleId);
        if ((!bubble || !document.contains(bubble)) && wrap.nextElementSibling
            && wrap.nextElementSibling.classList
            && wrap.nextElementSibling.classList.contains('agent-msg')) {
          bubble = wrap.nextElementSibling;
          wrap.dataset.bubbleId = bubble.id;
          if (wrapId) bubble.dataset.wrapId = wrapId;
        }
        if (!bubble) return;
        const toggle = bubble.querySelector('.sre-run-toggle');
        if (!toggle) return;
        toggle.classList.remove('sre-hidden');
        toggle.classList.remove('sre-done', 'sre-failed');
        if (opts.done) toggle.classList.add('sre-done');
        if (opts.failed) toggle.classList.add('sre-failed');
        const glyph = toggle.querySelector('.sre-run-glyph');
        const label = toggle.querySelector('.sre-run-title');
        const dur = toggle.querySelector('.sre-run-dur');
        if (glyph) {
          if (opts.spinner) {
            glyph.style.color = '';
            glyph.innerHTML = '<div class="spinner-border spinner-border-sm" role="status" style="width:11px; height:11px; border-width:2px;"></div>';
          } else if (opts.failed) {
            glyph.style.color = '';
            glyph.innerHTML = window.sreXSvg(12);
          } else if (opts.done) {
            glyph.style.color = '';
            glyph.innerHTML = window.sreCheckSvg(12);
          } else if (opts.glyphHtml != null) {
            glyph.innerHTML = opts.glyphHtml;
          }
        }
        if (label && title != null) {
          label.textContent = title;
          label.classList.remove('sre-run-phase');
          if (opts.working) label.classList.add('sre-run-phase');
        }
        if (dur) dur.textContent = (opts.duration != null) ? `✓ ${Number(opts.duration).toFixed(1)}s` : '';
        const chev = toggle.querySelector('.sre-run-chev');
        if (chev) chev.style.transform = (bubble.dataset.chainOpen === '1') ? 'rotate(0deg)' : 'rotate(-90deg)';
      } catch (err) { /* best-effort */ }
    };

    // A bubble that owns a run always shows its pill. Seating, painting and
    // replay all resolve through here, so a silent failure on any one path can
    // no longer leave the pill hidden while the run exists.
    window.syncBubblePill = function (bubble) {
      try {
        if (!bubble) return false;
        const wrapId = bubble.dataset.wrapId;
        const wrap = wrapId && document.getElementById(wrapId);
        if (!wrap || !document.contains(wrap)) return false;
        const toggle = bubble.querySelector('.sre-run-toggle');
        if (!toggle) return false;
        toggle.classList.remove('sre-hidden');
        const last = wrap.dataset.lastStatus || '';
        const rawDur = wrap.dataset.lastDuration;
        const dur = (rawDur !== '' && rawDur != null) ? Number(rawDur) : null;
        if (last) {
          const low = last.toLowerCase();
          const terminal = window.SRE_TERMINAL.includes(low);
          window.paintBubblePill(wrapId, terminal ? last : 'working',
            terminal
              ? { done: low === 'completed', failed: low !== 'completed', duration: dur }
              : { spinner: true, working: true });
        } else {
          window.paintBubblePill(wrapId, 'working', { spinner: true, working: true });
        }
        return true;
      } catch (err) { return false; }
    };

    function paintRunWrap(wrapId, status, duration) {
      // A plain conversation reply still ran: the card stays, marked
      // completed. Hiding it used to orphan the run state and leave the turn
      // without its trace.
      if (status === 'answered') status = 'completed';
      // The bubble may only link up later (replay paints before seating), so
      // the latest state is kept on the card for the link to pick up.
      try {
        const _w = document.getElementById(wrapId);
        if (_w) {
          _w.dataset.lastStatus = String(status || '');
          _w.dataset.lastDuration = (duration != null) ? String(duration) : '';
        }
      } catch (err) { /* best-effort */ }
      const pill = document.getElementById(wrapId + '-pill');
      const dur = document.getElementById(wrapId + '-dur');
      const spin = document.getElementById(wrapId + '-spin');
      const ok = String(status || '').toLowerCase() === 'completed';
      const terminal = window.SRE_TERMINAL.includes(String(status || '').toLowerCase());
      if (pill && (terminal || status)) {
        pill.textContent = status || (ok ? 'completed' : 'failed');
        pill.style.backgroundColor = '';
        pill.style.padding = '';
        pill.style.borderRadius = '';
        pill.style.color = ok ? 'var(--success-text)' : (terminal ? 'var(--error)' : 'var(--text-strong)');
      }
      if (dur && duration != null) dur.textContent = `✓ ${Number(duration).toFixed(1)}s`;
      if (pill && terminal) pill.classList.remove('sre-run-phase');
      if (spin && terminal) spin.innerHTML = `<i class="fa-solid ${ok ? 'fa-circle-check' : 'fa-circle-exclamation'}" style="color: ${ok ? 'var(--success-text)' : 'var(--error)'};"></i>`;
      const stat = document.getElementById(wrapId + '-stat');
      if (stat && terminal) {
        stat.innerHTML = ok ? window.sreCheckSvg(14) : window.sreXSvg(14);
        stat.style.color = ok ? 'var(--success-text)' : 'var(--error)';
      }
      const durSecs = (duration != null) ? Number(duration) : null;
      if (terminal) {
        window.paintBubblePill(wrapId, status || (ok ? 'completed' : 'failed'),
          { done: ok, failed: !ok, duration: durSecs });
      } else if (status) {
        window.paintBubblePill(wrapId, status, { spinner: true, working: true });
      }
    }

    function finalizeRunWrap(status, duration) {
      const liveBubble = currentAIMsg
        || (window.liveBubbleCurrent && window.liveBubbleCurrent.bubble) || null;
      const linkedWrapId = liveBubble && liveBubble.dataset ? liveBubble.dataset.wrapId : '';
      const linkedBody = linkedWrapId && document.getElementById(linkedWrapId + '-body');
      const body = window.activeRunWrap || window.lastRunBody || linkedBody;
      if (!body) return;
      const wrapId = body.dataset.wrapId;
      paintRunWrap(wrapId, status, duration);
      // Resolve the response bubble directly as well as through the run card.
      // The card can finish after its active pointer was cleared by a socket
      // reconnect; without this explicit link the workflow says completed
      // while the bubble pill keeps its old "thinking" label.
      if (liveBubble && wrapId) {
        const outerWrap = document.getElementById(wrapId);
        if (outerWrap) outerWrap.dataset.bubbleId = liveBubble.id;
        liveBubble.dataset.wrapId = wrapId;
        const ok = String(status || '').toLowerCase() === 'completed';
        const terminal = window.SRE_TERMINAL.includes(String(status || '').toLowerCase());
        if (terminal) {
          window.paintBubblePill(wrapId, status, {
            done: ok,
            failed: !ok,
            duration: duration != null ? Number(duration) : null,
          });
        }
      }
      // Keep the completed turn together on screen: user prompt, collapsed
      // workflow summary, and AI bubble with its terminal pill.
      window.lastRunBody = body;
      toggleRunWrap(wrapId, false);
      safeBeamRunning(false);
      window.activeRunWrap = null;
      window.runHeaderPinned = true;
      window.centerRunTurn(wrapId);
    }

    // History replay grouping: one collapsed container per past run_id.
    function ensureHistoryWrap(runId) {
      if (!runId) return null;
      window.historyRunWraps = window.historyRunWraps || {};
      let wrapId = window.historyRunWraps[runId];
      if (wrapId && document.getElementById(wrapId + '-body')) {
        window.activeRunWrap = document.getElementById(wrapId + '-body');
        return window.activeRunWrap;
      }
      startRunWrap();
      wrapId = window.activeRunWrap ? window.activeRunWrap.dataset.wrapId : null;
      if (wrapId) {
        window.historyRunWraps[runId] = wrapId;
        toggleRunWrap(wrapId, false);
        // A replayed run is over: no shimmer, no spinning glyph. The header
        // stays neutral until its terminal event paints the real outcome.
        const histPill = document.getElementById(wrapId + '-pill');
        if (histPill) {
          histPill.classList.remove('sre-run-phase');
          histPill.textContent = 'archived run';
          histPill.style.color = 'var(--text-secondary)';
        }
      }
      return window.activeRunWrap;
    }

    function updateRunStateCard(runId, status, duration = null, startedAt = null) {
      const safeRunId = String(runId || window.activeAgentRunId || 'current').replace(/[^a-zA-Z0-9_-]/g, '-');
      const stepId = `run-state-${safeRunId}`;
      const terminal = window.SRE_TERMINAL.includes(String(status).toLowerCase());
      // The Run State row also keeps the phase label and status dot in sync.
      if (!window.isLoadingHistory) {
        const phase = {
          starting: ['exploring', 'starting'],
          resuming: ['exploring', 'resuming'],
          exploring: ['exploring', 'observing'],
          discovering_tools: ['search', 'discovering tools'],
          planning: ['planning', 'planning'],
          thinking: ['thinking', 'thinking'],
          verifying: ['thinking', 'verifying'],
          executing: ['working', 'executing'],
          running: ['working', 'executing'],
          awaiting_approval: ['listening', 'awaiting approval'],
        }[String(status).toLowerCase()];
        if (phase && !terminal) window.setRunPhase(phase[0], phase[1]);
      }
      const successful = String(status).toLowerCase() === 'completed';
      const blocked = String(status).toLowerCase() === 'security_blocked';
      const color = terminal && !successful ? 'var(--error)' : '#79c0ff';
      const existing = document.getElementById(`step-${stepId}`);
      const stateLabel = blocked ? 'Blocked by Security Policy' : 'Run State';
      if (!existing) {
        const timer = terminal ? `✓ ${Number(duration || 0).toFixed(1)}s` : null;
        addAgentStep(stateLabel, escapeHtml(status || 'running'), color,
          successful ? 'check-circle' : terminal ? 'x-circle' : 'activity', stepId, terminal, timer);
        if (!terminal && startedAt) startAgentStepTimer(stepId, startedAt);
        return;
      }
      if (blocked) {
        const title = document.querySelector(`#step-${stepId} .sre-tl-title`);
        if (title) title.textContent = stateLabel;
      }

      const content = document.getElementById(`step-content-${stepId}`);
      if (content) content.textContent = String(status || 'running');
      if (terminal) {
        stopStep(stepId);
        const icon = document.getElementById(`icon-${stepId}`);
        if (icon) {
          icon.innerHTML = getIcon(successful ? 'check-circle' : 'x-circle');
          icon.style.color = successful ? 'var(--success-text)' : 'var(--error)';
          icon.querySelector('svg')?.classList.remove('fa-spin');
        }
      } else {
        startAgentStepTimer(stepId, startedAt);
      }
    }


    function addAgentStep(label, contentHtml, color, iconName = 'terminal', stepId = null, isEnd = false, customTimer = null) {
      if (!window.sessionStartTime) window.sessionStartTime = new Date();
      if (!window.isLoadingHistory && window.turnIsOpen() && window.revealRunWrap) {
        window.revealRunWrap();
      }

      let isGeneric = false;
      if (!stepId) {
        if (isEnd && lastGenericStepId) {
          stepId = lastGenericStepId;
        } else {
          stepId = 'step-' + Math.random().toString(36).substr(2, 9);
          isGeneric = true;
        }
      }
      // Status first, looks second: a live step is active (blue ring +
      // spinner), a finished one is success (emerald + check), a failed one is
      // error (rose + cross) no matter which phase color it was born with.
      let tlStatus = 'success';
      if (/^(Error|Cancelled|Failed)/i.test(label) || iconName === 'x-circle') tlStatus = 'error';
      else if (!window.isLoadingHistory && !isEnd && !customTimer) tlStatus = 'active';
      const tlOpen = tlStatus === 'active' || !window.isLoadingHistory;
      // Operator-requested accent for landed tasks: green icon/text on a
      // mint card instead of the neutral timeline look.
      const isTaskDone = /^Task Completed/i.test(String(label || ''));
      const tlPal = isTaskDone
        ? ['rgba(29, 173, 111, .18)', '#1dad6f', 'rgba(29, 173, 111, .35)']
        : window.sreTlPalette(tlStatus);
      const tlTitleColor = isTaskDone
        ? '#1dad6f'
        : (tlStatus === 'error' ? 'var(--error)' : 'var(--text-primary)');
      const tlPhase = window.srePhaseIcon(label, iconName);
      // A working step shows its phase icon with a quiet ring; a landed step
      // shows a check. Nothing is tinted by phase.
      const iconHtml = tlStatus === 'active'
        ? window.sreIconSvg(tlPhase, 13)
        : (tlStatus === 'error' ? window.sreXSvg(13) : window.sreCheckSvg(13));
      const tlTimerStyle = 'min-width: 45px; text-align: right; font-size: 12px; font-family: monospace; color: var(--text-secondary); opacity: .85; white-space: nowrap;';
      let initialTimer;
      if (customTimer) {
        initialTimer = `<span id="timer-${stepId}" class="sre-timer" style="${tlTimerStyle}">${customTimer}</span>`;
      } else if (window.isLoadingHistory && !isEnd) {
        initialTimer = `<span id="timer-${stepId}" class="sre-timer" style="${tlTimerStyle}">✓</span>`;
      } else {
        initialTimer = `<span id="timer-${stepId}" class="sre-timer" style="${tlTimerStyle}">0.0s</span>`;
      }

      if (lastGenericStepId && lastGenericStepId !== stepId && !isEnd) {
        stopStep(lastGenericStepId);
        lastGenericStepId = null;
      }

      if (isGeneric) {
        lastGenericStepId = stepId;
      }

      if (isEnd && stepId === lastGenericStepId) {
        lastGenericStepId = null;
      }

      let stepDiv = document.getElementById('step-' + stepId);

      if (!stepDiv) {
        stepDiv = document.createElement('div');
        stepDiv.id = 'step-' + stepId;
        stepDiv.className = 'sre-agent-step';
        stepDiv.dataset.status = tlStatus;
      stepDiv.dataset.phaseIcon = tlPhase;
        stepDiv.dataset.open = tlOpen ? '1' : '0';
        stepDiv.style.cssText = 'position: relative; display: flex; gap: 14px; padding-left: 2px; width: 100%; align-self: auto; flex: 0 0 auto;'
          + (isTaskDone ? ' background: #edfaf8; border-color: rgba(29, 173, 111, .35) !important;' : '');
        stepDiv.innerHTML = `
                <div class="sre-tl-line" style="position: absolute; left: 15px; top: 36px; bottom: 0; width: 2px; background: var(--border-color); opacity: .55; display: none;"></div>
                <div class="sre-tl-dot" style="position: relative; z-index: 1; flex: none; width: 25px; height: 25px; margin-top: 8px; border-radius: 50%; overflow: visible; display: flex; align-items: center; justify-content: center; background: ${tlPal[0]}; color: ${tlPal[1]}; box-shadow: 0 0 0 3px ${tlPal[2]}; margin-left: 3px;">
                    <span id="icon-${stepId}" style="display: flex; align-items: center; justify-content: center; width: 100%; height: 100%;">
                        ${iconHtml}
                    </span>
                </div>
                <div style="flex: 1 1 auto; min-width: 0; width: 100%; align-self: auto; padding: 8px 0 24px;">
                    <div onclick="toggleStep('${stepId}', event)" onmouseover="this.style.background='rgba(127,140,160,.08)'" onmouseout="this.style.background='transparent'" style="display: flex; align-items: center; gap: 10px; padding: 1px 6px; margin: 0 -6px; border-radius: 6px; cursor: pointer; user-select: none;">
                        <span style="display: flex; align-items: baseline; gap: 8px; min-width: 0;">
                            <span class="sre-tl-title" style="font-size: 14px; font-weight: ${tlStatus === 'active' ? '600' : '500'}; color: ${tlTitleColor}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${label}</span>
                            ${initialTimer}
                        </span>
                        <span class="sre-tl-chev" style="display: flex; margin-left: auto; color: var(--text-secondary); opacity: .55; transition: transform .2s; transform: rotate(${tlOpen ? '0deg' : '-90deg'});">${window.sreChevSvg(14)}</span>
                    </div>
                    <div id="collapse-${stepId}" style="display: grid; grid-template-rows: ${tlOpen ? '1fr' : '0fr'}; opacity: ${tlOpen ? '1' : '0'}; transition: grid-template-rows .35s ease, opacity .3s ease;">
                        <div style="overflow: hidden; min-height: 0;">
                            <div id="step-content-${stepId}" class="sre-text-secondary" style="padding: 8px 2px 2px; font-size: 13px;">
                                ${contentHtml}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        // Stream into the active run container (roadmap rail); fall back to
        // the bare timeline for ungrouped contexts. A container owned by another
        // chat is never a valid target, even if a stale reference survived.
        const stepParent = window.resolveStepParent() || messagesDiv;
        if (window.isLoadingHistory) {
          const _tlCount = stepParent.querySelectorAll(':scope > .sre-agent-step').length;
          stepDiv.style.animationDelay = Math.min(_tlCount * 60, 480) + 'ms';
        }
        stepParent.appendChild(stepDiv);
        // The rail runs through every step but the last: earlier siblings keep
        // their line, the newcomer (always last) hides its own.
        Array.from(stepParent.children).forEach((ch) => {
          if (ch !== stepDiv && ch.classList && ch.classList.contains('sre-agent-step')) {
            const ln = ch.querySelector(':scope > .sre-tl-line');
            if (ln) ln.style.display = '';
          }
        });

        if (!isEnd && !window.isLoadingHistory) {
          startAgentStepTimer(stepId);
        }
      } else {
        const contentDiv = document.getElementById('step-content-' + stepId);
        if (contentDiv) {
          contentDiv.innerHTML += `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed var(--border-color);">${contentHtml}</div>`;
        }

        if (isEnd) {
          stopStep(stepId, false);
          const iconContainer = document.getElementById('icon-' + stepId);
          if (iconContainer) {
            iconContainer.innerHTML = window.sreCheckSvg(14);
            iconContainer.style.color = 'var(--success-text)';
          }
        }
      }

      // Each run card follows its own newest step while its run is live, so
      // watching the agent work reads top-to-bottom inside the card instead of
      // freezing on the first step. Scrolling up inside the card pauses just
      // that card; scrolling back to its bottom resumes. Replays never move.
      const _host = stepDiv.parentElement;
      const _isRunBody = !!(_host && _host.id && /-body$/.test(_host.id));
      if (!window.isLoadingHistory && !window.runHeaderPinned && window.activeRunWrap) {
        const _wrapId = window.activeRunWrap.dataset.wrapId;
        if (_wrapId) {
          window.runHeaderPinned = true;
          window.centerRunTurn(_wrapId);
        }
      }
      if (!window.isLoadingHistory && window.runHeaderPinned && window.activeRunWrap
          && window.activeRunWrap.dataset.wrapId) {
        window.centerRunTurn(window.activeRunWrap.dataset.wrapId);
      }
      if (_isRunBody) {
        const _ownerOk = String(_host.dataset.sessionId || '') === String(sessionId || '');
        const _mine = _host === window.activeRunWrap || _host === window.lastRunBody;
        const _follow = _host.dataset.follow !== '0';
        if (!window.isLoadingHistory && !window.replayActive && _ownerOk && _mine && _follow) {
          _host.scrollTop = _host.scrollHeight;
        }
      } else {
        scrollToBottom();
      }
      if (window.lucide) window.lucide.createIcons();
    }

    // Exposed for the helper blocks that live outside this IIFE (agent
    // permission, model picker, ...). Without this, a successful permission
    // PUT raised "ReferenceError: addSystemMsg is not defined", which the
    // catch block then reported as "Permission update rejected" and silently
    // reverted the operator's choice back to Need Approval.
    window.addSystemMsg = addSystemMsg;

    // --- Send / Stop button -------------------------------------------------
    // While a run is live the same button becomes Stop, so the operator always
    // has an obvious way to interrupt instead of watching a spinner.
    const SEND_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-left:-2px;"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>';
    const STOP_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="pointer-events:none;"><rect x="6" y="6" width="12" height="12" rx="2"></rect></svg>';

    // The button shows Stop exactly while this chat has a live run, and Send
    // otherwise. It used to be painted directly from a dozen call sites, so any
    // path that forgot to repaint it left the operator with no way to stop a
    // running agent - or with a Stop button for a run that was already over.
    // Every mutation below funnels through here instead.
    window.refreshSendButton = function () {
      try {
        const sid = String((typeof sessionId !== 'undefined' && sessionId) || '');
        const running = !!((window.runsBySession || {})[sid]) ||
          (typeof isProcessing !== 'undefined' && !!isProcessing &&
           String(window.processingSid || '') === sid);
        window.setSendButtonState(running ? 'running' : 'idle');
      } catch (err) { /* best-effort */ }
    };

    window.paintSendButton = function () {
      const btn = document.getElementById('send-btn');
      const input = document.getElementById('chat-input');
      if (!btn) return;
      const running = btn.dataset.state === 'running';
      const empty = !input || !input.value.trim();
      // A running agent can always be stopped; an empty box sends nothing.
      btn.disabled = !running && empty;
      btn.style.opacity = btn.disabled ? '0.45' : '1';
      btn.style.cursor = btn.disabled ? 'not-allowed' : 'pointer';
    };

    window.setSendButtonState = function (state) {
      const btn = document.getElementById('send-btn');
      if (!btn) return;
      if (state === 'running') {
        btn.dataset.state = 'running';
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.background = 'var(--error)';
        btn.title = 'Stop the running agent';
        btn.innerHTML = STOP_ICON;
      } else {
        btn.dataset.state = 'idle';
        btn.style.background = 'var(--accent)';
        btn.title = 'Send';
        btn.innerHTML = SEND_ICON;
      }
      window.paintSendButton();
    };

    // Stop a run that belongs to another chat, from its history row. The
    // current chat is never touched: only that session's task stops.
    window.stopOtherRun = function (sid) {
      if (!sid) return;
      window.stoppingRuns = window.stoppingRuns || {};
      window.stoppingRuns[String(sid)] = Date.now();
      window.refreshHistoryRowState(String(sid));
      // Settle immediately instead of waiting for the backstop poll: one direct
      // read of the server truth right after the stop.
      try {
        Promise.resolve().then(() => window.refreshRunPresence());
      } catch (err) { /* best-effort */ }
      setTimeout(() => window.refreshInvestigations(), 1500);
      try {
        if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: 'cancel', session_id: String(sid) }));
      } catch (err) { /* socket closing */ }
      try {
        if (window.runsBySession) delete window.runsBySession[String(sid)];
        window.refreshHistoryRowState(String(sid));
        window.renderActiveRuns();
        window.refreshSendButton();
        addSystemMsg('Stop requested for that chat\u2019s run.', 'circle-info');
      } catch (err) { /* best-effort */ }
    };

    // Stop one investigation from its own card. A live run in this chat is
    // stopped the usual way; a case whose run is already gone but which still
    // reads as active is closed honestly instead of left running forever.
    // The panel reads from memory, so anything the server changed behind its
    // back (a repair, another tab, a watchdog) shows stale until the chat is
    // reopened. Every terminal event and every stop re-pulls instead.
    window.refreshInvestigations = async function () {
      try {
        const sid = String((typeof sessionId !== 'undefined' && sessionId) || '');
        if (!sid) return;
        const res = await fetch(`/api/v1/chat-sessions/${encodeURIComponent(sid)}/investigations/`,
          { credentials: 'same-origin' });
        if (!res.ok) return;
        const data = await res.json();
        investigations = {};
        activeInvestigationId = null;
        (data || []).forEach((inv) => {
          investigations[inv.id] = {
            id: inv.id,
            title: inv.title,
            status: inv.status,
            createdAt: inv.created_at || inv.createdAt || 0,
            plan: inv.tasks || [],
            findings: inv.findings ? inv.findings.map((f) => f.content) : [],
          };
          if (inv.status === 'active' && !activeInvestigationId) activeInvestigationId = inv.id;
        });
        renderInvestigationTimeline();
      } catch (err) { /* best-effort */ }
    };

    window.stopInvestigationCase = async function (invId) {
      if (!invId) return;
      const sid = String((typeof sessionId !== 'undefined' && sessionId) || '');
      window.stoppingRuns = window.stoppingRuns || {};
      window.stoppingRuns[String(sid)] = Date.now();
      window.refreshHistoryRowState(String(sid));
      try {
        // A stop button on a case stops that case, not whichever run happens
        // to be live. Falling back to the live run made the card look untouched.
        const data = await window.wsCall('investigation.cancel',
          { session_id: sid, inv_id: invId });
        // Paint from the answer itself: pressing stop always lands on a
        // finished badge, whatever the database already held.
        const finalState = String((data && data.status) || '').toLowerCase();
        if (investigations[invId] && finalState) {
          investigations[invId].status = finalState;
          if (data && data.previous_status && data.previous_status !== finalState) {
            // What the case was before the operator stopped it stays readable.
            investigations[invId].stoppedFrom = data.previous_status;
          }
          (investigations[invId].plan || []).forEach((p) => {
            const st = String(p.status || '').toLowerCase();
            if (['pending', 'running', 'in_progress', 'executing'].includes(st)) {
              p.status = (data && data.stopped) ? 'stopped' : finalState;
            }
          });
          renderInvestigationTimeline();
        }
      } catch (err) {
        // A refused or failed stop still has to leave the card alone on a
        // decided state rather than spinning forever.
        if (investigations[invId]) {
          investigations[invId].status = window.SRE_TERMINAL.includes(
            String(investigations[invId].status || '').toLowerCase())
            ? investigations[invId].status : 'stopped';
          renderInvestigationTimeline();
        }
      }
      // The marker exists only to cover the round trip; the answer above ends it.
      delete window.stoppingRuns[String(sid)];
      try { await window.refreshRunPresence(); } catch (err) { /* best-effort */ }
      window.refreshHistoryRowState(String(sid));
      try { await window.refreshInvestigations(); } catch (err) { /* best-effort */ }
    };

    window.stopCurrentRun = function () {
      // One button, one run: only this chat's run stops. Background runs in
      // other chats are cancelled from their own row in History.
      const sid = String(sessionId || '');
      const tracked = !!((window.runsBySession || {})[sid]);
      if (!tracked && !(isProcessing && String(window.processingSid || '') === sid)) return;
      addSystemMsg('Stopping the run...', 'circle-notch');
      window.cancelRunForSession(sid);
      addAgentStep('Cancelled', 'Stopped by the operator before it finished.', 'var(--warning)', 'circle-xmark', null, true);
      isProcessing = false;
      window.closeTurn();
      window.setSendButtonState('idle');
      window.renderActiveRuns();
    };

    document.addEventListener('DOMContentLoaded', () => {
      const input = document.getElementById('chat-input');
      if (input && !input.dataset.sendPaint) {
        input.dataset.sendPaint = '1';
        input.addEventListener('input', () => window.paintSendButton());
        window.paintSendButton();
      }
      const btn = document.getElementById('send-btn');
      if (!btn) return;
      btn.addEventListener('click', (e) => {
        if (btn.dataset.state === 'running') {
          e.preventDefault();
          e.stopPropagation();
          window.stopCurrentRun();
        }
      }, true);
    });

    // Placeholder content while a panel loads. Defined with the other globals
    // so it exists before any loader can call it.
    window.showPanelSkeleton = function (host, rows) {
      if (!host) return;
      const count = rows || 4;
      const widths = ['w90', 'w70', 'w45'];
      let html = '<div class="sre-skeleton">';
      for (let i = 0; i < count; i++) {
        html += '<div class="sk-line ' + widths[i % widths.length] + '"></div>';
      }
      html += '</div>';
      host.innerHTML = html;
    };

    // --- Global run registry -------------------------------------------------
    // A run belongs to a chat, but the operator must always be able to see
    // that something is executing, from any chat, and cancel it.
    window.runsBySession = window.runsBySession || {};
    window.unreadSessions = window.unreadSessions || {};

    window.markRunActive = function (sid, label, startedAt, phase) {
      if (!sid) return;
      window.runsBySession[String(sid)] = {
        id: String(sid),
        label: label || 'Agent run',
        startedAt: Number(startedAt) || Date.now(),
        phase: phase || 'running',
      };
      delete window.unreadSessions[String(sid)];
      window.renderActiveRuns();
      window.refreshSendButton();
    };

    // Update a run's pill by its id. The registry is session-keyed, so the
    // run's entry is found through its session. This used to be called without
    // ever being defined, which killed every handler that touched it - a
    // denied run therefore left its turn spinning forever.
    window.updateRunStateCard = function (runId, status) {
      try {
        var keys = Object.keys(window.runsBySession || {});
        for (var i = 0; i < keys.length; i++) {
          var entry = window.runsBySession[keys[i]];
          if (entry && String(entry.id) === String(runId)) {
            if (window.SRE_TERMINAL.includes(String(status || '').toLowerCase())) {
              window.markRunFinished(keys[i], status === 'completed');
            } else {
              entry.phase = status;
              window.renderActiveRuns();
            }
            return;
          }
        }
        var sid = String(window.liveRunSessionId || '');
        if (sid && window.runsBySession[sid]) {
          if (window.SRE_TERMINAL.includes(String(status || '').toLowerCase())) {
            window.markRunFinished(sid, status === 'completed');
          } else {
            window.runsBySession[sid].phase = status;
            window.renderActiveRuns();
          }
        }
      } catch (err) { /* best-effort */ }
    };

    window.markRunFinished = function (sid, ok) {
      if (!sid) return;
      delete window.runsBySession[String(sid)];
      if (String(sid) !== String(sessionId)) window.unreadSessions[String(sid)] = { ok: !!ok, at: Date.now() };
      window.renderActiveRuns();
      window.refreshHistoryRowState(String(sid));
      window.refreshSendButton();
    };

    window.cancelRunForSession = function (sid) {
      if (!sid) return;
      window.stoppingRuns = window.stoppingRuns || {};
      window.stoppingRuns[String(sid)] = Date.now();
      window.refreshHistoryRowState(String(sid));
      try {
        Promise.resolve().then(() => window.refreshRunPresence());
      } catch (err) { /* best-effort */ }
      document.querySelectorAll('.sre-run-actions').forEach((block) => {
        if (String(block.dataset.sessionId) === String(sid)) {
          block.innerHTML = '<span style="font-size:11px; color:var(--text-secondary);">Cancelled.</span>';
          block.dataset.consumed = '1';
        }
      });
      if (window.runsBySession && window.runsBySession[String(sid)]) {
        try {
          if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: 'cancel', session_id: String(sid) }));
        } catch (err) { /* socket closing */ }
      }
      if (String(sid) === String(sessionId)) {
        isProcessing = false;
        if (String(window.processingSid || '') === String(sid)) window.processingSid = '';
        window.setSendButtonState && window.setSendButtonState('idle');
        // The cancelled card leaves with the run: error UI and steps.
        if (window.activeRunWrap && String(window.activeRunWrap.dataset.sessionId || '') === String(sid)) {
          window.removeRunCard(window.activeRunWrap);
        }
        window.activeRunWrap = null;
        window.discardLiveBubble(String(sid || ''));
        safeBeamRunning(false);
        stopAllAgentStepTimers();
        addSystemMsg('Run cancelled.', 'circle-xmark');
      }
      window.cancelledAt = window.cancelledAt || {};
      window.cancelledAt[String(sid)] = Date.now();
      delete window.runsBySession[String(sid)];
      window.refreshSendButton();
      window.renderActiveRuns();
    };

    // Entries the server no longer reports are resolved once against the
    // run snapshot: a finished run becomes "new result" instead of lingering
    // as active, and a run that never started anywhere is dropped quietly.
    window.resolveStaleRunEntry = async function (sid) {
      const entry = (window.runsBySession || {})[String(sid)];
      if (!entry || entry.probed) return;
      entry.probed = true;
      if (Date.now() - (entry.startedAt || 0) < 45000) return;
      try {
        const res = await fetch('/api/v1/agent-runs/snapshot/?session_id=' + encodeURIComponent(sid), { credentials: 'same-origin' });
        if (!res.ok) return;
        const data = await res.json();
        const run = data.run;
        if (!run) { delete window.runsBySession[String(sid)]; }
        else {
          if (window.SRE_TERMINAL.includes(String(run.status))) {
            window.markRunFinished(String(sid), run.status === 'completed');
          }
        }
        window.renderActiveRuns();
        window.refreshHistoryRowState(String(sid));
      } catch (err) { /* best-effort */ }
    };

    // Live presence: the sidebar reflects what the server is actually doing,
    // even for runs this page never saw start (reload mid-run, another tab).
    // One merge for run presence, whoever delivers it: the socket pushes on
    // every transition, and the poll below is only a consistency backstop.
    window.applyPresence = function (data) {
      try {
        const _latest = {};
        (data.latest || []).forEach((row) => {
          const sid = String(row.session_id || '');
          if (sid) _latest[sid] = row;
        });
        window.latestRunBySession = _latest;
        (data.runs || []).forEach((run) => {
          const sid = String(run.session_id || '');
          if (!sid) return;
          const stopping = (window.stoppingRuns || {})[String(sid)];
          if (stopping) {
            if (Date.now() - stopping > 120000) delete window.stoppingRuns[String(sid)];
            else { window.refreshHistoryRowState(sid); return; }
          }
          const local = window.runsBySession[String(sid)];
          if (local) {
            if (run.current_node) local.phase = run.current_node;
            if (run.created_at) local.startedAt = new Date(run.created_at).getTime() || local.startedAt;
            local.serverSeen = true;
          } else {
            window.runsBySession[String(sid)] = {
              id: sid,
              label: run.goal || 'Agent run',
              phase: run.status === 'awaiting_approval' ? 'awaiting approval' : (run.current_node || run.status || 'running'),
              startedAt: new Date(run.created_at || run.updated_at).getTime() || Date.now(),
              serverSeen: true,
            };
          }
          if (window.unreadSessions) delete window.unreadSessions[String(sid)];
          window.refreshHistoryRowState(sid);
        });
        Object.keys(window.runsBySession || {}).forEach((sid) => window.resolveStaleRunEntry(sid));
        // Chats without a live run still need their state, from the same poll.
        Object.keys(_latest).forEach((sid) => {
          const st = String((_latest[sid] || {}).status || '');
          if (window.SRE_TERMINAL.includes(st) && window.stoppingRuns) {
            delete window.stoppingRuns[String(sid)];
          }
          if (!(window.runsBySession || {})[sid]) window.refreshHistoryRowState(sid);
        });
        window.renderActiveRuns();
      } catch (err) { /* presence is best-effort */ }
    };

    window.refreshRunPresence = async function () {
      try {
        const res = await fetch('/api/v1/agent-runs/active/', { credentials: 'same-origin' });
        if (!res.ok) return;
        window.applyPresence(await res.json());
      } catch (err) { /* presence is best-effort */ }
    };

    // The socket pushes presence on every run transition; this timer is only
    // a consistency backstop in case a push was ever missed.
    if (!window._runPresenceTimer && typeof setInterval === 'function') {
      window._runPresenceTimer = setInterval(() => {
        if (document.visibilityState !== 'visible') return;
        window.refreshRunPresence();
      }, 300000);
    }

    if (!window._runElapsedTimer && typeof setInterval === 'function') {
      window._runElapsedTimer = setInterval(() => {
        document.querySelectorAll('[data-run-elapsed]').forEach((el) => {
          const since = parseInt(el.dataset.runElapsed || '0', 10);
          if (since) el.textContent = ' · ' + Math.max(0, Math.round((Date.now() - since) / 1000)) + 's';
        });
      }, 2000);
    }

    window.phaseLabelForEvent = function (payload) {
      const type = String(payload.type || '');
      if (window.runPhaseLabels && window.runPhaseLabels[type]) return window.runPhaseLabels[type];
      if (type === 'tool_start' || type === 'tool_end') return 'executing';
      if (type === 'message_chunk') return 'composing';
      if (type === 'lifecycle') return payload.status || 'executing';
      if (type === 'verifying') return 'verifying';
      if (type === 'approval_required') return 'awaiting approval';
      return '';
    };

    window.noteForeignRunEvent = function (payload, explicitSid) {
      const sid = explicitSid || window.liveRunSessionId;
      if (!sid) return;
      const status = String(payload.status || '');
      if (payload.type === 'lifecycle' && window.SRE_TERMINAL.includes(status.toLowerCase())) {
        window.markRunFinished(sid, status === 'completed');
        return;
      }
      const label = window.phaseLabelForEvent(payload);
      const entry = window.runsBySession[String(sid)] || { id: String(sid), label: 'Agent run', startedAt: Date.now() };
      if (label) entry.phase = label;
      if (!entry.startedAt) entry.startedAt = Date.now();
      window.runsBySession[String(sid)] = entry;
      if (window.unreadSessions) delete window.unreadSessions[String(sid)];
      window.refreshHistoryRowState(sid);
      window.renderActiveRuns();
    };

    window.refreshHistoryRowState = function (sid) {
      const row = document.getElementById('history-item-' + sid);
      if (!row) return;
      const slot = row.querySelector('[data-run-state]');
      if (!slot) return;
      row.classList.remove('run-completed');
      row.classList.remove('run-failed');
      const stopping = (window.stoppingRuns || {})[String(sid)];
      if (stopping && Date.now() - stopping < 120000) {
        slot.innerHTML = '<i class="fa-solid fa-circle-notch spin-anim" title="Stopping the run…" style="color:var(--warning); font-size:11px; flex-shrink:0;"></i>'
          + '<span style="font-size:10px; color:var(--warning); font-weight:700;">stopping…</span>';
        return;
      }
      if (stopping) delete window.stoppingRuns[String(sid)];
      const run = (window.runsBySession || {})[String(sid)];
      const unread = !!(window.unreadSessions || {})[String(sid)];
      const latest = (window.latestRunBySession || {})[String(sid)];
      if (run) {
        const phase = run.phase || 'running';
        slot.innerHTML =
          '<i class="fa-solid fa-spinner spin-anim" title="Run in progress" style="color:var(--accent); font-size:11px; flex-shrink:0;"></i>' +
          '<span style="font-size:10px; color:var(--accent); font-weight:700;">' + escapeHtml(phase) + '</span>' +
          '<span data-run-elapsed="' + (run.startedAt || Date.now()) + '" style="font-size:10px; color:var(--text-secondary);"></span>' +
          '<button type="button" title="Stop the run in this chat" onclick="event.stopPropagation(); window.stopOtherRun(\'' + escapeHtml(String(sid)) + '\')" style="flex:none; width:20px; height:20px; border-radius:6px; border:1px solid var(--border-color); background:rgba(248,81,73,.12); color:var(--error); cursor:pointer; display:inline-flex; align-items:center; justify-content:center;"><i class="fa-solid fa-stop" style="font-size:8px; pointer-events:none;"></i></button>';
      } else if (unread && unread.ok === false) {
        row.classList.add('run-failed');
        slot.innerHTML = '';
      } else if (unread) {
        row.classList.add('run-completed');
        slot.innerHTML = '';
      } else if (latest && latest.status) {
        // Every chat with a run shows how it ended, from the server's record.
        // A run the operator stopped is not a failure, so it must not wear the
        // error colour: red means the agent could not finish.
        const state = String(latest.status);
        const label = state.replace(/_/g, ' ');
        const failed = ['failed', 'error', 'blocked', 'denied', 'denied_timeout', 'security_blocked'].includes(state);
        const stopped = ['cancelled', 'finalized'].includes(state);
        const done = state === 'completed';
        // Run outcome wears the big circle (✓ completed / ✗ failed) instead
        // of a second tiny icon beside it. Selection never shows the check.
        if (done) row.classList.add('run-completed');
        else if (failed) row.classList.add('run-failed');
        slot.innerHTML = failed || done
          ? ''
          : (stopped
            ? '<i class="fa-solid fa-circle-minus" title="Last run: ' + escapeHtml(label) + '" style="color:var(--text-secondary); font-size:11px; flex-shrink:0;"></i>'
            : '<i class="fa-solid fa-circle-dot" title="Last run: ' + escapeHtml(label) + '" style="color:var(--text-secondary); font-size:11px; flex-shrink:0;"></i>');
      } else {
        slot.innerHTML = '';
      }
    };

    window.renderActiveRuns = function () {
      const bar = document.getElementById('active-runs-bar');
      const list = document.getElementById('active-runs-list');
      const count = document.getElementById('active-runs-count');
      if (!bar || !list) return;
      // Only runs in OTHER chats appear here. The open chat shows its own run
      // card with its phase, so listing it again is noise - and it was the
      // source of the flickering bar.
      const runs = Object.values(window.runsBySession || {})
        .filter((run) => String(run.id) !== String(sessionId));
      if (!runs.length) { bar.style.display = 'none'; list.innerHTML = ''; return; }
      bar.style.display = 'flex';
      if (count) {
        count.textContent = runs.length === 1 ? '1 run active' : runs.length + ' runs active';
      }
      list.innerHTML = '';
      runs.forEach((run) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex; align-items:center; gap:8px; font-size:11px; color:var(--text-secondary);';
        row.innerHTML =
          '<i class="fa-solid fa-spinner spin-anim" style="color:var(--accent); font-size:10px;"></i>' +
          '<span style="flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
          'Another chat · ' +
          (run.phase ? escapeHtml(run.phase) + ' · ' : '') + escapeHtml(run.label) + '</span>';
        const btn = document.createElement('button');
        btn.textContent = 'Cancel';
        btn.style.cssText = 'background:transparent; border:1px solid var(--border-color); color:var(--text-strong);' +
          ' border-radius:6px; padding:2px 8px; font-size:11px; cursor:pointer; font-weight:600;';
        btn.onclick = (e) => { e.stopPropagation(); window.cancelRunForSession(run.id); };
        row.appendChild(btn);
        list.appendChild(row);
      });
    };

    window.updateForeignRunBadge = function (payload) {
      const sid = window.liveRunSessionId;
      if (!sid) return;
      const terminal = ['completed', 'error', 'failed', 'cancelled', 'blocked', 'denied', 'security_blocked'];
      if (!terminal.includes(String(payload.type))) return;
      window.markRunFinished(sid, payload.type === 'completed');
      const title = payload.type === 'completed' ? 'Run finished' : 'Run ended: ' + payload.type;
      const body = payload.type === 'completed'
        ? 'The run in another chat completed. Open it to read the result.'
        : 'The run in another chat ended with ' + payload.type + '.';
      if (typeof window.sreToast === 'function') window.sreToast(title, body, payload.type === 'completed');
    };

    // Global toast so background news is never silent.
    window.sreToast = function (title, body, ok) {
      if (document.getElementById('sre-toast')) return;
      const host = document.createElement('div');
      host.id = 'sre-toast';
      host.style.cssText = 'position:fixed; bottom:18px; right:18px; z-index:9999; max-width:340px; padding:12px 14px;' +
        ' border-radius:12px; border:1px solid var(--border-color); background:var(--bg-panel); color:var(--text-strong);' +
        ' box-shadow:0 10px 30px rgba(0,0,0,0.35); font-size:12px;';
      host.innerHTML =
        '<div style="display:flex; align-items:center; gap:8px; font-weight:700; margin-bottom:4px;">' +
        '<i class="fa-solid ' + (ok ? 'fa-circle-check' : 'fa-circle-exclamation') + '" style="color:' +
        (ok ? 'var(--success-text)' : 'var(--warning)') + ';"></i>' + escapeHtml(title) + '</div>' +
        '<div style="color:var(--text-secondary); line-height:1.45;">' + escapeHtml(body || '') + '</div>';
      document.body.appendChild(host);
      setTimeout(() => { host.remove(); }, 9000);
      host.onclick = () => host.remove();
    };

    function addSystemMsg(text, iconName = 'info') {
      if (text.includes('Connected to NeuroSysAI') || text.includes('🚀')) {
        if (messagesDiv.querySelector('[data-agent-connection-card="true"]')) return;
      }
      const div = document.createElement('div');

      if (text.includes('Connected to NeuroSysAI') || text.includes('🚀')) {
        div.dataset.agentConnectionCard = 'true';
        div.className = 'my-2 w-100';
        div.style.cssText = 'width: 100%; max-width: 100%; box-sizing: border-box; align-self: stretch; flex-shrink: 0; border-radius: 14px; overflow: hidden; background: var(--bg-panel); border: 1px solid var(--border-color); padding: 14px 18px; margin: 12px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.15);';
        div.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%;">
            <div style="display: flex; align-items: center; gap: 12px;">
              <div style="width: 36px; height: 36px; border-radius: 10px; background: rgba(45, 164, 78, 0.12); border: 1px solid rgba(45, 164, 78, 0.3); display: flex; align-items: center; justify-content: center; color: var(--success-text); font-size: 16px; flex-shrink: 0;">
                <i class="fa-solid fa-rocket"></i>
              </div>
              <div>
                <div style="font-weight: 700; font-size: 13px; color: var(--text-strong);">Connected to NeuroSysAI SRE Agent</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Real-time WebSocket pipeline active & Ready for SRE tasks</div>
              </div>
            </div>
            <span style="font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 12px; background: rgba(45, 164, 78, 0.12); color: var(--success-text); border: 1px solid rgba(45, 164, 78, 0.3); white-space: nowrap; flex-shrink: 0;">
              <i class="fa-solid fa-circle-check me-1"></i> Connected
            </span>
          </div>
        `;
      } else if (text.includes('Sudo password') || text.includes('🔒')) {
        div.className = 'my-2 w-100';
        div.style.cssText = 'width: 100%; max-width: 100%; box-sizing: border-box; align-self: stretch; flex-shrink: 0; border-radius: 14px; overflow: hidden; background: var(--bg-panel); border: 1px solid var(--border-color); padding: 14px 18px; margin: 12px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.15);';
        div.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%;">
            <div style="display: flex; align-items: center; gap: 12px;">
              <div style="width: 36px; height: 36px; border-radius: 10px; background: rgba(137, 87, 229, 0.12); border: 1px solid rgba(137, 87, 229, 0.3); display: flex; align-items: center; justify-content: center; color: var(--purple); font-size: 16px; flex-shrink: 0;">
                <i class="fa-solid fa-shield-halved"></i>
              </div>
              <div>
                <div style="font-weight: 700; font-size: 13px; color: var(--text-strong);">Sudo Authentication Secured</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">End-to-End Encrypted (RSA-2048) in-memory session</div>
              </div>
            </div>
            <span style="font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 12px; background: rgba(137, 87, 229, 0.12); color: var(--purple); border: 1px solid rgba(137, 87, 229, 0.3); white-space: nowrap; flex-shrink: 0;">
              <i class="fa-solid fa-lock me-1"></i> Encrypted
            </span>
          </div>
        `;
      } else if (text.includes('Full Access enabled') || text.includes('Need Approval enabled') || text.includes('Permission update rejected')) {
        const isFull = text.includes('Full Access enabled');
        const isFallback = text.includes('Permission update rejected');
        const title = isFull ? 'Full Access enabled' : isFallback ? 'Permission update rejected' : 'Need Approval enabled';
        const sub = isFull ? 'In-goal actions auto-approved. Hard security boundaries remain enforced.'
          : isFallback ? 'Falling back to Need Approval.'
          : 'Mutating actions require Allow Once.';
        const tone = isFallback ? 'var(--error)' : 'var(--accent)';
        div.className = 'my-2 w-100';
        div.style.cssText = 'width: 100%; max-width: 100%; box-sizing: border-box; align-self: stretch; flex-shrink: 0; border-radius: 14px; overflow: hidden; background: var(--bg-panel); border: 1px solid var(--border-color); padding: 12px 16px; margin: 12px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.15);';
        div.innerHTML = `
          <div style="display: flex; align-items: center; gap: 12px; width: 100%;">
            <div style="width: 34px; height: 34px; border-radius: 50%; background: rgba(31, 111, 235, 0.12); border: 1px solid rgba(31, 111, 235, 0.3); display: flex; align-items: center; justify-content: center; color: ${tone}; font-size: 15px; flex-shrink: 0;">
              <i class="fa-solid fa-circle-info"></i>
            </div>
            <div>
              <div style="font-weight: 700; font-size: 13px; color: var(--text-strong);">${escapeHtml(title)}</div>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(sub)}</div>
            </div>
          </div>
        `;
      } else if (text.includes('Approved once; resuming the pending action.')) {
        div.className = 'my-2 w-100';
        div.style.cssText = 'width: 100%; max-width: 100%; box-sizing: border-box; align-self: stretch; flex-shrink: 0; border-radius: 14px; overflow: hidden; background: var(--bg-panel); border: 1px solid var(--border-color); padding: 12px 16px; margin: 12px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.15);';
        div.innerHTML = `
          <div style="display: flex; align-items: center; gap: 12px; width: 100%;">
            <div style="width: 34px; height: 34px; border-radius: 50%; background: rgba(45, 164, 78, 0.12); border: 1px solid rgba(45, 164, 78, 0.3); display: flex; align-items: center; justify-content: center; color: var(--success-text); font-size: 15px; flex-shrink: 0;">
              <i class="fa-solid fa-circle-check"></i>
            </div>
            <div>
              <div style="font-weight: 700; font-size: 13px; color: var(--text-strong);">Approved once</div>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Resuming the pending action.</div>
            </div>
          </div>
        `;
      } else if (text.includes('Only the latest message can be')) {
        const isDelete = text.includes('deleted');
        div.className = 'my-2 w-100';
        div.style.cssText = 'width: 100%; max-width: 100%; box-sizing: border-box; align-self: stretch; flex-shrink: 0; border-radius: 14px; overflow: hidden; background: var(--bg-panel); border: 1px solid var(--border-color); padding: 12px 16px; margin: 12px 0; box-shadow: 0 4px 15px rgba(0,0,0,0.15);';
        div.innerHTML = `
          <div style="display: flex; align-items: center; gap: 12px; width: 100%;">
            <div style="width: 34px; height: 34px; border-radius: 50%; background: rgba(31, 111, 235, 0.12); border: 1px solid rgba(31, 111, 235, 0.3); display: flex; align-items: center; justify-content: center; color: var(--accent); font-size: 15px; flex-shrink: 0;">
              <i class="fa-solid fa-circle-info"></i>
            </div>
            <div>
              <div style="font-weight: 700; font-size: 13px; color: var(--text-strong);">${isDelete ? 'Only the latest message can be deleted' : 'Only the latest message can be edited'}</div>
              <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${isDelete ? 'Only the most recent message can be deleted.' : 'Start a new chat to ask something else.'}</div>
            </div>
          </div>
        `;
      } else {
        div.style.cssText = 'width: 100%; align-self: stretch; text-align: center; font-size: 12px; padding: 6px 0; display: flex; justify-content: center; align-items: center; margin: 6px 0;';
        div.innerHTML = `
          <div style="display: inline-flex; align-items: center; gap: 8px; background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 20px; padding: 4px 14px; color: var(--text-secondary); box-shadow: 0 2px 6px rgba(0,0,0,0.06); font-size: 11px; font-weight: 500;">
            <span style="color: var(--accent); display: flex; align-items: center;">${getIcon(iconName)}</span>
            <span>${escapeHtml(text)}</span>
          </div>
        `;
      }

      messagesDiv.appendChild(div);
      scrollToBottom();
    }

    function ensureConnectionCard() {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      addSystemMsg('Connected to NeuroSysAI SRE Agent', 'check');
      const card = messagesDiv.querySelector('[data-agent-connection-card="true"]');
      if (card && messagesDiv.firstElementChild !== card) messagesDiv.prepend(card);
    }

    window.closeSessionGraph = function () {
      document.getElementById('session-graph-modal').style.display = 'none';
    };

    window.openSessionGraph = async function () {
      const modal = document.getElementById('session-graph-modal');
      const canvas = document.getElementById('session-graph-canvas');
      modal.style.display = 'flex';
      if (!sessionId) {
        canvas.innerHTML = '<div style="color:var(--text-secondary); padding:30px; text-align:center;">Start a chat to create the first case node.</div>';
        return;
      }
      canvas.innerHTML = '<div style="color:var(--text-secondary); padding:30px; text-align:center;"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading case graph…</div>';
      try {
        const response = await fetch(`/api/v1/chat-sessions/${encodeURIComponent(sessionId)}/case-graph/`, { credentials: 'same-origin' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        renderSessionGraph(await response.json());
      } catch (error) {
        canvas.innerHTML = `<div style="color:var(--error); padding:30px; text-align:center;">Unable to load graph: ${escapeHtml(error.message)}</div>`;
      }
    };

    // --- Session Graph case detail: alur + artifacts side panel ---
    function _sgEventLabel(evt) {
      const t = (evt && evt.type) ? String(evt.type) : '';
      switch (t) {
        case 'exploring': return ['search', 'Exploring'];
        case 'discovering_tools': return ['plug', 'Discovering tools'];
        case 'planning': return ['list-check', 'Planning'];
        case 'thinking': return ['brain', 'Thinking'];
        case 'tool_start': return ['zap', 'Executing ' + (evt.tool || '') + (evt.command ? ' — ' + evt.command : '')];
        case 'tool_end': {
          const len = evt && evt.result ? String(evt.result).length : 0;
          return ['check-circle', 'Result ' + (evt.tool || '') + ' (' + (len ? len : 0) + ' chars)'];
        }
        case 'resolution_plan': return ['list-checks', 'Resolution plan'];
        case 'worker_activity': return ['users', 'Worker activity'];
        case 'completed': return ['check', 'Completed'];
        case 'error': case 'failed': case 'cancelled': case 'blocked': case 'denied': case 'security_blocked':
          return ['circle-exclamation', t.replace(/_/g, ' ')];
        default: return ['circle', t || 'event'];
      }
    }

    window.openCaseDetail = async function (rawId, label) {
      const panel = document.getElementById('session-graph-detail');
      if (!panel) return;
      panel.style.display = 'block';
      panel.innerHTML = '<div style="padding:30px;text-align:center;color:var(--text-secondary);"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading case detail…</div>';

      // --- A. timeline filtered by case_id from recorded message events ---
      let timelineHtml = '<div style="color:var(--text-secondary);font-size:12px;">No timeline recorded for this case yet.</div>';
      try {
        const res = await fetch(`/api/v1/chat-sessions/${encodeURIComponent(sessionId)}/messages/?limit=100&order=asc`, { credentials: 'same-origin' });
        if (res.ok) {
          const payload = await res.json();
          // The endpoint is paged now; accept both shapes.
          const messages = Array.isArray(payload) ? payload : (payload.results || []);
          const evts = [];
          (Array.isArray(messages) ? messages : []).forEach(m => {
            const evs = m && m.metadata && Array.isArray(m.metadata.events) ? m.metadata.events : [];
            evs.forEach(ev => {
              if (!ev || typeof ev !== 'object') return;
              if (String(ev.case_id || '') === String(rawId) || String(ev.inv_id || '') === String(rawId)) evts.push(ev);
            });
            // Older sessions were not stamped with case_id. Do not leave the
            // panel blank: show the session's other agent events as a
            // best-effort replay, clearly labelled as unfiltered.
            if (evts.length === 0) {
              (Array.isArray(messages) ? messages : []).forEach(m => {
                const evs = m && m.metadata && Array.isArray(m.metadata.events) ? m.metadata.events : [];
                evs.forEach(ev => { if (ev && typeof ev === 'object' && !ev.case_id) evts.push(ev); });
              });
              if (evts.length > 0) evts.unshift({ type: '_note', content: 'Sesi lama' });
            }
          });
          const known = evts.filter(ev => ['exploring','discovering_tools','planning','thinking','tool_start','tool_end','resolution_plan','worker_activity','completed','error','failed','cancelled','blocked','denied','denied_timeout','security_blocked','status','verifying','hypothesis'].includes(String(ev.type)));
          const shown = known.length ? known : evts.filter(ev => ev && ev.type !== '_note');
          const hasOldSessionNote = evts.some(ev => ev && ev.type === '_note');
          if (shown.length > 0 || hasOldSessionNote) {
            timelineHtml = (hasOldSessionNote
              ? `<div style="padding:6px 10px;margin:4px 0;border-radius:10px;background:rgba(210,153,34,.12);color:var(--warning);font-size:11px;">Older session has no case stamp — showing whole-session events (unfiltered).</div>`
              : '') + shown.map((ev, idx) => {
                const [icon, text] = _sgEventLabel(ev);
                const last = idx === shown.length - 1;
                return `<div style="position:relative;display:flex;gap:12px;align-items:stretch;padding:6px 0;">
                  <div style="position:relative;width:26px;display:flex;justify-content:center;padding-top:9px;">
                    <i class="fa-solid fa-${icon}" style="color:var(--accent);width:18px;text-align:center;position:relative;z-index:1;"></i>
                    ${last ? '' : '<span style="position:absolute;top:30px;bottom:-6px;width:2px;background-image:linear-gradient(to bottom, var(--border-color) 40%, transparent 40%);background-size:2px 5px;opacity:.75;"></span>'}
                  </div>
                  <div style="flex:1;min-width:0;border:1px solid var(--border-color);border-radius:12px;padding:8px 12px;background:rgba(127,140,160,.04);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(text)}</div>
                </div>`;
              }).join('');
          }
        }
      } catch (e) { /* keep fallback */ }

      // --- B. artifacts for this investigation ---
      let artifactsHtml = '<div style="color:var(--text-secondary);font-size:12px;">No artifacts for this case yet.</div>';
      try {
        const res = await fetch(`/api/v1/workspace/artifacts/?session_id=${encodeURIComponent(sessionId)}`, { credentials: 'same-origin' });
        if (res.ok) {
          const all = await res.json();
          const ours = (Array.isArray(all) ? all : []).filter(a => String(a.file_path || '').includes('/investigations/' + rawId + '/'));
          if (ours.length > 0) {
            artifactsHtml = ours.map((a, _i) => {
              const name = String(a.file_path || '').split('/').pop() || 'artifact';
              const kind = a.action_type || 'file';
              const when = a.created_at ? new Date(a.created_at).toLocaleString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }) : '';
              const content = (a.new_content || a.old_content || '');
              const safeId = 'a_' + (a.id || _i);
              return `<div data-artifact-id="${safeId}" data-name="${escapeHtml(name)}" data-content="${encodeURIComponent(content)}" style="display:flex;gap:10px;align-items:center;padding:9px 0;border-bottom:1px solid var(--border-color);font-size:12px;">
                <i class="fa-solid fa-file-lines" style="color:var(--purple);width:18px;text-align:center;"></i>
                <div style="flex:1;min-width:0;">
                  <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${escapeHtml(name)}</b></div>
                  <div style="color:var(--text-secondary);font-size:11px;margin-top:2px;">${escapeHtml(kind)} · ${escapeHtml(when)}</div>
                </div>
                <button class="sg-artifact-dl" title="Download" style="border:1px solid var(--border-color);background:transparent;color:var(--text-secondary);cursor:pointer;padding:4px 8px;border-radius:8px;font-size:11px;"><i class="fa-solid fa-download"></i></button>
              </div>`;
            }).join('');
          }
        }
      } catch (e) { /* keep fallback */ }

      panel.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
          <div style="font-weight:800;color:var(--text-strong);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:15px;">${escapeHtml(label || 'Case')}</div>
          <button id="sg-detail-close" title="Close" style="border:0;background:transparent;color:var(--text-secondary);cursor:pointer;font-size:20px;line-height:1;">&times;</button>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <span style="font-size:11px;color:var(--text-secondary);background:rgba(127,140,160,.12);border:1px solid var(--border-color);border-radius:16px;padding:2px 10px;">Case id: <code>${escapeHtml(rawId || '')}</code></span>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:18px;margin-top:12px;">
          <div style="flex:1;min-width:300px;">
            <div style="font-weight:700;font-size:13px;color:var(--text-strong);margin-bottom:8px;">Agent flow</div>
            <div style="padding:12px 14px;border:1px solid var(--border-color);border-radius:14px;background:rgba(127,140,160,.04);max-height:420px;overflow-y:auto;">${timelineHtml}</div>
          </div>
          <div style="flex:1;min-width:300px;">
            <div style="font-weight:700;font-size:13px;color:var(--text-strong);margin-bottom:8px;">Artifacts (evidence files)</div>
            <div style="padding:12px 14px;border:1px solid var(--border-color);border-radius:14px;background:rgba(127,140,160,.04);max-height:420px;overflow-y:auto;">${artifactsHtml}</div>
          </div>
        </div>`;
      document.getElementById('sg-detail-close').addEventListener('click', () => { panel.style.display = 'none'; });
      // File-style download: click the row or the download button to save the artifact.
      panel.querySelectorAll('[data-artifact-id]').forEach(row => {
        const trigger = () => {
          const name = row.dataset.name || 'artifact';
          let content = '';
          try { content = decodeURIComponent(row.dataset.content || ''); } catch (_) { content = ''; }
          const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = name.endsWith('.md') ? name : (name + (name.includes('.') ? '' : '.md'));
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 1500);
        };
        row.style.cursor = 'pointer';
        row.addEventListener('click', trigger);
        row.querySelector('.sg-artifact-dl')?.addEventListener('click', (e) => { e.stopPropagation(); trigger(); });
      });
    };

    function renderSessionGraph(graph) {
      const canvas = document.getElementById('session-graph-canvas');
      const nodes = graph && Array.isArray(graph.nodes) ? graph.nodes : [];
      const edges = graph && Array.isArray(graph.edges) ? graph.edges : [];
      if (nodes.length === 0) {
        canvas.innerHTML = '<div style="color:var(--text-secondary); padding:30px; text-align:center;">No case nodes in this session yet.</div>';
        return;
      }
      const cases = nodes.filter(node => node.node_type === 'case');
      const entities = nodes.filter(node => node.node_type === 'entity');
      const evidence = nodes.filter(node => node.node_type === 'evidence');
      const width = Math.max(820, cases.length * 240 + 100, Math.max(entities.length, evidence.length) * 185 + 100);
      const height = 560;
      const positions = {};
      cases.forEach((node, index) => { positions[node.id] = { x: 140 + index * 240, y: 105 }; });
      entities.forEach((node, index) => { positions[node.id] = { x: 105 + index * 185, y: 300 }; });
      evidence.forEach((node, index) => { positions[node.id] = { x: 105 + index * 185, y: 470 }; });
      const edgeSvg = edges.filter(edge => positions[edge.source] && positions[edge.target]).map(edge => {
        const from = positions[edge.source], to = positions[edge.target];
        const semantic = edge.relation === 'same_entity' || edge.relation === 'semantically_related';
        const color = semantic ? 'var(--success)' : (edge.relation === 'evidence' ? 'var(--warning)' : 'var(--accent)');
        const confidence = semantic ? ` ${Math.round(Number(edge.confidence || 0) * 100)}%` : '';
        const midY = (from.y + to.y) / 2;
        return `<g><path d="M ${from.x} ${from.y + 45} C ${from.x} ${midY}, ${to.x} ${midY}, ${to.x} ${to.y - 34}" fill="none" stroke="${color}" stroke-opacity=".7" stroke-width="1.5" marker-end="url(#case-arrow)"/><text x="${(from.x + to.x) / 2}" y="${midY - 5}" text-anchor="middle" fill="var(--text-secondary)" font-size="10">${escapeHtml((edge.relation || 'related') + confidence)}</text></g>`;
      }).join('');
      const nodeSvg = nodes.map(node => {
        const p = positions[node.id];
        const active = node.raw_id === activeInvestigationId;
        const statusColor = node.status === 'completed' ? 'var(--success)' : (node.status === 'failed' ? 'var(--error)' : 'var(--accent)');
        const title = String(node.label || 'Untitled');
        const label = title.length > 30 ? title.slice(0, 30) + '…' : title;
        const isCase = node.node_type === 'case';
        const nodeColor = isCase ? statusColor : (node.node_type === 'entity' ? 'var(--purple)' : 'var(--warning)');
        const w = isCase ? 184 : 160, h = isCase ? 94 : 68;
        const secondary = isCase ? (node.kind || 'general') : node.node_type;
        return `<g ${isCase ? `class="sg-case" data-case-raw-id="${node.raw_id}" data-case-label="${escapeHtml(label)}" style="cursor:pointer"` : ''}><rect x="${p.x - w / 2}" y="${p.y - h / 2}" width="${w}" height="${h}" rx="12" fill="var(--bg-panel)" stroke="${active ? 'var(--accent)' : nodeColor}" stroke-opacity="${active ? 1 : .65}" stroke-width="${active ? 3 : 1.5}"/><text x="${p.x}" y="${p.y - 12}" text-anchor="middle" fill="var(--text-secondary)" font-size="10">${escapeHtml(secondary)}</text><text x="${p.x}" y="${p.y + 9}" text-anchor="middle" fill="var(--text-strong)" font-size="12" font-weight="600">${escapeHtml(label)}</text>${isCase ? `<text x="${p.x}" y="${p.y + 31}" text-anchor="middle" fill="${statusColor}" font-size="10">${escapeHtml(node.status || 'active')}</text>` : ''}<title>${escapeHtml(title + (node.summary ? '\n' + node.summary : ''))}</title></g>`;
      }).join('');
      canvas.innerHTML = `<div style="display:flex; gap:14px; flex-wrap:wrap; color:var(--text-secondary); font-size:11px; margin-bottom:8px;"><span>● Case</span><span style="color:var(--purple)">● Entity</span><span style="color:var(--warning)">● Evidence</span><span style="color:var(--success)">— Semantic correlation</span></div><svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Semantic session memory graph"><defs><marker id="case-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="var(--accent)"/></marker></defs>${edgeSvg}${nodeSvg}</svg>`;
      canvas.querySelectorAll('g[data-case-raw-id]').forEach(el => {
        el.addEventListener('click', () => window.openCaseDetail(el.dataset.caseRawId, el.dataset.caseLabel));
      });
    }



    // -- Investigation Timeline State --
    let investigations = {};
    let activeInvestigationId = null;
    let activeWorkers = [];
    let investigationFilter = 'all';
    // ← ADD THIS

    // Status vocabulary shared by the task rows and the case badge.
    const SRE_INV_TONE = {
      completed: 'var(--success-text)',
      success: 'var(--success-text)',
      running: 'var(--accent)',
      in_progress: 'var(--accent)',
      executing: 'var(--accent)',
      thinking: 'var(--accent)',
      planning: 'var(--accent)',
      pending: 'var(--text-secondary)',
      queued: 'var(--text-secondary)',
      blocked: 'var(--warning)',
      awaiting_approval: 'var(--warning)',
      warning: 'var(--warning)',
      failed: 'var(--error)',
      error: 'var(--error)',
      denied: 'var(--error)',
      denied_timeout: 'var(--error)',
      security_blocked: 'var(--error)',
      expired: 'var(--text-secondary)',
      superseded: 'var(--text-secondary)',
      stopped: 'var(--error)',
      cancelled: 'var(--error)',
    };
    const sreInvTone = (state) => SRE_INV_TONE[String(state || 'pending').toLowerCase()] || 'var(--text-secondary)';
    const sreInvGlyph = (state) => {
      const st = String(state || '').toLowerCase();
      if (st === 'completed' || st === 'success') return '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      if (['stopped', 'cancelled'].includes(st)) return '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"></rect></svg>';
      if (['failed', 'error', 'denied', 'denied_timeout', 'security_blocked'].includes(st)) return '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
      if (['blocked', 'awaiting_approval', 'warning'].includes(st)) return '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><rect x="4" y="10" width="16" height="10" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path></svg>';
      if (['running', 'in_progress', 'executing', 'thinking', 'planning'].includes(st)) return '<i class="fa-solid fa-circle-notch fa-spin" style="font-size:8px;"></i>';
      return '';
    };

    const investigationFilterGroup = (status) => {
      const state = String(status || '').toLowerCase();
      if (['active', 'running', 'in_progress', 'executing', 'planning', 'thinking'].includes(state)) return 'active';
      if (['completed', 'success'].includes(state)) return 'completed';
      if (['failed', 'error', 'blocked', 'security_blocked', 'denied', 'denied_timeout'].includes(state)) return 'failed';
      if (['cancelled', 'stopped', 'expired', 'superseded', 'finalized'].includes(state)) return 'stopped';
      return 'other';
    };

    window.setInvestigationFilter = function (filter) {
      const allowed = new Set(['all', 'active', 'completed', 'failed', 'stopped']);
      if (!allowed.has(String(filter || '').toLowerCase())) return;
      investigationFilter = String(filter).toLowerCase();
      renderInvestigationTimeline();
    };

    function renderInvestigationTimeline() {
      const container = document.getElementById('investigation-timeline-container');
      if (!container) return;

      const allInvKeys = Object.keys(investigations).sort((a, b) => {
        const createdAt = (key) => {
          const inv = investigations[key] || {};
          const raw = inv.createdAt || inv.created_at || inv.updatedAt || inv.updated_at || 0;
          const time = new Date(raw).getTime();
          return Number.isFinite(time) ? time : 0;
        };
        return createdAt(b) - createdAt(a) || String(b).localeCompare(String(a));
      });
      const filters = [
        { id: 'all', label: 'All' },
        { id: 'active', label: 'Active' },
        { id: 'completed', label: 'Done' },
        { id: 'failed', label: 'Failed' },
        { id: 'stopped', label: 'Stopped' },
      ];
      const counts = { all: allInvKeys.length, active: 0, completed: 0, failed: 0, stopped: 0 };
      allInvKeys.forEach((key) => {
        const group = investigationFilterGroup((investigations[key] || {}).status);
        if (Object.prototype.hasOwnProperty.call(counts, group)) counts[group] += 1;
      });
      const filterIndex = Math.max(0, filters.findIndex((item) => item.id === investigationFilter));
      const filterHtml = '<div class="sre-inv-filter" role="tablist" aria-label="Filter investigations" '
        + 'style="--sre-filter-index:' + filterIndex + ';">'
        + filters.map((item) => '<button type="button" role="tab" aria-selected="'
          + (item.id === investigationFilter ? 'true' : 'false') + '"'
          + ' class="' + (item.id === investigationFilter ? 'is-active' : '') + '"'
          + ' onclick="window.setInvestigationFilter(\'' + item.id + '\')">'
          + '<span>' + item.label + '</span><small>' + counts[item.id] + '</small></button>').join('')
        + '</div>';
      const invKeys = investigationFilter === 'all' ? allInvKeys : allInvKeys.filter((key) => {
        const group = investigationFilterGroup((investigations[key] || {}).status);
        return investigationFilter === 'active' ? group === 'active'
          : investigationFilter === 'completed' ? group === 'completed'
            : investigationFilter === 'failed' ? group === 'failed'
              : group === 'stopped';
      });
      if (allInvKeys.length === 0) {
        container.innerHTML = filterHtml + '<div class="sre-inv-empty">No investigations yet.</div>';
        return;
      }

      let html = filterHtml;
      if (invKeys.length === 0) {
        html += '<div class="sre-inv-empty">No ' + escapeHtml(investigationFilter) + ' investigations.</div>';
      }
      invKeys.forEach((key) => {
        const inv = investigations[key] || {};
        const isOpen = inv.id === activeInvestigationId;
        const rawStatus = String(inv.status || 'pending').toLowerCase();
        // A case that was superseded or expired never reached an outcome either;
        // what the operator needs to see is that it is stopped. Historical rows
        // written with those words fold into the same red stop badge.
        const status = ['superseded', 'expired', 'cancelled'].includes(rawStatus) ? 'stopped' : rawStatus;
        const tone = sreInvTone(status);
        const plan = Array.isArray(inv.plan) ? inv.plan : [];
        const findings = Array.isArray(inv.findings) ? inv.findings : [];
        const createdRaw = inv.createdAt || inv.created_at || inv.updatedAt || inv.updated_at;
        let createdLabel = '';
        try {
          const createdDate = createdRaw ? new Date(createdRaw) : null;
          if (createdDate && !Number.isNaN(createdDate.getTime())) {
            createdLabel = createdDate.toLocaleString('id-ID', {
              day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
            });
          }
        } catch (err) { /* optional metadata */ }
        const done = plan.filter((p) => String(p.status || '').toLowerCase() === 'completed').length;
        const pct = plan.length ? Math.round((done / plan.length) * 100) : 0;

        const planHtml = plan.length
          ? plan.map((p) => {
              const st = String(p.status || 'pending').toLowerCase();
              const rowTone = sreInvTone(st);
              const done_ = st === 'completed' || st === 'success';
              const text = p.description || p.task || p.title || '';
              return '<div class="sre-inv-row">'
                + '<span class="sre-inv-dot" style="color:' + rowTone + ';">' + sreInvGlyph(st) + '</span>'
                + '<span class="sre-inv-text" style="' + (done_ ? 'opacity:.6;text-decoration:line-through;' : '') + '">'
                + (p.role ? '<span class="sre-inv-chip" style="background:rgba(88,166,255,.14);color:var(--accent);margin-right:6px;">' + escapeHtml(p.role) + '</span>' : '')
                + escapeHtml(text)
                + '</span>'
                + '<span class="sre-inv-chip" style="color:' + rowTone + ';">' + escapeHtml(st.replace(/_/g, ' ')) + '</span>'
                + '</div>';
            }).join('')
          : '<div class="sre-inv-empty" style="padding:4px 0;">No tasks yet</div>';

        const findingsHtml = findings.length
          ? findings.map((f) => {
              const raw = String(f == null ? '' : f);
              const match = raw.match(/^\[(.*?)\]\[(.*?)\]\s*([\s\S]*)$/);
              const level = match ? String(match[2]).toUpperCase() : 'INFO';
              const worker = match ? String(match[1]) : '';
              let text = match ? String(match[3]) : raw;
              const fTone = ['FAILURE', 'ERROR', 'CRITICAL', 'BLOCKED'].includes(level) ? 'var(--error)'
                : ['WARNING'].includes(level) ? 'var(--warning)' : 'var(--success-text)';

              let textHtml = escapeHtml(text);
              if (text.length > 280) {
                const fid = 'finding-' + (window.findingSeq = (window.findingSeq || 0) + 1);
                window.findingContents = window.findingContents || {};
                window.findingContents[fid] = text;
                textHtml = '<span id="' + fid + '-short">' + escapeHtml(text.slice(0, 280)) + '… </span>'
                  + '<span id="' + fid + '-full" style="display:none;">' + escapeHtml(text) + '</span>'
                  + '<a href="javascript:void(0)" class="sre-inv-more" onclick="window.toggleFinding(\'' + fid + '\')">Show all</a>';
              }

              return '<div class="sre-inv-finding" style="color:' + fTone + ';">'
                + '<span class="sre-inv-stripe"></span>'
                + '<div style="flex:1; min-width:0;">'
                + '<div style="display:flex; align-items:center; gap:6px; margin-bottom:3px; flex-wrap:wrap;">'
                + '<span class="sre-inv-chip" style="color:' + fTone + '; background:color-mix(in srgb, currentColor 14%, transparent);">' + escapeHtml(level) + '</span>'
                + (worker ? '<span class="sre-inv-chip" style="color:var(--text-secondary); background:rgba(127,140,160,.14);">' + escapeHtml(worker) + '</span>' : '')
                + '</div>'
                + '<div class="sre-inv-text" style="color:var(--text-primary);">' + textHtml + '</div>'
                + '</div></div>';
            }).join('')
          : '<div class="sre-inv-empty" style="padding:4px 0;">No findings yet</div>';

        const invWorkers = Array.isArray(inv.workers) ? inv.workers : [];
        const workerWorkflowHtml = invWorkers.length
          ? '<div class="sre-inv-section"><i class="fa-solid fa-diagram-project" style="font-size:10px;"></i> Worker workflow</div>'
            + invWorkers.map((worker) => {
                const workerStatus = String(worker.status || 'running').toLowerCase();
                const workerTone = sreInvTone(workerStatus);
                const steps = Array.isArray(worker.workflow) ? worker.workflow : [];
                const stepsHtml = steps.length
                  ? '<div style="position:relative;margin:8px 0 2px 5px;padding-left:16px;border-left:1px solid var(--border-color);">'
                    + steps.map((step) => {
                        const stepStatus = String(step.tool_status || step.status || 'running').toLowerCase();
                        const stepTone = sreInvTone(stepStatus);
                        const detail = step.last_tool_result
                          ? '<div style="margin:3px 0 6px;">' + window.sreTerminalHtml(step.last_tool_result, 900) + '</div>' : '';
                        const tool = step.last_tool
                          ? '<span class="sre-inv-chip" style="color:' + stepTone + ';margin-left:4px;">' + escapeHtml(step.last_tool) + '</span>' : '';
                        return '<div style="position:relative;margin:0 0 6px;color:var(--text-primary);font-size:11px;">'
                          + '<span style="position:absolute;left:-21px;top:3px;color:' + stepTone + ';background:var(--bg-panel);">' + sreInvGlyph(stepStatus) + '</span>'
                          + '<span>' + escapeHtml(step.current_action || step.status || 'Working') + '</span>' + tool + detail
                          + '</div>';
                      }).join('')
                    + '</div>'
                  : '<div class="sre-inv-empty" style="padding:3px 0 6px;">Waiting for worker activity…</div>';
                const lastResult = worker.last_tool_result && !steps.length
                  ? '<div style="margin:4px 0 6px;">' + window.sreTerminalHtml(worker.last_tool_result, 900) + '</div>' : '';
                return '<div style="margin:0 0 10px;padding:9px 10px;border:1px solid var(--border-color);border-radius:10px;background:rgba(127,140,160,.04);">'
                  + '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">'
                  + '<span style="font-weight:700;color:var(--text-primary);font-size:11px;">' + escapeHtml(worker.role || ('Worker ' + worker.id)) + '</span>'
                  + '<span class="sre-inv-chip" style="color:' + workerTone + ';">' + escapeHtml(workerStatus.replace(/_/g, ' ')) + '</span>'
                  + '<span style="font-size:10px;color:var(--text-secondary);">' + Number(worker.findings_count || 0) + ' findings · ' + Number(worker.evidence_count || 0) + ' evidence</span>'
                  + '</div>'
                  + '<div style="margin-top:4px;color:var(--text-secondary);font-size:10px;">' + escapeHtml(worker.goal || '') + '</div>'
                  + lastResult + stepsHtml + '</div>';
              }).join('')
          : '';

        html += '<section class="sre-inv-card" data-open="' + (isOpen ? '1' : '0') + '">'
          + '<button class="sre-inv-head" onclick="window.toggleInvestigationCard(this)">'
          + '<span class="sre-inv-chev"><i class="fa-solid fa-chevron-right"></i></span>'
          + '<span class="sre-inv-title" title="' + escapeHtml(inv.title || '') + '">' + escapeHtml(inv.title || 'Investigation') + '</span>'
          + '<span class="sre-inv-badge" style="color:' + tone + ';">' + escapeHtml(status.replace(/_/g, ' ')) + '</span>'
          + (((inv.plan || []).some((p) => ['pending', 'running', 'in_progress', 'executing'].includes(String(p.status || '').toLowerCase())) || status === 'active')
            ? '<span role="button" tabindex="0" title="Stop this investigation" onclick="event.stopPropagation(); window.stopInvestigationCase(\'' + escapeHtml(inv.id || '') + '\')" onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();event.stopPropagation();window.stopInvestigationCase(\'' + escapeHtml(inv.id || '') + '\');}" style="flex:none; display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:6px; border:1px solid rgba(248,81,73,.5); background:rgba(248,81,73,.12); color:var(--error); cursor:pointer;" onmouseover="this.style.background=\'rgba(248,81,73,.25)\'" onmouseout="this.style.background=\'rgba(248,81,73,.12)\'"><i class="fa-solid fa-stop" style="font-size:8px; pointer-events:none;"></i></span>'
            : '')
          + '</button>'
          + '<div class="sre-inv-meta">'
          + '<span>' + done + '/' + plan.length + ' tasks</span>'
          + '<span>' + findings.length + ' finding' + (findings.length === 1 ? '' : 's') + '</span>'
          + (inv.id ? '<span style="font-family:monospace; opacity:.7;">' + escapeHtml(inv.id) + '</span>' : '')
          + (createdLabel ? '<span class="sre-inv-date"><i class="fa-regular fa-clock"></i> ' + escapeHtml(createdLabel) + '</span>' : '')
          + '</div>'
          + '<div class="sre-inv-bar"><i style="width:' + pct + '%;"></i></div>'
          + '<div class="sre-inv-body" ' + (isOpen ? '' : 'hidden') + '>'
          + workerWorkflowHtml
          + '<div class="sre-inv-section"><i class="fa-solid fa-list-check" style="font-size:10px;"></i> Task plan</div>'
          + planHtml
          + '<div class="sre-inv-section"><i class="fa-solid fa-magnifying-glass" style="font-size:10px;"></i> Findings</div>'
          + findingsHtml
          + '</div></section>';
      });

      container.innerHTML = html;
    }

    function updateInvestigationWorkerActivity(workers, caseId) {
      if (!Array.isArray(workers)) return;
      activeWorkers = workers;
      const invId = caseId || activeInvestigationId;
      const inv = invId && investigations[invId];
      if (inv) {
        const previous = new Map((inv.workers || []).map((worker) => [String(worker.id), worker]));
        inv.workers = workers.map((worker) => {
          const prior = previous.get(String(worker.id)) || {};
          const workflow = Array.isArray(prior.workflow) ? prior.workflow.slice() : [];
          const stepKey = [worker.current_action, worker.last_tool, worker.last_tool_status,
            worker.last_tool_result, worker.status].join('|');
          if (!workflow.length || workflow[workflow.length - 1].key !== stepKey) {
            workflow.push({
              key: stepKey,
              current_action: worker.current_action || 'Working',
              status: worker.status || 'running',
              last_tool: worker.last_tool || '',
              tool_status: worker.last_tool_status || 'unknown',
              last_tool_result: worker.last_tool_result || '',
            });
          }
          return Object.assign({}, prior, worker, { workflow: workflow.slice(-30) });
        });
        renderInvestigationTimeline();
      }
      renderWorkerActivity();
    }

    window.toggleInvestigationCard = function (btn) {
      const card = btn.closest('.sre-inv-card');
      if (!card) return;
      const open = card.dataset.open !== '1';
      card.dataset.open = open ? '1' : '0';
      const body = card.querySelector('.sre-inv-body');
      if (body) body.hidden = !open;
    };

    function renderWorkerActivity() {
      const container = document.getElementById('worker-activity-container');
      if (!container) return;

      if (!activeWorkers || activeWorkers.length === 0) {
        container.innerHTML = '';
        container.style.display = 'none';
        return;
      }

      container.style.display = 'flex';
      const terminalWorkerStates = new Set(['completed', 'failed', 'blocked', 'cancelled']);
      const workerStatuses = activeWorkers.map(w => String(w.status || w.current_action || '').toLowerCase());
      const allWorkersTerminal = workerStatuses.every(status => terminalWorkerStates.has(status));
      const allWorkersSucceeded = allWorkersTerminal && workerStatuses.every(status => status === 'completed');
      const failedWorkerCount = workerStatuses.filter(status => ['failed', 'blocked', 'cancelled'].includes(status)).length;
      const headerIcon = !allWorkersTerminal
        ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="spin-anim" style="color: var(--accent);"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="4.93"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line></svg>`
        : allWorkersSucceeded
          ? `<i class="fa-solid fa-circle-check" style="color:var(--success);"></i>`
          : `<i class="fa-solid fa-circle-exclamation" style="color:var(--error);"></i>`;
      let html = `<div style="padding: 12px 16px; font-weight: 600; color: var(--text-primary); background: var(--bg-panel); display: flex; align-items: center; gap: 8px;">
            ${headerIcon}
            ${!allWorkersTerminal ? 'Active Workers' : allWorkersSucceeded ? 'Workers Completed' : `Workers Finished · ${failedWorkerCount} not completed`}
        </div>
        <div style="padding: 12px 16px; display: flex; flex-direction: column; gap: 16px;">`;

      activeWorkers.forEach((w) => {
        const workerStatus = String(w.status || w.current_action || '').toLowerCase();
        const workerTerminal = terminalWorkerStates.has(workerStatus);
        let toolHtml = '';
        if (w.last_tool) {
          const toolStatus = String(w.last_tool_status || 'unknown').toLowerCase();
          const toolColor = toolStatus === 'completed' ? 'var(--success)' : toolStatus === 'failed' || toolStatus === 'blocked' ? 'var(--error)' : 'var(--text-secondary)';
          const toolIcon = toolStatus === 'completed' ? 'fa-circle-check' : toolStatus === 'failed' || toolStatus === 'blocked' ? 'fa-circle-exclamation' : 'fa-circle-dot';
          toolHtml += `<div style="display: flex; align-items: center; gap: 6px; font-size: 12px; color: ${toolColor};">
                    <i class="fa-solid ${toolIcon}"></i>
                    ${escapeHtml(w.last_tool)}
                </div>`;
          if (w.last_tool_result) {
            toolHtml += `<div style="margin:3px 0 0 18px;">${window.sreTerminalHtml(w.last_tool_result, 900)}</div>`;
          }
        }

        const currentAction = String(w.current_action || 'Working');
        let actionColor = currentAction.toLowerCase().includes('executing') ? 'var(--warning)' : 'var(--text-secondary)';
        const workerIcon = workerTerminal
          ? `<i class="fa-solid ${workerStatus === 'completed' ? 'fa-circle-check' : 'fa-circle-exclamation'}"></i>`
          : `<i class="fa-solid fa-spinner spin-anim"></i>`;
        let currentActionHtml = `<div style="display: flex; align-items: center; gap: 6px; font-size: 12px; color: ${workerTerminal && workerStatus === 'completed' ? 'var(--success)' : actionColor}; margin-top: 4px;">
                ${workerIcon}
                ${escapeHtml(currentAction)}
            </div>`;

        html += `
                <div style="background: var(--bg-main); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.2);">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <div style="font-weight: 600; color: var(--text-primary); font-size: 13px;">${escapeHtml(w.role || ('Worker ' + String(w.id || '').substring(0, 4).toUpperCase()))} <span style="font-weight: 400; color: var(--text-secondary); font-size: 11px;">[${escapeHtml(String(w.id || ''))}]</span></div>
                        <div style="display: flex; gap: 6px;">
                            <span style="font-size: 10px; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; color: var(--text-secondary);" title="Findings Count">${w.findings_count} findings</span>
                            <span style="font-size: 10px; background: rgba(63, 185, 80, 0.2); padding: 2px 6px; border-radius: 4px; color: var(--success);" title="Evidence Count">${w.evidence_count} evidence</span>
                        </div>
                    </div>
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; font-style: italic;">
                        Goal: ${escapeHtml(w.goal)}
                    </div>
                    ${toolHtml}
                    ${currentActionHtml}
                </div>
            `;
      });
      html += `</div>`;
      container.innerHTML = html;
    }

    // Auto-scroll is opt-in and conditional: it only follows the newest content
    // while the viewport is already parked at the bottom. Reading history is
    // never interrupted - not while a reply streams either - and a 'Latest'
    // button is offered instead of yanking the page.
    window.SRE_SCROLL_THRESHOLD = 80;
    window.agentAutoScroll = true;

    window.isPinnedToBottom = function () {
      if (!messagesDiv) return false;
      return messagesDiv.scrollHeight - messagesDiv.scrollTop - messagesDiv.clientHeight <= window.SRE_SCROLL_THRESHOLD;
    };

    window.showJumpToLatest = function () {
      const beam = document.getElementById('chat-beam');
      const host = (beam && beam.parentElement) || (messagesDiv && messagesDiv.parentElement);
      if (!host) return;
      let btn = document.getElementById('sre-jump-latest');
      if (!btn) {
        btn = document.createElement('button');
        btn.id = 'sre-jump-latest';
        btn.style.cssText = 'position:absolute; right:18px; bottom:calc(100% + 8px); z-index:20; display:none;' +
          ' align-items:center; gap:6px; padding:7px 12px; border-radius:999px; font-size:12px;' +
          ' font-weight:600; cursor:pointer; color:#fff; border:1px solid rgba(255,255,255,.25);' +
          ' background:rgba(31,111,235,.92); box-shadow:0 6px 18px rgba(0,0,0,.28); white-space:nowrap;' +
          ' pointer-events:auto;';
        btn.innerHTML = '<i class="fa-solid fa-arrow-down" style="font-size:11px;"></i> Latest';
        btn.onclick = () => {
          window.agentAutoScroll = true;
          messagesDiv.scrollTo({ top: messagesDiv.scrollHeight, behavior: 'smooth' });
          window.hideJumpToLatest();
        };
        if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
        host.appendChild(btn);
      }
      btn.style.display = 'inline-flex';
    };

    window.hideJumpToLatest = function () {
      const btn = document.getElementById('sre-jump-latest');
      if (btn) btn.style.display = 'none';
    };

    function scrollToBottom(force) {
      if (window.isLoadingHistory) return;
      if (!force && window.runHeaderPinned) {
        // A pinned run owns the scroll position, so this used to bail out
        // silently and left the reader scrolled up with no way back. While a
        // run holds the pin, leaving the follow position still offers Latest.
        if (!window.agentAutoScroll && !window.isPinnedToBottom()) window.showJumpToLatest();
        return;
      }
      if (force) {
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        window.hideJumpToLatest();
        return;
      }
      if (!window.agentAutoScroll && !window.isPinnedToBottom()) {
        window.showJumpToLatest();
        return;
      }
      window.agentAutoScroll = true;
      messagesDiv.scrollTop = messagesDiv.scrollHeight;
      window.hideJumpToLatest();
    }

    window.centerRunTurn = function (wrapId) {
      if (window.isLoadingHistory || !messagesDiv) return;
      // Centering the live turn used to run on every step and every streamed
      // chunk, and it wrote scrollTop unconditionally: scrolling up to read an
      // older answer was undone the moment the agent took its next step, which
      // read as the page yanking itself back down. Once the reader has left the
      // follow position, the view is theirs - the Latest button is the way
      // back, exactly as it already is for ordinary new content.
      if (!window.agentAutoScroll && !window.isPinnedToBottom()) return;
      const wrap = document.getElementById(wrapId);
      const bubbleId = wrap && wrap.dataset.bubbleId;
      const bubble = (bubbleId && document.getElementById(bubbleId))
        || (wrap && wrap.nextElementSibling && wrap.nextElementSibling.classList.contains('agent-msg')
          ? wrap.nextElementSibling : null);
      if (!bubble) return;
      let userBubble = null;
      for (const child of messagesDiv.children) {
        if (child === wrap) break;
        if (child.classList && child.classList.contains('sre-msg-user')) userBubble = child;
      }
      const align = () => {
        if (!document.contains(bubble)) return;
        const hostRect = messagesDiv.getBoundingClientRect();
        const bubbleRect = bubble.getBoundingClientRect();
        const userRect = userBubble && userBubble.getBoundingClientRect();
        const groupTop = userRect ? userRect.top : (wrap ? wrap.getBoundingClientRect().top : bubbleRect.top);
        const groupCenter = (groupTop + bubbleRect.bottom) / 2;
        const viewCenter = hostRect.top + messagesDiv.clientHeight / 2;
        const maxScroll = Math.max(0, messagesDiv.scrollHeight - messagesDiv.clientHeight);
        messagesDiv.scrollTop = Math.max(0, Math.min(maxScroll, messagesDiv.scrollTop + groupCenter - viewCenter));
        window.hideJumpToLatest();
      };
      align();
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(align);
    };

    // A new turn inserts its user bubble, run card, and empty AI bubble in the
    // same task. Defer the forced follow until those changes have been laid out
    // so the starting state is fully visible, even if the user was reading up.
    window.scrollToNewTurn = function () {
      if (window.isLoadingHistory || !messagesDiv) return;
      window.runHeaderPinned = false;
      window.agentAutoScroll = true;
      const follow = () => {
        if (!window.isLoadingHistory) scrollToBottom(true);
      };
      if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => requestAnimationFrame(follow));
      } else {
        setTimeout(follow, 0);
      }
    };

    if (messagesDiv) {
      messagesDiv.addEventListener('scroll', () => {
        if (window.isPinnedToBottom()) {
          window.agentAutoScroll = true;
          window.hideJumpToLatest();
        } else {
          window.agentAutoScroll = false;
          if (messagesDiv.scrollHeight > messagesDiv.clientHeight + 200) window.showJumpToLatest();
        }
        window.turnRailActiveSchedule && window.turnRailActiveSchedule();
      }, { passive: true });
    }
    window.turnRailObserve && window.turnRailObserve();

    // --- Form submit ---
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      let msg = input.value.trim();
      if (!msg) return;
      const silent = window.silentSubmit === true;
      window.silentSubmit = false;
      // Multitasking: only this chat's own live run blocks a new message here.
      // Runs in other chats keep going and are tracked in History.
      const ownRunActive = !!(window.runsBySession || {})[String(sessionId || '')] ||
        (isProcessing && String(window.processingSid || '') === String(sessionId || ''));
      if (ownRunActive) {
        // Single flight per socket: a background run elsewhere blocks a new one
        // here, so name it instead of failing silently.
        const others = Object.keys(window.runsBySession || {}).filter((sid) => String(sid) !== String(sessionId));
        if (others.length) {
          const where = others.map((sid) => {
            const item = document.getElementById('history-item-' + sid);
            const title = item ? (item.querySelector('.sre-history-title') || {}).textContent : '';
            return title ? ('\u201c' + String(title).trim().slice(0, 40) + '\u201d') : 'another chat';
          }).join(', ');
          addSystemMsg('A run is still active in ' + where + '. Stop it or wait for it to finish before sending here.', 'circle-info');
        } else {
          addSystemMsg('A run is still going. Press Stop to cancel it before sending a new message.', 'circle-info');
        }
        return;
      }

      // The attached file is context for this one message only: capture it,
      // then drop the chip so it does not sit above the composer forever.
      const attachedFile = window.selectedFile || '';
      const attachedFileName = attachedFile ? attachedFile.split('/').pop() : '';
      if (attachedFile) {
        msg = msg + `\n\n[Context Attached: file://${attachedFile}]`;
      }

      // A retry resends the failed goal without stacking another user bubble.
      if (!silent) addUserMessage(msg);
      input.value = '';
      input.style.height = 'auto';
      stopAllAgentStepTimers();
      window.openTurn();
      currentTurnWasDirect = false;
      currentDirectAnswerSaved = false;
      currentDirectRunId = '';
      // Create the run card, avatar and starting pill immediately for every
      // turn. A direct reply later adds only Thinking; tool runs add their phases.
      startRunWrap({ deferOpen: true });
      // Sending means following so the live card and reply stay in view.
      window.agentAutoScroll = true;
      window.scrollToNewTurn();
      window.sessionStartTime = new Date();
      isProcessing = true;
      window.processingSid = String(sessionId || '');
      // A fresh attempt invalidates any cancel horizon for this chat.
      if (window.cancelledAt) delete window.cancelledAt[String(sessionId || '')];
      currentAIMsg = null;
      window.setSendButtonState('running');

      window.lastSubmittedMessage = msg;
      window.liveRunSessionId = String(sessionId || '');
      window.expectingSession = true;
      window.markRunActive(sessionId, msg.slice(0, 60));
      window.setAgentDotState('running');
      sendBtn.classList.remove('sre-press');
      // Force a reflow so the press animation replays on every send.
      void sendBtn.offsetWidth;
      sendBtn.classList.add('sre-press');
      ws.send(JSON.stringify({
        type: 'message',
        message: msg,
        session_id: sessionId || '',
        terminal_cwd: window.currentTerminalCwd || '',
        active_workspace: window.customWorkspaceOverride || window.currentTerminalCwd || '',
        selected_file: attachedFile,
        selected_file_name: attachedFileName,
        model: document.getElementById('model-selector').value,
        auto_model_rotation: localStorage.getItem('sre_auto_models') === 'true',
        mode: document.getElementById('mode-selector').value,
        resume_case_id: window.pendingResumeCaseId || '',
        resume_mode: window.pendingResumeMode || ''
      }));
      window.pendingResumeCaseId = '';
      window.pendingResumeMode = '';
      if (attachedFile) window.clearSelectedFile();
    });

    // Auto-resize textarea and Enter key submit
    input.addEventListener('input', function () {
      this.style.height = 'auto';
      this.style.height = (this.scrollHeight) + 'px';
    });

    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        form.dispatchEvent(new Event('submit'));
      }
    });

    // --- Tabs ---
    window.switchTab = function (tabName, el) {
      document.querySelectorAll('.tab-btn').forEach(b => {
        b.style.color = '#8b949e';
        b.style.borderBottom = 'none';
      });
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');

      let targetEl = el;
      if (!targetEl && typeof event !== 'undefined' && event && event.currentTarget) {
        targetEl = event.currentTarget;
      }

      if (targetEl) {
        targetEl.style.color = '#c9d1d9';
        targetEl.style.borderBottom = '2px solid #58a6ff';
      } else {
        document.querySelectorAll('.tab-btn').forEach(b => {
          if (b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + tabName + "'")) {
            b.style.color = '#c9d1d9';
            b.style.borderBottom = '2px solid #58a6ff';
          }
        });
      }

      const tabContent = document.getElementById('tab-' + tabName);
      if (tabContent) {
        tabContent.style.display = 'flex';
      }

      if (tabName === 'explorer') {
        loadExplorer();
      }
      if (tabName === 'artifacts') {
        loadArtifacts();
      }
      if (tabName === 'investigation') {
        renderInvestigationTimeline();
      }
      if (tabName === 'terminal' && window.fitTerminal) {
        setTimeout(window.fitTerminal, 50);
      }
    };

    // --- History ---
    async function loadHistory() {
      window.loadHistoryGlobal = loadHistory;
      window.showPanelSkeleton(document.getElementById('history-list'), 5);
      window.renderActiveRuns && window.renderActiveRuns();
      window.onSessionDeleted = function (deletedId) {
        if (deletedId === sessionId) {
          window.startNewChat();
        }
        loadHistory();
      };

      try {
        // Pagination: first page resets the list; subsequent pages append.
        // `window.__historyAppend` is set by the Load More button.
        const appendMode = window.__historyAppend === true;
        const url = appendMode
          ? `/api/v1/chat-sessions/?limit=50&offset=${window.__historyOffset || 0}`
          : '/api/v1/chat-sessions/?limit=50';
        const res = await fetch(url);
        const data = await res.json();
        const list = document.getElementById('history-list');
        if (!appendMode) {
          list.innerHTML = '';
          window.__historyOffset = 0;
        }
        let sessions = data.results || data;

        sessions.forEach(sess => {
          let el = document.createElement('div');
          el.className = 'sre-history-item' + (sess.id === sessionId ? ' active' : '');
          el.id = 'history-item-' + sess.id;

          const dateStr = new Date(sess.created_at).toLocaleString('en-US', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

          el.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px; width: 100%;">
              <input type="checkbox" class="history-checkbox" value="${sess.id}" style="display: ${isBulkEditMode ? 'inline-block' : 'none'}; appearance: auto; -webkit-appearance: auto; accent-color: var(--purple); width: 16px; height: 16px; cursor: pointer; flex-shrink: 0;">
              <span class="sre-history-check"><i class="fa-solid fa-check"></i></span>
              <span data-run-state style="display:inline-flex; align-items:center; gap:4px; flex-shrink:0;"></span>
              <div style="flex: 1; min-width: 0;">
                <div class="sre-history-title">${escapeHtml(sess.title || 'Chat Session')}</div>
                <div class="sre-history-date">${dateStr}</div>
              </div>
              <button class="delete-single-history-btn" title="Delete chat session" style="display: ${isBulkEditMode ? 'none' : 'inline-flex'}; background: transparent; border: none; color: var(--text-secondary); cursor: pointer; padding: 4px; border-radius: 4px; transition: color 0.2s;" onmouseover="this.style.color='var(--error)'" onmouseout="this.style.color='var(--text-secondary)'" onclick="event.stopPropagation(); deleteSingleHistory('${sess.id}');">
                <i class="fa-solid fa-trash-can" style="font-size: 12px; pointer-events: none;"></i>
              </button>
              <i class="fa-solid fa-chevron-right sre-history-chev"></i>
            </div>
          `;

          const checkbox = el.querySelector('.history-checkbox');
          if (checkbox) {
            checkbox.addEventListener('change', (e) => {
              e.stopPropagation();
              updateBulkSelectedCount();
            });
            checkbox.addEventListener('click', (e) => {
              e.stopPropagation();
            });
          }

          el.onclick = (e) => {
            if (isBulkEditMode) {
              if (checkbox) {
                checkbox.checked = !checkbox.checked;
                updateBulkSelectedCount();
              }
            } else {
              // Only load if different session
              if (sessionId !== sess.id) {
                document.querySelectorAll('.sre-history-item').forEach(i => i.classList.remove('active'));
                el.classList.add('active');
                loadSession(sess.id);
              }
            }
          };

          list.appendChild(el);
        });

        updateBulkSelectedCount();
        Object.keys(window.runsBySession || {}).forEach((sid) => window.refreshHistoryRowState(sid));
        Object.keys(window.unreadSessions || {}).forEach((sid) => window.refreshHistoryRowState(sid));
        window.refreshRunPresence();

        window.__historyOffset = (window.__historyOffset || 0) + sessions.length;
        window.__historyAppend = false;
        const oldLoadMore = document.getElementById('history-load-more');
        if (oldLoadMore) oldLoadMore.remove();
        const total = typeof data.count === 'number' ? data.count : null;
        if ((data.next) || (total !== null && window.__historyOffset < total)) {
          const btn = document.createElement('button');
          btn.id = 'history-load-more';
          btn.type = 'button';
          btn.style.cssText = 'margin: 8px 4px; width: calc(100% - 8px); padding: 6px; border-radius: 8px; border: 1px dashed var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer; font-size: 12px;';
          btn.innerHTML = `<i class="fa-solid fa-ellipsis"></i> Load more (${window.__historyOffset}${total !== null ? '/' + total : ''})`;
          btn.onclick = () => {
            window.__historyAppend = true;
            loadHistory();
          };
          list.appendChild(btn);
        }

        // ONLY auto-load if there's a URL param AND no current session
        if (!appendMode) {
          const urlParams = new URLSearchParams(window.location.search);
          const urlSessionId = urlParams.get('session');
          if (urlSessionId && !sessionId) {
            sessionId = urlSessionId;
            const el = document.getElementById('history-item-' + sessionId);
            if (el) el.classList.add('active');
            loadSession(sessionId);
          } else if (!sessionId && !urlSessionId) {
            // No session at all - start new chat
            window.startNewChat();
          }
        }
        // If sessionId already exists (from WebSocket), DON'T reload

      } catch (e) {
        console.error('Failed to load history', e);
      }
    }

    function hideApprovalCard() {
      const card = document.getElementById('approval-card');
      if (card) card.hidden = true;
      if (approvalTimer) { clearInterval(approvalTimer); approvalTimer = null; }
    }

    async function bootstrapActiveRun() {
      if (!sessionId || snapshotInFlight) return;
      snapshotInFlight = true;
      try {
        const res = await fetch(`/api/v1/agent-runs/snapshot/?session_id=${encodeURIComponent(sessionId)}`, { credentials: 'same-origin' });
        if (!res.ok) return;
        const snapshot = await res.json();
        const run = snapshot.run;
        if (!run) {
          stopSnapshotPolling();
          return;
        }
        const sameRun = String(window.activeAgentRunId || '') === String(run.id);
        const checkpointAdvanced = !sameRun || Number(run.checkpoint_version || 0) > lastSnapshotCheckpoint;
        if (!sameRun) lastSnapshotCheckpoint = 0;
        lastSnapshotCheckpoint = Math.max(lastSnapshotCheckpoint, Number(run.checkpoint_version || 0));
        window.activeAgentRunId = run.id;
        const terminalRunStates = window.SRE_TERMINAL;
        const runIsTerminal = terminalRunStates.includes(run.status);
        if (runIsTerminal) {
          // The replay already carries that run's steps and its outcome. Adding
          // a fresh Run State row here is what made a finished chat flash
          // "starting" the moment it was opened.
          stopAllAgentStepTimers();
        }
        if (rehydratedSessionId !== sessionId) {
          rehydratedSessionId = sessionId;
          // A locally-started run already owns the live DOM. Replacing it with
          // a history snapshot here races the Agent WebSocket and erases
          // Discovering/Planning/Executing steps. Hydrate only on initial load
          // or recovery when no local run is actively rendering.
          if (!isProcessing) await loadSession(sessionId);
        }
        if (run.pending_approval) {
          showApprovalCard({ ...run.pending_approval, approval_id: run.pending_approval.id, session_id: sessionId });
        } else if (runIsTerminal) {
          hideApprovalCard();
          window.sessionStartTime = null;
          isProcessing = false;
          window.setSendButtonState('idle');
          stopSnapshotPolling();
        } else {
          isProcessing = true;
          window.setSendButtonState('running');
        }
        if (checkpointAdvanced) {
          (run.events || []).slice().reverse().forEach(evt => {
            if (evt.event_type === 'provider_fallback') handleEvent({ type: 'provider_fallback', content: 'Provider fallback recorded', ...evt.payload });
            else if (evt.event_type === 'task_verified') handleEvent({ type: 'verifying', content: 'Task verification recorded' });
          });
        }

        // History replay can build the card before the durable run snapshot
        // arrives. Re-adopt that exact card, or create one if the run began
        // before its first timeline checkpoint, then restore its real phase
        // instead of leaving the default "starting" pill in place.
        const knownWrap = window.historyRunWraps && window.historyRunWraps[run.id];
        let adopted = knownWrap && document.getElementById(knownWrap + '-body') ? knownWrap : null;
        const currentWrap = window.activeRunWrap;
        if (!adopted && currentWrap && document.contains(currentWrap)
            && String(currentWrap.dataset.sessionId || '') === String(sessionId || '')) {
          adopted = currentWrap.dataset.wrapId;
        }
        if (!adopted && !runIsTerminal) {
          startRunWrap();
          adopted = window.activeRunWrap && window.activeRunWrap.dataset.wrapId;
        }
        if (adopted) {
          window.historyRunWraps = window.historyRunWraps || {};
          window.historyRunWraps[run.id] = adopted;
          const body = document.getElementById(adopted + '-body');
          if (body) {
            window.activeRunWrap = body;
            window.liveRunSessionId = String(sessionId || '');
            if (runIsTerminal) {
              paintRunWrap(adopted, run.status, run.duration || null);
              updateRunStateCard(run.id, run.status, run.duration || null);
              window.activeRunWrap = null;
            } else {
              toggleRunWrap(adopted, true);
              paintRunWrap(adopted, run.status || 'running');
              const phase = run.current_node || run.status || 'running';
              updateRunStateCard(run.id, phase, null,
                run.created_at ? new Date(run.created_at).getTime() : null);
              isProcessing = true;
              window.setSendButtonState('running');
              window.markRunActive(sessionId, run.goal || 'Agent run',
                run.created_at ? new Date(run.created_at).getTime() : Date.now(), phase);
              startSnapshotPolling();
            }
          }
        } else if (runIsTerminal) {
          updateRunStateCard(run.id, run.status, run.duration || null);
        }
      } catch (err) {
        console.warn('Agent run snapshot unavailable', err);
      } finally {
        snapshotInFlight = false;
      }
    }

    function startSnapshotPolling() {
      if (snapshotPollTimer || !sessionId) return;
      snapshotPollTimer = setInterval(() => {
        const sid = String(sessionId || '');
        if (!sid || (!isProcessing && !(window.runsBySession || {})[sid])) {
          stopSnapshotPolling();
          return;
        }
        bootstrapActiveRun();
      }, 10000);
    }

    function stopSnapshotPolling() {
      if (snapshotPollTimer) clearInterval(snapshotPollTimer);
      snapshotPollTimer = null;
    }

    function showApprovalCard(data) {
      const approvalId = data.approval_id;
      if (!approvalId) return;
      const card = document.getElementById('approval-card');
      if (!card) return;
      card.hidden = false;
      const _tool = escapeHtml(data.tool || 'unknown');
      let _target = 'action arguments (details withheld by policy)';
      try {
        const _a = data.args;
        if (_a && typeof _a === 'object' && _a.target && String(_a.target).indexOf('redacted') === -1) {
          _target = String(_a.target);
        } else if (typeof _a === 'string' && _a && _a !== 'redacted') {
          _target = _a;
        }
      } catch (e) { /* keep default */ }
      const _risk = escapeHtml(String(data.risk || 'high'));
      const _riskColor = /high|critical/i.test(String(data.risk || '')) ? 'var(--error)' : 'var(--warning)';
      document.getElementById('approval-action').innerHTML =
        `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
           <span style="font-size:11px;color:var(--text-secondary);width:52px;flex-shrink:0;">Tool</span>
           <span style="font-family:monospace;font-size:12px;color:var(--accent);background:rgba(31,111,235,0.1);border:1px solid rgba(31,111,235,0.3);padding:3px 10px;border-radius:8px;">${_tool}</span>
         </div>
         <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
           <span style="font-size:11px;color:var(--text-secondary);width:52px;flex-shrink:0;">Target</span>
           <span style="font-size:12px;color:var(--text-primary);">${escapeHtml(_target)}</span>
         </div>
         <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
           <span style="font-size:11px;color:var(--text-secondary);width:52px;flex-shrink:0;">Risk</span>
           <span style="font-size:11px;font-weight:700;color:${_riskColor};background:rgba(127,140,160,0.1);border:1px solid var(--border-color);padding:3px 10px;border-radius:999px;">${_risk}</span>
         </div>`;
      document.getElementById('approval-reason').textContent = `${data.content || 'This action needs operator approval.'}`;
      const expires = Date.parse(data.expires_at);
      if (!Number.isFinite(expires)) { hideApprovalCard(); return; }
      Object.keys(stepTimers).forEach(stopStep);
      pendingApproval = {id: approvalId};
      isProcessing = true;
      window.setSendButtonState('running');
      document.getElementById('approval-deny').disabled = false;
      document.getElementById('approval-allow').disabled = false;
      const sendDecision = (approved, timedOut = false) => {
        if (window.sreAgentWs && window.sreAgentWs.readyState === WebSocket.OPEN) {
          window.sreAgentWs.send(JSON.stringify({type:'approval', approved, timed_out: timedOut, approval_id: approvalId, session_id: data.session_id}));
          document.getElementById('approval-deny').disabled = true;
          document.getElementById('approval-allow').disabled = true;
        }
      };
      document.getElementById('approval-deny').onclick = () => sendDecision(false);
      document.getElementById('approval-allow').onclick = () => sendDecision(true);
      if (approvalTimer) clearInterval(approvalTimer);
      approvalTimer = setInterval(() => {
        const left = Math.max(0, Math.ceil((expires - Date.now()) / 1000));
        document.getElementById('approval-countdown').textContent = `${left}s remaining`;
        if (!left) { clearInterval(approvalTimer); document.getElementById('approval-countdown').textContent = 'Waiting for server timeout decision…'; }
      }, 250);
    }


    // The welcome bubble is a front-end greeting only - it is never stored in
    // the database. Rendered at the top of every chat surface: fresh chat,
    // loaded history, and history replays.
    function welcomeBubbleHtml() {
      return `
        <div style="display:flex; align-items:flex-start; gap:12px; max-width: 92%;">
          <div style="flex-shrink:0; width:56px; height:56px; border-radius:50%; background:rgba(31, 111, 235, 0.12); border:1px solid var(--border-color); display:flex; align-items:center; justify-content:center; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
            ${window.neuroBotAvatar(42)}
          </div>
          <div class="sre-panel p-3 my-2" style="background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 14px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); flex:1;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
              <strong style="font-size: 13px;"><span class="theme-gradient">NeuroSysAI</span><i class="sre-agent-dot" data-state="idle" title="Agent idle"></i></strong>
            </div>
            <div style="font-size: 13px; color: var(--text-primary); line-height: 1.6;">
              Hello! I am ready to assist you with SRE tasks, system monitoring, incident investigation, and infrastructure automation. Please type your command or inquiry below.
            </div>
          </div>
        </div>
      `;
    }

    window.startNewChat = function () {

      window.msgPage = null;
      window.clearHistoryPreloader && window.clearHistoryPreloader();
      window.liveRunSessionId = null;
      window.expectingSession = false;
      window.continueSessionId = null;
      stopSnapshotPolling();
      stopAllAgentStepTimers();
      window.sessionStartTime = null;
      isProcessing = false;
      window.setSendButtonState('idle');
      window.activeAgentRunId = null;
      sessionId = null;
      lastSnapshotCheckpoint = 0;
      rehydratedSessionId = null;
      document.querySelectorAll('.sre-history-item').forEach(i => i.classList.remove('active'));
      activeWorkers = [];
      renderWorkerActivity();
      messagesDiv.innerHTML = welcomeBubbleHtml();
      ensureConnectionCard();

      investigations = {};
      activeInvestigationId = null;
      window.activeRunWrap = null;
      renderInvestigationTimeline();
      document.getElementById('artifacts-list').innerHTML = '<div class="sre-text-secondary" style="font-style: italic; padding: 16px;">No artifacts for this session</div>';
      window.history.pushState({}, '', window.location.pathname);

    };


    window.SRE_PAGE_SIZE = 30;

    // Scroll-up pagination. Opening a chat fetches only its newest page; older
    // pages arrive when the operator scrolls back, so a session with thousands
    // of messages neither blocks the first paint nor transfers megabytes.
    window.historyPreloader = function (label) {
      let el = document.getElementById('sre-history-preloader');
      if (!el) {
        el = document.createElement('div');
        el.id = 'sre-history-preloader';
        el.style.cssText = 'display:flex; align-items:center; justify-content:center; gap:8px; padding:10px; font-size:12px; color:var(--text-secondary);';
        messagesDiv.prepend(el);
      }
      el.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin" style="font-size:10px;"></i> ${label || 'Loading earlier messages...'}`;
      el.style.display = 'flex';
      return el;
    };
    window.clearHistoryPreloader = function () {
      const el = document.getElementById('sre-history-preloader');
      if (el) el.remove();
    };
    window.clearHistoryPreloaderText = function (text) {
      const el = document.getElementById('sre-history-preloader');
      if (!el) return;
      el.innerHTML = `<i class="fa-solid fa-check" style="font-size:10px; color:var(--success-text);"></i> ${text}`;
      setTimeout(() => { if (el && el.parentElement) el.remove(); }, 1200);
    };

    window.loadOlderMessages = async function () {
      const page = window.msgPage;
      if (!page || page.loading || !page.hasMore) return;
      if (!page.sessionId || String(page.sessionId) !== String(sessionId || '')) return;
      if (!page.oldest) { page.hasMore = false; return; }
      page.loading = true;
      window.historyPreloader();
      const anchor = messagesDiv.scrollHeight;
      try {
        const res = await fetch(
          `/api/v1/chat-sessions/${encodeURIComponent(page.sessionId)}/messages/?limit=${window.SRE_PAGE_SIZE}&before=${encodeURIComponent(page.oldest)}`
        );
        if (!res.ok) throw new Error('history page failed');
        const data = await res.json();
        const older = data.results || data || [];
        if (!older.length) { page.hasMore = false; return; }
        // New nodes land at the bottom, then move above what is already on
        // screen. Scroll offset is restored so reading position never jumps.
        const before = new Set(Array.from(messagesDiv.children));
        window.isLoadingHistory = true;
        window.replayingOlder = true;
        window.renderHistoryMessages(older, window.historyReplaySet || new Set());
        window.isLoadingHistory = false;
        window.replayingOlder = false;
        const fresh = Array.from(messagesDiv.children).filter((el) => !before.has(el) && el.id !== 'sre-history-preloader');
        const preloader = document.getElementById('sre-history-preloader');
        fresh.forEach((el) => messagesDiv.insertBefore(el, preloader || messagesDiv.firstChild));
        window.normalizeRunCards();
        page.oldest = older[0].created_at;
        page.hasMore = (typeof data.count === 'number') ? older.length < data.count : false;
        if (window.lucide) window.lucide.createIcons();
        messagesDiv.scrollTop = messagesDiv.scrollHeight - anchor;
        if (!page.hasMore) window.clearHistoryPreloaderText('Beginning of the conversation');
      } catch (err) {
        page.hasMore = false;
      } finally {
        page.loading = false;
        const el = document.getElementById('sre-history-preloader');
        if (el && !page.hasMore) el.remove();
      }
    };

    window.installHistoryScrollLoader = function () {
      const box = document.getElementById('chat-messages');
      if (!box || box.dataset.scrollPaged === '1') return;
      box.dataset.scrollPaged = '1';
      box.addEventListener('scroll', () => {
        if (box.scrollTop > 160) return;
        const page = window.msgPage;
        if (!page || !page.hasMore || page.loading) return;
        window.loadOlderMessages();
      }, { passive: true });
    };

    // Renders one page of recorded messages. Shared by the first page (built
    // after the welcome bubble) and by the scroll-up loader (prepended above
    // what is already on screen), so a long chat is never fetched in one go.
    window.renderHistoryMessages = function (list, replayMessages) {
      // Scoped to the synchronous render only. A live event arriving in an
      // async gap must take the live path; isLoadingHistory stays true across
      // the whole load and cannot tell the two apart. try/finally because a
      // throw here used to wedge the flag on and strand every later step on
      // the bare timeline.
      window.replayActive = true;
      try {
      let sessionStartTimestamp = null;
      let lastEventTimestamp = null;
      const messages = (list || []).slice().sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      // Replayed runs carry no server duration, so the span between their first
      // and last recorded event is measured here and painted into the card.
      const spans = window.historyRunSpans || (window.historyRunSpans = {});
      messages.forEach(msg => {
        if (msg.id && replayMessages.has(msg.id)) return;
        if (msg.id) replayMessages.add(msg.id);
        // A message that owns no run must not inherit the previous one. The
        // active card was still pointing at the earlier run, so the answer for a
        // turn that never ran dragged that run's card down to sit beside it.
        window.activeRunWrap = null;
        const _evts = (msg.metadata && Array.isArray(msg.metadata.events)) ? msg.metadata.events : [];
        // Older messages were recorded before run grouping existed and carry no
        // run_id. They still belong to a card: opening one here is what stops
        // their steps from spilling onto the bare chat timeline. A message with
        // no renderable trace gets no card at all - an empty "archived run" with
        // nothing to open is worse than no card, especially for a turn that
        // never ran.
        // Only event types that actually draw a row count as a trace. Opening a
        // card for a message whose events produce no row and then deleting it
        // again is what made cards vanish on reload.
        const _STEP_TYPES = ['exploring', 'discovering_tools', 'planning', 'thinking',
          'tool_start', 'tool_end', 'investigation_started', 'task_plan', 'task_updated',
          'resolution_plan', 'hypothesis', 'findings', 'parallel_start', 'parallel_complete',
          'completed', 'error', 'failed', 'cancelled', 'blocked', 'denied',
          'denied_timeout', 'security_blocked'];
        // A card is opened only for a turn that recorded something. An empty
        // "archived run" card between every pair of turns is noise, and a run
        // with no steps has nothing to open anyway.
        const _hasTrace = _evts.some((e) => e && _STEP_TYPES.includes(String(e.type)));
        if (_evts.some((e) => e && e.run_id) || !_hasTrace) {
          window.historyReplayWrap = null;
        } else {
          const _own = ensureHistoryWrap('msg-' + (msg.id || 'orphan'));
          window.historyReplayWrap = _own;
          // The card this turn owns has to be the active one, not just the
          // replay fallback: steps and the answer bubble are both placed
          // through it, and only one of them was looking at it before. That is
          // why stored runs (which carry no run_id) were drawing steps into
          // someone else's card while their own card stayed empty and detached.
          window.activeRunWrap = _own;
        }
        if (msg.sender === 'user') {
          addUserMessage(msg.message, msg.created_at, msg.id);
        } else if (msg.sender === 'ai') {
          if (msg.metadata && msg.metadata.events && Array.isArray(msg.metadata.events)) {

            // Set start timestamp dari event pertama
            if (!sessionStartTimestamp && msg.metadata.events.length > 0) {
              sessionStartTimestamp = msg.metadata.events[0].timestamp;
              if (!lastEventTimestamp) {
                lastEventTimestamp = sessionStartTimestamp;
              }
            }

            msg.metadata.events.forEach(evt => {
              // Group replayed steps into the same collapsible run
              // container the live view uses (collapsed by default).
              if (evt.run_id) {
                ensureHistoryWrap(evt.run_id);
                if (['completed', 'error', 'failed', 'cancelled', 'blocked', 'denied', 'denied_timeout', 'security_blocked'].includes(evt.type)) {
                  const wid = window.historyRunWraps[evt.run_id];
                  if (wid) paintRunWrap(wid, evt.type === 'completed' ? 'completed' : (evt.status || evt.type), evt.duration);
                }
              } else if (['completed', 'error', 'failed', 'cancelled', 'blocked', 'denied', 'denied_timeout', 'security_blocked'].includes(evt.type)
                           && window.historyReplayWrap && document.contains(window.historyReplayWrap)) {
                  // Stored runs from before grouping existed carry no run_id, so
                  // their card was never painted and stayed on the neutral
                  // placeholder while the turn below it was plainly blocked.
                  paintRunWrap(window.historyReplayWrap.dataset.wrapId,
                    evt.type === 'completed' ? 'completed' : (evt.status || evt.type), evt.duration);
              }
              if (evt.run_id) window.historyReplayRunId = evt.run_id;
              if (evt.event_id && window.agentSeenEvents.has(evt.event_id)) return;
              if (evt.event_id) window.agentSeenEvents.add(evt.event_id);
              if (evt.type === 'completed' && evt.run_id) {
                if (window.agentCompletedRuns.has(evt.run_id)) return;
                window.agentCompletedRuns.add(evt.run_id);
              }
              // === HITUNG DURASI DARI EVENT SEBELUMNYA ===
              if (evt.run_id && evt.timestamp) {
                const _sp = spans[evt.run_id] || (spans[evt.run_id] = { min: evt.timestamp, max: evt.timestamp });
                if (evt.timestamp < _sp.min) _sp.min = evt.timestamp;
                if (evt.timestamp > _sp.max) _sp.max = evt.timestamp;
              }
              const diff = lastEventTimestamp ? (evt.timestamp - lastEventTimestamp) : 0;
              const time = '✓ ' + (diff >= 0 ? diff : 0).toFixed(1) + 's';

              // Update lastEventTimestamp untuk event berikutnya
              lastEventTimestamp = evt.timestamp;

              switch (evt.type) {
                case 'lifecycle':
                case 'resuming':
                case 'provider_fallback':
                case 'verifying':
                  updateRunStateCard(evt.run_id || `history-${msg.id || 'current'}`, evt.status || evt.content || evt.type);
                  break;
                case 'session_id':
                  sessionStartTimestamp = evt.timestamp;
                  break;

                case 'session_title':
                  break;

                case 'exploring':
                  addAgentStep('Exploring', evt.content, 'var(--accent)', 'search', null, false, time);
                  break;

                case 'task_plan':
                  (function () {
                    const planData = evt.plan;
                    if (planData && planData.investigation_id) {
                      if (!investigations[planData.investigation_id]) {
                        investigations[planData.investigation_id] = {
                          id: planData.investigation_id,
                          title: planData.title || 'Investigation',
                          status: 'active',
                          createdAt: evt.timestamp ? new Date(evt.timestamp).getTime() : Date.now(),
                          plan: [],
                          findings: []
                        };
                      }
                      investigations[planData.investigation_id].plan = Array.isArray(planData) ? planData : (planData.tasks || []);
                      renderInvestigationTimeline();
                    }
                  })();
                  addAgentStep('Task Plan', 'Plan updated', '#dac654', 'list-todo', null, false, time);
                  break;

                case 'discovering_tools':
                  let toolsHtml = evt.content;
                  if (evt.tools && evt.tools.length) {
                    toolsHtml += '<div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px;">';
                    evt.tools.forEach(t => {
                      toolsHtml += `<span style="font-size: 11px; background: #21262d; padding: 2px 8px; border-radius: 4px; color: #79c0ff;">${t}</span>`;
                    });
                    toolsHtml += '</div>';
                  }
                  addAgentStep('Discovering Tools', toolsHtml, 'var(--purple)', 'wrench', null, false, time);
                  break;

                case 'planning':
                  addAgentStep('Planning', evt.content, '#dac654', 'list-todo', null, false, time);
                  break;

                case 'thinking':
                  addAgentStep('Thinking', String(evt.content || '').slice(0, 600), '#ff69b4', 'brain', null, false, time);
                  break;

                case 'tool_start':
                  addAgentStep('Executing', window.sreToolChip(escapeHtml(evt.tool || 'tool'), evt.command ? escapeHtml(evt.command) : ''), 'var(--warning)', 'zap', evt.step_id, false, time);
                  break;

                case 'tool_end':
                  const resultTxt = (evt.result || evt.content || '').trim();
                  addAgentStep('Result', window.sreResultHtml(resultTxt), 'var(--success)', 'check-circle', evt.step_id, true, time);
                  break;

                case 'message_chunk':
                  break;

                case 'direct_chat':
                  // Plain conversation turn: the answer is already
                  // rendered as the message, nothing to rebuild here.
                  break;

                case 'worker_activity':
                  if (evt.workers) {
                    updateInvestigationWorkerActivity(
                      evt.workers,
                      evt.investigation_id || (evt.metadata && evt.metadata.investigation_id)
                        || evt.case_id || (evt.metadata && evt.metadata.case_id)
                    );
                  }
                  break;

                case 'hypothesis':
                  addAgentStep('Hypothesis', evt.content, '#a371f7', 'lightbulb', null, false, time);
                  break;

                case 'parallel_start':
                  addAgentStep('Parallel', `⚡ ${evt.content || 'Executing tasks...'}`, '#00d4ff', 'layers', null, false, time);
                  break;

                case 'parallel_complete':
                  addAgentStep('Parallel Done', `✅ ${evt.content || 'All tasks completed.'}`, 'var(--success)', 'check-circle', null, false, time);
                  break;

                case 'findings':
                  (function () {
                    const f = evt.findings;
                    const invId = (f && f.investigation_id) || null;
                    if (invId) {
                      if (!investigations[invId]) {
                        investigations[invId] = { id: invId, title: 'Investigation', status: 'active', createdAt: Date.now(), plan: [], findings: [] };
                      }
                      investigations[invId].findings = Array.isArray(f) ? f : (f.findings || []);
                      renderInvestigationTimeline();
                    }
                  })();
                  addAgentStep('Findings', 'New findings recorded', 'var(--success)', 'check-square', null, false, time);
                  break;

                case 'completed':
                  updateRunStateCard(evt.run_id || `history-${msg.id || 'current'}`, 'completed', evt.duration);
                  const endTime = new Date(evt.timestamp * 1000);
                  const startTime = new Date(endTime.getTime() - ((evt.duration || 0) * 1000));
                  const dur = (evt.duration || 0).toFixed(1);

                  const auditHtml = window.buildAuditHtml({
                    summary: evt.content || '',
                    started: startTime.toLocaleTimeString(),
                    finished: endTime.toLocaleTimeString(),
                    total: dur + ' seconds',
                  });
                  // Held until the reply exists so the summary can sit under it.
                  window.pendingAuditHtml = auditHtml;
        window.normalizeRunCards();
                  break;

                case 'error':
                case 'failed':
                case 'cancelled':
                case 'blocked':
                case 'denied':
                case 'denied_timeout':
                case 'security_blocked': {
                  const _blocked = String(evt.type) === 'security_blocked';
                  updateRunStateCard(evt.run_id || `history-${msg.id || 'current'}`, evt.type);
                  try { finalizeRunWrap(String(evt.type)); } catch (err) { /* best-effort */ }
                  try {
                    const _w = window.activeRunWrap
                      || (window.lastRunBody && document.contains(window.lastRunBody) ? window.lastRunBody : null);
                    if (_w && _w.dataset && _w.dataset.wrapId) {
                      window.paintRunWrap(_w.dataset.wrapId, String(evt.type), evt.duration || null);
                    }
                  } catch (err) { /* best-effort */ }
                  try {
                    const _cid = String(evt.case_id || evt.investigation_id || '');
                    const _term = String(evt.type || '').toLowerCase();
                    if (_cid && investigations[_cid]) {
                      const _inv = investigations[_cid];
                      _inv.status = _term === 'error' ? 'failed' : _term;
                      (_inv.plan || []).forEach((p) => {
                        const _p = String(p.status || '').toLowerCase();
                        if (['pending', 'running', 'in_progress', 'executing'].includes(_p)) {
                          p.status = _term === 'security_blocked' ? 'failed'
                            : _term === 'error' ? 'failed' : _term;
                        }
                      });
                      renderInvestigationTimeline();
                    }
                  } catch (err) { /* best-effort */ }
                  try { finalizeRunWrap(String(evt.type)); } catch (err) { /* best-effort */ }
                  try {
                    const _w = window.activeRunWrap
                      || (window.lastRunBody && document.contains(window.lastRunBody) ? window.lastRunBody : null);
                    if (_w && _w.dataset && _w.dataset.wrapId) window.paintRunWrap(_w.dataset.wrapId, String(evt.type), evt.duration || null);
                  } catch (err) { /* best-effort */ }
                  // The saved plan events left the case with running/pending
                  // tasks; the final event decides how every still-open row
                  // ended. Without this the stopped/denied run kept a
                  // task plan that never stopped.
                  try {
                    const _cid = String(evt.case_id || evt.investigation_id || '');
                    const _term = String(evt.type || '').toLowerCase();
                    if (_cid && investigations[_cid]) {
                      const _inv = investigations[_cid];
                      _inv.status = _term === 'error' ? 'failed' : _term;
                      (_inv.plan || []).forEach((p) => {
                        const _p = String(p.status || '').toLowerCase();
                        if (['pending', 'running', 'in_progress', 'executing'].includes(_p)) {
                          p.status = _term === 'security_blocked' ? 'blocked'
                            : _term === 'error' ? 'failed' : _term;
                        }
                      });
                      renderInvestigationTimeline();
                    }
                  } catch (err) { /* best-effort */ }
                  addAgentStep(
                    _blocked ? 'Blocked by Security Policy'
                      : String(evt.type) === 'cancelled' ? 'Cancelled' : 'Error',
                    escapeHtml(evt.content || String(evt.type)),
                    'var(--error)', _blocked ? 'shield-alert' : 'x-circle', null, true,
                  );
                  // A blocked prompt is not something to retry, so it gets no
                  // Retry/Cancel bar. Every other stop keeps the same
                  // affordances the live run offered.
                  if (!_blocked) {
                    messagesDiv.appendChild(window.renderRunFailureActions(sessionId, evt.case_id));
                  }
      window.scrollToNewTurn();
                  break;
                }

                case 'investigation_started': {
                  // Live runs print their investigation id in the card header;
                  // a replayed run must show it too.
                  const _replayWrap = window.activeRunWrap;
                  if (_replayWrap) {
                    const slot = document.getElementById(_replayWrap.dataset.wrapId + '-case');
                    if (slot && !slot.textContent.trim()) {
                      const _cid = evt.case_id || evt.investigation_id || '';
                      slot.textContent = _cid;
                      if (_cid) slot.style.display = '';
                    }
                  }
                  if (evt.investigation_id) {
                    if (!investigations[evt.investigation_id]) {
                      investigations[evt.investigation_id] = {
                        id: evt.investigation_id,
                        title: evt.content || 'Investigation',
                        status: 'active',
                        createdAt: evt.timestamp ? new Date(evt.timestamp).getTime() : Date.now(),
                        plan: [],
                        findings: []
                      };
                    }
                    activeInvestigationId = evt.investigation_id;
                    renderInvestigationTimeline();
                  }
                  addAgentStep('Investigation Started', evt.content || 'Starting new investigation...', 'var(--accent)', 'search', null, false, time);
                    break;
                  }

                case 'task_updated':
                  const taskData = evt.task;
                  if (taskData && taskData.new_status === 'completed') {
                    addAgentStep('Task Completed', window.sreMarkdownHtml(taskData.task), 'var(--success)', 'check-circle', null, false, time);
                  }
                  break;

                case 'resolution_plan': {
                  const steps = evt.steps || [];
                  const stepsHtml = Array.isArray(steps) && steps.length > 0
                    ? '<ol style="margin: 6px 0 0 18px; padding: 0;">' + steps.map(s => `<li>${escapeHtml(String(s))}</li>`).join('') + '</ol>'
                    : escapeHtml(evt.content || '');
                  addAgentStep('Resolution Plan', stepsHtml, '#39c5cf', 'list-checks', null, false, time);
                  break;
                }

                case 'status':
                  addSystemMsg(evt.content, 'check');
                  break;

                default:
                  console.log('Unknown event type in history:', evt.type);
              }
            });
          }
          if (!(msg.message || '').trim() && window.pendingAuditHtml) {
            messagesDiv.insertAdjacentHTML('beforeend', window.pendingAuditHtml);
            window.pendingAuditHtml = '';
          }
          // An empty card is never deleted: deleting it silently removed real
          // runs, and a card that truthfully says it recorded nothing is far
          // more useful than a missing one.
          if (window.historyReplayWrap && document.contains(window.historyReplayWrap)
              && window.historyReplayWrap.childElementCount === 0
              && !_hasTrace) {
            const _note = document.createElement('div');
            _note.className = 'sre-run-empty-note';
            _note.style.cssText = 'padding: 10px 12px; font-size: 12px; color: var(--text-secondary); font-style: italic;';
            _note.textContent = 'This turn recorded no agent steps.';
            window.historyReplayWrap.appendChild(_note);
          }
          // The owned chain has to be resolved here: activeRunWrap is cleared
          // below on purpose, so reading it afterwards always missed.
          let _ownedWrap = null;
          if (window.historyReplayWrap && document.contains(window.historyReplayWrap)) {
            _ownedWrap = window.historyReplayWrap.parentElement;
          } else if (window.historyReplayRunId && (window.historyRunWraps || {})[window.historyReplayRunId]) {
            const _body = document.getElementById(window.historyRunWraps[window.historyReplayRunId] + '-body');
            if (_body && document.contains(_body)) _ownedWrap = _body.parentElement;
          }
          window.historyReplayWrap = null;
          window.historyReplayRunId = null;
          window.activeRunWrap = null;
          if (msg.message && msg.message.trim() !== "") {
            const _wasBlocked = _evts.some((e) => e && e.type === 'security_blocked');
            if (_wasBlocked) {
              try {
                const users = messagesDiv.querySelectorAll('.sre-msg-user');
                if (users.length) window.quarantineUserBubble(users[users.length - 1]);
              } catch (err) { /* best-effort */ }
            }
            const _bubble = addAIMessage(msg.message, msg.created_at, msg.id);
            if (_wasBlocked) window.paintBlockedBubble(_bubble);
            if (_bubble) window.syncBubblePill(_bubble);
            // The chain of thought seats inside the bubble's own slot.
            if (_bubble && _ownedWrap && _ownedWrap.id && _ownedWrap.id.indexOf('runwrap-') === 0) {
              window.seatChain(_bubble, _ownedWrap);
            }
            // Reading order for a finished turn: run card, answer, and the
            // completion summary tucked under that answer.
            if (window.pendingAuditHtml) {
              const _audit = window.pendingAuditHtml;
              window.pendingAuditHtml = '';
              if (!window.attachRunAudit(_bubble, _audit)) {
                messagesDiv.insertAdjacentHTML('beforeend', _audit);
              }
            }
          }
        }
      });
      // Paint the measured totals now that every page is in the DOM.
      Object.keys(spans).forEach((runId) => {
        const wrapId = (window.historyRunWraps || {})[runId];
        if (!wrapId) return;
        const slot = document.getElementById(wrapId + '-dur');
        if (!slot || slot.textContent.trim()) return;
        const total = (spans[runId].max - spans[runId].min) / 1000;
        if (!isFinite(total) || total < 0) return;
        slot.textContent = `\u2713 ${total.toFixed(1)}s`;
      });
      } finally {
        window.replayActive = false;
      }
    };

    // Beam glow is cosmetic: never let it break session loading if the beam
    // block hasn't executed (stale cache / partial load).
    function safeBeamRunning(running) {
      try {
        if (typeof setBeamRunning === 'function') setBeamRunning(running);
        else if (window.setBeamRunning) window.setBeamRunning(running);
      } catch (e) { /* cosmetic only */ }
    }

    async function loadSession(id) {

      const previousSessionId = sessionId;
      // Switching chats never cancels: the run keeps executing in the
      // background and the sidebar tracks it. Only the local render state is
      // dropped below; the guards refuse foreign content regardless.
      if ((previousSessionId !== id) && (typeof isProcessing !== 'undefined') && isProcessing) {
        addSystemMsg('Switched chats. The run in the previous chat keeps going - watch it in History.', 'arrow-right');
        isProcessing = false;
        window.setSendButtonState && window.setSendButtonState('idle');
        window.activeRunWrap = null;
        safeBeamRunning(false);
      }
      // Claim this chat's live events up front: a run that is still going
      // must stream here the moment we return, not only after a reload.
      window.liveRunSessionId = String(id || '');
      window.expectingSession = false;
      window.continueSessionId = null;
      window.continueCaseId = null;
      window.pendingResumeCaseId = '';
      window.activeRunWrap = null;
      currentAIMsg = null;
      window.renderActiveRuns && window.renderActiveRuns();
      stopAllAgentStepTimers();
      window.sessionStartTime = null;
      isProcessing = false;
      window.refreshSendButton();
      if (previousSessionId !== id) window.activeAgentRunId = null;
      sessionId = id;
      rehydratedSessionId = id;
      window.history.pushState({}, '', window.location.pathname + '?session=' + id);
      activeWorkers = [];
      renderWorkerActivity();

      window.showPanelSkeleton(messagesDiv, 6);
      try {
        // Both payloads are independent; fetching them in parallel removes one
        // full round trip from every chat open.
        const [res, invRes] = await Promise.all([
          fetch(`/api/v1/chat-sessions/${id}/messages/?limit=${window.SRE_PAGE_SIZE}&order=desc`),
          fetch(`/api/v1/chat-sessions/${id}/investigations/`),
        ]);
        const data = await res.json();
        messagesDiv.innerHTML = welcomeBubbleHtml();
        window.agentSeenEvents = new Set();
        window.agentCompletedRuns = new Set();
        const replayMessages = new Set();
        investigations = {};
        activeInvestigationId = null;

        if (invRes.ok) {
          const invData = await invRes.json();
          invData.forEach(inv => {
            investigations[inv.id] = {
              id: inv.id,
              title: inv.title,
              status: inv.status,
              createdAt: inv.created_at || inv.createdAt || 0,
              plan: inv.tasks || [],
              findings: inv.findings ? inv.findings.map(f => f.content) : []
            };
            if (inv.status === 'active' && !activeInvestigationId) {
              activeInvestigationId = inv.id;
            }
          });
        }

        window.isLoadingHistory = true;
        window.historyRunWraps = {};
        window.historyRunSpans = {};
        window.historyRunOwners = {};
        window.activeRunWrap = null;
        const messages = (data.results || data || []);
        window.installHistoryScrollLoader();
        window.msgPage = {
          sessionId: id,
          oldest: messages.length ? messages[0].created_at : null,
          total: (typeof data.count === 'number') ? data.count : messages.length,
          hasMore: (typeof data.count === 'number') ? messages.length < data.count : false,
          loading: false
        };
        window.historyReplaySet = replayMessages;

        window.renderHistoryMessages(messages, replayMessages);
        // Replay backfill: worker_activity events that arrived before their
        // investigation entry existed (or in another page) left inv.workers
        // empty, so replay showed plan/findings but no worker flow while live
        // did. Re-apply every snapshot in order now that all investigations
        // are known; the merge accumulates the full workflow steps.
        try {
          const _waByCase = {};
          (messages || []).forEach(msg => {
            const _evts = (msg.metadata && Array.isArray(msg.metadata.events)) ? msg.metadata.events : [];
            _evts.forEach(evt => {
              if (evt && evt.type === 'worker_activity' && Array.isArray(evt.workers) && evt.workers.length) {
                const _cid = evt.case_id || evt.investigation_id || '';
                if (!_cid) return;
                (_waByCase[_cid] = _waByCase[_cid] || []).push(evt.workers);
              }
            });
          });
          Object.keys(_waByCase).forEach(_cid => {
            const _inv = investigations[_cid];
            if (_inv && Array.isArray(_inv.workers) && _inv.workers.length) return;
            _waByCase[_cid].forEach(_w => updateInvestigationWorkerActivity(_w, _cid));
          });
        } catch (_e) { /* best-effort */ }
        window.historyReplayWrap = null;
        window.isLoadingHistory = false;
        window.normalizeRunCards();
        window.activeRunWrap = null;
        window.agentAutoScroll = false;
        // Opening a chat lands on its newest message; that is a deliberate jump,
        // not an interruption of reading.
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        window.hideJumpToLatest();
        ensureConnectionCard();
        lucide.createIcons();
        window.refreshTurnRail && window.refreshTurnRail();
        loadArtifacts();
        renderInvestigationTimeline();
        if (ws && ws.readyState === WebSocket.OPEN) {
          // `subscribe` is session-scoped; switching chats must leave the old
          // channel group and join the newly opened chat before snapshotting.
          // The snapshot itself must not block the already-painted history.
          ws.send(JSON.stringify({type: 'subscribe', session_id: sessionId}));
          bootstrapActiveRun().catch(() => {});
        }

      } catch (e) {
        console.error('Failed to load session', e);
      }

    }

    // --- Explorer Logic ---
    // Set by the inline bootstrap script in chat3.html (Django injects the value there).
    window.WORKSPACE_PROJECT_ROOT = window.WORKSPACE_PROJECT_ROOT || "";
    window.workspaceFollow = true;

    function workspaceInput() {
      return document.getElementById('workspace-path-input');
    }

    function effectiveWorkspacePath() {
      const input = workspaceInput();
      if (window.workspaceFollow && window.currentTerminalCwd) return window.currentTerminalCwd;
      if (input && input.value.trim()) return input.value.trim();
      return window.currentTerminalCwd || window.WORKSPACE_PROJECT_ROOT || '/';
    }

    function paintWorkspacePath() {
      const input = workspaceInput();
      const followBtn = document.getElementById('workspace-follow-btn');
      const current = effectiveWorkspacePath();
      if (input && document.activeElement !== input) input.value = current;
      if (followBtn) {
        followBtn.setAttribute('aria-pressed', window.workspaceFollow ? 'true' : 'false');
        followBtn.style.color = window.workspaceFollow ? '#fff' : 'var(--text-secondary)';
        followBtn.style.background = window.workspaceFollow ? 'var(--accent)' : 'transparent';
        followBtn.style.borderColor = window.workspaceFollow ? 'var(--accent)' : 'var(--border-color)';
      }
    }

    window.setWorkspacePath = function (path) {
      window.workspaceFollow = false;
      const input = workspaceInput();
      if (input) input.value = path;
      try { localStorage.setItem('sre_workspace_path', path); } catch (e) {}
      paintWorkspacePath();
      loadExplorer();
    };

    window.toggleWorkspaceFollow = function () {
      window.workspaceFollow = !window.workspaceFollow;
      const input = workspaceInput();
      if (window.workspaceFollow && window.currentTerminalCwd && input) {
        input.value = window.currentTerminalCwd;
      }
      try { localStorage.setItem('sre_workspace_follow', window.workspaceFollow ? '1' : '0'); } catch (e) {}
      paintWorkspacePath();
      loadExplorer();
    };

    window.refreshExplorer = function () { loadExplorer(); };

    (function () {
      try {
        const storedFollow = localStorage.getItem('sre_workspace_follow');
        window.workspaceFollow = storedFollow === null ? true : storedFollow === '1';
        const storedPath = localStorage.getItem('sre_workspace_path');
        const input = workspaceInput();
        if (input && storedPath && !window.workspaceFollow) input.value = storedPath;
      } catch (e) {}
      paintWorkspacePath();
    })();

    async function loadExplorer() {
      try {
        const targetPath = effectiveWorkspacePath();
        if (!targetPath) return;

        const input = workspaceInput();
        if (input && window.workspaceFollow && window.currentTerminalCwd) input.value = window.currentTerminalCwd;

        const cwdParam = `?path=${encodeURIComponent(targetPath)}`;
        const res = await fetch(`/api/v1/workspace/tree/${cwdParam}`);
        const data = await res.json();
        const container = document.getElementById('explorer-tree');
        container.innerHTML = '';
        const rows = Array.isArray(data) ? data : (Array.isArray(data.children) ? data.children : []);
        if (rows.length === 0) {
          container.innerHTML = `<div class="sre-text-secondary" style="padding: 12px; font-style: italic;">No entries found in this workspace.</div>`;
        } else {
          renderTree(rows, container, 0);
        }
      } catch (e) {
        document.getElementById('explorer-tree').innerHTML = `<div class="sre-text-secondary" style="padding: 12px;">Error loading workspace.</div>`;
      }
    }

    function renderTree(nodes, parentEl, depth) {
      depth = depth || 0;
      nodes.forEach(node => {
        let el = document.createElement('div');
        el.style.paddingLeft = (depth * 14) + 'px';

        if (node.type === 'directory') {
          let wrap = document.createElement('div');
          const row = document.createElement('div');
          row.style.cssText = 'display:flex; align-items:center; gap:6px; padding:4px 8px; border-radius:8px; cursor:pointer; user-select:none; overflow:hidden; white-space:nowrap; text-overflow:ellipsis; transition:background .12s;';
          row.onmouseover = () => row.style.background = 'rgba(127,140,160,.08)';
          row.onmouseout = () => row.style.background = 'transparent';
          const arrow = document.createElement('i');
          arrow.className = 'fa-solid fa-chevron-right';
          arrow.style.cssText = 'font-size:10px;color:var(--text-secondary);width:12px;text-align:center;transition:transform .15s;';
          const labelText = document.createElement('span');
          labelText.innerHTML = `<i class="fa-solid fa-folder" style="font-size:12px;color:var(--accent);margin-right:6px;"></i>${escapeHtml(node.name)}`;
          labelText.style.cssText = 'font-size:13px;font-weight:600;color:var(--text-primary);';
          row.appendChild(arrow);
          row.appendChild(labelText);
          wrap.appendChild(row);

          let childrenWrap = document.createElement('div');
          childrenWrap.style.cssText = 'display:none; border-left:1px dotted var(--border-color); margin-left:12px;';
          childrenWrap.dataset.loaded = node.children && node.children.length ? 'true' : '';
          if (node.children && node.children.length > 0) {
            renderTree(node.children, childrenWrap, depth + 1);
          }
          wrap.appendChild(childrenWrap);

          row.onclick = async (e) => {
            e.stopPropagation();
            childrenWrap.style.display = childrenWrap.style.display === 'none' ? 'block' : 'none';
            arrow.style.transform = childrenWrap.style.display === 'none' ? 'rotate(0deg)' : 'rotate(90deg)';
            if (childrenWrap.style.display !== 'none' && !childrenWrap.dataset.loaded && node.has_children) {
              childrenWrap.dataset.loaded = 'true';
              let loading = document.createElement('div');
              loading.style.cssText = 'padding:4px 8px;color:var(--text-secondary);font-style:italic;';
              loading.innerText = 'Loading...';
              childrenWrap.appendChild(loading);
              try {
                const subRes = await fetch(`/api/v1/workspace/tree/?path=${encodeURIComponent(node.path)}`);
                const subData = await subRes.json();
                childrenWrap.removeChild(loading);
                const rows = Array.isArray(subData) ? subData : (Array.isArray(subData.children) ? subData.children : []);
                let childContainer = document.createElement('div');
                renderTree(rows, childContainer, depth + 1);
                childrenWrap.appendChild(childContainer);
              } catch (err) {
                loading.innerText = 'Error loading';
              }
            }
          };
          el.appendChild(wrap);
        } else {
          const fileDiv = document.createElement('div');
          fileDiv.style.cssText = 'display:flex; align-items:center; gap:6px; padding:4px 8px; border-radius:8px; cursor:pointer; overflow:hidden; white-space:nowrap; text-overflow:ellipsis; transition:background .12s;';
          fileDiv.onmouseover = () => fileDiv.style.background = 'rgba(127,140,160,.08)';
          fileDiv.onmouseout = () => fileDiv.style.background = 'transparent';
          fileDiv.innerHTML = `<i class="fa-solid fa-file-lines" style="font-size:12px;color:var(--text-secondary);width:14px;text-align:center;"></i><span style="font-size:13px;color:var(--text-primary);">${escapeHtml(node.name)}</span>`;
          fileDiv.onclick = (e) => {
            e.stopPropagation();
            window.selectedFile = node.path;
            try { localStorage.setItem('sre_selected_file', node.path); } catch (err) {}
            updateContextAttachments();
          };
          el.appendChild(fileDiv);
        }
        parentEl.appendChild(el);
      });
    }

    // --- Artifacts ---
    window.artifactTimeLabel = function (iso) {
      if (!iso) return '';
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return '';
      return d.toLocaleString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
    };

    // GitHub-style diff: coloured +/- lines, hunk headers kept readable.
    window.renderArtifactDiff = function (diffText) {
      const lines = String(diffText || '').split('\n');
      const html = lines.map((line) => {
        if (!line) return '';
        let bg = 'transparent', fg = 'var(--text-secondary)', prefix = ' ';
        if (line.startsWith('+++') || line.startsWith('---')) {
          bg = 'rgba(127,140,160,0.14)'; fg = 'var(--text-primary)'; prefix = '';
        } else if (line.startsWith('@@')) {
          bg = 'rgba(88,166,255,0.10)'; fg = '#79c0ff'; prefix = '';
        } else if (line.startsWith('+')) {
          bg = 'rgba(63,185,80,0.14)'; fg = '#7ee787'; prefix = '';
        } else if (line.startsWith('-')) {
          bg = 'rgba(248,81,73,0.14)'; fg = '#ffa198'; prefix = '';
        }
        const pad = prefix === '' ? '' : 'padding-left:2px;';
        return `<div style="background:${bg}; color:${fg}; ${pad} padding:1px 10px; white-space:pre-wrap; word-break:break-word;">${escapeHtml(line)}</div>`;
      }).join('');
      return `<div style="border:1px solid var(--border-color); border-radius:8px; overflow:hidden; background:var(--bg-panel); font-family:'JetBrains Mono','Fira Code',monospace; font-size:11px; line-height:1.55;">${html}</div>`;
    };

    window.isMarkdownArtifact = function (art) {
      const name = String(art.file_path || '').toLowerCase();
      if (name.endsWith('.md') || name.endsWith('.markdown')) return true;
      return ['report', 'plan', 'finding', 'subagent_execution', 'agent_execution'].includes(String(art.action_type || ''));
    };

    // --- file viewers -------------------------------------------------------
    // Artifacts are files, so they are shown as files: a code editor surface
    // with line numbers for code, a key/value view for JSON, rendered markdown
    // for .md, and the diff when the change is known.
    window.sreArtifactLang = function (filePath) {
      const name = String(filePath || '').toLowerCase();
      const ext = (name.split('.').pop() || '');
      if (['py', 'pyi'].includes(ext)) return 'python';
      if (['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx'].includes(ext)) return 'js';
      if (['css', 'scss', 'less'].includes(ext)) return 'css';
      if (['html', 'htm', 'xml', 'svg', 'vue'].includes(ext)) return 'html';
      if (['json', 'jsonc'].includes(ext)) return 'json';
      if (['yml', 'yaml'].includes(ext)) return 'yaml';
      if (['sh', 'bash', 'zsh', 'conf', 'cfg', 'ini', 'toml', 'service', 'env'].includes(ext)) return 'shell';
      if (['md', 'markdown'].includes(ext)) return 'markdown';
      return 'text';
    };

    const SRE_KEYWORDS = {
      python: ['def', 'class', 'return', 'import', 'from', 'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'async', 'await', 'yield', 'None', 'True', 'False', 'pass', 'raise', 'lambda', 'in', 'not', 'and', 'or', 'self'],
      js: ['const', 'let', 'var', 'function', 'return', 'import', 'export', 'from', 'if', 'else', 'for', 'while', 'try', 'catch', 'finally', 'class', 'extends', 'new', 'async', 'await', 'typeof', 'instanceof', 'null', 'undefined', 'true', 'false', 'this'],
      shell: ['if', 'then', 'else', 'fi', 'for', 'do', 'done', 'while', 'case', 'esac', 'function', 'return', 'export', 'local', 'sudo', 'echo', 'set'],
      yaml: ['true', 'false', 'null', 'yes', 'no'],
      css: ['important', 'inherit', 'initial', 'none'],
    };

    // One pass, one regex: the text is escaped first and tokenized afterwards,
    // so highlighting can never inject markup or re-colour our own tags.
    window.sreHighlight = function (text, lang) {
      const escaped = escapeHtml(String(text == null ? '' : text));
      const keywords = (SRE_KEYWORDS[lang] || []).join('|');
      const hashComment = (lang === 'python' || lang === 'shell' || lang === 'yaml');
      const commentPart = lang === 'css' || lang === 'html'
        ? '(\\/\\*[\\s\\S]*?\\*\\/)'
        : '(\\/\\/[^\\n]*' + (hashComment ? '|#[^\\n]*' : '') + '|\\/\\*[\\s\\S]*?\\*\\/)';
      const pattern = new RegExp(
        commentPart +
        '|(&quot;[^&\\n]*?&quot;|&#39;[^&\\n]*?&#39;|`[^`]*?`|"[^"\\n]*?"|\'[^\'\\n]*?\')' +
        '|\\b(\\d+(?:\\.\\d+)?)\\b' +
        (keywords ? '|\\b(' + keywords + ')\\b' : ''),
        'g'
      );
      return escaped.replace(pattern, (match, comment, str, num, kw) => {
        if (comment) return '<span style="color:#8b949e;font-style:italic;">' + comment + '</span>';
        if (str) return '<span style="color:#a5d6ff;">' + str + '</span>';
        if (num) return '<span style="color:#79c0ff;">' + num + '</span>';
        if (kw) return '<span style="color:#ff7b72;font-weight:600;">' + kw + '</span>';
        return match;
      });
    };

    // A small editor surface: line-number gutter, monospace, and the theme's
    // own colours so it reads correctly in light and dark.
    window.sreCodeView = function (text, lang) {
      const lines = String(text == null ? '' : text).split('\n');
      const gutter = '<div style="flex:none; padding:10px 8px 10px 10px; text-align:right; color:var(--text-secondary); opacity:.45; user-select:none; font-family:\'JetBrains Mono\',\'Fira Code\',monospace; font-size:11px; line-height:1.6; background:rgba(127,140,160,.05); border-right:1px solid var(--border-color);">'
        + lines.map((_, i) => '<div>' + (i + 1) + '</div>').join('') + '</div>';
      const body = '<div style="flex:1; min-width:0; overflow-x:auto; padding:10px 12px; font-family:\'JetBrains Mono\',\'Fira Code\',monospace; font-size:11.5px; line-height:1.6; color:var(--text-primary);">'
        + lines.map((line) => '<div style="white-space:pre;">' + (window.sreHighlight(line, lang) || '&nbsp;') + '</div>').join('')
        + '</div>';
      return '<div style="display:flex; max-height:420px; overflow:hidden; border:1px solid var(--border-color); border-radius:10px; background:var(--bg-main);">'
        + gutter + body + '</div>';
    };

    window.sreJsonView = function (text) {
      let pretty = text;
      try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (e) { pretty = String(text); }
      return '<div style="max-height:420px; overflow:auto; border:1px solid var(--border-color); border-radius:10px; background:var(--bg-main); padding:10px 12px; font-family:\'JetBrains Mono\',\'Fira Code\',monospace; font-size:11.5px; line-height:1.6;">'
        + escapeHtml(pretty)
          .replace(/(&quot;[^&]*?&quot;)(\s*:)/g, '<span style="color:#79c0ff;">$1</span>$2')
          .replace(/:\s*(&quot;[^&]*?&quot;)/g, ': <span style="color:#a5d6ff;">$1</span>')
          .replace(/\b(true|false|null)\b/g, '<span style="color:#ff7b72;">$1</span>')
          .replace(/\b(\d+(?:\.\d+)?)\b/g, '<span style="color:#79c0ff;">$1</span>')
        + '</div>';
    };

    window.renderArtifactDiff = window.renderArtifactDiff || function () { return ''; };

    window.renderArtifactBody = function (art, cardId) {
      const text = art.new_content || '';
      const lang = window.sreArtifactLang(art.file_path);
      if (art.has_diff) {
        const stat = '<div style="display:flex; align-items:center; gap:10px; padding:6px 10px; font-family:monospace; font-size:11px; border-bottom:1px solid var(--border-color); background:var(--bg-panel);">'
          + '<span style="color:var(--text-secondary);">' + escapeHtml(String(art.file_path || '').split('/').pop()) + '</span>'
          + (art.added ? '<span style="color:#3fb950; font-weight:700;">+' + art.added + '</span>' : '')
          + (art.removed ? '<span style="color:#f85149; font-weight:700;">−' + art.removed + '</span>' : '')
          + '</div>';
        return stat + window.renderArtifactDiff(art.diff);
      }
      // Ekstensi menang atas tebakan action_type: findings.json harus ke
      // pretty-print JSON, bukan ke-parse sebagai markdown. Hint markdown
      // cuma dipakai buat file teks polos.
      const _isMdExt = lang === 'markdown';
      const _isMdHint = !_isMdExt && (lang === 'text') && window.isMarkdownArtifact(art);
      if (_isMdExt || _isMdHint) {
        try {
          return '<div class="sre-md ai-content" style="font-size:13px; line-height:1.6; padding:10px 12px; border:1px solid var(--border-color); border-radius:10px; background:var(--bg-main);">' + window.sreMarkdownHtml(text) + '</div>';
        } catch (e) { /* fall through to plain */ }
      }
      if (lang === 'json') return window.sreJsonView(text);
      if (lang !== 'text') return window.sreCodeView(text, lang);
      return '<pre style="white-space:pre-wrap; word-break:break-word; font-size:11px; margin:0;">' + escapeHtml(text) + '</pre>';
    };

    // Failure actions are rendered from one place and bound to the chat that
    // owns the run, so a replayed run offers exactly what a live one did.
    window.renderRunFailureActions = function (sid, caseId) {
      const host = document.createElement('div');
      host.className = 'sre-run-actions';
      host.dataset.sessionId = String(sid || sessionId || '');
      host.dataset.caseId = String(caseId || '');
      const priorUser = Array.from(messagesDiv.querySelectorAll('.sre-msg-user')).pop();
      host.dataset.retryGoal = String(
        (priorUser && priorUser.dataset.originalText) || window.lastSubmittedMessage || ''
      );
      host.style.cssText = 'margin: 8px 0;';
      host.innerHTML = `<div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;"></div>`;
      const row = host.firstElementChild;
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.style.cssText = 'background: rgba(88,166,255,0.12); color: var(--text-strong); border: 1px solid var(--border-color); border-radius: 8px; padding: 6px 14px; font-size: 12px; cursor: pointer; font-weight: 600;';
      retry.innerHTML = '<i class="fa-solid fa-rotate-right" style="font-size:11px;"></i> Retry';
      retry.addEventListener('click', () => window.continueRun(
        host.dataset.sessionId, host.dataset.caseId, true, host.dataset.retryGoal
      ));
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.style.cssText = 'background: transparent; color: var(--text-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 6px 12px; font-size: 12px; cursor: pointer; font-weight: 600;';
      cancel.innerHTML = '<i class="fa-solid fa-xmark" style="font-size:11px;"></i> Cancel';
      cancel.addEventListener('click', () => window.cancelRunForSession(host.dataset.sessionId));
      const hint = document.createElement('span');
      hint.style.cssText = 'font-size: 11px; color: var(--text-secondary);';
      hint.textContent = host.dataset.caseId
        ? 'The run stopped; retry continues this case with re-verification.'
        : 'The run stopped; retry sends the original request again.';
      row.append(retry, cancel, hint);
      return host;
    };

    async function loadArtifacts() {
      try {
        if (!sessionId) {
          document.getElementById('artifacts-list').innerHTML = '<div class="sre-text-secondary" style="font-style: italic; padding: 16px;">No artifacts for this session</div>';
          return;
        }
        window.showPanelSkeleton(document.getElementById('artifacts-list'), 4);
        const res = await fetch(`/api/v1/workspace/artifacts/?session_id=${encodeURIComponent(sessionId)}`);
        const data = await res.json();
        const container = document.getElementById('artifacts-list');
        container.innerHTML = '';

        if (!data || data.length === 0) {
          container.innerHTML = '<div class="sre-text-secondary" style="font-style: italic; padding: 16px;">No artifacts generated yet for this session.</div>';
          return;
        }

        const BADGE = {
          create: ['#3fb950', 'rgba(63,185,80,0.15)', 'fa-file-circle-plus', 'FILE CREATED'],
          edit: ['#d29922', 'rgba(210,153,34,0.15)', 'fa-file-pen', 'FILE MODIFIED'],
          backup: ['#a371f7', 'rgba(163,113,247,0.15)', 'fa-file-shield', 'FILE BACKUP'],
          report: ['#58a6ff', 'rgba(88,166,255,0.15)', 'fa-file-lines', 'REPORT'],
          plan: ['#39c5cf', 'rgba(57,197,207,0.15)', 'fa-list-check', 'TASK PLAN'],
          finding: ['#f0883e', 'rgba(240,136,62,0.15)', 'fa-magnifying-glass', 'FINDINGS'],
          history: ['#8b949e', 'rgba(139,148,158,0.15)', 'fa-clock-rotate-left', 'HISTORY'],
          agent_execution: ['#a371f7', 'rgba(163,113,247,0.15)', 'fa-terminal', 'AGENT EXECUTION'],
          subagent_execution: ['#a371f7', 'rgba(163,113,247,0.15)', 'fa-robot', 'SUBAGENT RUN'],
          task_plan: ['#39c5cf', 'rgba(57,197,207,0.15)', 'fa-list-check', 'TASK PLAN'],
          findings: ['#f0883e', 'rgba(240,136,62,0.15)', 'fa-magnifying-glass', 'FINDINGS'],
          delete: ['#f85149', 'rgba(248,81,73,0.15)', 'fa-file-circle-minus', 'FILE DELETED'],
        };

        // Group by case so a long session stays readable: newest group first.
        const groups = [];
        const byKey = new Map();
        data.forEach((art) => {
          const key = art.case_id || 'session';
          if (!byKey.has(key)) {
            const group = {
              key: key,
              title: art.case_title || (art.case_id ? 'Case ' + art.case_id : 'Session level'),
              caseId: art.case_id || '',
              items: [],
            };
            byKey.set(key, group);
            groups.push(group);
          }
          const group = byKey.get(key);
          group.items.push(art);
          if (!group.latest || new Date(art.created_at) > new Date(group.latest)) group.latest = art.created_at;
          if (!group.earliest || new Date(art.created_at) < new Date(group.earliest)) group.earliest = art.created_at;
        });

        groups.forEach((group) => {
          const section = document.createElement('section');
          section.style.cssText = 'margin-bottom: 18px; border:1px solid var(--border-color); border-radius:12px; overflow:hidden;';

          const header = document.createElement('div');
          header.style.cssText = 'display:flex; align-items:center; gap:10px; padding:10px 12px;' +
            ' background:var(--bg-panel); border-bottom:1px solid var(--border-color); position:sticky; top:0; z-index:2;';
          header.innerHTML =
            '<i class="fa-solid fa-diagram-project" style="color:var(--accent); font-size:12px;"></i>' +
            '<div style="flex:1; min-width:0;">' +
            '<div style="font-size:12px; font-weight:700; color:var(--text-primary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
            escapeHtml(group.title) + '</div>' +
            '<div style="font-size:10px; color:var(--text-secondary);">' +
            group.items.length + ' change' + (group.items.length === 1 ? '' : 's') +
            (group.earliest ? ' · ' + window.artifactTimeLabel(group.earliest) : '') +
            '</div></div>' +
            '<span style="font-size:10px; font-family:monospace; color:var(--text-secondary);">' +
            escapeHtml(group.caseId || 'session') + '</span>' +
            (group.earliest
              ? '<span class="sre-art-locate" data-when="' + escapeHtml(group.earliest) + '" data-label="' + escapeHtml(group.title || 'this investigation') + '" title="Go to this investigation in the chat" onclick="window.jumpToArtifact(this)" style="display:flex; align-items:center; justify-content:center; width:24px; height:24px; border-radius:6px; color:var(--text-secondary); flex:none;"><i class="fa-solid fa-arrow-up" style="font-size:11px;"></i></span>'
              : '');
          section.appendChild(header);

          group.items.forEach((art) => {
            const [badgeColor, badgeBg, icon, typeLabel] = BADGE[art.action_type] ||
              ['#58a6ff', 'rgba(88,166,255,0.15)', 'fa-file', String(art.action_type || 'ARTIFACT').toUpperCase()];
            const fileName = art.file_path ? art.file_path.split('/').pop() : 'unknown';
            const cardId = 'artifact-' + art.id;
            const when = window.artifactTimeLabel(art.created_at);
            const timeStr = art.created_at
              ? new Date(art.created_at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
              : '';
            const stat = art.has_diff
              ? '<span style="font-family:monospace; font-size:10px;">' +
                '<span style="color:#7ee787;">+' + (art.added || 0) + '</span>' +
                '<span style="color:var(--text-secondary);">/</span>' +
                '<span style="color:#ffa198;">-' + (art.removed || 0) + '</span></span>'
              : '';
            const renderable = window.renderArtifactBody(art, cardId);
            const rawContent = art.diff || art.new_content || '';

            window.artifactContents[cardId] = {
              full: rawContent,
              preview: String(rawContent).split('\n').slice(0, 8).join('\n'),
              fileName: fileName
            };

            const canRestore = ['edit', 'create', 'backup', 'delete'].includes(art.action_type);
            const wrap = document.createElement('div');
            wrap.style.cssText = 'padding:8px 12px; border-bottom:1px solid var(--border-color);';
            wrap.innerHTML =
              '<div style="background:var(--bg-main); border:1px solid var(--border-color); border-radius:10px; overflow:hidden;">' +
                '<div onclick="toggleArtifactCard(\'' + cardId + '\')" style="cursor:pointer; padding:10px 12px; display:flex; align-items:center; gap:10px; user-select:none;">' +
                  '<span style="font-size:10px; font-weight:700; padding:3px 8px; border-radius:12px; color:' + badgeColor + '; background:' + badgeBg + '; letter-spacing:0.5px; white-space:nowrap; flex-shrink:0;">' +
                    '<i class="fa-solid ' + icon + '" style="margin-right:4px; font-size:9px;"></i>' + typeLabel + '</span>' +
                  '<span style="font-weight:600; font-size:12.5px; color:var(--text-primary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1;">' +
                    '<i class="fa-solid fa-file-lines" style="font-size:11px; color:var(--text-secondary); margin-right:6px;"></i>' + escapeHtml(fileName) + '</span>' +
                  stat +
                  '<span title="' + escapeHtml(when) + '" style="font-size:10px; color:var(--text-secondary);">' + timeStr + '</span>' +
                  '<i class="fa-solid fa-chevron-down" id="' + cardId + '-chevron" style="font-size:10px; color:var(--text-secondary); transition:transform 0.2s;"></i>' +
                '</div>' +
                '<div id="' + cardId + '-content" style="display:none; border-top:1px solid var(--border-color);">' +
                '<div style="padding:7px 12px; background:rgba(0,0,0,0.12); font-size:10px; color:var(--text-secondary); font-family:monospace; border-bottom:1px solid var(--border-color); word-break:break-all;" title="' + escapeHtml(art.file_path || '') + '">' +
                  '<i class="fa-solid fa-folder" style="margin-right:4px;"></i>' + escapeHtml(String(art.file_path || '').replace(/^\.neurosys\/sessions\/[^/]+\//, '')) + '</div>' +
                  '<div style="padding:10px 12px;">' +
                    (renderable || ('<pre style="background:var(--bg-panel); color:var(--text-primary); padding:10px; border-radius:6px; overflow:auto; font-size:11px; max-height:220px; border:1px solid var(--border-color); font-family:\'JetBrains Mono\',\'Fira Code\',monospace; line-height:1.5; margin:0; white-space:pre-wrap; word-break:break-word;">' +
                      escapeHtml(String(rawContent).split('\n').slice(0, 12).join('\n')) + (String(rawContent).split('\n').length > 12 ? '\n... (truncated — use Download or Copy)' : '') + '</pre>')) +
                  '</div>' +
                  '<div style="padding:8px 12px; border-top:1px solid var(--border-color); display:flex; justify-content:flex-end; gap:6px; flex-wrap:wrap;">' +
                    '<button onclick="window.toggleArtifactFull(\'' + cardId + '\')" style="background:rgba(88,166,255,0.12); color:var(--text-strong); border:1px solid var(--border-color); border-radius:6px; padding:4px 10px; font-size:11px; cursor:pointer;">Copy full</button>' +
                    '<button onclick="window.downloadArtifact(\'' + cardId + '\')" style="background:rgba(88,166,255,0.12); color:var(--text-strong); border:1px solid var(--border-color); border-radius:6px; padding:4px 10px; font-size:11px; cursor:pointer;">Download</button>' +
                    (canRestore
                      ? '<button data-rollback-id="' + art.id + '" onclick="window.rollbackArtifact(' + art.id + ')" title="Restore the file as it was before this change" style="background:rgba(210,153,34,0.14); color:#e3b341; border:1px solid rgba(210,153,34,0.35); border-radius:6px; padding:4px 10px; font-size:11px; cursor:pointer; font-weight:600;">↩ Restore</button>'
                      : '') +
                  '</div>' +
                '</div>' +
              '</div>';
            section.appendChild(wrap);
          });

          container.appendChild(section);
        });
      } catch (e) {
        document.getElementById('artifacts-list').innerHTML = '<div class="sre-text-secondary" style="font-style: italic; padding: 16px;">Error loading artifacts.</div>';
      }
    }

    // Add this toggle function globally
    // Scroll the chat to the turn that produced an artifact, and point at it
    // so the operator lands on the work rather than hunting for it.
    // Arguments travel as data attributes so a quote in a filename can never
    // break the inline handler.
    window.jumpToArtifact = async function (trigger) {
      const createdAt = trigger && trigger.dataset ? trigger.dataset.when : '';
      const box = document.getElementById('chat-messages');
      if (!box) return;
      const when = Date.parse(createdAt || '');
      let target = null;
      if (isFinite(when)) {
        let best = null;
        document.querySelectorAll('#chat-messages [data-created]').forEach((el) => {
          const t = Date.parse(el.dataset.created || '');
          if (!isFinite(t) || t > when) return;
          if (!best || t > Date.parse(best.dataset.created || '')) best = el;
        });
        target = best;
      }
      // The turn may live on a page that was never loaded; pull a few older
      // pages before giving up.
      if (!target) {
        for (let attempt = 0; attempt < 3 && !target && window.msgPage && window.msgPage.hasMore; attempt++) {
          await window.loadOlderMessages();
          if (isFinite(when)) {
            let best = null;
            document.querySelectorAll('#chat-messages [data-created]').forEach((el) => {
              const t = Date.parse(el.dataset.created || '');
              if (!isFinite(t) || t > when) return;
              if (!best || t > Date.parse(best.dataset.created || '')) best = el;
            });
            target = best;
          }
        }
      }
      if (!target) {
        target = document.querySelector('#chat-messages .sre-msg-user, #chat-messages .sre-msg-ai');
      }
      if (!target) {
        addSystemMsg('That part of the conversation is not in this chat any more.', 'circle-info');
        return;
      }
      box.scrollTo({ top: Math.max(0, target.offsetTop - box.offsetTop - 80), behavior: 'smooth' });
      target.style.transition = 'box-shadow .25s ease, outline-color .25s ease';
      target.style.outline = '2px solid var(--accent)';
      target.style.outlineOffset = '6px';
      target.style.borderRadius = '14px';
      setTimeout(() => { target.style.outline = 'none'; }, 2600);
    };

    window.toggleArtifactCard = function (cardId) {
      const content = document.getElementById(cardId + '-content');
      const chevron = document.getElementById(cardId + '-chevron');

      if (content && chevron) {
        if (content.style.display === 'none') {
          content.style.display = 'block';
          chevron.style.transform = 'rotate(180deg)';
        } else {
          content.style.display = 'none';
          chevron.style.transform = 'rotate(0deg)';
        }
      }
    };

    window.rollbackArtifact = async function (id) {
      if (!confirm('Restore the file to the content it had before this change?')) return;
      const btn = document.querySelector(`[data-rollback-id="${id}"]`);
      if (btn) { btn.disabled = true; btn.textContent = 'Restoring...'; }
      try {
        await window.wsCall('artifact.rollback', { id });
        addSystemMsg('File restored to its previous content.', 'rotate-left');
        loadArtifacts();
      } catch (e) {
        addSystemMsg('Restore failed: ' + (e.message || e), 'alert-triangle');
        if (btn) { btn.disabled = false; btn.textContent = '↩ Restore'; }
      }
    };

    window.artifactContents = window.artifactContents || {};

    // A run card and its presence row always leave together, so neither can
    // orphan the other on retry or cancel.
    window.removeRunCard = function (body) {
      if (!body) return;
      try {
        if (body.parentElement) body.parentElement.remove();
      } catch (err) { /* best-effort */ }
    };

    // Remove the visible traces of a failed run so a retry starts clean:
    // consumed action blocks, Error/Cancelled step cards and the error bubble.
    window.clearRunFailureUI = function (sid) {
      const owner = String(sid || sessionId || '');
      document.querySelectorAll('.sre-run-actions').forEach((block) => {
        if (String(block.dataset.sessionId || '') !== owner) return;
        if (block.dataset.consumed === '1') return;
        block.dataset.consumed = '1';
        block.remove();
      });
      const wrap = window.activeRunWrap;
      if (wrap) {
        wrap.querySelectorAll('.sre-agent-step').forEach((step) => {
          const label = (step.textContent || '').trim().slice(0, 60);
          if (/^(Error|Cancelled|Failed)/i.test(label)) step.remove();
        });
      }
      const prefixes = ['Agent execution failed', 'The case is not finished',
        'Investigation paused', 'Step budget reached'];
      const bubbles = Array.from(messagesDiv.querySelectorAll('.agent-msg.sre-msg-ai'));
      for (let i = bubbles.length - 1; i >= 0; i--) {
        const text = (bubbles[i].innerText || '').trim();
        if (prefixes.some((p) => text.startsWith(p))) bubbles[i].remove();
        else break;
      }
    };

    window.continueRun = function (forSessionId, forCaseId, fresh, originalGoal) {
      try {
        if (typeof isProcessing !== 'undefined' && isProcessing) return;
        const owner = forSessionId || window.continueSessionId || sessionId;
        const caseId = String(forCaseId || '');
        window.pendingResumeCaseId = caseId;
        window.pendingResumeMode = caseId && fresh !== false ? 'fresh' : '';
        // Refuse to continue a case that belongs to a chat the operator has
        // since navigated away from.
        if (owner && String(owner) !== String(sessionId)) {
          addSystemMsg('That case belongs to another chat. Open it there to continue.', 'alert-triangle');
          return;
        }
        const inputEl = document.getElementById('chat-input') || (typeof input !== 'undefined' ? input : null);
        const formEl = (typeof form !== 'undefined' && form) ? form : (inputEl ? inputEl.form : null);
        if (!inputEl || !formEl) return;
        const retryText = caseId ? 'continue' : String(originalGoal || window.lastSubmittedMessage || '').trim();
        if (!retryText) {
          addSystemMsg('The original request is unavailable. Please send it again.', 'circle-info');
          return;
        }
        // A retry is a refresh, not a new turn: clear the old error traces,
        // then resend without adding another user bubble.
        window.clearRunFailureUI(owner);
        // The failed card goes away with the retry: the fresh attempt builds
        // its own card under its own investigation id.
        if (window.activeRunWrap && String(window.activeRunWrap.dataset.sessionId || '') === String(owner)) {
          window.removeRunCard(window.activeRunWrap);
        }
        window.activeRunWrap = null;
        window.silentSubmit = true;
        inputEl.value = retryText;
        if (formEl.requestSubmit) formEl.requestSubmit();
        else formEl.dispatchEvent(new Event('submit', { cancelable: true }));
      } catch (e) { /* no-op */ }
    };

    window.toggleFinding = function (fid) {
      const shortEl = document.getElementById(fid + '-short');
      const fullEl = document.getElementById(fid + '-full');
      // The trigger is matched by class as well as by its old id, so both the
      // current markup and anything already on screen keep working.
      const btn = document.getElementById(fid + '-btn') ||
        (fullEl && fullEl.parentElement
          ? fullEl.parentElement.querySelector('.sre-inv-more')
          : null);
      if (!shortEl || !fullEl || !btn) return;
      const expanded = fullEl.style.display !== 'none';
      fullEl.style.display = expanded ? 'none' : 'inline';
      shortEl.style.display = expanded ? 'inline' : 'none';
      btn.textContent = expanded ? 'Show all' : 'Show less';
    };

    window.toggleArtifactFull = function (cardId) {
      const entry = window.artifactContents[cardId];
      const pre = document.getElementById(cardId + '-pre');
      const btn = document.getElementById(cardId + '-expandbtn');
      if (!entry || !pre) return;
      if (pre.dataset.expanded === '1') {
        pre.textContent = entry.preview;
        pre.style.maxHeight = '200px';
        pre.dataset.expanded = '0';
        if (btn) btn.textContent = '⤢ Show full';
      } else {
        pre.textContent = entry.full;
        pre.style.maxHeight = '600px';
        pre.dataset.expanded = '1';
        if (btn) btn.textContent = '⤢ Show less';
      }
    };

    window.copyArtifact = async function (cardId) {
      const entry = window.artifactContents[cardId];
      if (!entry) return;
      try {
        await navigator.clipboard.writeText(entry.full);
        alert('Artifact copied to clipboard!');
      } catch (e) {
        alert('Copy failed.');
      }
    };

    window.downloadArtifact = function (cardId) {
      const entry = window.artifactContents[cardId];
      if (!entry) return;
      const blob = new Blob([entry.full], { type: 'text/markdown;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = entry.fileName || 'artifact.md';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    };

    // --- Terminal ---
    function initTerminal() {
      if (typeof Terminal === 'undefined') {
        document.getElementById('terminal-container').innerHTML = '<div style="color: #f85149; padding: 20px;">Tidak dapat membuka terminal karena dependency xterm.js belum tersedia.</div>';
        return;
      }

      const termContainer = document.getElementById('terminal-container');
      if (!termContainer) return;

      const term = new Terminal({
        cursorBlink: true,
        theme: { background: '#000000', foreground: '#f0f6fc' },
        fontFamily: 'Menlo, Monaco, monospace',
        fontSize: 13
      });

      const fitAddon = new FitAddon.FitAddon();
      term.loadAddon(fitAddon);
      term.open(termContainer);
      window.fitTerminal = () => {
        fitAddon.fit();
        try {
          if (window.termWs && window.termWs.readyState === WebSocket.OPEN) {
            window.termWs.send(JSON.stringify({
              type: 'resize',
              cols: term.cols,
              rows: term.rows
            }));
          }
        } catch (err) { /* not connected */ }
      };

      window.addEventListener('resize', () => {
        if (document.getElementById('tab-terminal').style.display !== 'none') {
          window.fitTerminal();
        }
      });

      term.writeln('Welcome to NeuroSysAI Interactive Terminal\n');

      window.termWs = null;
      window.terminalRetryTimer = null;
      window.terminalRetryCount = 0;

      window.setTerminalStatus = function (state) {
        const btn = document.getElementById('terminal-status-btn');
        const dot = document.getElementById('terminal-status-dot');
        const text = document.getElementById('terminal-status-text');
        if (!btn || !dot || !text) return;
        if (state === 'open') {
          dot.style.background = 'var(--success-text)';
          text.textContent = 'Connected';
          btn.style.cursor = 'default';
          btn.title = 'Terminal connected';
        } else if (state === 'connecting') {
          dot.style.background = 'var(--warning)';
          text.textContent = 'Connecting…';
          btn.style.cursor = 'default';
          btn.title = 'Connecting the terminal…';
        } else {
          dot.style.background = 'var(--error)';
          text.textContent = 'Reconnect';
          btn.style.cursor = 'pointer';
          btn.title = 'Terminal disconnected - click to reconnect';
        }
      };

      const statusBtn = document.getElementById('terminal-status-btn');
      if (statusBtn) statusBtn.onclick = () => {
        if (!window.termWs || window.termWs.readyState === WebSocket.CLOSED) window.connectTerminal(true);
      };

      window.connectTerminal = function (manual) {
        try {
          if (window.termWs && (window.termWs.readyState === WebSocket.OPEN
              || window.termWs.readyState === WebSocket.CONNECTING)) return;
        } catch (err) { /* fall through and dial again */ }
        if (window.terminalRetryTimer) {
          clearTimeout(window.terminalRetryTimer);
          window.terminalRetryTimer = null;
        }
        window.setTerminalStatus('connecting');
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const sock = new WebSocket(`${protocol}//${location.host}/ws/terminal/`);
        window.termWs = sock;
        if (manual) {
          window.terminalRetryCount = 0;
          term.writeln('\r\nReconnecting the terminal…\r\n');
        }
        sock.onopen = () => {
          window.terminalRetryCount = 0;
          window.setTerminalStatus('open');
          setTimeout(window.fitTerminal, 500);
        };
        sock.onmessage = (e) => {
          try {
            const msg = JSON.parse(e.data);
            if (msg.type === 'output') {
              term.write(msg.data);
            } else if (msg.type === 'cwd') {
              if (window.currentTerminalCwd !== msg.cwd) {
                window.currentTerminalCwd = msg.cwd;
                localStorage.setItem('sre_terminal_cwd', msg.cwd);
                if (window.workspaceFollow) {
                  const input = document.getElementById('workspace-path-input');
                  if (input) input.value = msg.cwd;
                  loadExplorer();
                }
              }
            }
          } catch (err) {
            term.write(e.data);
          }
        };
        const scheduleRetry = () => {
          window.terminalRetryCount = (window.terminalRetryCount || 0) + 1;
          const wait = Math.min(30000, 2000 * Math.pow(2, window.terminalRetryCount - 1));
          window.terminalRetryTimer = setTimeout(() => window.connectTerminal(false), wait);
        };
        sock.onerror = () => {
          try { sock.close(); } catch (err) { /* already closing */ }
        };
        sock.onclose = () => {
          if (window.termWs !== sock) return;
          window.setTerminalStatus('closed');
          scheduleRetry();
        };
      };

      window.currentTerminalCwd = null;

      term.onData((data) => {
        if (window.termWs && window.termWs.readyState === WebSocket.OPEN) {
          window.termWs.send(JSON.stringify({ type: 'input', data: data }));
        }
      });

      window.connectTerminal(false);
    }

    // --- Init ---
    loadHistory();
    connect();
    initTerminal();
    updateContextAttachments();

    // --- Resizer Logic ---
    const panelResizer = document.getElementById('panel-resizer');
    const rightPanel = document.getElementById('right-panel');
    let isResizing = false;

    if (panelResizer && rightPanel) {
      panelResizer.addEventListener('mousedown', (e) => {
        isResizing = true;
        document.body.style.cursor = 'col-resize';
        panelResizer.style.background = 'var(--accent)';
        e.preventDefault();
      });

      document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;

        const containerRect = rightPanel.parentElement.getBoundingClientRect();
        const newWidth = containerRect.right - e.clientX - 12;

        if (newWidth > 300 && newWidth < containerRect.width * 0.8) {
          rightPanel.style.width = newWidth + 'px';
          rightPanel.style.flex = 'none';
          if (window.fitTerminal) {
            window.fitTerminal();
          }
        }
      });

      document.addEventListener('mouseup', () => {
        if (isResizing) {
          isResizing = false;
          document.body.style.cursor = 'default';
          panelResizer.style.background = 'rgba(255,255,255,0.05)';
          if (window.fitTerminal) {
            window.fitTerminal();
          }
        }
      });
    }
  })();
