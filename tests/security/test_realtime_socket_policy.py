from pathlib import Path


ROOT = Path(__file__).parents[2]
CHAT = (ROOT / "ai_config/templates/chat3.html").read_text()
LAYOUT = (ROOT / "ai_config/templates/layout/layout1.html").read_text()
NETWORK = (ROOT / "ai_config/templates/network_security.html").read_text()
CONSUMERS = (ROOT / "ai_config/ai_config/consumers.py").read_text()


def test_suricata_close_does_not_reload_page():
    assert "location.reload()" not in LAYOUT
    assert "location.reload()" not in NETWORK
    assert "setTimeout(() => this.initWebSocket(), delay)" in LAYOUT


def test_suricata_reconnect_is_bounded_and_jittered():
    assert "Math.min(30000" in LAYOUT
    assert "Math.random() * 0.5" in LAYOUT
    assert "Math.min(30000" in NETWORK


def test_suricata_heartbeat_has_ping_pong_consumer():
    assert "type: 'ping'" in LAYOUT
    assert 'payload.get("type") == "ping"' in CONSUMERS
    assert '"type": "pong"' in CONSUMERS


def test_agent_survives_independent_suricata_disconnect():
    assert "/ws/sre-agent/" in CHAT
    assert "/ws/suricata_monitor/" not in CHAT
    assert "startSnapshotPolling();" in CHAT


def test_agent_reconnect_does_not_duplicate_run_execution():
    assert "if (ws && ws.readyState === WebSocket.OPEN)" in CHAT
    assert "if (ws && ws.readyState === WebSocket.CONNECTING)" in CHAT
    assert "clearTimeout(reconnectTimer)" in CHAT


def test_background_events_are_routed_to_their_own_chat_after_switching():
    sender = CONSUMERS[CONSUMERS.index("async def send_event(event):") : CONSUMERS.index("self.lifecycle = ApprovalLifecycle(send_event)")]
    assert "_event_sid = str(event.get(\"session_id\") or getattr(engine, \"session_id\", \"\") or \"\")" in sender
    assert "_event_group" in sender
    assert "_event_group == self.run_group" in sender
    assert "group_send(self.run_group" not in sender


def test_fresh_run_events_reach_the_local_socket_before_subscribe():
    sender = CONSUMERS[CONSUMERS.index("async def send_event(event):") : CONSUMERS.index("self.lifecycle = ApprovalLifecycle(send_event)")]
    # Before the subscribe round-trip the consumer is not in the run's group;
    # group_send alone would drop the run's first events (the "stuck at
    # starting" race). It must also self.send while the group differs.
    else_branch = sender[sender.index("if _event_group == self.run_group"):]
    assert "await self.send(text_data=json.dumps(event))" in else_branch


def test_agent_reconciles_snapshot_after_every_websocket_reconnect():
    assert "bootstrapActiveRun();" in CHAT
    assert "Reconcile after every reconnect" in CHAT
    assert "badge.textContent = 'Live';" in CHAT


def test_agent_snapshot_backstop_keeps_running_while_socket_is_open():
    assert "startSnapshotPolling();" in CHAT
    poller = CHAT[CHAT.index("function startSnapshotPolling()") : CHAT.index("function stopSnapshotPolling()")]
    assert "bootstrapActiveRun();" in poller
    assert "WebSocket.OPEN" not in poller
    assert "}, 10000);" in poller


def test_switching_history_sessions_resubscribes_the_run_socket():
    load_session = CHAT[CHAT.index("async function loadSession(id)") : CHAT.index("// --- Explorer Logic ---")]
    assert "type: 'subscribe', session_id: sessionId" in load_session
    assert "await bootstrapActiveRun();" in load_session


def test_rehydrated_active_run_restores_live_pill_and_state_row():
    bootstrap = CHAT[CHAT.index("async function bootstrapActiveRun()") : CHAT.index("function startSnapshotPolling()")]
    assert "paintRunWrap(adopted, run.status || 'running')" in bootstrap
    assert "updateRunStateCard(run.id, phase, null," in bootstrap
    assert "run.created_at" in bootstrap


def test_permanent_auth_failure_stops_retry_and_shows_offline():
    assert "[4401, 4403].includes(event.code)" in CHAT
    assert "badge.textContent = permanent ? 'Offline' : 'Reconnecting';" in CHAT
    assert "if (permanent) return;" in CHAT
    assert "[1000, 1002, 1003, 1008, 4401, 4403].includes(event.code)" in LAYOUT
