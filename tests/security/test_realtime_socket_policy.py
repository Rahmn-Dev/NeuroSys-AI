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


def test_agent_initial_snapshot_then_websocket_first():
    assert "let initialSnapshotDone = false;" in CHAT
    assert "if (!initialSnapshotDone)" in CHAT
    assert "stopSnapshotPolling();" in CHAT
    assert "badge.textContent = 'Live';" in CHAT


def test_agent_fallback_only_when_unavailable_and_stops_when_open():
    assert "startSnapshotPolling();" in CHAT
    assert "if (ws && ws.readyState === WebSocket.OPEN) { stopSnapshotPolling(); return; }" in CHAT
    assert "}, 5000);" in CHAT


def test_permanent_auth_failure_stops_retry_and_shows_offline():
    assert "[4401, 4403].includes(event.code)" in CHAT
    assert "badge.textContent = permanent ? 'Offline' : 'Reconnecting';" in CHAT
    assert "if (permanent) return;" in CHAT
    assert "[1000, 1002, 1003, 1008, 4401, 4403].includes(event.code)" in LAYOUT
