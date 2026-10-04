# Durable UI rehydration

## Root cause

Before this change, `chat3.html` retained only `sessionId`, `pendingApproval`, and websocket state in page memory. `connect()` re-opened `/ws/sre-agent/` after a close (`chat3.html:751-789`) but did not request the durable `AgentRun` checkpoint. `loadHistory()` created a new chat when no URL session existed (`chat3.html:1652-1664`), and `loadSession()` restored transcript messages but not run/task/approval state (`chat3.html:1740-1805`). The backend consumer also cancels active work on disconnect except a pending approval (`consumers.py:SREAgentConsumer.disconnect`, lines 1297-1300). Development hot reload can therefore recreate the page and lose active UI state even when database state exists.

## New authoritative flow

1. The authenticated browser keeps the session ID in the URL.
2. Websocket `onopen` and `session_id` events call `bootstrapActiveRun()`.
3. `GET /api/v1/agent-runs/snapshot/?session_id=...` checks authentication and `AgentRun.user_id` ownership before returning anything.
4. The snapshot contains run status/goal/provider/model/checkpoint, task nodes, lifecycle transitions, bounded transcript, and sanitized pending approval with server expiry.
5. The frontend records the checkpoint version and ignores older duplicate snapshots.
6. Transcript is reloaded through the existing session history path once per session; approval reuses the stored approval ID/request ID and expiry instead of creating a new token.
7. Expired pending approvals are finalized server-side as `denied_timeout` and the run is marked `blocked` before the snapshot is returned.

## Security and limitations

The endpoint is authenticated and ownership checked. If no run exists, it returns no transcript, avoiding session-ID enumeration. Approval arguments are the existing sanitized preview. The websocket still needs a separate resume command if a process restart occurs while the worker itself is gone; the snapshot accurately exposes the durable state and prevents a duplicate run from being created by the browser.
### Realtime socket policy

Agent, Suricata, and terminal streams are independent WebSockets. A Suricata
disconnect is handled by reconnecting that stream only; it never reloads the
page or resets AgentRun, approvals, transcript, or terminal state. Reconnects
use exponential backoff with 25% jitter, capped at 30 seconds. Authentication
close codes (4401/4403) stop retries and show an auth-required state.

The Agent UI performs one initial snapshot fetch, then consumes live events over
WebSocket. Snapshot polling is a five-second fallback only while the Agent
socket is unavailable and stops immediately after a healthy open. Suricata uses
an application ping/pong heartbeat because browser JavaScript cannot emit a
WebSocket protocol ping; inactivity closes only the Suricata socket.

Reverse proxies and Channels deployments should allow WebSocket upgrade and a
read timeout longer than the 15-second heartbeat interval (at least 60 seconds)
so idle connections are not removed by the proxy.
