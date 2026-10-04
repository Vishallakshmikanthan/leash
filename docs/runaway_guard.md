# Leash: Runaway Guard (N6)

## 1. Overview

The **Runaway Guard** (`session/runaway_guard.py`) protects developer workstations and API rate limits by monitoring agent cadence and detecting spinning loops, repeated failures, rapid edit cycles, and expired session time limits.

When runaway behavior is identified:
1. **Agent Paused**: The session immediately transitions to `SessionState.PAUSED`, blocking further unapproved actions.
2. **Android Guard Notified**: An instantaneous `runaway_alert` event and high-severity approval card are transmitted to paired Android Guard devices over the secure WebSocket channel.
3. **User Decision Required**: The human must deliberate and provide an explicit decision (Resume / Allow vs Deny / Terminate).
4. **Audit History Logged**: The incident is recorded in append-only JSONL audit logs (`audit.jsonl`) and highlighted in the PR-ready Agent Receipt.
5. **Normal Activity Unaffected**: Standard development commands (`pytest`, `git status`, clean edits) and normal sequential workflows operate without interference.

---

## 2. Detection Vectors

| Vector | Trigger Condition | Severity | Primary Risk Mitigated |
|---|---|---|---|
| **Repeated Failing Commands** | Identical or consecutive command failures reaching configured threshold (default: 3). | **HIGH** | Agent spinning on failing commands, consuming rate limits, or thrashing shell environments. |
| **File Edit Loops** | >= 5 edits to the same file within a rolling 15s window (`file_edit_loop_threshold`). | **HIGH** | Infinite edit-save-fail loops causing disk churn or corrupting source files. |
| **File Edit Oscillation** | Rapid alternating edits between <= 2 files within rolling window. | **HIGH** | Agent thrashing between mutually incompatible syntax or configuration edits. |
| **Action Cadence Burst** | >= 15 actions within 5s sliding window (`rate_limit_count` / `rate_limit_window`). | **HIGH** | Runaway prompt or loop blasting rapid-fire tool calls and shell invocations. |
| **Session Time Limit** | Active session duration exceeding `time_limit_seconds` configured at startup. | **HIGH** | Unattended agent continuing execution past approved developer time allotment. |

---

## 3. Subsystem Lifecycle & Architecture

```
[ Coding Agent ]
       │
       ▼ (Action Request)
[ SessionManager ] ──► RunawayGuard.check_action()
       │                      │
       │                      ├── Trip: repeated failures / edit loop / burst / timeout
       │                      ▼
       │               Session Paused (SessionState.PAUSED)
       │               request.scope_flags += ["runaway-behavior-detected"]
       ▼
[ Daemon Interceptor ]
       │
       ├── Record Audit Alert (AuditLogger.record_runaway_alert)
       ├── Broadcast WebSocket "runaway_alert"
       │
       ▼
[ Android Guard (Phone) ]
       │
       ├── Displays Runaway Warning Banner & On-Device Risk Explanation
       ├── Vibrate / Sound Haptic Notification
       │
       ▼ Human Decision (Tap / Biometric)
       │
       ├── APPROVE / RESUME:
       │     ├── RunawayGuard.reset()
       │     ├── SessionManager.resume_session()
       │     └── Action permitted to execute
       │
       └── DENY / TERMINATE:
             ├── Session remains PAUSED or is TERMINATED
             └── Action blocked with Verdict.DENY
```

---

## 4. REST & WebSocket Protocols

### REST Endpoints
- `POST /sessions/{session_id}/runaway/decision`:
  - Payload: `{"verdict": "allow" | "resume" | "deny" | "terminate", "action_id": "...", "note": "..."}`
  - Resumes or terminates session and resolves pending action decisions.
- `POST /sessions`:
  - Supports `"time_limit_seconds"` parameter to enforce maximum session runtime.

### WebSocket Messages
- **Outbound to Phone**:
  - `runaway_alert`: `{ "session_id": "...", "action_id": "...", "reason": "...", "category": "runaway-behavior-detected", "severity": "high", "stats": {...}, "state": "paused" }`
  - `session_state_changed`: `{ "session_id": "...", "state": "paused" | "active" | "terminated" }`
- **Inbound from Phone**:
  - `runaway_decision`: `{ "session_id": "...", "verdict": "allow" | "resume" | "terminate" | "deny", "action_id": "...", "biometric": true }`
  - `runaway_decision_ack`: `{ "session_id": "...", "status": "active" | "terminated" | "paused", "success": true }`

---

## 5. Audit Logging & Agent Receipt

- **Audit Log Event**:
  - Event type: `runaway_security_alert`
  - Category: `runaway-behavior-detected`
  - Details: `reason`, `runaway_type`, `stats` (streaks, recent action count, remaining time).
- **Agent PR Receipt**:
  - Summarized under Security & Risk Events with badge: `🛑 RUNAWAY GUARD`.
