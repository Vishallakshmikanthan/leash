# Leash: Architecture Specification

## 1. Executive Overview

Leash is an out-of-band safety and governance layer for autonomous AI coding agents. It separates agent execution on the developer's laptop from the authorization checkpoint on the developer's mobile phone (Android Guard app).

```
+-------------------------------------------------------------------+
|                           LAPTOP HOST                             |
|                                                                   |
|   +------------------+         +-------------------------------+  |
|   | AI Coding Agent  | ------> |      Command Shim Layer       |  |
|   +------------------+         +-------------------------------+  |
|                                                |                  |
|                                                v                  |
|                                 +------------------------------+  |
|                                 |         Leash Daemon         |  |
|                                 |  - Policy Evaluator          |  |
|                                 |  - Session / Worktree Mgr    |  |
|                                 |  - Modular Security Gates    |  |
|                                 |  - Audit Logger & Receipts   |  |
|                                 +------------------------------+  |
+------------------------------------------------|------------------+
                                                 | (Signed JSON over
                                                 |  WebSocket / USB)
+------------------------------------------------v------------------+
|                      ANDROID GUARD APP (PHONE)                    |
|                                                                   |
|   +------------------+   +-------------------+   +------------+   |
|   |  Risk Engine     |   | On-Device Model   |   | Biometric  |   |
|   |  (Rules First)   |   | (Plain English)   |   | Prompt     |   |
|   +------------------+   +-------------------+   +------------+   |
|                                                                   |
|   +-----------------------------------------------------------+   |
|   | Approval Card UI (Haptics, Taint Escalation, 1-Tap Rewind)|   |
|   +-----------------------------------------------------------+   |
+-------------------------------------------------------------------+
```

---

## 2. Core Architectural Components

### 2.1 Laptop Interceptor & Daemon
- **Command Shim (`shim/`)**: Sits between the coding agent and the system shell. Intercepts bash/sh commands and tool invocations, generating canonical `ActionRequest` objects.
- **Git Guard (`shim/git_guard.py`)**: Intercepts high-risk git operations (`push --force`, `reset --hard`, `clean -fdx`).
- **Tool Hooks (`shim/tool_hooks.py`)**: Intercepts file reads/edits and tool calls, detecting untrusted input ingestion (`README.md`, issue templates).
- **Leash Daemon (`daemon/`)**: Orchestrates security gate evaluation, provenance tracking, session worktrees, phone WebSocket transport, and append-only audit logging.

### 2.2 Security Gates (`gates/`)
- **Provenance Tracker (`gates/provenance_tracker.py`)**: Identifies untrusted content (README files, issue text, web downloads, configured sources), extracts relevant instruction line numbers, marks sessions tainted, and escalates subsequent action severity.
- **Secret Fence (`gates/secret_fence.py`)**: Blocks reads of `.env`, `~/.ssh`, cloud credentials, and alerts on canary token access.
- **Package Gate (`gates/package_gate.py`)**: Offline typosquatting detection (Levenshtein distance against popular packages) and malicious install script checks.
- **Hidden Text Scanner (`gates/hidden_text.py`)**: Detects zero-width Unicode and bidirectional (BiDi) override codepoints used to disguise malicious shell payloads.
- **Workflow Watchlist (`gates/workflow_watchlist.py`)**: Protects CI/CD workflows, Dockerfiles, and package lockfiles.


### 2.3 Session & Provenance Management (`session/`)
- **Worktree Isolation (`session/worktree.py`)**: Runs each agent session in an isolated git worktree (`leash/<session-id>`).
- **Task Scope Contract (`session/scope.py`)**: Enforces allowable file paths, commands, and network hosts.
- **Snapshots & Rewind (`session/snapshot.py`)**: Captures point-in-time git snapshots (`refs/leash/<session>/<n>`) prior to risky commands, enabling one-tap rollback.
- **Runaway Guard (`session/runaway_guard.py`)**: Identifies execution loops or consecutive failing command streaks.

### 2.4 Android Guard App (`android/`)
- **Native Android (Kotlin + Jetpack Compose)**: Leverages platform security capabilities.
- **Biometric Security**: High-risk actions require fingerprint verification (`BiometricPrompt`).
- **Distinct Haptics**: Differentiated waveforms for Medium vs. High risk alerts.
- **Foreground Service**: Ensures background connectivity over LAN or USB (`adb reverse`).

---

## 3. Threat Model & Fail-Closed Guarantees

1. **Unreachable Phone**: If the WebSocket connection to the phone is severed, high-risk and medium-risk operations are denied immediately (`fail-closed`).
2. **Replay & Tampering Prevention**: All messages include timestamps, nonces, and HMAC-SHA256 signatures derived from a pairing secret.
3. **Prompt Injection & Untrusted Input (F1)**: When an agent ingests an untrusted document, the session is marked `tainted`. Subsequent actions escalate from Medium to High severity and display the exact source file and line on the approval card.
