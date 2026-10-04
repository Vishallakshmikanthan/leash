# Leash Agent Receipt System (N5)

## Overview

The **Leash Agent Receipt System** produces an auditable, human-readable, and machine-verifiable Markdown report at the end of each AI agent session. It captures the full trajectory of agent actions, approvals, denials, blocked actions, changed files, added dependencies, security risk events, and overall session outcome.

Developers can paste this receipt directly into a GitHub or GitLab Pull Request description, giving reviewers complete visibility into what the agent attempted and how Leash governed it.

```
+--------------------------------------------------------------------------+
|                       LEASH AGENT PR RECEIPT                             |
+--------------------------------------------------------------------------+
| 1. Header & Outcome Badge    (Clean / Protected / Tainted / Blocked)     |
| 2. Executive Summary Table   (Evaluated, Approved, Denied, Tainted, ...) |
| 3. Session Scope & Env       (Worktree, Branch, Allowed Paths, Taint)    |
| 4. Blocked Actions Section   (Attempt, Gate, Reason, Safer Alternative)  |
| 5. Changed Files Table       (Status, Path, Additions, Deletions)        |
| 6. Added Dependencies Table  (Package Gate results, Typosquat checks)    |
| 7. Security & Risk Events    (Canary alerts, Injection taints, Rewinds)  |
| 8. Evaluated Actions Log     (Collapsible full audit trail for review)   |
| 9. PR Reviewer Checklist     (Actionable checkboxes for code reviewers)  |
+--------------------------------------------------------------------------+
```

---

## 1. Core Capabilities

| Section | Description | Source |
| :--- | :--- | :--- |
| **Session Outcome** | High-level verdict: `CLEAN COMPLETION`, `PROTECTED (RISKS MITIGATED)`, `TAINTED SESSION`, or `CRITICAL VIOLATION`. | `ReceiptBuilder.determine_session_outcome` |
| **Agent Actions** | All commands, file operations, and tool calls evaluated by the policy layer. | `daemon.audit_logger` |
| **Approvals & Denials** | Full count and breakdown of decisions by method (`auto`, `tap`, `biometric`, `rule`). | `contracts.models.Decision` |
| **Blocked Actions** | Detailed callout of denied commands, security gates triggered, reasons, and suggested safer alternatives. | `ReceiptBuilder.extract_blocked_actions` |
| **Changed Files** | Persistent tracking of files added, modified, or deleted in the session git worktree, preserved across worktree cleanup. | `session.worktree.WorktreeManager` |
| **Added Dependencies** | Packages evaluated by Package Gate, including lockfile verification status, typosquatting checks, and allow-once grants. | `gates.package_gate` |
| **Security Risk Events** | Canary credential reads (`Secret Fence`), prompt injections (`Provenance Tracker`), and git snapshots/rewinds. | `daemon.audit_logger` |
| **PR Reviewer Guidance** | Context-specific checklist and recommendation for PR author and reviewer. | `ReceiptBuilder.generate_markdown` |

---

## 2. Session Lifecycle Integration

1. **Session Termination (`POST /sessions/{id}/terminate`)**:
   - `SessionManager.terminate_session()` captures changed files from the worktree before cleanup.
   - Any uncommitted work is committed to the isolated git branch `leash/<session_id>`.
   - `ReceiptBuilder.generate_markdown()` builds the PR receipt.
   - `ReceiptBuilder.save_receipt()` writes the markdown receipt to `.leash/receipt.md`.
   - The daemon broadcasts `session_receipt` over WebSocket to connected Android Guard apps.

2. **HTTP API**:
   - `GET /sessions/{session_id}/receipt`: Returns structured JSON with receipt metadata or raw Markdown when `Accept: text/markdown` is requested.

3. **WebSocket API**:
   - `get_receipt`: Clients request the receipt for any session ID and receive `session_receipt`.
   - `terminate_session`: Returns the final session state with embedded receipt markdown.

4. **CLI**:
   - `leash report [--session <id>]`: Generates and prints the markdown receipt to stdout and writes it to `.leash/receipt.md`.
   - `leash run -- <cmd>`: Cleanly terminates the session on agent exit and generates the receipt automatically.

5. **Android Guard App**:
   - The **Session** screen features a dedicated **Agent Receipt (PR-Ready)** card.
   - **Copy PR Receipt**: Copies the Markdown receipt directly to the Android clipboard.
   - **Preview Receipt**: Displays the formatted receipt directly in a scrollable viewer.

---

## 3. Pull Request Formatting Standard

Receipts are formatted with GitHub-flavored Markdown:
- Collapsible `<details>` blocks for verbose action timelines to keep PR descriptions clean and scannable.
- Sanitized pipe characters (`\|`) to prevent Markdown table formatting breaks.
- Secret and credential sanitization via `SecretRedactor` to prevent accidental credential leakage in pull requests.
